#!/usr/bin/env python3
"""Web portal for the sandbox: live worker logs and control (stdlib, plus paramiko's `cryptography` for the
certificate).

  ./portal.py                                           # https://127.0.0.1:8765/?token=...
  ./portal.py --pants-down-mode --host 0.0.0.0   # no token, no TLS, every interface: see README

By default the portal listens on localhost only, over HTTPS with a self-signed certificate (fingerprint printed at
startup), and needs the token in the printed URL (stored in the state dir as portal_token; opening the URL once sets a
cookie). Reach it from another device by forwarding the port. --pants-down-mode turns all three off.
VM lifecycle (create/unlock/destroy) and `take` are CLI-only on purpose.
"""

import argparse
import datetime
import hmac
import ipaddress
import json
import os
import secrets
import ssl
import sys
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sandbox import EFFORTS, MODELS, Sandbox, SandboxError  # noqa: E402


COOKIE = "sbportal"
LOOPBACK = ("127.0.0.1", "localhost", "::1")
INSECURE_FLAG = "--pants-down-mode"


def _private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def load_token(sb: Sandbox) -> str:
    path = sb.state / "portal_token"
    if not path.exists():
        sb.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        _private_file(path, secrets.token_urlsafe(24).encode())
    return path.read_text().strip()


def load_cert(sb: Sandbox) -> Tuple[Path, Path, str]:
    """Self-signed certificate for localhost, made once (delete portal_cert.pem to replace it): cert, key, fingerprint."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    cert_path, key_path = sb.state / "portal_cert.pem", sb.state / "portal_key.pem"
    if not (cert_path.exists() and key_path.exists()):
        sb.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{sb.vm} portal")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1"))]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        _private_file(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
        _private_file(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert_path, key_path, cert.fingerprint(hashes.SHA256()).hex(":").upper()


class Server(ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        # failed TLS handshakes (plain-HTTP clients, a browser rejecting the certificate) and dropped connections
        if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError)):
            return
        super().handle_error(request, client_address)


def make_handler(sb: Sandbox, autoresume: bool = True, token: Optional[str] = None) -> type:
    """token None: no authentication (--pants-down-mode)."""
    mutate = threading.Lock()  # one state-changing operation at a time (sync vs spawn, etc.)
    stopping: Set[str] = set()  # stops run in the background, so several can be queued at once
    stopping_lock = threading.Lock()
    auto = {"enabled": autoresume}  # resume workers whose run ended on the usage limit, once it resets

    class Handler(BaseHTTPRequestHandler):
        server_version = "sandbox-portal"

        def log_message(self, fmt: str, *args: Any) -> None:
            if not self.path.startswith(("/api/log/", "/api/state", "/api/orch/log")):
                sys.stderr.write("portal: " + fmt % args + "\n")

        # ------------------------------------------------------------ helpers

        def authed(self) -> bool:
            if token is None:
                return True
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            got = c[COOKIE].value if COOKIE in c else self.headers.get("X-Token", "")
            return hmac.compare_digest(got, token)

        def send(self, code: int, body: Any, ctype: str = "application/json", extra: Optional[Dict[str, str]] = None) -> None:
            data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def api(self, fn: Callable[[], Any], lock: bool = False) -> None:
            try:
                if lock:
                    if not mutate.acquire(timeout=1):
                        return self.send(409, {"error": "another operation is in progress; try again shortly"})
                    try:
                        result = fn()
                    finally:
                        mutate.release()
                else:
                    result = fn()
                self.send(200, {"ok": True, "result": result})
            except SandboxError as e:
                self.send(400, {"error": str(e)})
            except Exception as e:  # keep the portal alive; show the error in the UI
                self.send(500, {"error": f"{type(e).__name__}: {e}"})

        # ------------------------------------------------------------ routes

        def do_GET(self) -> None:
            url = urlparse(self.path)
            q = parse_qs(url.query)
            if url.path == "/":
                if token is not None and "token" in q:
                    if not hmac.compare_digest(q["token"][0], token):
                        return self.send(403, "bad token", "text/plain")
                    c = f"{COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=31536000"
                    return self.send(303, b"", "text/plain", {"Location": "/", "Set-Cookie": c})
                if not self.authed():
                    return self.send(403, "Open the URL printed by portal.py (it contains the access token).", "text/plain")
                return self.send(200, PAGE, "text/html")
            if not self.authed():
                return self.send(403, {"error": "not authorised"})
            parts = url.path.strip("/").split("/")

            def num(k: str) -> Optional[int]:
                return int(q[k][0]) if q.get(k, [""])[0].isdigit() else None
            if url.path == "/api/state":
                return self.api(lambda: state())
            if len(parts) == 3 and parts[:2] == ["api", "log"]:
                return self.api(lambda: sb.log_view(parts[2], num("offset"), num("before")))
            if url.path == "/api/orch/sessions":
                return self.api(sb.orchestrator_sessions)
            if url.path == "/api/orch/log":
                return self.api(lambda: sb.orchestrator_log(q.get("session", [""])[0], num("offset"), num("before")))
            if len(parts) == 3 and parts[:2] == ["api", "review"]:
                return self.api(lambda: sb.review(parts[2]))
            if len(parts) == 3 and parts[:2] == ["api", "diff"]:
                return self.api(lambda: sb.diff(parts[2]))
            if url.path == "/api/learnings":
                return self.api(lambda: sb.learnings())
            self.send(404, {"error": "not found"})

        def do_POST(self) -> None:
            # custom header: cross-site forms can't set it, so this also blocks CSRF
            if not self.authed():
                return self.send(403, {"error": "not authorised"})
            if self.headers.get("X-Portal") != "1":
                return self.send(403, {"error": "missing X-Portal header"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            except ValueError:
                return self.send(400, {"error": "bad json"})
            name, prompt = body.get("name", ""), body.get("prompt", "")
            model, effort = body.get("model", ""), body.get("effort", "")
            routes: Dict[str, Callable[[], Any]] = {
                "/api/check": sb.check,
                "/api/sync": sb.sync,
                "/api/spawn": lambda: sb.spawn(name, prompt, model, effort),
                "/api/resume": lambda: sb.resume(name, prompt, model, effort),
                "/api/stop": lambda: stop(name),
                "/api/pause": lambda: sb.pause(name),
                "/api/unpause": lambda: sb.unpause(name),
                "/api/autoresume": lambda: set_auto(bool(body.get("enabled"))),
                "/api/rm": lambda: sb.rm(name),
                "/api/fetch": lambda: sb.fetch([name] if name else []),
            }
            fn = routes.get(urlparse(self.path).path)
            if fn is None:
                return self.send(404, {"error": "not found"})
            # stop/pause/unpause are quick or backgrounded and don't conflict with sync/spawn: never refused
            self.api(fn, lock=urlparse(self.path).path not in ("/api/stop", "/api/pause", "/api/unpause", "/api/autoresume"))

    def stop(name: str) -> str:
        sb.live_container(name)  # report "isn't running" now, not from the background
        with stopping_lock:
            if name in stopping:
                return f"{name} is already stopping"
            stopping.add(name)

        def run() -> None:
            try:
                sb.stop(name)
            except Exception as e:
                sys.stderr.write(f"portal: stopping {name} failed: {e}\n")
            finally:
                with stopping_lock:
                    stopping.discard(name)
        threading.Thread(target=run, daemon=True).start()
        return f"stopping {name}"

    def set_auto(enabled: bool) -> str:
        auto["enabled"] = enabled
        return f"auto-resume after the usage limit: {'on' if enabled else 'off'}"

    def autoresume_loop() -> None:
        while True:
            time.sleep(60)
            if not auto["enabled"] or not mutate.acquire(blocking=False):
                continue
            try:
                if sb.vm_state() == "running":
                    for m in sb.autoresume():
                        sys.stderr.write(f"portal: {m}\n")
            except Exception as e:  # keep the timer alive
                sys.stderr.write(f"portal: auto-resume: {type(e).__name__}: {e}\n")
            finally:
                mutate.release()
    threading.Thread(target=autoresume_loop, daemon=True).start()

    def state() -> Dict[str, Any]:
        vm = sb.vm_state()
        common = {"models": MODELS, "efforts": EFFORTS, "autoresume": auto["enabled"]}
        if vm != "running":
            return {"vm": vm, "locked": False, "workers": [], "usage": None, **common}
        data = sb.overview()
        with stopping_lock:
            for w in data["workers"]:
                w["stopping"] = w["name"] in stopping
        return {"vm": vm, "locked": sb.locked(), "ip": sb.vm_ip(), "workers": data["workers"], "usage": data.get("usage"),
                **common}

    return Handler


def serve(sb: Sandbox, host: str = "127.0.0.1", port: int = 8765, autoresume: bool = True,
          insecure: bool = False) -> None:
    """insecure: --pants-down-mode (no token, plain HTTP, any address)."""
    if insecure:
        httpd = Server((host, port), make_handler(sb, autoresume))
        print(f"sandbox portal: http://{host}:{port}/", flush=True)
        print(f"  {INSECURE_FLAG}: NO login, NO encryption. Anyone who can reach {host}:{port} can run, stop and delete\n"
              "  your workers, spend your subscription and read every log.", flush=True)
    else:
        if host not in LOOPBACK:
            raise SandboxError(f"refusing to listen on {host}: the portal only listens on localhost. From another "
                               f"device, forward the port (e.g. ssh -L {port}:127.0.0.1:{port} this-host). "
                               f"{INSECURE_FLAG} lifts this and turns off the login and TLS too.")
        token = load_token(sb)
        cert, key, fingerprint = load_cert(sb)
        httpd = Server((host, port), make_handler(sb, autoresume, token))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        # handshake in the request's thread, so a stalled client can't block accept()
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
        print(f"sandbox portal: https://{host}:{port}/?token={token}", flush=True)
        print(f"  self-signed certificate; your browser warns once. Accept it only if it shows SHA-256\n  {fingerprint}",
              flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>BW1 sandbox</title>
<style>
:root{--bg:#f6f5f2;--panel:#fff;--ink:#1d1d1b;--muted:#6b6a66;--line:#e2e0da;--accent:#3a5fcd;--ok:#2e7d4f;--warn:#b26a00;--bad:#c0392b;--code:#f0efeb;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--panel:#1f1f1d;--ink:#ecebe7;--muted:#9a9993;--line:#34332f;--accent:#7d9bf0;--ok:#5cbf85;--warn:#e0a040;--bad:#ef6f5f;--code:#2a2a27;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,sans-serif}
header{position:sticky;top:0;z-index:2;display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--line)}
header h1{font-size:15px;margin:0 8px 0 0}
.badge{padding:2px 8px;border-radius:99px;font-size:12px;border:1px solid var(--line)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
button,select,input,textarea{font:inherit;color:inherit}
button{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:5px 10px;cursor:pointer}
button:hover{border-color:var(--accent)}button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
button.danger{color:var(--bad)}button:disabled{opacity:.5;cursor:default}
main{display:grid;grid-template-columns:260px 1fr;gap:16px;padding:16px}
@media (max-width:760px){main{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;min-width:0}
.worker{display:block;width:100%;text-align:left;margin-bottom:6px;padding:8px}
.worker.sel{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
.worker small{display:block;color:var(--muted)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:var(--muted)}
.dot.running{background:var(--ok)}.dot.exited{background:var(--muted)}.dot.err{background:var(--bad)}
.dot.paused,.dot.stopping{background:var(--warn)}.dot.limited{background:none;border:2px solid var(--warn)}
.ts{color:var(--muted);font-size:11px;font-variant-numeric:tabular-nums;margin-right:6px;font-family:system-ui,sans-serif}
.ev>.ts{display:block}.ev.prompt{border-left:3px solid var(--accent);padding-left:8px}
#earlier{text-align:center}#earlier button{margin:4px 0 8px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;margin-top:10px}
.card{text-align:left;padding:10px;display:flex;flex-direction:column;gap:4px;min-width:0}
.card .last{word-break:break-word;max-height:9em;overflow:hidden;font-size:13px}.card .last p{margin:2px 0}
.auto{display:flex;align-items:center;gap:4px;margin:0;font-size:12px;color:var(--muted)}.auto input{width:auto}
label{display:block;font-size:12px;color:var(--muted);margin:8px 0 2px}
input,select,textarea{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px}
textarea{min-height:90px;resize:vertical}
.row{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
#log{margin-top:10px;max-height:calc(100vh - 200px);overflow:auto;border-top:1px solid var(--line);padding-top:8px}
.ev{margin:6px 0}.ev.text{white-space:pre-wrap}
details.tool{border-left:3px solid var(--line);padding-left:8px;margin:4px 0}
details.tool summary{cursor:pointer;color:var(--muted);font-family:ui-monospace,monospace;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
details.tool.err{border-left-color:var(--bad)}
pre{background:var(--code);padding:8px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word;margin:4px 0}
.result{border:1px solid var(--accent);border-radius:8px;padding:8px 12px}
.md blockquote{margin:6px 0;padding-left:10px;border-left:3px solid var(--line);color:var(--muted)}
.md hr{border:0;border-top:1px solid var(--line);margin:10px 0}
.md p{margin:6px 0}.md ul,.md ol{margin:6px 0;padding-left:22px}.md li.sub{margin-left:18px}
.md h3,.md h4,.md h5,.md h6{margin:10px 0 4px;font-size:14px}.md h3{font-size:15px}
.md code{background:var(--code);padding:1px 4px;border-radius:4px;font-size:12px;font-family:ui-monospace,monospace}
.md pre code{padding:0}.tw{overflow-x:auto}.md table{border-collapse:collapse;margin:6px 0;font-size:13px}
.md th,.md td{border:1px solid var(--line);padding:3px 8px;text-align:left;vertical-align:top}.md a{color:var(--accent)}
.meta{color:var(--muted);font-size:12px}
#toast{position:fixed;bottom:16px;right:16px;max-width:min(560px,90vw);padding:10px 14px;border-radius:8px;background:var(--panel);border:1px solid var(--line);white-space:pre-wrap;display:none;z-index:5}
.empty{color:var(--muted);padding:20px 0}
.usage{flex:1;display:flex;justify-content:center;align-items:center;gap:6px;min-width:0;
  font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.usage .sep{margin:0 4px;opacity:.5}
.bar{display:inline-block;width:64px;height:6px;border-radius:3px;background:var(--line);overflow:hidden}
.bar i{display:block;height:100%;background:var(--ok)}.bar i.mid{background:var(--warn)}.bar i.high{background:var(--bad)}
@media (max-width:760px){.usage{order:10;flex-basis:100%}}
</style></head><body>
<header>
  <h1>BW1 sandbox</h1>
  <span id="vm" class="badge">…</span><span id="lock" class="badge">…</span>
  <div id="usage" class="usage" title="subscription usage, from the latest worker API call"></div>
  <button onclick="act('check')">Check lockdown</button>
  <button onclick="act('sync')" title="push committed HEAD + toolchain to the VM">Sync</button>
  <button onclick="showOverview()">Overview</button>
  <button onclick="showOrch()" title="the orchestrator Claude session(s) started in this folder">Orchestrator</button>
  <button onclick="showLearnings()">Learnings</button>
  <label class="auto" title="resume workers whose run ended on the usage limit, once it resets"><input type="checkbox" id="auto" onchange="setAuto(this.checked)"> auto-resume</label>
</header>
<main>
  <section class="panel">
    <div class="row" style="justify-content:space-between"><b>Workers</b><button onclick="select(null)">+ New</button></div>
    <div id="workers" style="margin-top:8px"></div>
  </section>
  <section class="panel" id="detail"></section>
</main>
<div id="toast"></div>
<script>
let S = {workers: [], models: [], efforts: []}, view = 'new', sel = null, follow = true;
// log viewer: url prefix, next byte to follow from, first byte shown (for "Load earlier"), tool call elements by id
let L = {gen: 0, url: '', off: null, start: 0, timer: null, tools: {}};
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
// Minimal markdown: escape first, then add a known-safe subset of tags (worker output is untrusted)
function mdInline(t){
  return t.replace(/`([^`]+)`/g,'<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>').replace(/(^|\W)__([^_]+)__(?!\w)/g,'$1<b>$2</b>')
    .replace(/~~([^~]+)~~/g,'<s>$1</s>')
    .replace(/(^|[^*\w])\*([^*\s][^*]*)\*(?!\w)/g,'$1<i>$2</i>')
    .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g,'<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
}
const unesc = s => s.replace(/&(lt|gt|quot|amp);/g, (_, e) => ({lt:'<',gt:'>',quot:'"',amp:'&'}[e]));
function md(src){
  const lines=esc(src).split('\n'), out=[]; let i=0;
  while(i<lines.length){
    let l=lines[i];
    if(/^```/.test(l)){const buf=[];i++;while(i<lines.length&&!/^```/.test(lines[i]))buf.push(lines[i++]);i++;out.push('<pre>'+buf.join('\n')+'</pre>');continue}
    if(/^\s*([-*_])(\s*\1){2,}\s*$/.test(l)){out.push('<hr>');i++;continue}
    if(/^\s*&gt;/.test(l)){const buf=[];while(i<lines.length&&/^\s*&gt;/.test(lines[i]))buf.push(lines[i++].replace(/^\s*&gt;\s?/,''));
      out.push('<blockquote>'+md(unesc(buf.join('\n')))+'</blockquote>');continue}
    let m=l.match(/^(#{1,6})\s+(.*)/);
    if(m){out.push(`<h${Math.min(m[1].length+2,6)}>${mdInline(m[2])}</h${Math.min(m[1].length+2,6)}>`);i++;continue}
    if(/^\s*\|.*\|\s*$/.test(l)&&i+1<lines.length&&/^\s*\|[\s:|-]+\|\s*$/.test(lines[i+1])){
      const row=r=>r.trim().replace(/^\||\|$/g,'').split('|').map(c=>mdInline(c.trim()));
      let h='<table><tr>'+row(l).map(c=>'<th>'+c+'</th>').join('')+'</tr>';i+=2;
      while(i<lines.length&&/^\s*\|.*\|\s*$/.test(lines[i]))h+='<tr>'+row(lines[i++]).map(c=>'<td>'+c+'</td>').join('')+'</tr>';
      out.push('<div class="tw">'+h+'</table></div>');continue}
    if(/^\s*([-*]|\d+\.)\s+/.test(l)){
      const ordered=/^\s*\d+\./.test(l), items=[];
      while(i<lines.length&&(/^\s*([-*]|\d+\.)\s+/.test(lines[i])||(/^\s{2,}\S/.test(lines[i])&&items.length))){
        const it=lines[i].match(/^(\s*)([-*]|\d+\.)\s+(.*)/);
        if(it)items.push([it[1].length,it[3]]);else items[items.length-1][1]+=' '+lines[i].trim();i++}
      const tag=ordered?'ol':'ul';
      out.push(`<${tag}>`+items.map(([ind,t])=>`<li${ind>=2?' class="sub"':''}>${mdInline(t)}</li>`).join('')+`</${tag}>`);continue}
    if(!l.trim()){i++;continue}
    const para=[];while(i<lines.length&&lines[i].trim()&&!/^(```|#{1,6}\s|\s*([-*]|\d+\.)\s|\s*\||\s*&gt;)/.test(lines[i]))para.push(lines[i++]);
    if(!para.length)para.push(lines[i++]);
    out.push('<p>'+mdInline(para.join('<br>'))+'</p>');
  }
  return out.join('');
}
function toast(msg, bad){const t=$('#toast');t.textContent=msg;t.style.display='block';t.style.borderColor=bad?'var(--bad)':'var(--line)';clearTimeout(t._h);t._h=setTimeout(()=>t.style.display='none',bad?12000:5000)}
async function get(p){const r=await fetch(p);const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j.result}
async function post(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json','X-Portal':'1'},body:JSON.stringify(b||{})});const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j.result}
async function act(what, body, confirmText){
  if(confirmText && !confirmDialog(confirmText)) return;
  const b=document.activeElement&&document.activeElement.tagName==='BUTTON'?document.activeElement:null;
  if(b)b.disabled=true;  // only the clicked button waits; the rest of the page stays usable
  toast(what+'…');
  try{const r=await post('/api/'+what, body);toast(r||'done');}catch(e){toast(e.message,true)}
  if(b)b.disabled=false;
  refresh();
}
function confirmDialog(t){return window.confirm ? window.confirm(t) : true}
async function refresh(){
  try{S = await get('/api/state')}catch(e){$('#vm').textContent='error: '+e.message;return}
  $('#vm').innerHTML = 'VM <b class="'+(S.vm==='running'?'ok':'bad')+'">'+esc(S.vm)+'</b>';
  $('#lock').innerHTML = S.locked ? '<span class="ok">locked down</span>' : '<span class="bad">NOT locked</span>';
  renderUsage(S.usage);
  $('#auto').checked = !!S.autoresume;
  $('#workers').innerHTML = S.workers.length ? S.workers.map(w=>
    `<button class="worker ${w.name===sel?'sel':''}" onclick="select('${esc(w.name)}')"><span class="dot ${dotCls(w)}"></span><b>${esc(w.name)}</b><small>${esc(statusText(w))}${runInfo(w)?' · '+esc(runInfo(w)):''}${w.result&&w.result.cost!=null?' · $'+w.result.cost.toFixed(2):''}</small></button>`).join('')
    : '<div class="empty">No workers yet.</div>';
  if(view==='new' && !$('#newform')) renderNew();
  else if(view==='worker') renderHeader();
  else if(view==='overview') renderOverview();
}
const live = w => w.state==='running' || w.state==='paused';
function dotCls(w){
  if(w.stopping) return 'stopping';
  if(live(w)) return w.state;
  if(w.state==='created') return 'err';  // container made but never started
  if(w.limited) return 'limited';
  return w.result&&w.result.subtype!=='success'?'err':'exited';
}
function statusText(w){
  let t=(w.stopping?'stopping… ':'')+w.status;
  if(w.limited&&!live(w)){
    const r=w.limited.resetsAt;
    t+=' · usage limit'+(r?(S.autoresume?' · auto-resume after ':' · resets ')+fmtEpoch(r):'');
  }
  return t;
}
// Times: 24-hour, in the browser's time zone unless one is picked (Overview); a browser that hides its zone reports UTC
const detectedTZ = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
let TZ = (()=>{try{return localStorage.getItem('tz')||detectedTZ}catch(_){return detectedTZ}})();
function tfmt(d, opt){try{return d.toLocaleString([],{hourCycle:'h23',timeZone:TZ,...opt})}catch(_){return d.toLocaleString([],{hourCycle:'h23',...opt})}}
const sameDay = (a,b) => tfmt(a,{year:'numeric',month:'numeric',day:'numeric'})===tfmt(b,{year:'numeric',month:'numeric',day:'numeric'});
const fmtEpoch = t => tfmt(new Date(t*1000),{weekday:'short',hour:'2-digit',minute:'2-digit'});
function setTZ(z){TZ=z||detectedTZ;try{z&&z!==detectedTZ?localStorage.setItem('tz',z):localStorage.removeItem('tz')}catch(_){};refresh();if(L.url)startLog(L.url)}
function tzPicker(){
  const zones=(Intl.supportedValuesOf?Intl.supportedValuesOf('timeZone'):[]).filter(z=>z!==TZ);
  return `<label class="auto">times in <select style="width:auto" onchange="setTZ(this.value)"><option value="${esc(TZ)}">${esc(TZ)}${TZ===detectedTZ?' (detected)':''}</option>${TZ!==detectedTZ?`<option value="${esc(detectedTZ)}">${esc(detectedTZ)} (detected)</option>`:''}${zones.map(z=>`<option>${esc(z)}</option>`).join('')}</select></label>`;
}
function ago(t){const s=Math.max(0,Math.round(Date.now()/1000-t));return s<90?s+'s':s<5400?Math.round(s/60)+' min':s<172800?Math.round(s/3600)+' h':Math.round(s/86400)+' d'}
function fmtTs(ts){
  const d=new Date(ts); if(!ts||isNaN(d))return '';
  return sameDay(d,new Date())
    ? tfmt(d,{hour:'2-digit',minute:'2-digit',second:'2-digit'})
    : tfmt(d,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
}
function tsTag(ts){const t=fmtTs(ts);return t?`<time class="ts" title="${esc(tfmt(new Date(ts),{dateStyle:'medium',timeStyle:'long'}))}">${esc(t)}</time>`:''}
async function setAuto(on){try{toast(await post('/api/autoresume',{enabled:on}))}catch(e){toast(e.message,true)}refresh()}
function renderUsage(u){
  const el=$('#usage');
  if(!u){el.innerHTML='<span class="note">usage: no data yet</span>';return}
  const w=u.unifiedWindows||{}, fmt=(t,opt)=>tfmt(new Date(t*1000),opt);
  const row=(label,x,opt)=>{ if(!x)return''; const p=Math.round((x.utilization||0)*100);
    const cls=p>=90?'high':p>=70?'mid':'';
    return `<span>${label}</span><span class="bar" title="resets ${esc(fmt(x.resetsAt,opt))}"><i class="${cls}" style="width:${Math.min(p,100)}%"></i></span><span>${p}%</span><span class="sep">·</span>`};
  const age=Math.round((Date.now()/1000-(u.observed_at||0))/60);
  el.title=`session resets ${w.five_hour?fmt(w.five_hour.resetsAt,{hour:'2-digit',minute:'2-digit'}):'?'} · week resets ${w.seven_day?fmt(w.seven_day.resetsAt,{weekday:'short',hour:'2-digit',minute:'2-digit'}):'?'} · from the latest worker API call`;
  el.innerHTML = (u.status&&u.status!=='allowed'?`<b class="bad note">${esc(u.status)}</b>`:'')
    + row('5h',w.five_hour,{hour:'2-digit',minute:'2-digit'}) + row('7d',w.seven_day,{weekday:'short',hour:'2-digit',minute:'2-digit'})
    + `<span class="note">${age<1?'updated now':age+' min ago'}</span>`;
}
function models(cur){return S.models.map(m=>`<option value="${m}"${m===(cur||'')?' selected':''}>${m||'default model'}</option>`).join('')}
function efforts(cur){return S.efforts.map(e=>`<option value="${e}"${e===(cur||'')?' selected':''}>${e?'effort: '+e:'default effort'}</option>`).join('')}
const runInfo = w => [w.model, w.effort && 'effort '+w.effort].filter(Boolean).join(' · ');
const EXAMPLE_TASK='For the following TU, try to get all the .text functions to 100%, then do the data segments, then backport to 1.1 and 1.0, then set the TU to matching in configure.py: FileToDecompile.cpp';
// First focus selects the trailing TU name so typing replaces just that.
function pickTU(t){if(t.dataset.picked)return;t.dataset.picked=1;if(t.value!==EXAMPLE_TASK)return;
  setTimeout(()=>t.setSelectionRange(t.value.lastIndexOf(' ')+1,t.value.length))}
// The example's TU name must be replaced before the form submits.
function checkTU(t){t.setCustomValidity(/\bFileToDecompile\.cpp\s*$/.test(t.value)?'Replace FileToDecompile.cpp with your TU':'')}
function renderNew(){
  stopLog();
  $('#detail').innerHTML = `<form id="newform" onsubmit="event.preventDefault();spawn()">
    <b>New worker</b>
    <label>Name (letters, digits, - _)</label><input id="nname" required pattern="[A-Za-z0-9_-]+" autocomplete="off">
    <label>Model / effort</label><div class="row"><select id="nmodel" style="flex:1">${models()}</select><select id="neffort" style="flex:1">${efforts()}</select></div>
    <label>Task</label><textarea id="nprompt" required onfocus="pickTU(this)" oninput="checkTU(this)">${EXAMPLE_TASK}</textarea>
    <div class="row" style="margin-top:8px"><button class="primary">Spawn</button></div></form>`;
  checkTU($('#nprompt'));
}
async function spawn(){
  const name=$('#nname').value.trim();
  await act('spawn',{name,prompt:$('#nprompt').value,model:$('#nmodel').value,effort:$('#neffort').value});
  if(S.workers.some(w=>w.name===name)) select(name);
}
function select(name){
  sel=name; headKey='';
  if(name===null){view='new';renderNew();refresh();return}
  view='worker';
  $('#detail').innerHTML = `<div id="whead"></div><div id="wout"></div><div id="log"></div>`;
  renderHeader(); startLog('/api/log/'+encodeURIComponent(name)+'?'); refresh();
}
function metaText(w){const r=w.result;return `${statusText(w)}${runInfo(w)?' · '+runInfo(w):''}${r?` · ${r.turns} turns · $${(r.cost||0).toFixed(2)} · ${Math.round(r.seconds/60)} min`:''}`}
let headKey='';
function renderHeader(){
  const w=S.workers.find(x=>x.name===sel); if(!w||!$('#whead'))return;
  const running=live(w), n=esc(w.name);
  // Rebuild only when the buttons/forms change; otherwise the 5s refresh would wipe what you're typing
  const key=w.name+'|'+w.state+'|'+!!w.stopping;
  if(key===headKey && $('#wmeta')){$('#wmeta').textContent=metaText(w);return}
  headKey=key;
  $('#whead').innerHTML = `<div class="row" style="justify-content:space-between">
      <div><b style="font-size:16px">${esc(w.name)}</b> <span class="meta" id="wmeta">${esc(metaText(w))}</span></div>
      <div class="row">
        ${w.state==='running'&&!w.stopping?`<button onclick="act('pause',{name:'${n}'})" title="freeze in place: no API requests until unpaused">Pause</button>`:''}
        ${w.state==='paused'&&!w.stopping?`<button onclick="act('unpause',{name:'${n}'})">Unpause</button>`:''}
        ${running&&!w.stopping?`<button class="danger" onclick="act('stop',{name:'${n}'},'Stop ${n}?')">Stop</button>`:''}
        <button onclick="fetchReview('${esc(w.name)}')">Fetch + review</button>
        <button onclick="showDiff('${esc(w.name)}')">Diff</button>
        ${running||w.stopping?'':`<button class="primary" onclick="resumeNow('${n}')" title="continue its session with the last run's model and effort">Resume</button>`}
        ${running||w.stopping?'':`<button class="danger" onclick="act('rm',{name:'${esc(w.name)}'},'Delete worker ${esc(w.name)} and its clone? Fetch first if you want its work.').then(()=>select(null))">Remove</button>`}
        <label style="margin:0"><input type="checkbox" style="width:auto" ${follow?'checked':''} onchange="follow=this.checked"> follow</label>
      </div></div>
    <details><summary class="meta">Task</summary><div class="md">${md(w.prompt)}</div></details>
    ${running||w.stopping?'':`<form onsubmit="event.preventDefault();followup('${esc(w.name)}')" style="margin-top:6px">
      <label>Follow-up prompt (continues this worker's session)</label><textarea id="fprompt" required></textarea>
      <div class="row" style="margin-top:6px"><select id="fmodel" style="width:auto">${models(w.run_model)}</select><select id="feffort" style="width:auto">${efforts(w.effort)}</select><button class="primary">Send follow-up</button></div></form>`}`;
}
async function resumeNow(name){
  const w=S.workers.find(x=>x.name===name)||{};
  await act('resume',{name,prompt:'Continue the task from where you left off.',model:w.run_model||'',effort:w.effort||''});startLog(L.url,true)
}
async function followup(name){await act('resume',{name,prompt:$('#fprompt').value,model:$('#fmodel').value,effort:$('#feffort').value});startLog(L.url,true)}
async function fetchReview(name){
  $('#wout').innerHTML='<p class="meta">fetching…</p>';
  try{const f=await post('/api/fetch',{name});const r=await get('/api/review/'+encodeURIComponent(name));
      $('#wout').innerHTML=`<details open><summary class="meta">Review (${esc(f)})</summary><pre>${esc(r)}</pre></details>`}
  catch(e){$('#wout').innerHTML='';toast(e.message,true)}
}
async function showDiff(name){
  try{const d=await get('/api/diff/'+encodeURIComponent(name));$('#wout').innerHTML=`<details open><summary class="meta">Diff</summary><pre>${esc(d)||'(empty)'}</pre></details>`}
  catch(e){toast(e.message,true)}
}
async function showLearnings(){
  sel=null; view='learn'; stopLog(); refresh();
  try{const l=await get('/api/learnings');$('#detail').innerHTML=`<b id="learnview">Proposed learnings</b><div class="md">${l?md(l):'<p class="meta">(none yet)</p>'}</div>`}catch(e){toast(e.message,true)}
}
function showOverview(){view='overview';sel=null;stopLog();$('#detail').innerHTML='<div id="ov"></div>';refresh()}
function renderOverview(){
  const el=$('#ov'); if(!el)return;
  const count=st=>S.workers.filter(w=>w.state===st).length, lim=S.workers.filter(w=>w.limited&&!live(w)).length;
  el.innerHTML=`<div class="row" style="justify-content:space-between"><b>Overview</b><span class="meta">${tzPicker()} ${count('running')} running · ${count('paused')} paused${lim?' · '+lim+' stopped on usage limit':''} · ${S.workers.length} total</span></div>
    <div class="grid">${S.workers.map(w=>`<button class="card" onclick="select('${esc(w.name)}')">
      <div><span class="dot ${dotCls(w)}"></span><b>${esc(w.name)}</b></div>
      <div class="meta">${esc(statusText(w))}${runInfo(w)?' · '+esc(runInfo(w)):''}${w.result&&w.result.cost!=null?' · $'+w.result.cost.toFixed(2):''}</div>
      <div class="meta">${w.active_at?'last message '+ago(Date.parse(w.active_at)/1000)+' ago':'no messages yet'}</div>
      ${w.last?`<div class="last md">${md(w.last.text)}</div>`:''}</button>`).join('')||'<div class="empty">No workers yet.</div>'}</div>`;
}
async function showOrch(){
  view='orch'; sel=null; stopLog(); refresh();
  $('#detail').innerHTML=`<div class="row" style="justify-content:space-between"><b>Orchestrator</b>
      <div class="row"><select id="osess" style="width:auto;max-width:60vw" onchange="startLog('/api/orch/log?session='+encodeURIComponent(this.value)+'&')"></select>
      <label style="margin:0"><input type="checkbox" style="width:auto" ${follow?'checked':''} onchange="follow=this.checked"> follow</label></div></div>
    <div class="meta">Claude Code sessions started in this folder, newest first (read-only).</div><div id="log"></div>`;
  try{
    const ss=await get('/api/orch/sessions'); if(view!=='orch')return;
    if(!ss.length){$('#log').innerHTML='<div class="empty">No sessions yet: start one in this folder (see README, Orchestrator).</div>';return}
    $('#osess').innerHTML=ss.map(x=>`<option value="${esc(x.id)}">${esc(x.title||x.id.slice(0,8))} · ${esc(ago(x.mtime))} ago</option>`).join('');
    startLog('/api/orch/log?session='+encodeURIComponent(ss[0].id)+'&');
  }catch(e){toast(e.message,true)}
}
// Logs open on the newest events; "Load earlier" walks back. While catching up, windows are fetched back to back.
function stopLog(){clearTimeout(L.timer);L.timer=null;L.gen++}
function startLog(url,keep){
  stopLog(); L.url=url;
  if(!keep||L.off===null){L.off=null;L.start=0;L.tools={};$('#log').innerHTML='<div id="earlier"></div><div id="evs"></div>'}
  pollLog(L.gen);
}
async function pollLog(gen){
  let more=false;
  try{
    const first=L.off===null, r=await get(L.url+(first?'':'offset='+L.off));
    if(gen!==L.gen)return;
    const box=$('#evs'); if(!box)return;
    r.events.forEach(e=>addEvent(e,box));
    L.off=r.offset; more=!!r.more;
    if(first){L.start=r.start;renderEarlier()}
    if(r.events.length&&(follow||first)){const l=$('#log');l.scrollTop=l.scrollHeight}
  }catch(e){}
  if(gen!==L.gen)return;
  const w=S.workers.find(x=>x.name===sel);
  L.timer=setTimeout(()=>pollLog(gen), more?0:view==='orch'?3000:w&&w.state==='running'?2000:8000);
}
function renderEarlier(){const el=$('#earlier');if(el)el.innerHTML=L.start>0?'<button onclick="loadEarlier()">Load earlier</button>':''}
async function loadEarlier(){
  const gen=L.gen;
  try{
    const r=await get(L.url+'before='+L.start); if(gen!==L.gen)return;
    const tmp=document.createElement('div'); r.events.forEach(e=>addEvent(e,tmp));
    const log=$('#log'), h=log.scrollHeight;
    $('#evs').prepend(...tmp.childNodes);
    log.scrollTop+=log.scrollHeight-h;  // keep what you were reading in place
    L.start=r.start; renderEarlier();
  }catch(e){toast(e.message,true)}
}
function addEvent(e,box){
  const ts=tsTag(e.ts);
  if(e.kind==='text'){box.insertAdjacentHTML('beforeend',`<div class="ev md">${ts}${md(e.text)}</div>`)}
  else if(e.kind==='prompt'){box.insertAdjacentHTML('beforeend',`<div class="ev prompt md">${ts}${md(e.text)}</div>`)}
  else if(e.kind==='tool'){
    let first=e.input; try{const o=JSON.parse(e.input);first=o.command||o.file_path||o.pattern||o.description||e.input}catch(_){}
    const d=document.createElement('details');d.className='tool';
    d.innerHTML=`<summary>${ts}${esc(e.name)} · ${esc(String(first).split('\n')[0])}</summary><pre>${esc(e.input)}</pre>`;
    box.appendChild(d); L.tools[e.id]=d;
  } else if(e.kind==='tool_result'){
    const d=L.tools[e.id]; const html=`<pre>${esc(e.text)}</pre>`;
    if(d){d.insertAdjacentHTML('beforeend',html); if(e.error)d.classList.add('err')} else box.insertAdjacentHTML('beforeend',html);
  } else if(e.kind==='result'){
    box.insertAdjacentHTML('beforeend',`<div class="ev result md"><div class="meta"><b>${esc(e.subtype)}</b> · ${e.turns} turns · $${(e.cost||0).toFixed(2)}</div>${md(e.text)}</div>`);
  } else box.insertAdjacentHTML('beforeend',`<div class="ev meta">${ts}${esc(e.text)}</div>`);
}
refresh(); setInterval(refresh, 5000);
</script></body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1",
                    help=f"address to bind (only localhost, unless {INSECURE_FLAG})")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-autoresume", action="store_true", help="start with auto-resume after the usage limit off")
    ap.add_argument(INSECURE_FLAG, dest="insecure", action="store_true",
                    help="no access token, plain HTTP, and any --host. Anyone who can reach the port controls your workers")
    args = ap.parse_args()
    try:
        serve(Sandbox(), args.host, args.port, not args.no_autoresume, args.insecure)
    except SandboxError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
