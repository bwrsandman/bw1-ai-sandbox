#!/usr/bin/env python3
"""Web portal for the sandbox: live worker logs and control (stdlib only).

  ./portal.py                                           # http://127.0.0.1:8765
  ./portal.py --host 0.0.0.0     # bind your VPN address to use it from a phone

Open the URL printed at startup; the portal has no authentication.
VM lifecycle (create/unlock/destroy) and `take` are CLI-only on purpose.
"""

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sandbox import EFFORTS, MODELS, Sandbox, SandboxError  # noqa: E402

def make_handler(sb: Sandbox) -> type:
    mutate = threading.Lock()  # one state-changing operation at a time (sync vs spawn, etc.)

    class Handler(BaseHTTPRequestHandler):
        server_version = "sandbox-portal"

        def log_message(self, fmt: str, *args: Any) -> None:
            if not self.path.startswith("/api/log/") and not self.path.startswith("/api/state"):
                sys.stderr.write("portal: " + fmt % args + "\n")

        # ------------------------------------------------------------ helpers

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
                return self.send(200, PAGE, "text/html")
            parts = url.path.strip("/").split("/")
            if url.path == "/api/state":
                return self.api(lambda: state())
            if len(parts) == 3 and parts[:2] == ["api", "log"]:
                off = int(q.get("offset", ["0"])[0])
                return self.api(lambda: dict(zip(("events", "offset"), sb.read_log(parts[2], off))))
            if len(parts) == 3 and parts[:2] == ["api", "review"]:
                return self.api(lambda: sb.review(parts[2]))
            if len(parts) == 3 and parts[:2] == ["api", "diff"]:
                return self.api(lambda: sb.diff(parts[2]))
            if url.path == "/api/learnings":
                return self.api(lambda: sb.learnings())
            self.send(404, {"error": "not found"})

        def do_POST(self) -> None:
            # custom header: cross-site forms can't set it, so this also blocks CSRF
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
                "/api/stop": lambda: sb.stop(name),
                "/api/rm": lambda: sb.rm(name),
                "/api/fetch": lambda: sb.fetch([name] if name else []),
            }
            fn = routes.get(urlparse(self.path).path)
            if fn is None:
                return self.send(404, {"error": "not found"})
            self.api(fn, lock=True)

    def state() -> Dict[str, Any]:
        vm = sb.vm_state()
        if vm != "running":
            return {"vm": vm, "locked": False, "workers": [], "usage": None, "models": MODELS, "efforts": EFFORTS}
        data = sb.overview()
        return {"vm": vm, "locked": sb.locked(), "ip": sb.vm_ip(), "workers": data["workers"], "usage": data.get("usage"),
                "models": MODELS, "efforts": EFFORTS}

    return Handler


def serve(sb: Sandbox, host: str = "127.0.0.1", port: int = 8765) -> None:
    httpd = ThreadingHTTPServer((host, port), make_handler(sb))
    print(f"sandbox portal: http://{host}:{port}/", flush=True)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("  listening beyond localhost: make sure this address is only reachable over your VPN", flush=True)
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
label{display:block;font-size:12px;color:var(--muted);margin:8px 0 2px}
input,select,textarea{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px}
textarea{min-height:90px;resize:vertical}
.row{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
#log{margin-top:10px;max-height:calc(100vh - 260px);overflow:auto;border-top:1px solid var(--line);padding-top:8px}
.ev{margin:6px 0}.ev.text{white-space:pre-wrap}
details.tool{border-left:3px solid var(--line);padding-left:8px;margin:4px 0}
details.tool summary{cursor:pointer;color:var(--muted);font-family:ui-monospace,monospace;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
details.tool.err{border-left-color:var(--bad)}
pre{background:var(--code);padding:8px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word;margin:4px 0}
.result{border:1px solid var(--accent);border-radius:8px;padding:8px 12px}
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
  <button onclick="showLearnings()">Learnings</button>
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
let S = {workers: [], models: [], efforts: []}, sel = null, logOff = 0, logTimer = null, follow = true, tools = {};
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
// Minimal markdown: escape first, then add a known-safe subset of tags (worker output is untrusted)
function mdInline(t){
  return t.replace(/`([^`]+)`/g,'<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>')
    .replace(/(^|[^*\w])\*([^*\s][^*]*)\*(?!\w)/g,'$1<i>$2</i>')
    .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g,'<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
}
function md(src){
  const lines=esc(src).split('\n'), out=[]; let i=0;
  while(i<lines.length){
    let l=lines[i];
    if(/^```/.test(l)){const buf=[];i++;while(i<lines.length&&!/^```/.test(lines[i]))buf.push(lines[i++]);i++;out.push('<pre>'+buf.join('\n')+'</pre>');continue}
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
    const para=[];while(i<lines.length&&lines[i].trim()&&!/^(```|#{1,6}\s|\s*([-*]|\d+\.)\s|\s*\|)/.test(lines[i]))para.push(lines[i++]);
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
  document.querySelectorAll('button').forEach(b=>b.disabled=true);
  toast(what+'…');
  try{const r=await post('/api/'+what, body);toast(r||'done');}catch(e){toast(e.message,true)}
  document.querySelectorAll('button').forEach(b=>b.disabled=false);
  refresh();
}
function confirmDialog(t){return window.confirm ? window.confirm(t) : true}
async function refresh(){
  try{S = await get('/api/state')}catch(e){$('#vm').textContent='error: '+e.message;return}
  $('#vm').innerHTML = 'VM <b class="'+(S.vm==='running'?'ok':'bad')+'">'+esc(S.vm)+'</b>';
  $('#lock').innerHTML = S.locked ? '<span class="ok">locked down</span>' : '<span class="bad">NOT locked</span>';
  renderUsage(S.usage);
  $('#workers').innerHTML = S.workers.length ? S.workers.map(w=>{
    const cls = w.state==='running'?'running':(w.result&&w.result.subtype!=='success'?'err':'exited');
    return `<button class="worker ${w.name===sel?'sel':''}" onclick="select('${esc(w.name)}')"><span class="dot ${cls}"></span><b>${esc(w.name)}</b><small>${esc(w.status)}${runInfo(w)?' · '+esc(runInfo(w)):''}${w.result&&w.result.cost!=null?' · $'+w.result.cost.toFixed(2):''}</small></button>`}).join('')
    : '<div class="empty">No workers yet.</div>';
  if(sel===null && !$('#newform') && !$('#learnview')) renderNew();
  else if(sel) renderHeader();
}
function renderUsage(u){
  const el=$('#usage');
  if(!u){el.innerHTML='<span class="note">usage: no data yet</span>';return}
  const w=u.unifiedWindows||{}, fmt=(t,opt)=>new Date(t*1000).toLocaleString([],opt);
  const row=(label,x,opt)=>{ if(!x)return''; const p=Math.round((x.utilization||0)*100);
    const cls=p>=90?'high':p>=70?'mid':'';
    return `<span>${label}</span><span class="bar" title="resets ${esc(fmt(x.resetsAt,opt))}"><i class="${cls}" style="width:${Math.min(p,100)}%"></i></span><span>${p}%</span><span class="sep">·</span>`};
  const age=Math.round((Date.now()/1000-(u.observed_at||0))/60);
  el.title=`session resets ${w.five_hour?fmt(w.five_hour.resetsAt,{hour:'2-digit',minute:'2-digit'}):'?'} · week resets ${w.seven_day?fmt(w.seven_day.resetsAt,{weekday:'short',hour:'2-digit',minute:'2-digit'}):'?'} · from the latest worker API call`;
  el.innerHTML = (u.status&&u.status!=='allowed'?`<b class="bad note">${esc(u.status)}</b>`:'')
    + row('5h',w.five_hour,{hour:'2-digit',minute:'2-digit'}) + row('7d',w.seven_day,{weekday:'short',hour:'2-digit',minute:'2-digit'})
    + `<span class="note">${age<1?'updated now':age+' min ago'}</span>`;
}
function models(){return S.models.map(m=>`<option value="${m}">${m||'default model'}</option>`).join('')}
function efforts(){return S.efforts.map(e=>`<option value="${e}">${e?'effort: '+e:'default effort'}</option>`).join('')}
const runInfo = w => [w.model, w.effort && 'effort '+w.effort].filter(Boolean).join(' · ');
function renderNew(){
  stopLog();
  $('#detail').innerHTML = `<form id="newform" onsubmit="event.preventDefault();spawn()">
    <b>New worker</b>
    <label>Name (letters, digits, - _)</label><input id="nname" required pattern="[A-Za-z0-9_-]+" autocomplete="off">
    <label>Model / effort</label><div class="row"><select id="nmodel" style="flex:1">${models()}</select><select id="neffort" style="flex:1">${efforts()}</select></div>
    <label>Task</label><textarea id="nprompt" required placeholder="e.g. follow the decomp-matching skill for unit VillagerFarmer"></textarea>
    <div class="row" style="margin-top:8px"><button class="primary">Spawn</button></div></form>`;
}
async function spawn(){
  const name=$('#nname').value.trim();
  await act('spawn',{name,prompt:$('#nprompt').value,model:$('#nmodel').value,effort:$('#neffort').value});
  if(S.workers.some(w=>w.name===name)) select(name);
}
function select(name){
  sel=name; tools={}; headKey='';
  if(name===null){renderNew();refresh();return}
  $('#detail').innerHTML = `<div id="whead"></div><div id="wout"></div><div id="log"></div>`;
  renderHeader(); startLog(); refresh();
}
function metaText(w){const r=w.result;return `${w.status}${runInfo(w)?' · '+runInfo(w):''}${r?` · ${r.turns} turns · $${(r.cost||0).toFixed(2)} · ${Math.round(r.seconds/60)} min`:''}`}
let headKey='';
function renderHeader(){
  const w=S.workers.find(x=>x.name===sel); if(!w||!$('#whead'))return;
  const running=w.state==='running';
  // Rebuild only when the buttons/forms change; otherwise the 5s refresh would wipe what you're typing
  const key=w.name+'|'+running;
  if(key===headKey && $('#wmeta')){$('#wmeta').textContent=metaText(w);return}
  headKey=key;
  $('#whead').innerHTML = `<div class="row" style="justify-content:space-between">
      <div><b style="font-size:16px">${esc(w.name)}</b> <span class="meta" id="wmeta">${esc(metaText(w))}</span></div>
      <div class="row">
        ${running?`<button class="danger" onclick="act('stop',{name:'${esc(w.name)}'},'Stop ${esc(w.name)}?')">Stop</button>`:''}
        <button onclick="fetchReview('${esc(w.name)}')">Fetch + review</button>
        <button onclick="showDiff('${esc(w.name)}')">Diff</button>
        ${running?'':`<button class="danger" onclick="act('rm',{name:'${esc(w.name)}'},'Delete worker ${esc(w.name)} and its clone? Fetch first if you want its work.').then(()=>select(null))">Remove</button>`}
        <label style="margin:0"><input type="checkbox" style="width:auto" ${follow?'checked':''} onchange="follow=this.checked"> follow</label>
      </div></div>
    <details><summary class="meta">Task</summary><pre>${esc(w.prompt)}</pre></details>
    ${running?'':`<form onsubmit="event.preventDefault();followup('${esc(w.name)}')" style="margin-top:6px">
      <label>Follow-up prompt (continues this worker's session)</label><textarea id="fprompt" required></textarea>
      <div class="row" style="margin-top:6px"><select id="fmodel" style="width:auto">${models()}</select><select id="feffort" style="width:auto">${efforts()}</select><button class="primary">Send follow-up</button></div></form>`}`;
}
async function followup(name){await act('resume',{name,prompt:$('#fprompt').value,model:$('#fmodel').value,effort:$('#feffort').value});startLog(true)}
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
  sel=null; stopLog();
  try{const l=await get('/api/learnings');$('#detail').innerHTML=`<b id="learnview">Proposed learnings</b><pre>${esc(l)||'(none yet)'}</pre>`}catch(e){toast(e.message,true)}
}
function stopLog(){clearTimeout(logTimer);logTimer=null}
function startLog(keep){stopLog(); if(!keep){logOff=0; $('#log').innerHTML=''} pollLog()}
async function pollLog(){
  const name=sel; if(!name)return;
  try{
    const r=await get('/api/log/'+encodeURIComponent(name)+'?offset='+logOff);
    if(name!==sel)return;
    logOff=r.offset; r.events.forEach(addEvent);
    if(r.events.length&&follow){const l=$('#log');l.scrollTop=l.scrollHeight}
  }catch(e){}
  const w=S.workers.find(x=>x.name===name);
  logTimer=setTimeout(pollLog, w&&w.state==='running'?2000:8000);
}
function addEvent(e){
  const log=$('#log'); if(!log)return;
  if(e.kind==='text'){log.insertAdjacentHTML('beforeend',`<div class="ev md">${md(e.text)}</div>`)}
  else if(e.kind==='tool'){
    let first=e.input; try{const o=JSON.parse(e.input);first=o.command||o.file_path||o.pattern||o.description||e.input}catch(_){}
    const d=document.createElement('details');d.className='tool';
    d.innerHTML=`<summary>${esc(e.name)} · ${esc(String(first).split('\n')[0])}</summary><pre>${esc(e.input)}</pre>`;
    log.appendChild(d); tools[e.id]=d;
  } else if(e.kind==='tool_result'){
    const d=tools[e.id]; const html=`<pre>${esc(e.text)}</pre>`;
    if(d){d.insertAdjacentHTML('beforeend',html); if(e.error)d.classList.add('err')} else log.insertAdjacentHTML('beforeend',html);
  } else if(e.kind==='result'){
    log.insertAdjacentHTML('beforeend',`<div class="ev result md"><div class="meta"><b>${esc(e.subtype)}</b> · ${e.turns} turns · $${(e.cost||0).toFixed(2)}</div>${md(e.text)}</div>`);
  } else log.insertAdjacentHTML('beforeend',`<div class="ev meta">${esc(e.text)}</div>`);
}
refresh(); setInterval(refresh, 5000);
</script></body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="address to bind (use your VPN address for phone access)")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    serve(Sandbox(), args.host, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
