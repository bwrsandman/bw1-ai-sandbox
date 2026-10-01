#!/usr/bin/env python3
"""VM-side helper for sandbox.py. Runs inside the VM as root (sudo), one operation per call:

  sudo python3 /srv/decomp/bin/vm_agent.py OP   < JSON args   > JSON result

Errors go to stderr as {"error": ...} with exit status 1. Stdlib only (the VM has no pip packages).
"""

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT = Path("/srv/decomp")
WORKERS = ROOT / "workers"
MIRROR = ROOT / "mirror.git"
SHARED = ROOT / "shared"
WORKER_UID = WORKER_GID = 2000  # the container user; distinct from decomp (1000)


class AgentError(Exception):
    pass


def git(*args: str, cwd: Path = None, as_worker: Path = None) -> str:
    """git as root, or as the worker uid with HOME=<worker home> (so .git never gets root-owned files)."""
    kw: Dict[str, Any] = {}
    env = dict(os.environ)
    if as_worker is not None:
        kw.update(user=WORKER_UID, group=WORKER_GID, extra_groups=[])
        env["HOME"] = str(as_worker / "home")
    p = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        raise AgentError(f"git {' '.join(args[:2])} failed: {p.stderr.strip()[-500:]}")
    return p.stdout.strip()


def chown_tree(path: Path, skip: List[Path]) -> None:
    """Give `path` to the worker uid, except the `skip` trees (which stay root's, including their top directory).
    Never chown the toolchain hardlinks: they share inodes with /srv/decomp/shared, so that would hand every
    worker write access to the toolchain all workers use."""
    skip_set = {p.resolve() for p in skip}
    os.lchown(path, WORKER_UID, WORKER_GID)
    for dirpath, dirnames, filenames in os.walk(path):
        d = Path(dirpath)
        dirnames[:] = [n for n in dirnames if (d / n).resolve() not in skip_set]
        for n in dirnames + filenames:
            os.lchown(d / n, WORKER_UID, WORKER_GID)


def worker_dir(name: str) -> Path:
    if not name or not all(c.isalnum() or c in "-_" for c in name):
        raise AgentError(f"bad worker name {name!r}")
    return WORKERS / name


def mark_mirror_safe(w: Path) -> None:
    """The mirror belongs to decomp; the worker uid's git refuses it unless marked safe."""
    cfg = w / "home" / ".gitconfig"
    existing = cfg.read_text() if cfg.exists() else ""
    if str(MIRROR) not in existing:
        with open(cfg, "a") as f:
            f.write(f"[safe]\n\tdirectory = {MIRROR}\n")
    os.lchown(cfg, WORKER_UID, WORKER_GID)


# ------------------------------------------------------------------ operations

def op_prepare(a: Dict[str, Any]) -> Dict[str, Any]:
    """New worker: clone the mirror on agent/<name>, link the read-only toolchain, hand it to the worker uid."""
    w = worker_dir(a["name"])
    if w.exists():
        raise AgentError(f"worker {a['name']} already exists (sandbox.py rm {a['name']})")
    try:
        (w / "home").mkdir(parents=True)
        (w / "prompt.md").write_text(a["prompt"])
        (w / "followup.md").write_text("")
        mark_mirror_safe(w)
        repo = w / "repo"
        # --shared borrows the mirror's objects read-only instead of copying ~400 MB per worker.
        # origin stays: the mirror is mounted read-only in the container, so fetch works and push can't.
        git("clone", "-q", "--shared", "--no-checkout", str(MIRROR), str(repo))
        git("checkout", "-q", "-b", f"agent/{a['name']}", f"origin/{a['ref']}", cwd=repo)
        git("config", "user.name", f"sandbox {a['name']}", cwd=repo)
        git("config", "user.email", f"sandbox-{a['name']}@localhost", cwd=repo)
        # Toolchain: root-owned read-only hardlinks of the shared copy, at the same paths as in the repo
        # (the project's setup command points its build at them, so nothing gets downloaded).
        tree = Path(a.get("tree", str(SHARED / "tree")))
        rels = list(a.get("toolchain", []))
        for rel in rels:
            src, dst = tree / rel, repo / rel
            if not src.is_dir():
                raise AgentError(f"toolchain {rel} not in the VM yet (sandbox.py sync)")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, dst, copy_function=os.link, symlinks=True)
        if a.get("data_link"):
            (repo / a["data_link"]).symlink_to(a.get("data_mount", "/opt/data"))
        chown_tree(w, skip=[repo / rel for rel in rels])
    except Exception:
        shutil.rmtree(w, ignore_errors=True)  # never leave a half-made worker (it would block a retry)
        raise
    return {"path": str(w)}


def op_followup(a: Dict[str, Any]) -> Dict[str, Any]:
    """Record a follow-up prompt (kept as prompt.N.md) and make it the container's /task/followup.md."""
    w = worker_dir(a["name"])
    if not w.is_dir():
        raise AgentError(f"no worker {a['name']}")
    n = len(list(w.glob("prompt*.md")))
    (w / f"prompt.{n}.md").write_text(a["prompt"])
    (w / "followup.md").write_text(a["prompt"])
    mark_mirror_safe(w)  # workers made before this existed
    return {"prompt": f"prompt.{n}.md"}


def op_record_run(a: Dict[str, Any]) -> Dict[str, Any]:
    """Append what a run was started with (the stream-json log doesn't record effort)."""
    w = worker_dir(a["name"])
    with open(w / "runs.jsonl", "a") as f:
        f.write(json.dumps(a["run"]) + "\n")
    return {}


def op_rm(a: Dict[str, Any]) -> Dict[str, Any]:
    shutil.rmtree(worker_dir(a["name"]), ignore_errors=True)
    return {}


def op_update_workers(a: Dict[str, Any]) -> Dict[str, Any]:
    """Refresh origin/* in every worker from the mirror, as the worker uid. Adds origin to older workers."""
    updated, failed = [], {}
    for w in sorted(WORKERS.iterdir()) if WORKERS.is_dir() else []:
        repo = w / "repo"
        if not (repo / ".git").is_dir():
            continue
        try:
            mark_mirror_safe(w)
            remotes = git("remote", cwd=repo, as_worker=w).split()
            if "origin" not in remotes:
                git("remote", "add", "origin", str(MIRROR), cwd=repo, as_worker=w)
            git("fetch", "-q", "origin", "+refs/heads/*:refs/remotes/origin/*", cwd=repo, as_worker=w)
            updated.append(w.name)
        except AgentError as e:
            failed[w.name] = str(e)
    return {"updated": updated, "failed": failed}


# A run ended on the subscription limit: Claude Code's result text, as a fallback to the rate_limit_event status
LIMIT_RE = re.compile(r"usage limit|hit your (?:\w+ )?limit", re.I)


def tail_lines(log: Path, size: int = 512_000) -> List[bytes]:
    """The log's last `size` bytes as lines (the first may be partial; it then fails to parse and is skipped)."""
    with open(log, "rb") as f:
        f.seek(max(0, log.stat().st_size - size))
        return f.read().splitlines()


def last_rate_limit(lines: List[bytes]) -> Dict[str, Any]:
    """The newest rate_limit_event (Claude Code writes one per API response)."""
    for line in reversed(lines):
        if b'"rate_limit_event"' in line:
            try:
                return json.loads(line).get("rate_limit_info") or {}
            except ValueError:
                continue
    return {}


def last_activity(lines: List[bytes]) -> Tuple[Optional[Dict[str, Any]], str]:
    """The newest assistant text (for the overview) and the newest message timestamp."""
    last, active = None, ""
    for line in reversed(lines):
        if last is not None:
            break
        if b'"timestamp"' not in line:
            continue
        try:
            m = json.loads(line)
        except ValueError:
            continue
        active = active or m.get("timestamp") or ""
        if m.get("type") == "assistant":
            texts = [c.get("text", "") for c in m.get("message", {}).get("content", [])
                     if c.get("type") == "text" and c.get("text", "").strip()]
            if texts:
                last = {"text": texts[-1][:600], "ts": m.get("timestamp")}
    return last, active


def scan_log(log: Path) -> Dict[str, Any]:
    """One pass over a worker's log: model, newest result, and whether the newest run ended on the usage limit."""
    result = model = run_result = None
    run_limit: Dict[str, Any] = {}
    with open(log, "rb") as f:
        for line in f:
            if b'"type":"result"' not in line and b'"subtype":"init"' not in line and b'"rate_limit_event"' not in line:
                continue
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get("type") == "result":
                result = run_result = {"subtype": m.get("subtype"), "text": (m.get("result") or "")[:4000],
                                       "turns": m.get("num_turns"), "cost": m.get("total_cost_usd"),
                                       "seconds": (m.get("duration_ms") or 0) / 1000, "error": bool(m.get("is_error"))}
            elif m.get("type") == "rate_limit_event":
                run_limit = m.get("rate_limit_info") or {}
            elif m.get("subtype") == "init":
                model, run_result, run_limit = m.get("model"), None, {}
    limited = None
    if run_result is not None:
        rejected = run_limit.get("status") == "rejected"
        if rejected or (run_result["error"] and LIMIT_RE.search(run_result["text"])):
            windows = (run_limit.get("unifiedWindows") or {}).values()
            # only a rejection says which reset matters; otherwise use a window that is actually full
            resets = (run_limit.get("resetsAt") if rejected else None) or max(
                (w.get("resetsAt") or 0 for w in windows if (w.get("utilization") or 0) >= 1), default=0)
            limited = {"resetsAt": resets or None, "type": run_limit.get("rateLimitType")}
    return {"result": result, "model": model, "limited": limited}


def op_workers(a: Dict[str, Any]) -> Dict[str, Any]:
    """Per worker: final result, model (from the log), last run's settings, the task prompt, the newest message,
    and whether the latest run ended on the usage limit (`limited`, with the reset time).
    Plus the account's subscription usage, from the most recently written log that has a reading."""
    out: List[Dict[str, Any]] = []
    usage: Dict[str, Any] = {}
    usage_at = 0.0
    for w in sorted(WORKERS.iterdir()) if WORKERS.is_dir() else []:
        log = w / "home" / "agent.jsonl"
        size = log.stat().st_size if log.exists() else 0
        scan: Dict[str, Any] = {"result": None, "model": None, "limited": None}
        last, active = None, ""
        if size:
            tail = tail_lines(log)
            if log.stat().st_mtime > usage_at:
                info = last_rate_limit(tail)
                if info:
                    usage, usage_at = info, log.stat().st_mtime
            last, active = last_activity(tail)
            scan = scan_log(log)
        run: Dict[str, Any] = {}
        runs = w / "runs.jsonl"
        if runs.exists():
            lines = [l for l in runs.read_text().splitlines() if l.strip()]
            if lines:
                try:
                    run = json.loads(lines[-1])
                except ValueError:
                    pass
        prompt = (w / "prompt.md").read_text(errors="replace") if (w / "prompt.md").exists() else ""
        out.append({"name": w.name, "log_bytes": size, "result": scan["result"], "limited": scan["limited"],
                    "model": scan["model"] or run.get("model") or None, "run_model": run.get("model") or "",
                    "effort": run.get("effort") or None, "prompt": prompt.split("## Task", 1)[-1].strip()[:2000],
                    "last": last, "active_at": active, "learnings": (w / "home" / "learnings.md").exists()})
    return {"workers": out, "usage": {**usage, "observed_at": usage_at} if usage else None}


def op_install_token(a: Dict[str, Any]) -> Dict[str, Any]:
    secrets = ROOT / "secrets"
    secrets.mkdir(mode=0o700, exist_ok=True)
    path = secrets / "token.env"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(a["content"])
    return {}


def op_tree_digest(a: Dict[str, Any]) -> Dict[str, Any]:
    """sha1 of 'relpath size' lines (byte-sorted) — compared against the host's copy of the same tree."""
    root = Path(a["path"])
    entries = sorted(f"{p.relative_to(root)} {p.stat().st_size}".encode() for p in root.rglob("*") if p.is_file())
    return {"sha1": hashlib.sha1(b"\n".join(entries)).hexdigest(), "files": len(entries)}


def op_egress(a: Dict[str, Any]) -> Dict[str, Any]:
    """TCP connect results for (host, port) targets, by IP — DNS is blocked in the VM by design."""
    res = {}
    for host, port in a["targets"]:
        try:
            with socket.create_connection((host, port), timeout=a.get("timeout", 5)):
                res[f"{host}:{port}"] = True
        except OSError:
            res[f"{host}:{port}"] = False
    return {"results": res}


def op_cloud_init(a: Dict[str, Any]) -> Dict[str, Any]:
    p = subprocess.run(["cloud-init", "status", "--wait"], capture_output=True, text=True)
    return {"ok": p.returncode == 0, "status": p.stdout.strip()}


OPS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "prepare": op_prepare, "followup": op_followup, "record_run": op_record_run, "rm": op_rm,
    "update_workers": op_update_workers, "workers": op_workers, "install_token": op_install_token,
    "tree_digest": op_tree_digest, "egress": op_egress, "cloud_init": op_cloud_init,
}


def main() -> int:
    op = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        if op not in OPS:
            raise AgentError(f"unknown op {op!r}")
        raw = sys.stdin.read()
        print(json.dumps(OPS[op](json.loads(raw) if raw.strip() else {})))
        return 0
    except Exception as e:
        print(json.dumps({"error": f"{e}" if isinstance(e, AgentError) else f"{type(e).__name__}: {e}"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
