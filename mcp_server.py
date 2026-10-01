#!/usr/bin/env python3
"""MCP server (stdio) exposing the sandbox to a local orchestrator Claude session.

Registered in the repo's .mcp.json as "sandbox", so tools appear as mcp__sandbox__<name>.
Deliberately missing: create/unlock/destroy/take/push — VM lifecycle and anything that
reaches outside the sandbox stays with the human (sandbox.py CLI or the portal).
"""

import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from sandbox import Sandbox, SandboxError, format_event  # noqa: E402

mcp = FastMCP("sandbox")
sb = Sandbox()


def _call(fn, *args) -> Any:
    try:
        return fn(*args)
    except SandboxError as e:
        return f"error: {e}"


@mcp.tool()
def vm_status() -> Dict[str, Any]:
    """VM state, lockdown filter, running workers, and subscription usage (5-hour session / 7-day utilization
    0..1 with reset times, from the latest worker API call). Throttle spawning when session usage is high."""
    try:
        state = sb.vm_state()
        running = state == "running"
        return {"vm": state, "locked": running and sb.locked(), "ip": sb.vm_ip() if running else "",
                "running_workers": sb.running_workers() if running else [],
                "usage": sb.usage() if running else None}
    except SandboxError as e:
        return {"error": str(e)}


@mcp.tool()
def check() -> str:
    """Prove the lockdown: github/1.1.1.1 unreachable, Anthropic API reachable. Run before a batch."""
    return _call(sb.check)


@mcp.tool()
def sync() -> str:
    """Push the user's committed HEAD to the VM as the workers' base, plus toolchain/orig/token."""
    return _call(sb.sync)


@mcp.tool()
def workers() -> List[Dict[str, Any]] | str:
    """All workers: container state/status (running, paused, exited), model, effort, prompt, final result
    (subtype, text, turns, cost), newest message (`last`), and `limited` (with `resetsAt`, epoch seconds) when
    the latest run ended on the subscription usage limit. The portal resumes those after the reset."""
    return _call(sb.workers)


@mcp.tool()
def spawn(name: str, prompt: str, model: str = "", effort: str = "") -> str:
    """Start a new worker on branch agent/<name> from base. model: '' (default), sonnet, opus, haiku, fable.
    effort: '' (default), low, medium, high, xhigh, max.
    The standard preamble (sandbox rules, knowledge tools) is prepended to the prompt."""
    return _call(sb.spawn, name, prompt, model, effort)


@mcp.tool()
def resume(name: str, prompt: str, model: str = "", effort: str = "") -> str:
    """Send a follow-up prompt to a FINISHED worker; it continues its own Claude session in its clone.
    model/effort as for spawn (empty = default, not the previous run's setting)."""
    return _call(sb.resume, name, prompt, model, effort)


@mcp.tool()
def stop(name: str) -> str:
    """Stop a running worker (its work so far stays in its clone; resume can continue it)."""
    return _call(sb.stop, name)


@mcp.tool()
def pause(name: str) -> str:
    """Freeze a running worker in place: it sends no API requests until unpause (e.g. to save session usage)."""
    return _call(sb.pause, name)


@mcp.tool()
def unpause(name: str) -> str:
    """Continue a paused worker exactly where it was frozen."""
    return _call(sb.unpause, name)


@mcp.tool()
def log(name: str, offset: int = 0, results: bool = False, max_events: int = 60) -> Dict[str, Any] | str:
    """Worker log from byte `offset` (pass back the returned offset to get only new events).
    results=True includes tool outputs. At most max_events (the newest) are returned."""
    try:
        sb.need_worker(name)
        events, new_offset = sb.read_log(name, offset)
    except SandboxError as e:
        return f"error: {e}"
    lines = [line for e in events if (line := format_event(e, results)) is not None]
    return {"offset": new_offset, "skipped": max(0, len(lines) - max_events), "events": lines[-max_events:]}


@mcp.tool()
def fetch(names: List[str] | None = None) -> str:
    """Fetch worker branches into the host repo as refs sandbox/<name> (all workers if names is empty)."""
    return _call(sb.fetch, names or [])


@mcp.tool()
def review(name: str) -> str:
    """Commits + diffstat of a fetched worker branch relative to the base it started from."""
    return _call(sb.review, name)


@mcp.tool()
def diff(name: str, max_chars: int = 60000) -> str:
    """Full diff of a fetched worker branch vs its base (truncated to max_chars)."""
    text = _call(sb.diff, name)
    return text if len(text) <= max_chars else text[:max_chars] + f"\n... ({len(text) - max_chars} more chars)"


@mcp.tool()
def learnings(names: List[str] | None = None) -> str:
    """Idioms workers proposed in ~/learnings.md, for curation into docs/msvc6_idioms.md."""
    return _call(sb.learnings, names or [])


@mcp.tool()
def remove(name: str) -> str:
    """Delete a worker's container and clone in the VM. Fetch first if its work matters."""
    return _call(sb.rm, name)


if __name__ == "__main__":
    mcp.run()
