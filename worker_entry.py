#!/usr/bin/env python3
"""Container entrypoint (mounted over /usr/local/bin/worker-entry): run the project's setup command,
run the task headless, snapshot-commit whatever is left.

WORKER_MODE=resume continues the previous Claude session with /task/followup.md; the log is appended to.
WORKER_MODEL / WORKER_EFFORT select model and effort ('' = Claude Code's default).
WORKER_SETUP is the setup command (JSON argv list, from sandbox.toml [worker] setup), run once for a new worker.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

HOME = Path("/home/agent")
LOG, ERR = HOME / "agent.jsonl", HOME / "agent.err"


def first_session_id() -> str:
    if LOG.exists():
        with open(LOG) as f:
            for line in f:
                try:
                    sid = json.loads(line).get("session_id")
                except ValueError:
                    continue
                if sid:
                    return sid
    return ""


def main() -> int:
    os.chdir("/work")
    args = ["claude", "-p", "--dangerously-skip-permissions", "--output-format", "stream-json", "--verbose"]
    if Path("/opt/mcp/mcp.json").exists():
        args += ["--mcp-config", "/opt/mcp/mcp.json"]
    if os.environ.get("WORKER_MODEL"):
        args += ["--model", os.environ["WORKER_MODEL"]]
    if os.environ.get("WORKER_EFFORT"):
        args += ["--effort", os.environ["WORKER_EFFORT"]]

    if os.environ.get("WORKER_MODE") == "resume":
        session = first_session_id()
        if not session:
            with open(ERR, "a") as err:
                err.write("no session to resume\n")
            return 1
        args += ["--resume", session]
        prompt = Path("/task/followup.md")
    else:
        setup = json.loads(os.environ.get("WORKER_SETUP") or "[]")
        if setup:
            with open(HOME / "setup.log", "w") as log:
                if subprocess.run(setup, stdout=log, stderr=subprocess.STDOUT).returncode != 0:
                    print("setup command failed, see ~/setup.log", file=sys.stderr)
        prompt = Path("/task/prompt.md")

    with open(prompt, "rb") as stdin, open(LOG, "ab") as stdout, open(ERR, "ab") as stderr:
        status = subprocess.run(args, stdin=stdin, stdout=stdout, stderr=stderr).returncode

    dirty = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True).stdout.strip()
    if dirty:
        branch = subprocess.run(["git", "branch", "--show-current"], capture_output=True, text=True).stdout.strip()
        subprocess.run(["git", "add", "-A"])
        subprocess.run(["git", "commit", "-q", "-m", f"sandbox {branch}: uncommitted work at exit (status {status})"])
    return status


if __name__ == "__main__":
    sys.exit(main())
