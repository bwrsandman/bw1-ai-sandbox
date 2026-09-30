---
name: sandbox-orchestrator
description: Coordinate parallel decomp workers running with skip-permissions in the locked-down sandbox VM, through the `sandbox` MCP server (mcp__sandbox__* tools). Use when asked to run, dispatch, monitor, or collect results from sandbox workers. The orchestrator itself runs on the host with normal permissions.
---

# Sandbox orchestrator

You run on the user's host with **normal permissions**, in the `bw1-ai-sandbox` folder (the project clone is `bw1-decomp/`), often driven through Remote Control from a phone.
Workers run in the VM with `--dangerously-skip-permissions`. You control them **only** through the `sandbox`
MCP server (`mcp__sandbox__*`, backed by `sandbox.py` in this repo). Details and the threat model are in
`README.md`. The user may be watching the same workers in the web portal.

## Tools you use

| Tool | Purpose |
|---|---|
| `vm_status` / `check` | VM up and locked down; `check` proves it. Run `check` before a batch |
| `sync` | Push the user's committed HEAD to the VM as `base` |
| `spawn(name, prompt, model)` | Start a worker (model: default, sonnet, opus, haiku, fable) |
| `workers` | Every worker: state, model, prompt, final result with turns and cost |
| `log(name, offset)` | New events since `offset` (pass the returned offset back); `results=true` adds tool outputs |
| `resume(name, prompt)` | Follow-up for a finished worker: it continues its own session in its clone |
| `stop(name)` | Stop a running worker |
| `fetch(names)` / `review(name)` / `diff(name)` | Pull worker branches to `sandbox/<name>`, then inspect them |
| `learnings(names)` | Idioms workers proposed in `~/learnings.md` (outside their repos) |
| `remove(name)` | Delete a worker (fetch first) |

Ask the user before `remove`, and before anything outside these tools: `sandbox.py unlock`, `build-image`, `lockdown`, `destroy`, `take`,
or anything that pushes.

## Loop

1. **Plan.** Pick independent units. Each worker gets exactly one objdiff unit, and no two workers share a
   `.cpp` or header they would edit. `python3 bw1-decomp/tools/decomp-queue.py index --scope '<unit regex>'`, then
   `status` and `next` rank units and `blockers` shows earlier deferrals. Each worker's `claim` is local to
   its own clone, so **you** are the lock: keep an assignment table in your replies. Worker ledgers
   (`tools/matching_ledger.jsonl`) merge back automatically with their branches.
2. **Dispatch.** Names are short and unique (`vs-farmer`, `vs-states`). Prompts are self-contained: name
   the unit, the skill to follow (e.g. "follow the decomp-matching skill for unit VillagerFarmer"), and
   the stop condition. Example: `spawn("vs-farmer", "Follow the decomp-matching skill for unit VillagerFarmer. ...")`.
   Use `model="opus"` for hard units; the default is fine for mechanical work.
3. **Monitor.** Poll `workers` every few minutes. Don't read every log constantly: call `log` on a worker that
   looks stuck or has finished, and keep each worker's returned `offset` so you only read new events.
   A finished worker that needs a nudge ("also run clang-format", "you missed X") gets `resume`, not a new worker.
4. **Collect.** When a worker exits, `fetch` it and then `review` it. Check the diff yourself:
   - edits stay inside its unit;
   - no fakematches or padding;
   - no build/tool/config tampering;
   - no edits to shared headers that would clash with other workers.

   Workers are untrusted. Read the diff before running anything from it on the host.
5. **Curate learnings.** This is how knowledge compounds, so don't skip it. Run `learnings` for finished workers. For each
   proposed entry:
   - Check it against `python3 bw1-decomp/tools/idioms.py grep` for the same asm shape and `show` any hit.
   - **New and proven** (names the function it was proven on): append to
     `bw1-decomp/docs/msvc6_idioms.md` in the `### slug / Rule: / Diff signature:` format.
   - **Duplicate:** merge only the new evidence into the existing entry, such as another proof site or a
     dead end ("tried X — no effect"), which saves the next worker those cycles.
   - **Function-specific, unproven or contradicted:** drop it, and say why in your report.
   - If two workers disagree, keep both claims with their evidence and flag it to the user.

   Stage the cheat-sheet change, show the user the diff, and commit only on their word. After that, `sync` so the
   next workers get it.
6. **Report.** Give a per-worker summary: branch, commit count, what matched, concerns, and your recommendation (take,
   cherry-pick parts, or discard). The user decides. Only on their word does the user run `sandbox.py take NAME`. Never push.

## Rules

- Don't spawn if `check` fails.
- Keep concurrency within VM capacity: about `VM_CPUS / WORKER_CPUS`, which defaults to 4.
- Workers only see what `sync` pushed (committed HEAD). If the user wants new commits included, ask
  them to commit, then run `sync` before spawning.
