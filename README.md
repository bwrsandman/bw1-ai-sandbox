# bw1-ai-sandbox

Runs several `claude -p --dangerously-skip-permissions` decomp workers at once, each in its own container inside a
dedicated libvirt/KVM VM, for [bw1-decomp](https://github.com/openblack/bw1-decomp). Nothing to install: clone this repo,
clone the project repos into it, run the scripts.

## Layout

```
bw1-ai-sandbox/            ← this repo
    sandbox.py             CLI + implementation        portal.py      web portal
    mcp_server.py          MCP server (orchestrator)   dockervm.py    Docker SDK over the VM connection
    vm_agent.py            helper run inside the VM    worker_entry.py  container entrypoint
    Dockerfile  cloud-init.yaml.in  nwfilter.xml.in    VM / image / network-filter templates
    sandbox.toml           settings: VM, what to copy, worker setup command, image packages
    preamble.md            prepended to every worker prompt
    local/                 (you create, ignored) MCP config + bridge for workers, see "Ghidra MCP"
    bw1-decomp/            (you clone, ignored) the project: sync sends its checked-out HEAD to workers
    bw1-build/             (you clone, ignored) provides orig/
```

You maintain `bw1-decomp/` and `bw1-build/` like any clone (your remotes, your branches). The sandbox only reads from
them, except `fetch`, which adds worker branches to `bw1-decomp/` as `sandbox/<name>`.

## Setup

```sh
git clone <your server>/bw1-ai-sandbox && cd bw1-ai-sandbox
git clone git@github.com:openblack/bw1-decomp.git     # then add your own remotes
git clone <bw1-build url> bw1-build
(cd bw1-decomp && python3 configure.py && ninja build/tools/dtk)   # once, so build/tools and build/compilers exist

./sandbox.py setup-host        # enable libvirt (sudo, once)
./sandbox.py create            # VM + worker image + lockdown (skip if the VM already exists)
./sandbox.py token             # paste `claude setup-token` output
./sandbox.py sync
```

Host packages (Arch): `libvirt`, `qemu-base`, `virt-install`, `edk2-ovmf`, `python-libvirt`, `python-paramiko`,
`python-docker`, `rsync`, `git`. Python ≥ 3.11.

## Everyday use

```sh
./sandbox.py spawn farmer "Follow the decomp-matching skill for unit VillagerFarmer." -m opus -e high
./sandbox.py status            # workers + session/week usage
./sandbox.py logs farmer       # live
./portal.py                    # or all of it in the browser (see Portal)

./sandbox.py fetch farmer      # worker branch -> bw1-decomp as sandbox/farmer
cd bw1-decomp && git log -p HEAD..sandbox/farmer    # review, cherry-pick, rebase, push as usual
```

`sync` sends what `bw1-decomp/` has **checked out and committed** as the workers' starting point (`base`), plus a fresh
`origin/main`, which every existing worker also gets as `origin/main`. Commit and check out what you want first.

## Threat model

```
host ── nwfilter (host-enforced egress allowlist)
 └─ VM (no host mounts, no graphics)
     ├─ /srv/decomp/mirror.git            base + main, pushed in by sync
     ├─ /srv/decomp/shared/{tree,data,mcp}  root-owned, read-only to workers
     └─ docker w-<name>  uid 2000, cap-drop ALL, no-new-privileges, read-only rootfs, private /tmp
          /work = clone on branch agent/<name>; origin = the mirror, read-only (fetch works, push can't)
```

- **Host files:** unreachable. The VM has no shared folders. Code goes in over ssh (`sync`) and comes out only when
  your PC runs `fetch`.
- **Network:** the libvirt nwfilter runs on the host, so root inside the VM can't change it. It allows only TCP 443 to
  the Anthropic API range, the host's Ghidra port, DHCP, and inbound ssh from the host. Everything else is dropped,
  including DNS and all IPv6. `check` proves it by connecting to real IPs (1.1.1.1, 8.8.8.8, GitHub).
- **GitHub credentials** exist only on your PC and are only used to fetch upstream. Nothing here pushes to GitHub.
- **What remains exposed:** agents can modify your Ghidra project through MCP; an agent could send the OAuth token to the
  Anthropic API (the only place it can reach); workers can read each other's clones and logs at `/peers` (read-only),
  and share the VM kernel.
- **Escape surface:** a KVM guest.

## Files and front ends

All host-side logic is `sandbox.py` (class `Sandbox`): libvirt bindings for the VM, one pooled paramiko connection (SFTP
for files and logs), the Docker SDK over it. External programs remain only where they're the real tool: `git`, `rsync`,
`virt-install`, the `sudo` disk steps, and `ssh` for interactive terminals.

| Front end | For |
|---|---|
| `./sandbox.py <command>` | you, in a terminal |
| `./portal.py [--host VPN_IP]` | you, in a browser or on your phone: live logs, spawn, stop, follow-ups, review, diff, usage |
| `mcp_server.py` (via `.mcp.json`) | an orchestrator Claude session started in this folder (tools `mcp__sandbox__*`) |

VM lifecycle (`create`, `unlock`, `destroy`) and `take` exist only in the CLI, so neither the portal nor an agent can
open the network or touch your branches.

## Commands

```
setup-host | create | token | sync | check | start | shutdown | destroy
spawn NAME "prompt" [-m MODEL] [-e EFFORT]   (also: -f FILE, or - for stdin)
resume NAME "prompt"                         follow-up for a finished worker (continues its session)
ls | status | logs NAME [--results] | tail NAME [N] | shell NAME | stop NAME | rm NAME
fetch [NAME...] | review NAME | diff NAME | take NAME [BRANCH] | learnings [NAME...]
unlock | build-image | lockdown              update the worker image (Claude Code version, packages)
ghidra-forward                               forward the VM-visible host IP to Ghidra on 127.0.0.1
ssh [CMD] | portal [--host H] [--port P]
```

Settings live in `sandbox.toml`; `SANDBOX_CONFIG=/path/to/other.toml` selects another file.

## Portal

```sh
./portal.py                      # prints http://127.0.0.1:8765/?token=...
./portal.py --host 100.x.y.z     # your VPN address, for the phone
```

Open the printed URL once; it sets a cookie. The token lives in the state dir (`portal_token`); delete it to rotate.
Only bind an address reachable over your VPN: the portal is plain HTTP and can spawn and stop workers (inside the locked
VM), but can't unlock the network or push.

## Orchestrator

```sh
claude --remote-control bw1-orchestrator   # in this folder; drive it from claude.ai/code or the app
> use the sandbox-orchestrator skill: run 4 workers on the top villager units
```

Approve the `sandbox` MCP server once. To avoid approving every poll, allow in `.claude/settings.local.json`:
`mcp__sandbox__vm_status`, `check`, `workers`, `log`, `review`, `diff`, `learnings`, `fetch`, `spawn`, `resume`
(each prefixed `mcp__sandbox__`). Leave `stop`, `remove` and `sync` asking.

## Ghidra MCP

Copy `local.example/` to `local/`, put the MCP bridge script there and adjust `mcp.json` (server name `ghidra`, so tool
names match bw1-decomp's `.claude/agents/`). `sync` copies `local/` to `/opt/mcp` in workers. Ghidra must listen on the
libvirt bridge IP, or run `./sandbox.py ghidra-forward`. A host firewall must allow that port on `virbr0`.

## Shared knowledge

`preamble.md` points workers at bw1-decomp's own knowledge tools (`tools/idioms.py`, `tools/decomp-similar.py`,
`tools/decomp-queue.py`); they must be in the commit you sync. New idioms go to each worker's `~/learnings.md`; the
orchestrator curates them (`learnings` tool) into `bw1-decomp/docs/msvc6_idioms.md`, you commit, the next `sync` hands
them to every worker.
