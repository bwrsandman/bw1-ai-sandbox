# bw1-ai-sandbox

Runs several `claude -p --dangerously-skip-permissions` decomp workers at once, each in its own container inside a
dedicated libvirt/KVM VM, for [bw1-decomp](https://github.com/openblack/bw1-decomp). Install the host dependencies below,
clone this repo and the project repos into it, then run the scripts.

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
# Default: version 1.2. For another version, follow "Choosing the game version" below before syncing.
(cd bw1-decomp && python3 configure.py --version BW1W120 && ninja build/tools/dtk build/compilers/MSVC/6.5)

./sandbox.py setup-host        # enable libvirt (sudo, once)
./sandbox.py create            # VM + worker image + lockdown (skip if the VM already exists)
./sandbox.py token             # paste `claude setup-token` output
./sandbox.py sync
```

Host packages (Arch): `libvirt`, `qemu-base`, `virt-install`, `edk2-ovmf`, `dnsmasq`, `libvirt-python`, `python-paramiko`,
`python-docker`, `rsync`, `git`. Python ≥ 3.11.

`dnsmasq` provides DHCP and DNS for libvirt's default network; `libvirt-python` provides the Python bindings used by
the scripts.

`virt-install` is a separate package; installing libvirt alone does not provide it. If `create` reports it missing:

```sh
sudo pacman -S virt-install
./sandbox.py create
```

### Choosing the game version

The host compiler download and the worker configuration must target the same game version:

| Game version | `configure.py --version` | Compiler | Ninja compiler target |
|---|---|---|---|
| 1.0 | `BW1W100` | MSVC 6.0 SP4 | `build/compilers/MSVC/6.4` |
| 1.1 | `BW1W110` | MSVC 6.0 SP4 | `build/compilers/MSVC/6.4` |
| 1.2 (default) | `BW1W120` | MSVC 6.0 SP5 | `build/compilers/MSVC/6.5` |

These mappings come from [bw1-decomp's configuration](https://github.com/openblack/bw1-decomp/blob/main/configure.py).
Building only `build/tools/dtk` does not download the compiler or populate `build/compilers`.

For version 1.0, run this from the sandbox repository instead of the default toolchain command above:

```sh
(cd bw1-decomp && python3 configure.py --version BW1W100 && ninja build/tools/dtk build/compilers/MSVC/6.4)
```

Then update `sandbox.toml` before syncing:

- In `[worker].setup`, add `"--version", "BW1W100"` immediately after `"configure.py"`, retaining all other arguments.
  Configuring the host checkout alone does not select the workers' version; without this argument they default to 1.2.
- In `[project.data]`, set `required = "BW1W100/runblack-decrypted.exe"`. The data source must contain that version's
  original files (by default under `bw1-build/orig/BW1W100/`).

Use `BW1W110` in both settings for version 1.1. After completing VM setup, run `./sandbox.py sync` to copy the
toolchain and data before spawning workers.

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
pause NAME | unpause NAME                    freeze a running worker in place (no API requests) / continue it
autoresume                                   loop: resume workers stopped by the usage limit once it resets
fetch [NAME...] | review NAME | diff NAME | take NAME [BRANCH] | learnings [NAME...]
unlock | build-image | lockdown              update the worker image (Claude Code version, packages)
ghidra-forward                               forward the VM-visible host IP to Ghidra on 127.0.0.1
ssh [CMD] | portal [--host H] [--port P]
```

Settings live in `sandbox.toml`; `SANDBOX_CONFIG=/path/to/other.toml` selects another file.

## Portal

```sh
./portal.py                      # prints http://127.0.0.1:8765/
./portal.py --host 100.x.y.z     # your VPN address, for the phone
```

Open the printed URL directly; no token or login is required. Anyone who can reach the portal can use its controls
and read the orchestrator's transcripts. Only bind an address reachable over your VPN: the portal is plain HTTP and can
spawn and stop workers (inside the locked VM), but can't unlock the network or push.

- **Logs** open on the newest events (with timestamps); *Load earlier* walks back through the log.
- **Pause** freezes a worker in place (`docker pause`): it sends no API requests until *Unpause*. Its process, open
  files and in-flight tool calls stay as they were; a request that was streaming when frozen is retried by Claude Code.
- **Stop** runs in the background, so you can stop several workers in a row without waiting for each.
- **Overview** shows every worker at once: state, settings, cost, and its newest message.
- **Orchestrator** shows the transcripts of Claude Code sessions started in this folder (newest first, read-only).
- **Auto-resume** (header checkbox; on at startup unless `--no-autoresume`): a worker whose run ended on the subscription usage limit gets a
  follow-up ("the limit has reset, continue") with the same model and effort, a minute after the limit's reset time.
  Workers you stopped or paused are never touched. Without the portal, `./sandbox.py autoresume` does the same.

## Orchestrator

```sh
claude --remote-control bw1-orchestrator   # in this folder; drive it from claude.ai/code or the app
> use the sandbox-orchestrator skill: run 4 workers on the top villager units
```

Approve the `sandbox` MCP server once. To avoid approving every poll, allow in `.claude/settings.local.json`:
`mcp__sandbox__vm_status`, `check`, `workers`, `log`, `review`, `diff`, `learnings`, `fetch`, `spawn`, `resume`,
`pause`, `unpause` (each prefixed `mcp__sandbox__`). Leave `stop`, `remove` and `sync` asking.

## Ghidra MCP

Copy `local.example/` to `local/`, put the MCP bridge script there and adjust `mcp.json` (server name `ghidra`, so tool
names match bw1-decomp's `.claude/agents/`). `sync` copies `local/` to `/opt/mcp` in workers. Ghidra must listen on the
libvirt bridge IP, or run `./sandbox.py ghidra-forward`. A host firewall must allow that port on `virbr0`.

## Shared knowledge

`preamble.md` points workers at bw1-decomp's own knowledge tools (`tools/idioms.py`, `tools/decomp-similar.py`,
`tools/decomp-queue.py`); they must be in the commit you sync. New idioms go to each worker's `~/learnings.md`; the
orchestrator curates them (`learnings` tool) into `bw1-decomp/docs/msvc6_idioms.md`, you commit, the next `sync` hands
them to every worker.
