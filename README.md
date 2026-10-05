# bw1-ai-sandbox

Runs several `claude -p --dangerously-skip-permissions` decomp workers at once, each in its own container inside a
dedicated libvirt/KVM VM, for [bw1-decomp](https://github.com/openblack/bw1-decomp). Install the host dependencies below,
clone this repo and the project into it, then run the scripts.

> [!CAUTION]
> **Its security features are best effort. Do not rely on them to protect anything.**
>
> It is a personal tool for one person's machine. Nothing in it has been audited, reviewed, or tested against an
> attacker. Use it only on a machine and network you control, and only if you accept that it may expose them.
>
> - **Agents run unsupervised with `--dangerously-skip-permissions`.** They execute any command they decide to,
>   without asking anyone.
> - **`--pants-down-mode` removes all of the portal's protection.** By default the portal listens on
>   localhost only, over HTTPS, behind an access token. With this flag it has no login and no encryption, and it
>   listens on any `--host`. Anyone who can reach its port can then spawn, resume, stop and delete workers, spend
>   your Claude subscription, and read every worker log and orchestrator transcript. `--host 0.0.0.0` offers all of
>   that to every network your machine is on.
> - **The isolation is best effort, not a security boundary.** The VM, the network filter and the container settings
>   described under [Threat model](#threat-model) are what the scripts *try* to do, not guarantees. A bug in them, in
>   libvirt, QEMU/KVM, Docker or the kernel, or a simple misconfiguration, can give an agent your host or your network.
> - **Your Claude OAuth token is inside the VM**, in every worker's environment, where any agent can read it.
> - **Agents can write to your Ghidra project** through MCP, and the VM is allowed to reach the Ghidra port on your
>   host.
>
> This software is distributed without warranty. If you need real isolation, use a disposable machine you can
> wipe.

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
        orig/              (you supply, ignored by bw1-decomp) original game files, copied read-only to workers
```

You maintain `bw1-decomp/` like any clone (your remotes, your branches). The sandbox only reads from it, except
`fetch`, which adds worker branches to it as `sandbox/<name>`.

## Setup

Read the warning at the top first.

### 1. Host requirements

- Linux with KVM (`/dev/kvm`), `sudo`, and room for the VM (8 CPUs, 16 GB RAM and a 20 GB disk by default; change
  them under `[vm]` in `sandbox.toml`).
- Python ≥ 3.11.
- Packages (Arch): `libvirt`, `qemu-base`, `virt-install`, `edk2-ovmf`, `dnsmasq`, `libvirt-python`,
  `python-paramiko`, `python-docker`, `rsync`, `git`, `ninja`.
  - `dnsmasq` provides DHCP and DNS for libvirt's default network; `libvirt-python` provides the Python bindings used
    by the scripts.
  - `virt-install` is a separate package; installing libvirt alone does not provide it.
- [Claude Code](https://docs.claude.com/en/docs/claude-code) on the host, signed in to a subscription, to generate the
  workers' token with `claude setup-token`.
- Your user in the `libvirt` group (or equivalent), so the scripts can talk to libvirt without sudo.

### 2. Clone this repo and the project

```sh
git clone <your server>/bw1-ai-sandbox && cd bw1-ai-sandbox
git clone git@github.com:openblack/bw1-decomp.git     # then add your own remotes
```

The clone lives inside this folder and is ignored by git.

Then put the original game files in `bw1-decomp/orig/` as bw1-decomp's
[Getting Started](https://github.com/openblack/bw1-decomp/blob/main/docs/getting_started.md) describes (game binary
and DLLs, MSVC 6.0 libs, DirectX 7.0 DDK, Intel libraries). None of it is downloadable; you supply it. `sync` copies
that folder into the VM, and workers see it read-only as `orig/`. `orig/` may be a symlink to wherever you keep them.
To read them from somewhere else, set `source` under `[project.data]` in `sandbox.toml`.

### 3. Build the toolchain on the host

Workers have no internet, so the host downloads the tools and compiler once and `sync` copies them into the VM.
Default (game version 1.2):

```sh
(cd bw1-decomp && python3 configure.py --version BW1W120 && ninja build/tools/dtk build/compilers/MSVC/6.5)
```

For another version, follow [Choosing the game version](#choosing-the-game-version) instead.

### 4. Create the VM

```sh
./sandbox.py setup-host        # enable libvirt's sockets and default network (sudo, once per host)
./sandbox.py create            # download Debian, create the VM, build the worker image, lock the network down
./sandbox.py token             # paste the output of `claude setup-token`
./sandbox.py sync              # send bw1-decomp's checked-out HEAD, toolchain, data and local/ to the VM
./sandbox.py check             # confirm the VM reaches the Anthropic API and nothing else
```

`create` asks for sudo for the disk image steps. Skip it if the VM already exists. If it reports `virt-install`
missing, install it (`sudo pacman -S virt-install`) and run `create` again.

The ssh key, known_hosts and Claude token are kept in `~/.local/share/bw1-sandbox` (`state_dir` in `sandbox.toml`),
outside this repo.

### 5. Optional: Ghidra MCP

To give workers Ghidra, set up `local/` as described under [Ghidra MCP](#ghidra-mcp), then run `sync` again.

### 6. First worker

```sh
./sandbox.py spawn farmer "Follow the decomp-matching skill for unit VillagerFarmer." -m opus -e high
./sandbox.py logs farmer
```

See [Everyday use](#everyday-use) for the rest.

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
  original files (by default under `bw1-decomp/orig/BW1W100/`).

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
| `./portal.py` | you, in a browser or on your phone: live logs, spawn, stop, follow-ups, review, diff, usage |
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
ssh [CMD] | portal [--host H] [--port P] [--pants-down-mode]
```

Settings live in `sandbox.toml`; `SANDBOX_CONFIG=/path/to/other.toml` selects another file.

## Portal

```sh
./portal.py                      # prints https://127.0.0.1:8765/?token=...
```

The portal is secure by default:

- **Localhost only.** It refuses any `--host` other than `127.0.0.1`, `localhost` or `::1`. To use it from your phone
  or another computer, forward the port instead of exposing it, e.g. `ssh -L 8765:127.0.0.1:8765 your-pc`, or a
  reverse proxy you trust on your VPN.
- **HTTPS** with a self-signed certificate made on first start (`portal_cert.pem` and `portal_key.pem` in the state
  dir). Your browser warns about it once: accept it only if the SHA-256 fingerprint matches the one printed at startup.
  Delete both files to make a new certificate.
- **Access token.** Open the printed URL once; it sets a cookie (HttpOnly, Secure, SameSite=Strict) and drops the token
  from the address bar. Every page and API request without it gets 403. The token is kept in the state dir as
  `portal_token`; delete it and restart the portal to rotate it, which also logs out every browser.

Even with all three, anyone holding the token can spawn and stop workers (inside the locked VM), but can't unlock the
network or push.

> [!WARNING]
> `./portal.py --pants-down-mode` turns off **all three**: no token, plain HTTP, and any `--host`
> (`--host 0.0.0.0` for every interface). Anyone who can reach the port controls your workers and reads everything
> they and the orchestrator have written. Use it only on a network where you trust every device.

- **Logs** open on the newest events; *Load earlier* walks back through the log. Times are 24-hour, in the browser's
  time zone; pick another under *Overview* (a browser that hides its zone reports UTC).
- **Resume** continues a finished or stopped worker's session ("continue where you left off") with its last model and
  effort; the follow-up form below it takes your own prompt. A worker shown as *never started* (its container was
  created but not started) is resumed the same way.
- **Pause** freezes a worker in place (`docker pause`): it sends no API requests until *Unpause*. Its process, open
  files and in-flight tool calls stay as they were; a request that was streaming when frozen is retried by Claude Code.
- **Stop** runs in the background, so you can stop several workers in a row without waiting for each.
- **Overview** shows every worker at once: state, settings, cost, and its newest message.
- **Orchestrator** shows the transcripts of Claude Code sessions started in this folder (newest first, read-only).
- **Auto-resume** (header checkbox; on at startup unless `--no-autoresume`): a worker whose run ended on the subscription usage limit gets a
  follow-up ("the limit has reset, continue") with the same model and effort, a minute after the limit's reset time,
  and only within 3 hours of it (an older limit hit is left alone). Its runs are recorded as `"mode": "auto"` in the
  worker's `runs.jsonl`. Workers you stopped or paused are never touched. Without the portal, `./sandbox.py autoresume` does the same.

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

## License

[MIT](LICENSE). This software is distributed without warranty.
