#!/usr/bin/env python3
"""Parallel Claude Code decomp workers in a locked-down libvirt VM. See README.md.

Library + CLI: every command is a method on Sandbox, so the web portal (portal.py), the MCP server
(mcp_server.py) and the CLI share one implementation. Errors raise SandboxError with a user-facing message.

Native Python throughout: libvirt bindings for the VM, one pooled paramiko connection (SFTP for files and
logs), the Docker SDK over that connection for containers, and vm_agent.py for work inside the VM.
External programs remain only where they are the real tool: git and rsync (sync/fetch), virt-install and
the sudo disk steps (create/destroy), and ssh for interactive terminals (shell/ssh).
"""

import argparse
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import libvirt
import paramiko

HERE = Path(__file__).resolve().parent
CONFIG = Path(os.environ.get("SANDBOX_CONFIG", HERE / "sandbox.toml"))
IMAGE = "bw1-worker"
IMGDIR = Path("/var/lib/libvirt/images")
BASE_URL = "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
BIN = "/srv/decomp/bin"
WORKERS = "/srv/decomp/workers"
SHARED_TREE = "/srv/decomp/shared/tree"   # toolchain, at the same relative paths as in the repo
SHARED_DATA = "/srv/decomp/shared/data"   # project data (e.g. orig), mounted read-only in workers
SHARED_MCP = "/srv/decomp/shared/mcp"     # local/ (MCP config + bridge for workers)
NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MODELS = ("", "sonnet", "opus", "haiku", "fable")  # "" = Claude Code's default
EFFORTS = ("", "low", "medium", "high", "xhigh", "max")
# egress probes for `check`, by IP: DNS is blocked in the VM, so probing hostnames would only prove that
LEAK_PROBES = [("1.1.1.1", 443), ("8.8.8.8", 53)]
FALLBACK_API_IP = "160.79.104.10"
FALLBACK_GITHUB_IP = "140.82.112.3"

libvirt.registerErrorHandler(lambda _ctx, _err: None, None)  # errors arrive as exceptions; don't also print them


class SandboxError(Exception):
    pass


@dataclass
class Config:
    """sandbox.toml, resolved: paths relative to the file's folder become absolute."""
    vm_name: str
    state: Path
    vm_cpus: int
    vm_mem_mb: int
    vm_disk: str
    ghidra_port: int
    api_nets: List[str]
    repo: Path
    upstream_remote: str
    upstream_branch: str
    toolchain: List[str]
    data_source: Optional[Path]
    data_mount: str
    data_link: str
    data_verify: bool
    data_required: str
    worker_cpus: float
    worker_mem: str
    preamble: Path
    setup: List[str]
    packages: List[str]

    @classmethod
    def load(cls, path: Path = CONFIG) -> "Config":
        if not path.exists():
            raise SandboxError(f"no settings file {path}")
        with open(path, "rb") as f:
            t = tomllib.load(f)
        base = path.resolve().parent
        vm, proj, data, wk = t.get("vm", {}), t.get("project", {}), t.get("project", {}).get("data", {}), t.get("worker", {})
        remote, _, branch = proj.get("upstream", "origin/main").partition("/")
        return cls(
            vm_name=vm.get("name", "decomp-sandbox"),
            state=Path(vm.get("state_dir", f"~/.local/share/{vm.get('name', 'decomp-sandbox')}")).expanduser(),
            vm_cpus=int(vm.get("cpus", 8)), vm_mem_mb=int(vm.get("memory_mb", 16384)), vm_disk=str(vm.get("disk", "20G")),
            ghidra_port=int(vm.get("ghidra_port", 8080)), api_nets=list(vm.get("api_nets", ["160.79.104.0/23"])),
            repo=(base / proj.get("repo", "repo")).resolve(), upstream_remote=remote, upstream_branch=branch or "main",
            toolchain=list(proj.get("toolchain", [])),
            data_source=(base / data["source"]).resolve() if data.get("source") else None,
            data_mount=data.get("mount", "/opt/data"), data_link=data.get("link", ""),
            data_verify=bool(data.get("verify", True)), data_required=data.get("required", ""),
            worker_cpus=float(wk.get("cpus", 2)), worker_mem=str(wk.get("memory", "4g")),
            preamble=base / wk.get("preamble", "preamble.md"), setup=list(wk.get("setup", [])),
            packages=list(wk.get("packages", [])))


def run(cmd: List[str], *, input: Optional[bytes] = None, check: bool = True, capture: bool = True,
        env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    """For the external programs that remain (git, rsync, virt-install, sudo): argv lists only, never a shell."""
    try:
        p = subprocess.run(cmd, input=input, capture_output=capture, env=env)
    except FileNotFoundError:
        raise SandboxError(f"command not found: {cmd[0]}; install it and make sure it is on PATH") from None
    if check and p.returncode != 0:
        err = (p.stderr or b"").decode(errors="replace").strip() if capture else ""
        raise SandboxError(f"{cmd[0]} failed ({p.returncode}): {err[-800:]}")
    return p


def out(p: subprocess.CompletedProcess) -> str:
    return p.stdout.decode(errors="replace").strip()


def since(iso: str) -> str:
    """Docker timestamp -> '12 min' (the human-readable status string isn't part of the API)."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", iso or "")
    if not m or iso.startswith("0001"):
        return "?"
    s = int((datetime.now(timezone.utc) - datetime.fromisoformat(m.group(1) + "+00:00")).total_seconds())
    return f"{s}s" if s < 90 else f"{s // 60} min" if s < 5400 else f"{s // 3600} h" if s < 172800 else f"{s // 86400} d"


class Sandbox:
    def __init__(self, cfg: Optional[Config] = None):
        self.cfg = cfg or Config.load()
        self.state = self.cfg.state
        self.vm = self.cfg.vm_name
        self.repo = self.cfg.repo
        self._virt: Optional[libvirt.virConnect] = None
        self._ssh: Optional[paramiko.SSHClient] = None
        self._ssh_ip = ""
        self._docker: Any = None
        self._lock = threading.RLock()
        # git and rsync reach the VM with the dedicated key; nothing else gets these settings
        self.git_env = dict(os.environ)
        self.git_env["GIT_SSH_COMMAND"] = "ssh " + " ".join(shlex.quote(o) for o in self.ssh_cli_opts())

    # ---------------------------------------------------------------- libvirt

    @property
    def virt(self) -> libvirt.virConnect:
        with self._lock:
            if self._virt is None or not self._virt.isAlive():
                try:
                    self._virt = libvirt.open("qemu:///system")
                except libvirt.libvirtError as e:
                    raise SandboxError(f"can't connect to libvirt (sandbox.py setup-host?): {e}")
            return self._virt

    def dom(self) -> libvirt.virDomain:
        try:
            return self.virt.lookupByName(self.vm)
        except libvirt.libvirtError:
            raise SandboxError(f"no VM {self.vm} (sandbox.py create)")

    def vm_state(self) -> str:
        try:
            dom = self.virt.lookupByName(self.vm)
        except libvirt.libvirtError:
            return "absent"
        return {libvirt.VIR_DOMAIN_RUNNING: "running", libvirt.VIR_DOMAIN_SHUTOFF: "shut off",
                libvirt.VIR_DOMAIN_PAUSED: "paused", libvirt.VIR_DOMAIN_SHUTDOWN: "shutting down",
                libvirt.VIR_DOMAIN_CRASHED: "crashed"}.get(dom.state()[0], "other")

    def vm_ip(self) -> str:
        try:
            ifaces = self.dom().interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
        except (libvirt.libvirtError, SandboxError):
            return ""
        for iface in ifaces.values():
            for a in iface.get("addrs") or []:
                if a["type"] == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                    return a["addr"]
        return ""

    def host_ip(self) -> str:
        ip = ET.fromstring(self.virt.networkLookupByName("default").XMLDesc()).find("ip")
        return ip.get("address", "") if ip is not None else ""

    def locked(self) -> bool:
        return any(f.get("filter") == self.vm for f in ET.fromstring(self.dom().XMLDesc()).iter("filterref"))

    def api_ips(self) -> List[str]:
        try:
            return sorted({a[4][0] for a in socket.getaddrinfo("api.anthropic.com", 443, socket.AF_INET)})
        except OSError:
            return []

    def need_ip(self) -> str:
        st = self.vm_state()
        if st == "absent":
            raise SandboxError(f"no VM {self.vm} (sandbox.py create)")
        if st != "running":
            raise SandboxError(f"VM is {st} (sandbox.py start)")
        ip = self.vm_ip()
        if not ip:
            raise SandboxError(f"VM is running but has no DHCP lease yet (still booting? virsh console {self.vm})")
        return ip

    def _set_filter(self, attach: bool) -> None:
        root = ET.fromstring(self.dom().XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE))
        for iface in root.iter("interface"):
            for f in iface.findall("filterref"):
                iface.remove(f)
            if attach:
                ET.SubElement(iface, "filterref", filter=self.vm)
        self.virt.defineXML(ET.tostring(root, encoding="unicode"))
        self._restart()

    def _restart(self) -> None:
        dom = self.dom()
        self._drop_ssh()
        if dom.isActive():
            dom.shutdown()
            deadline = time.time() + 120
            while dom.isActive():
                if time.time() > deadline:
                    dom.destroy()
                time.sleep(2)
        dom.create()
        self.wait_ssh()

    # ---------------------------------------------------------------- ssh (paramiko)

    def ssh_cli_opts(self) -> List[str]:
        """Options for the external programs that still use ssh (git, rsync, interactive terminals)."""
        return ["-i", str(self.state / "id_ed25519"), "-o", f"UserKnownHostsFile={self.state / 'known_hosts'}",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5"]

    def _drop_ssh(self) -> None:
        with self._lock:
            if self._ssh is not None:
                self._ssh.close()
            self._ssh, self._ssh_ip, self._docker = None, "", None

    def ssh(self, timeout: float = 5) -> paramiko.SSHClient:
        """One pooled connection to the VM (portal threads share it; paramiko multiplexes channels)."""
        with self._lock:
            ip = self.need_ip()
            t = self._ssh.get_transport() if self._ssh is not None else None
            if t is not None and t.is_active() and self._ssh_ip == ip:
                return self._ssh
            self._drop_ssh()
            client = paramiko.SSHClient()
            known = self.state / "known_hosts"
            if known.exists():
                client.load_host_keys(str(known))
            # accept-new: remember the VM's key on first contact; a *changed* key still fails (BadHostKeyException)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(ip, username="decomp", key_filename=str(self.state / "id_ed25519"),
                               look_for_keys=False, allow_agent=False, timeout=timeout, banner_timeout=timeout,
                               auth_timeout=timeout)
            except (OSError, paramiko.SSHException) as e:
                raise SandboxError(f"ssh to VM failed: {e}")
            client.save_host_keys(str(known))
            client.get_transport().set_keepalive(30)
            self._ssh, self._ssh_ip = client, ip
            self._push_bin(client)  # every new connection: the VM never runs an older helper than this code
            return client

    def exec(self, argv: List[str], stdin: bytes = b"", check: bool = True) -> Tuple[int, bytes, bytes]:
        """Run a program in the VM (argv, quoted for the remote login shell)."""
        chan = self.ssh().get_transport().open_session()
        chan.exec_command(shlex.join(argv))
        if stdin:
            chan.sendall(stdin)
        chan.shutdown_write()
        stdout, stderr = chan.makefile("rb").read(), chan.makefile_stderr("rb").read()
        code = chan.recv_exit_status()
        chan.close()
        if check and code != 0:
            raise SandboxError(f"{argv[0]} failed in VM ({code}): {stderr.decode(errors='replace').strip()[-800:]}")
        return code, stdout, stderr

    def agent(self, op: str, **args: Any) -> Dict[str, Any]:
        """Call vm_agent.py (as root in the VM) with JSON args; returns its JSON result."""
        code, stdout, stderr = self.exec(["sudo", "python3", f"{BIN}/vm_agent.py", op],
                                         json.dumps(args).encode(), check=False)
        if code != 0:
            try:
                msg = json.loads(stderr)["error"]
            except (ValueError, KeyError, TypeError):
                msg = f"vm_agent {op} failed: {stderr.decode(errors='replace').strip()[-800:]}"
            raise SandboxError(msg)
        return json.loads(stdout)

    def read_file(self, path: str, offset: int = 0, limit: int = 2_000_000) -> bytes:
        with self.ssh().open_sftp() as sftp:
            try:
                with sftp.open(path, "rb") as f:
                    f.seek(offset)
                    return f.read(limit)
            except FileNotFoundError:
                return b""

    def wait_ssh(self, timeout: float = 600) -> None:
        deadline = time.time() + timeout
        while True:
            try:
                self.ssh(timeout=5)
                return
            except SandboxError:
                if time.time() > deadline:
                    raise SandboxError(f"VM not reachable over ssh; check boot with: virsh -c qemu:///system console {self.vm}")
                time.sleep(5)

    def push_bin(self) -> None:
        """The VM helper and the container entrypoint are copied on connect and on every spawn:
        fixes need no image rebuild."""
        self._push_bin(self.ssh())

    @staticmethod
    def _push_bin(client: paramiko.SSHClient) -> None:
        with client.open_sftp() as sftp:
            try:
                sftp.stat(BIN)
            except FileNotFoundError:
                return  # fresh VM: create() makes the directory, then pushes
            for f in ("vm_agent.py", "worker_entry.py"):
                sftp.put(str(HERE / f), f"{BIN}/{f}")
                sftp.chmod(f"{BIN}/{f}", 0o755)

    # ---------------------------------------------------------------- docker (SDK over the paramiko connection)

    @property
    def docker(self) -> Any:
        with self._lock:
            client = self.ssh()
            if self._docker is None:
                try:
                    from dockervm import docker_over_paramiko
                except ImportError:
                    raise SandboxError("the Docker SDK is missing on this machine: sudo pacman -S python-docker")
                self._docker = docker_over_paramiko(client)
            return self._docker

    def _containers(self) -> Dict[str, Any]:
        return {c.name[2:]: c for c in self.docker.containers.list(all=True, filters={"name": "^w-"})}

    def _container(self, name: str) -> Any:
        return self._containers().get(name)

    def running_workers(self) -> List[str]:
        return [n for n, c in self._containers().items() if c.status == "running"]

    @staticmethod
    def _status(c: Any) -> str:
        st = c.attrs.get("State", {})
        if c.status == "running":
            return f"running {since(st.get('StartedAt', ''))}"
        if c.status == "exited":
            return f"exited ({st.get('ExitCode')}) {since(st.get('FinishedAt', ''))} ago"
        return c.status

    # ---------------------------------------------------------------- VM lifecycle

    def setup_host(self) -> str:
        run(["sudo", "systemctl", "enable", "--now", "virtqemud.socket", "virtnetworkd.socket",
             "virtnwfilterd.socket", "virtstoraged.socket"], capture=False)
        try:
            net = self.virt.networkLookupByName("default")
        except libvirt.libvirtError:
            raise SandboxError("libvirt 'default' network missing")
        net.setAutostart(1)
        if not net.isActive():
            net.create()
        return "host ready"

    def create(self) -> str:
        if shutil.which("virt-install") is None:
            raise SandboxError("virt-install is missing; on Arch Linux, install it with: sudo pacman -S virt-install")
        if self.vm_state() != "absent":
            raise SandboxError(f"{self.vm} already exists")
        self.state.mkdir(parents=True, exist_ok=True)
        self.state.chmod(0o700)
        key = self.state / "id_ed25519"
        if not key.exists():
            # paramiko can't write OpenSSH-format ed25519 keys; ssh-keygen is the tool for that
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", self.vm, "-f", str(key)])
        base, disk = IMGDIR / f"{self.vm}-base.qcow2", IMGDIR / f"{self.vm}.qcow2"
        # privileged steps (root-owned image directory) stay as sudo programs
        if not base.exists():
            run(["sudo", "curl", "-fL", "-o", str(base), BASE_URL], capture=False)
        run(["sudo", "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(disk),
             self.cfg.vm_disk], capture=False)
        ud = self.state / "cloud-init.yaml"
        ud.write_text((HERE / "cloud-init.yaml.in").read_text().replace(
            "@SSH_PUBKEY@", (self.state / "id_ed25519.pub").read_text().strip()))
        try:
            # virt-install builds the cloud-init seed and domain XML; no bindings equivalent for that part.
            # No filesystem shares, no graphics: nothing on the host is reachable from inside.
            # UEFI: the Debian 13 cloud image reset-loops under SeaBIOS, and virt-install ejects the
            # cloud-init seed after that first boot, so a BIOS VM can never be provisioned.
            run(["virt-install", "--connect", "qemu:///system", "--name", self.vm, "--memory", str(self.cfg.vm_mem_mb),
                 "--vcpus", str(self.cfg.vm_cpus), "--cpu", "host-passthrough",
                 "--boot", "uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no",
                 "--disk", f"path={disk},format=qcow2,bus=virtio", "--import", "--osinfo", "linux2022",
                 "--network", "network=default,model=virtio", "--graphics", "none", "--noautoconsole",
                 "--cloud-init", f"user-data={ud}"], capture=False)
        finally:
            ud.unlink(missing_ok=True)
        print("waiting for first boot + cloud-init (a few minutes)...", file=sys.stderr)
        self.wait_ssh(900)
        self.exec(["sudo", "install", "-d", "-o", "decomp", "-g", "decomp", BIN])
        self.push_bin()
        if not self.agent("cloud_init")["ok"]:
            raise SandboxError("cloud-init reported errors: sandbox.py ssh cloud-init status --long")
        self.build_image()
        return self.lockdown()

    def build_image(self) -> str:
        if self.locked():
            raise SandboxError("VM is locked down; image build needs network: sandbox.py unlock first")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for f in ("Dockerfile", "worker_entry.py"):
                tar.add(str(HERE / f), arcname=f)
        buf.seek(0)
        self.docker.images.build(fileobj=buf, custom_context=True, tag=IMAGE, rm=True, forcerm=True,
                                 buildargs={"PACKAGES": " ".join(self.cfg.packages)})
        self.docker.api.prune_builds()
        return "worker image built"

    def lockdown(self) -> str:
        rules = []
        for net in self.cfg.api_nets:
            addr, mask = net.split("/")
            rules.append(f"  <rule action='accept' direction='out' priority='500'><tcp dstipaddr='{addr}' "
                         f"dstipmask='{mask}' dstportstart='443'/></rule>")
        for ip in self.api_ips():
            rules.append(f"  <rule action='accept' direction='out' priority='500'><tcp dstipaddr='{ip}' "
                         f"dstportstart='443'/></rule>")
        xml = (HERE / "nwfilter.xml.in").read_text().replace("@HOST_IP@", self.host_ip())
        xml = xml.replace("@GHIDRA_PORT@", str(self.cfg.ghidra_port)).replace("@API_RULES@\n", "\n".join(rules) + "\n")
        root = ET.fromstring(xml)
        try:
            existing = self.virt.nwfilterLookupByName(self.vm)
        except libvirt.libvirtError as e:
            if e.get_error_code() != libvirt.VIR_ERR_NO_NWFILTER:
                raise
        else:
            # Preserve the identity when updating an already-defined filter.
            uuid = root.find("uuid")
            if uuid is None:
                uuid = ET.SubElement(root, "uuid")
            uuid.text = existing.UUIDString()
        defined = self.virt.nwfilterDefineXML(ET.tostring(root, encoding="unicode"))
        if not self.locked():
            self._set_filter(True)
            # Reapply to the running interface after the restart, as a subsequent
            # lockdown does. Use libvirt's XML to retain the assigned UUID.
            self.virt.nwfilterDefineXML(defined.XMLDesc(0))
        return self.check()

    def unlock(self) -> str:
        if self.running_workers():
            raise SandboxError("workers running; stop them first")
        self._set_filter(False)
        return "UNLOCKED: VM has open internet. Run 'sandbox.py lockdown' when done."

    def check(self) -> str:
        if not self.locked():
            raise SandboxError("filter not attached to running VM")
        api = (self.api_ips() or [FALLBACK_API_IP])[0]
        try:
            github = socket.getaddrinfo("github.com", 443, socket.AF_INET)[0][4][0]
        except OSError:
            github = FALLBACK_GITHUB_IP
        probes = LEAK_PROBES + [(github, 443)]
        res = self.agent("egress", targets=probes + [(api, 443)])["results"]
        api_key = f"{api}:443"
        leaks = [k for k, ok in res.items() if ok and k != api_key]
        if leaks:
            raise SandboxError(f"LEAK: VM reached {', '.join(leaks)}")
        if not res[api_key]:
            raise SandboxError(f"VM cannot reach api.anthropic.com ({api})")
        blocked = ", ".join(k for k in res if k != api_key)
        return (f"lockdown OK: {blocked} (github) blocked; api.anthropic.com ({api}) reachable; "
                f"also allowed: {self.host_ip()}:{self.cfg.ghidra_port}")

    def token(self) -> str:
        import getpass
        self.state.mkdir(parents=True, exist_ok=True)
        self.state.chmod(0o700)
        t = getpass.getpass("Paste token from 'claude setup-token', then Enter: ").strip()
        if not t:
            raise SandboxError("empty token")
        fd = os.open(self.state / "token.env", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"CLAUDE_CODE_OAUTH_TOKEN={t}\n")
        return f"saved to {self.state / 'token.env'}"

    def _token_env(self) -> Dict[str, str]:
        path = self.state / "token.env"
        if not path.exists():
            raise SandboxError("no token: sandbox.py token")
        env = {}
        for line in path.read_text().splitlines():
            k, sep, v = line.partition("=")
            if sep and k.strip():
                env[k.strip()] = v.strip()
        return env

    def sync(self) -> str:
        self._token_env()
        if not (self.repo / ".git").exists():
            raise SandboxError(f"no project clone at {self.repo} (clone it there; see README 'Setup')")
        head = out(run(["git", "-C", str(self.repo), "rev-parse", "HEAD"]))
        up = f"{self.cfg.upstream_remote}/{self.cfg.upstream_branch}"
        # the host has internet; the VM doesn't. Refresh upstream with your own ssh setup (not the VM key).
        fetched = run(["git", "-C", str(self.repo), "fetch", "-q", self.cfg.upstream_remote, self.cfg.upstream_branch],
                      check=False).returncode == 0
        upstream = out(run(["git", "-C", str(self.repo), "rev-parse", "--verify", "-q", f"refs/remotes/{up}"], check=False))
        refspecs = [f"{head}:refs/heads/base"] + ([f"{upstream}:refs/heads/main"] if upstream else [])
        ip = self.need_ip()
        run(["git", "-C", str(self.repo), "push", "-q", "-f", f"ssh://decomp@{ip}/srv/decomp/mirror.git", *refspecs],
            env=self.git_env)
        self.push_bin()
        # a+rX: executables (wibo, dtk, objdiff-cli are 744 on the host) must run as the worker uid
        rs = ["rsync", "-a", "--delete", "--chown=0:0", "--chmod=Da+rx,Dgo-w,Fa+rX,Fgo-w",
              "-e", "ssh " + " ".join(shlex.quote(o) for o in self.ssh_cli_opts()), "--rsync-path=sudo rsync"]
        dest = f"decomp@{ip}:"
        missing = [t for t in self.cfg.toolchain if not (self.repo / t).exists()]
        if missing:
            raise SandboxError(f"toolchain missing in {self.repo}: {', '.join(missing)} (run configure.py + ninja there once)")
        if self.cfg.toolchain:
            # --relative with /./ keeps each path relative to the repo (build/tools -> tree/build/tools)
            run(rs + ["--relative"] + [f"{self.repo}/./{t}" for t in self.cfg.toolchain] + [dest + SHARED_TREE + "/"])
        src = self.cfg.data_source
        if src is not None:
            if not src.is_dir() or (self.cfg.data_required and not (src / self.cfg.data_required).exists()):
                raise SandboxError(f"data folder {src} missing or incomplete (needs {self.cfg.data_required or 'files'})")
            run(rs + ["--copy-links", str(src) + "/", dest + SHARED_DATA + "/"])
            if self.cfg.data_verify and tree_digest(src.resolve()) != self.agent("tree_digest", path=SHARED_DATA)["sha1"]:
                raise SandboxError(f"data copy in VM differs from {src} (file list/sizes)")
        if (HERE / "local").is_dir():
            run(rs + [str(HERE / "local") + "/", dest + SHARED_MCP + "/"])
        upd = self.agent("update_workers")
        note = (f"{up}={upstream[:8]}" + ("" if fetched else " (fetch failed; using the last fetched copy)")) \
            if upstream else f"no {up} on the host: workers get no origin/main"
        failed = "; ".join(f"{n}: {e}" for n, e in upd["failed"].items())
        return (f"synced base={head[:8]} (committed HEAD only; uncommitted changes are not sent); {note}; "
                f"origin/* refreshed in {len(upd['updated'])} worker(s)" + (f"; FAILED: {failed}" if failed else ""))

    def start(self) -> str:
        self.dom().create()
        self.wait_ssh()
        return f"{self.vm} up at {self.vm_ip()}"

    def shutdown(self) -> str:
        self._drop_ssh()
        self.dom().shutdown()
        return f"{self.vm} shutting down"

    def destroy(self) -> str:
        self._drop_ssh()
        dom = self.dom()
        if dom.isActive():
            dom.destroy()
        dom.undefineFlags(libvirt.VIR_DOMAIN_UNDEFINE_NVRAM)
        run(["sudo", "rm", "-f", str(IMGDIR / f"{self.vm}.qcow2")], capture=False)
        try:
            self.virt.nwfilterLookupByName(self.vm).undefine()
        except libvirt.libvirtError:
            pass
        return f"{self.vm} destroyed"

    def ghidra_forward(self) -> None:
        """Forward HOST_IP:port (reachable from the VM) to Ghidra on 127.0.0.1:port, until Ctrl-C."""
        hip, port = self.host_ip(), self.cfg.ghidra_port
        srv = socket.create_server((hip, port))
        print(f"forwarding {hip}:{port} -> 127.0.0.1:{port} (Ctrl-C to stop)", flush=True)

        def pipe(a: socket.socket, b: socket.socket) -> None:
            try:
                while data := a.recv(65536):
                    b.sendall(data)
            except OSError:
                pass
            finally:
                for s in (a, b):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        while True:
            conn, _ = srv.accept()
            try:
                target = socket.create_connection(("127.0.0.1", port))
            except OSError:
                conn.close()
                continue
            for a, b in ((conn, target), (target, conn)):
                threading.Thread(target=pipe, args=(a, b), daemon=True).start()

    # ---------------------------------------------------------------- workers

    def _check_name(self, name: str) -> None:
        if not NAME_RE.match(name or ""):
            raise SandboxError(f"bad name '{name}' (letters, digits, - and _)")

    def worker_names(self) -> List[str]:
        with self.ssh().open_sftp() as sftp:
            return sorted(sftp.listdir(WORKERS))

    def need_worker(self, name: str) -> None:
        self._check_name(name)
        if name not in self.worker_names():
            raise SandboxError(f"no worker '{name}' (create it with: sandbox.py spawn {name} \"prompt\")")

    def _launch(self, name: str, prompt: str, model: str, effort: str, resume: bool) -> str:
        if not self.locked():
            raise SandboxError("refusing to start a worker: VM not locked down")
        if model not in MODELS:
            raise SandboxError(f"unknown model '{model}' (one of: {', '.join(m for m in MODELS if m)})")
        if effort not in EFFORTS:
            raise SandboxError(f"unknown effort '{effort}' (one of: {', '.join(e for e in EFFORTS if e)})")
        if not prompt.strip():
            raise SandboxError("empty prompt")
        token = self._token_env()
        self.push_bin()
        text = prompt.rstrip() + "\n"
        if resume:
            self.agent("followup", name=name, prompt=text)
            old = self._container(name)
            if old is not None:
                old.remove(force=True)
        else:
            preamble = self.cfg.preamble.read_text() if self.cfg.preamble.exists() else ""
            self.agent("prepare", name=name, ref="base", prompt=preamble + text, toolchain=self.cfg.toolchain,
                       tree=SHARED_TREE, data_link=self.cfg.data_link, data_mount=self.cfg.data_mount)
        mode = "resume" if resume else "new"
        self.agent("record_run", name=name, run={"model": model, "effort": effort, "mode": mode,
                                                 "started": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        w = f"{WORKERS}/{name}"
        api = (self.api_ips() or [FALLBACK_API_IP])[0]
        try:
            self.docker.containers.run(
                IMAGE, name=f"w-{name}", detach=True,
                user="2000:2000", cap_drop=["ALL"], security_opt=["no-new-privileges"],
                read_only=True, tmpfs={"/tmp": "rw,exec,size=4g"},
                pids_limit=2048, nano_cpus=int(self.cfg.worker_cpus * 1e9), mem_limit=self.cfg.worker_mem,
                dns=["127.0.0.1"], extra_hosts={"api.anthropic.com": api, "ghidra.host": self.host_ip()},
                environment={**token, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1",
                             "WORKER_MODEL": model, "WORKER_EFFORT": effort, "WORKER_MODE": mode,
                             "WORKER_SETUP": json.dumps(self.cfg.setup)},
                # the entrypoint comes from /srv/decomp/bin (pushed every spawn), so it changes without a rebuild
                volumes={
                    f"{BIN}/worker_entry.py": {"bind": "/usr/local/bin/worker-entry", "mode": "ro"},
                    f"{w}/repo": {"bind": "/work", "mode": "rw"},
                    f"{w}/home": {"bind": "/home/agent", "mode": "rw"},
                    f"{w}/prompt.md": {"bind": "/task/prompt.md", "mode": "ro"},
                    f"{w}/followup.md": {"bind": "/task/followup.md", "mode": "ro"},
                    "/srv/decomp/mirror.git": {"bind": "/srv/decomp/mirror.git", "mode": "ro"},
                    WORKERS: {"bind": "/peers", "mode": "ro"},
                    SHARED_DATA: {"bind": self.cfg.data_mount, "mode": "ro"},
                    SHARED_MCP: {"bind": "/opt/mcp", "mode": "ro"},
                })
        except Exception as e:
            if not resume:
                self.agent("rm", name=name)  # never leave a half-made worker (it would block a retry)
            raise SandboxError(f"starting container failed: {e}")
        extra = " · ".join(x for x in (model and f"model {model}", effort and f"effort {effort}") if x)
        return f"{'resumed' if resume else 'spawned'} w-{name} on agent/{name}" + (f" ({extra})" if extra else "")

    def spawn(self, name: str, prompt: str, model: str = "", effort: str = "") -> str:
        self._check_name(name)
        return self._launch(name, prompt, model, effort, resume=False)

    def resume(self, name: str, prompt: str, model: str = "", effort: str = "") -> str:
        """Follow-up prompt for a finished worker: continues its Claude session in the same clone."""
        self.need_worker(name)
        if name in self.running_workers():
            raise SandboxError(f"worker '{name}' is still running; stop it first or wait for it to finish")
        return self._launch(name, prompt, model, effort, resume=True)

    def stop(self, name: str) -> str:
        self.need_worker(name)
        c = self._container(name)
        if c is None or c.status != "running":
            raise SandboxError(f"worker '{name}' isn't running")
        c.stop()
        return f"stopped {name}"

    def rm(self, name: str) -> str:
        self._check_name(name)
        c = self._container(name)
        if c is not None:
            c.remove(force=True)
        self.agent("rm", name=name)
        return f"removed {name}"

    def overview(self) -> Dict[str, Any]:
        """Workers (container state + status, model/effort, prompt, final result) and subscription usage."""
        containers = self._containers()
        data = self.agent("workers")
        for w in data["workers"]:
            c = containers.get(w["name"])
            w["state"] = c.status if c else "missing"
            w["status"] = self._status(c) if c else "no container"
        return data

    def workers(self) -> List[Dict[str, Any]]:
        return self.overview()["workers"]

    def usage(self) -> Optional[Dict[str, Any]]:
        """Latest 5-hour session / 7-day utilization seen in any worker log (None before any API call)."""
        return self.agent("workers").get("usage")

    def read_log(self, name: str, offset: int = 0, limit: int = 2_000_000) -> Tuple[List[Dict[str, Any]], int]:
        """Parsed events from byte `offset` of the worker's stream-json log; returns (events, new offset)."""
        self._check_name(name)
        data = self.read_file(f"{WORKERS}/{name}/home/agent.jsonl", offset, limit)
        end = data.rfind(b"\n") + 1  # only complete lines; the rest arrives next poll
        return parse_events(data[:end].splitlines()), offset + end

    def learnings(self, names: Iterable[str] = ()) -> str:
        parts = []
        for n in list(names) or self.worker_names():
            self._check_name(n)
            text = self.read_file(f"{WORKERS}/{n}/home/learnings.md").decode(errors="replace").strip()
            if text:
                parts.append(f"<!-- worker: {n} -->\n{text}\n")
        return "\n".join(parts)

    # ---------------------------------------------------------------- git (host side)

    def fetch(self, names: Iterable[str] = ()) -> str:
        """Only objects and refs come across (no hooks/config), so this is safe on untrusted work."""
        lines = []
        ip = self.need_ip()
        for n in list(names) or self.worker_names():
            self._check_name(n)
            run(["git", "-C", str(self.repo), "fetch", "-q", f"ssh://decomp@{ip}{WORKERS}/{n}/repo",
                 f"+agent/{n}:refs/remotes/sandbox/{n}"], env=self.git_env)
            count = out(run(["git", "-C", str(self.repo), "rev-list", "--count", f"sandbox/{n}", "--not", self.base_of(n)]))
            lines.append(f"sandbox/{n}: {count} commit(s)")
        return "\n".join(lines)

    def base_of(self, name: str) -> str:
        p = run(["git", "-C", str(self.repo), "merge-base", "HEAD", f"sandbox/{name}"], check=False)
        if p.returncode == 0:
            return out(p)
        return out(run(["git", "-C", str(self.repo), "rev-parse", f"sandbox/{name}^{{commit}}"]))

    def review(self, name: str) -> str:
        """Fetches the worker's latest commits first, so this always reflects its current branch."""
        self.need_worker(name)
        self.fetch([name])
        base = self.base_of(name)
        log = out(run(["git", "-C", str(self.repo), "log", "--stat", "--format=%n%h %s", f"{base}..sandbox/{name}"]))
        return (log or "(no commits)") + f"\n\nfull diff: git diff {base[:10]} sandbox/{name}"

    def diff(self, name: str) -> str:
        self.need_worker(name)
        self.fetch([name])
        return out(run(["git", "-C", str(self.repo), "diff", self.base_of(name), f"sandbox/{name}"]))

    def take(self, name: str, branch: str = "") -> str:
        self._check_name(name)
        branch = branch or f"sandbox-{name}"
        run(["git", "-C", str(self.repo), "branch", branch, f"sandbox/{name}"])
        return f"created local branch {branch}; rebase/squash as needed, then push it yourself"


def tree_digest(root: Path) -> str:
    """Same digest as vm_agent's tree_digest: sha1 over byte-sorted 'relpath size' lines (symlinks followed)."""
    entries = []
    for dirpath, _dirs, files in os.walk(root, followlinks=True):
        for f in files:
            p = Path(dirpath) / f
            entries.append(f"{p.relative_to(root)} {p.stat().st_size}".encode())
    return hashlib.sha1(b"\n".join(sorted(entries))).hexdigest()


# -------------------------------------------------------------------- log parsing

def clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"… ({len(s) - n} more chars)"


def parse_events(lines: Iterable[bytes]) -> List[Dict[str, Any]]:
    """stream-json lines -> display events: text, tool (call), tool_result, result, system."""
    events: List[Dict[str, Any]] = []
    for raw in lines:
        try:
            m = json.loads(raw)
        except ValueError:
            continue
        t = m.get("type")
        ts = m.get("timestamp")
        if t == "system" and m.get("subtype") == "init":
            events.append({"kind": "system", "text": f"session {m.get('session_id', '')[:8]} · model {m.get('model')}", "ts": ts})
        elif t == "assistant":
            for c in m.get("message", {}).get("content", []):
                if c.get("type") == "text" and c.get("text", "").strip():
                    events.append({"kind": "text", "text": c["text"], "ts": ts})
                elif c.get("type") == "tool_use":
                    events.append({"kind": "tool", "id": c.get("id"), "name": c.get("name"),
                                   "input": clip(json.dumps(c.get("input"), ensure_ascii=False), 4000), "ts": ts})
        elif t == "user":
            content = m.get("message", {}).get("content")
            for c in content if isinstance(content, list) else []:
                if c.get("type") == "tool_result":
                    body = c.get("content")
                    if isinstance(body, list):
                        body = "\n".join(x.get("text", "") for x in body if isinstance(x, dict))
                    events.append({"kind": "tool_result", "id": c.get("tool_use_id"), "error": bool(c.get("is_error")),
                                   "text": clip(str(body or ""), 6000), "ts": ts})
        elif t == "result":
            events.append({"kind": "result", "subtype": m.get("subtype"), "text": m.get("result") or "",
                           "turns": m.get("num_turns"), "cost": m.get("total_cost_usd"), "ts": ts})
    return events


def format_usage(u: Dict[str, Any]) -> str:
    """'session 29% (resets 14:30) · week 9% (resets Fri 18:00) · seen 3 min ago'"""
    parts = []
    for key, label, fmt in (("five_hour", "session", "%H:%M"), ("seven_day", "week", "%a %H:%M")):
        w = (u.get("unifiedWindows") or {}).get(key)
        if w:
            reset = datetime.fromtimestamp(w["resetsAt"]).strftime(fmt) if w.get("resetsAt") else "?"
            parts.append(f"{label} {round(w.get('utilization', 0) * 100)}% (resets {reset})")
    age = int(time.time() - u.get("observed_at", time.time()))
    parts.append(f"seen {age // 60} min ago" if age >= 60 else "seen just now")
    if u.get("status") not in (None, "allowed"):
        parts.insert(0, f"STATUS {u['status'].upper()}")
    return "usage: " + " · ".join(parts)


def format_event(e: Dict[str, Any], results: bool = False) -> Optional[str]:
    k = e["kind"]
    if k == "text":
        return e["text"]
    if k == "tool":
        return f"  > {e['name']} {e['input'][:200]}"
    if k == "tool_result":
        return ("  < " + e["text"][:300].replace("\n", "\n    ")) if results else None
    if k == "result":
        return f"== result: {e['subtype']} ({e.get('turns')} turns) {e['text'][:500]}"
    return f"-- {e['text']}"


# -------------------------------------------------------------------- CLI

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("setup-host", "create", "build-image", "lockdown", "unlock", "check", "token", "sync", "start",
              "shutdown", "ls", "status", "ghidra-forward"):
        sub.add_parser(c)
    sub.add_parser("destroy").add_argument("--yes", action="store_true")
    for c in ("spawn", "resume"):
        p = sub.add_parser(c, help="spawn: new worker; resume: follow-up prompt for a finished worker")
        p.add_argument("name")
        p.add_argument("prompt", nargs="*", help="prompt text (quote it), or use -f FILE / - for stdin")
        p.add_argument("-f", "--file")
        p.add_argument("-m", "--model", default="", choices=MODELS, metavar="{" + ",".join(m for m in MODELS if m) + "}")
        p.add_argument("-e", "--effort", default="", choices=EFFORTS, metavar="{" + ",".join(e for e in EFFORTS if e) + "}")
    for c in ("stop", "rm", "review", "diff"):
        sub.add_parser(c).add_argument("name")
    for c in ("fetch", "learnings"):
        sub.add_parser(c).add_argument("names", nargs="*")
    p = sub.add_parser("logs", help="follow a worker's log")
    p.add_argument("name")
    p.add_argument("--results", action="store_true", help="also show tool outputs")
    p = sub.add_parser("tail", help="last N events, non-blocking")
    p.add_argument("name")
    p.add_argument("n", nargs="?", type=int, default=20)
    p.add_argument("--results", action="store_true")
    p = sub.add_parser("take")
    p.add_argument("name")
    p.add_argument("branch", nargs="?", default="")
    p = sub.add_parser("shell", help="bash inside a running worker")
    p.add_argument("name")
    p = sub.add_parser("ssh", help="shell (or command) in the VM")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p = sub.add_parser("portal", help="web portal (see portal.py --help)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()

    try:
        sb = Sandbox()
        c = args.cmd
        if c in ("spawn", "resume"):
            if args.file:
                prompt = Path(args.file).read_text()
            elif args.prompt == ["-"]:
                prompt = sys.stdin.read()
            else:
                prompt = " ".join(args.prompt)
            print(getattr(sb, c)(args.name, prompt, args.model, args.effort))
        elif c in ("stop", "rm", "review", "diff"):
            print(getattr(sb, c)(args.name))
        elif c in ("fetch", "learnings"):
            print(getattr(sb, c)(args.names))
        elif c == "take":
            print(sb.take(args.name, args.branch))
        elif c in ("ls", "status"):
            data = sb.overview()
            if c == "status" and data.get("usage"):
                print(format_usage(data["usage"]))
            for w in data["workers"]:
                extra = " · ".join(x for x in (w.get("model"), w.get("effort") and f"effort {w['effort']}") if x)
                print(f"{w['name']:<20} {w['status']}{'  (' + extra + ')' if extra else ''}")
                if c == "status" and w["result"]:
                    r = w["result"]
                    print(f"    == {r['subtype']} ({r['turns']} turns, ${r['cost'] or 0:.2f}) {r['text'][:300]}")
        elif c == "tail":
            sb.need_worker(args.name)
            events, _ = sb.read_log(args.name)
            for e in events[-args.n:]:
                line = format_event(e, args.results)
                if line is not None:
                    print(line)
        elif c == "logs":
            sb.need_worker(args.name)
            offset = 0
            while True:
                events, offset = sb.read_log(args.name, offset)
                for e in events:
                    line = format_event(e, args.results)
                    if line is not None:
                        print(line, flush=True)
                time.sleep(2)
        elif c == "shell":
            # interactive terminals stay with the ssh program: it gives you a real TTY
            sb.need_worker(args.name)
            if args.name not in sb.running_workers():
                raise SandboxError(f"worker '{args.name}' has finished; its files are in the VM at {WORKERS}/{args.name}")
            os.execvp("ssh", ["ssh", "-t", *sb.ssh_cli_opts(), f"decomp@{sb.need_ip()}", "docker", "exec", "-it",
                              f"w-{args.name}", "bash"])
        elif c == "ssh":
            os.execvp("ssh", ["ssh", *(["-t"] if not args.command else []), *sb.ssh_cli_opts(),
                              f"decomp@{sb.need_ip()}", *args.command])
        elif c == "ghidra-forward":
            sb.ghidra_forward()
        elif c == "destroy":
            if not args.yes and input(f"Delete VM {sb.vm} and all worker data? [y/N] ").strip() != "y":
                return 1
            print(sb.destroy())
        elif c == "portal":
            from portal import serve
            serve(sb, args.host, args.port)
        else:
            print(getattr(sb, c.replace("-", "_"))())
    except SandboxError as e:
        print(f"sandbox: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
