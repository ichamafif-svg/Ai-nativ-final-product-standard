"""Agent process enclosure using native bubblewrap namespaces, not an authorization engine.

Only the agent's writable state, a read-only local source, configuration, admission
socket directory and optional public egress mount enter the root. Control keys,
journal, pins, host network and host homes never enter. Nested OCI candidates
retain their existing sandbox; the host-owned UID cgroup ceiling still applies.
"""
from __future__ import annotations

import os
import shutil
import sys
import tomllib
from pathlib import Path

from fabric.runtime.bac import BASE_ENV, GROUP


class AgentEnclosureError(ValueError):
    pass


def layout(config) -> dict:
    path = Path(config).resolve(strict=True)
    base = path.parent
    spec = tomllib.loads(path.read_text())
    resolve = lambda value: (base / value).resolve(strict=True)
    agent = spec.get("agent", {})
    state = resolve("agent")
    if resolve(agent.get("store", "agent/store")) != state / "store" or \
            resolve(agent.get("key", "agent/agent.key")) != state / "agent.key":
        raise AgentEnclosureError("enclosed agent requires its own agent/store and agent/agent.key")
    if spec["repository"]["kind"] != "git":
        raise AgentEnclosureError("enclosed agent requires a local read-only repository; remote Git is not exposed")
    source = resolve(spec["repository"]["path"])
    admission = resolve(spec["socket"]["path"]).parent
    if admission != base / "admission":
        raise AgentEnclosureError("admission socket must have its own installation/admission directory")
    if agent.get("api_key_file"):
        raise AgentEnclosureError("provider credentials must remain outside the enclosed agent")
    llm = spec.get("llm", {})
    egress = None
    if llm:
        if llm.get("egress") != "http://127.0.0.1:3128":
            raise AgentEnclosureError("enclosed model calls require the private loopback egress relay")
        egress = resolve(llm["egress_socket"]).parent
        if resolve(llm["egress_socket"]).name != "egress.sock" or resolve(llm["egress_ca"]) != egress / "ca.pem":
            raise AgentEnclosureError("egress socket and public CA must share their dedicated mount")
        if {p.name for p in egress.iterdir()} != {"egress.sock", "ca.pem"}:
            raise AgentEnclosureError("egress mount must contain only its socket and public CA")
        for tier in (value for value in llm.values() if isinstance(value, dict)):
            if tier.get("key_file") or not str(tier.get("key", "")).startswith("secret:"):
                raise AgentEnclosureError("enclosed model tiers require secret references, never key files")
    if source.is_relative_to(base):
        raise AgentEnclosureError("the source repository must be outside the control installation")
    if "public_context" not in agent:
        raise AgentEnclosureError("enclosed agent requires explicit public_context")
    public = resolve(agent["public_context"])
    if public != base / "public":
        raise AgentEnclosureError("agent context must use the dedicated installation/public directory")
    if spec.get("build"):
        requests = resolve(spec["build"].get("store", "requests"))
        if requests != public / "requests":
            raise AgentEnclosureError("BUILD contracts must use the public/requests store")
    reads = [source, admission, path, public]
    if spec.get("data"):
        data = resolve(spec["data"]["path"])
        if data.is_relative_to(base):
            raise AgentEnclosureError("the data snapshot must be outside the control installation")
        reads.append(data)
    if egress:
        reads.append(egress)
    # A mount must not replace the private root, runtime, API filesystems or scratch.
    reserved = (Path("/usr"), Path("/etc"), Path("/proc"), Path("/dev"), Path("/sys"), Path("/tmp"))
    for entry in [state, *reads]:
        if entry == Path("/") or any(entry == p or entry in p.parents for p in reserved):
            raise AgentEnclosureError("mount overlaps a reserved enclosure path")
        if entry != path and entry != state and (entry == base or entry in base.parents):
            raise AgentEnclosureError("mount would expose the control installation")
    return {"config": path, "state": state, "reads": reads, "source": source, "egress": egress}


def delegation(uid: int) -> Path:
    subtree = Path("/sys/fs/cgroup", GROUP, str(uid))
    if not (subtree / "launcher").is_dir():
        raise AgentEnclosureError("bounded UID cgroup delegation unavailable")
    for parent in (subtree.parent, subtree.parent.parent):
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise AgentEnclosureError("delegation ancestors must remain root-owned and non-writable")
    for name in ("memory.max", "pids.max", "cpu.max"):
        path = subtree / name
        try:
            info, values = path.stat(), path.read_text().split()
            bounded = bool(values) and all(v.isdigit() and int(v) > 0 for v in values)
            if info.st_uid != 0 or info.st_mode & 0o022 or not bounded:
                raise AgentEnclosureError("agent aggregate ceilings must be finite and root-owned")
        except OSError as exc:
            raise AgentEnclosureError("agent aggregate ceilings unavailable") from exc
    return subtree


def command(config, *, code=None, program=None) -> list[str]:
    """Fixed namespace/mount policy. The optional program is still executed inside this root."""
    view = layout(config)
    binary = shutil.which("bwrap")
    if not binary:
        raise AgentEnclosureError("bubblewrap unavailable; agent execution refused")
    code = Path(code or Path(__file__).resolve().parents[2]).resolve(strict=True)
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        raise AgentEnclosureError("agent must run under its dedicated unprivileged account")
    delegation(uid)
    args = [binary, "--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid",
            "--unshare-net", "--unshare-ipc", "--unshare-uts", "--uid", str(uid), "--gid", str(gid),
            "--cap-drop", "ALL", "--clearenv", "--ro-bind", "/usr", "/usr"]
    for name in ("/bin", "/lib", "/lib64", "/sbin"):
        path = Path(name)
        if path.is_symlink():
            args += ["--symlink", str(path.readlink()), name]
        elif path.exists():
            args += ["--ro-bind", name, name]
    for name in ("/etc/alternatives", "/etc/ssl/certs"):
        if Path(name).exists():
            args += ["--ro-bind", name, name]
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/run",
             # One native cgroup mount: runc intentionally refuses submount crossings.
             # DAC and the host-owned finite parent ceilings bound authority;
             # the unprivileged account can write only its delegated descendants.
             "--bind", "/sys/fs/cgroup", "/sys/fs/cgroup",
             "--ro-bind", str(code), str(code)]
    # The interpreter's environment may be installed outside /usr and the code directory.
    runtime = Path(sys.prefix).resolve()
    if not runtime.is_relative_to(Path("/usr")) and not runtime.is_relative_to(code):
        args += ["--ro-bind", str(runtime), str(runtime)]
    for path in view["reads"]:
        args += ["--ro-bind", str(path), str(path)]
    args += ["--bind", str(view["state"]), str(view["state"])]
    env = {**BASE_ENV, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory",
           "GIT_CONFIG_VALUE_0": str(view["source"])}
    for key, value in env.items():
        args += ["--setenv", key, value]
    return [*args, "--chdir", str(code), "--", *(program or [sys.executable, "-m", "engine.agents.enclosed",
                                                            "inside", str(view["config"])])]
