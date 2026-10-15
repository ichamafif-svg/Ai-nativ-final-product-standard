"""The walls as an OCI runtime configuration (D68): pure data, built from `Walls` and the declared mounts.

Any OCI runtime can execute it: crun here, gVisor's `runsc` for the managed service. The system-call filter is
Docker's default profile (`seccomp.json`, moby/profiles seccomp/v0.2.4, Apache-2.0), an allow list, resolved for
this machine's architecture and kernel with no capability granted: every rule that needs a capability falls away.
"""
from __future__ import annotations

import json
import os
import platform
import sys
from functools import lru_cache
from pathlib import Path

PROFILE = Path(__file__).with_name("seccomp.json")
ARCHES = {"x86_64": ("amd64", "SCMP_ARCH_X86_64"), "aarch64": ("arm64", "SCMP_ARCH_AARCH64")}
MASKED = ["/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list",
          "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware"]
READ_ONLY = ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"]
SYSTEM = ("/bin", "/lib", "/lib64", "/sbin")


def _kernel() -> tuple[int, int]:
    major, minor = platform.release().split(".")[:2]
    return int(major), int("".join(c for c in minor if c.isdigit()) or 0)


@lru_cache(maxsize=1)
def seccomp() -> dict:
    """Docker's profile for this architecture and kernel, with no capability granted, in OCI form."""
    machine = platform.machine()
    if machine not in ARCHES:
        raise OSError(f"no seccomp profile for {machine}")
    arch, scmp = ARCHES[machine]
    profile = json.loads(PROFILE.read_text())
    architectures = [scmp, *next(a.get("subArchitectures") or [] for a in profile["archMap"]
                                 if a["architecture"] == scmp)]
    kernel = _kernel()
    rules = []
    for rule in profile["syscalls"]:
        includes, excludes = rule.get("includes") or {}, rule.get("excludes") or {}
        if includes.get("caps") or (includes.get("arches") and arch not in includes["arches"]):
            continue
        if includes.get("minKernel") and kernel < tuple(int(x) for x in includes["minKernel"].split(".")[:2]):
            continue
        if arch in (excludes.get("arches") or []):
            continue
        entry = {"names": rule["names"], "action": rule["action"]}
        if rule.get("errnoRet") is not None:
            entry["errnoRet"] = rule["errnoRet"]
        if rule.get("args"):
            entry["args"] = [{"index": a["index"], "value": a["value"], "valueTwo": a.get("valueTwo", 0),
                              "op": a["op"]} for a in rule["args"]]
        rules.append(entry)
    return {"defaultAction": profile["defaultAction"], "defaultErrnoRet": profile.get("defaultErrnoRet", 1),
            "architectures": architectures, "syscalls": rules}


def _bind(path: Path, *, write: bool) -> dict:
    return {"destination": str(path), "type": "bind", "source": str(path),
            "options": ["rbind", "nosuid", "nodev", "rw" if write else "ro"]}


def mounts(cwd, readable=(), writable=()) -> list[dict]:
    """System read-only, private /proc, /dev and /tmp, then only the declared paths, outermost first."""
    out = [{"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
           {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
           {"destination": "/dev/shm", "type": "tmpfs", "source": "shm",
            "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]},
           {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777"]},
           _bind(Path("/usr"), write=False)]
    out += [_bind(Path(p), write=False) for p in SYSTEM if Path(p).is_dir() and not Path(p).is_symlink()]
    if Path("/etc/alternatives").is_dir():          # Debian's interpreter links resolve through it
        out.append(_bind(Path("/etc/alternatives"), write=False))
    declared = {Path(cwd).resolve(): False}
    declared.update({Path(p).resolve(): False for p in readable})
    declared.update({Path(p).resolve(): True for p in writable})
    runtime = Path(sys.prefix).resolve()
    if not runtime.is_relative_to(Path("/usr")):
        declared[runtime] = False
    for path, write in sorted(declared.items(), key=lambda item: (len(item[0].parts), str(item[0]))):
        out.append(_bind(path, write=write))
    return out


ADDRESS_SPACE_FLOOR_MB = 8192


def address_space_mb(walls, cgroup) -> int:
    """The per-process address-space ceiling: the memory itself without a group, a wider ceiling under one."""
    return max(4 * walls.memory_mb, ADDRESS_SPACE_FLOOR_MB) if cgroup else walls.memory_mb


def config(walls, args, cwd, *, env: dict, readable=(), writable=(), cgroup: str | None) -> dict:
    """The complete OCI configuration of one run. Same walls, same file, whichever runtime executes it.

    Memory has two nested walls. The control group bounds the run as a whole. Each process is also bounded by its
    address space: at the run's memory without a control group, and with one at `address_space_mb(walls)`, wide
    enough for runtimes that reserve address space up front (runc's start-up, V8, WebAssembly) and still a ceiling.
    No wall is removed when another is added (D69)."""
    uid, gid = os.getuid(), os.getgid()
    no_caps = {k: [] for k in ("bounding", "effective", "inheritable", "permitted", "ambient")}
    return {
        "ociVersion": "1.0.2",
        "process": {
            "terminal": False, "user": {"uid": 0, "gid": 0}, "args": [str(a) for a in args],
            "env": [f"{k}={v}" for k, v in env.items()], "cwd": str(Path(cwd).resolve()),
            "capabilities": no_caps, "noNewPrivileges": True,
            "rlimits": [{"type": "RLIMIT_AS", "hard": address_space_mb(walls, cgroup) << 20,
                         "soft": address_space_mb(walls, cgroup) << 20},
                        {"type": "RLIMIT_NPROC", "hard": walls.processes, "soft": walls.processes},
                        {"type": "RLIMIT_FSIZE", "hard": walls.file_bytes, "soft": walls.file_bytes},
                        {"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
                        {"type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096}],
        },
        "root": {"path": "rootfs", "readonly": True},
        "hostname": "bac",
        "mounts": mounts(cwd, readable, writable),
        "linux": {
            "namespaces": [{"type": t} for t in ("pid", "network", "ipc", "uts", "mount", "user",
                                                 *(("cgroup",) if cgroup else ()))],
            "uidMappings": [{"containerID": 0, "hostID": uid, "size": 1}],
            "gidMappings": [{"containerID": 0, "hostID": gid, "size": 1}],
            **({"cgroupsPath": cgroup, "resources": {
                "devices": [{"allow": False, "access": "rwm"}],
                "pids": {"limit": walls.processes},
                "memory": {"limit": walls.memory_mb << 20, "swap": walls.memory_mb << 20},
                "cpu": {"quota": walls.cpu_percent * 1000, "period": 100_000},
            }} if cgroup else {}),
            "seccomp": seccomp(),
            "maskedPaths": MASKED,
            "readonlyPaths": READ_ONLY,
        },
    }
