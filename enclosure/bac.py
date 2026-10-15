"""One bac definition for the agent's precheck, the tests and production (D68).

`Bac.run` writes the OCI configuration of the walls (`enclosure/oci.py`) into a fresh bundle and executes it with an
OCI runtime, runc by preference (it keeps a finished container until its counters are read) and crun otherwise: every namespace unshared, an empty network, no capability, Docker's allow-list seccomp profile, a read-only
system with only the declared paths mounted, rlimits per process and one control group per run bounding processes,
memory and CPU for the run as a whole. The host bounds wall time and removes the container afterwards, whatever
it left behind. The environment is exactly what the caller passes on top of a fixed base, never the caller's own.

Fail closed: nothing runs unless this very definition runs `true`. A host where control groups cannot be used (no
delegation, or crun's refusal of hybrid v1/v2 hosts) still runs the bac for an ordinary user, with the per-process
limits alone and `groups = False`; never for root, since Linux does not apply the process limit to root.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from enclosure import capabilities, oci

BASE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8"}
REFUSED, TIMED_OUT = 126, 124
OUTPUT_TAIL = 20_000
GROUP = "standard-bac"
RUNTIMES = ("runc", "crun")
CGROUP_ROOT = Path("/sys/fs/cgroup")


@dataclass(frozen=True)
class Walls:
    """Limits derived from the effective law or the operator's configuration, never chosen by the code inside."""
    timeout_s: int = 600
    memory_mb: int = 2048
    processes: int = 64
    file_bytes: int = 10_485_760
    cpu_percent: int = 100


@dataclass(frozen=True)
class Ran:
    code: int
    out: str
    limited: tuple[str, ...] | None = ()      # limits the kernel enforced on the run's group; None: not readable

    @property
    def ok(self) -> bool:
        return self.code == 0


def _limited(name: str) -> tuple[str, ...]:
    """The kernel's own counters for this run's group (cgroup v2, or the v1 pids and memory hierarchies)."""
    found = set()
    places = [CGROUP_ROOT / GROUP / name, CGROUP_ROOT / "pids" / GROUP / name, CGROUP_ROOT / "memory" / GROUP / name]
    for place in places:
        for file, wall in (("pids.events", "processes"), ("memory.events", "memory")):
            try:
                counts = dict(line.split() for line in (place / file).read_text().splitlines() if line.strip())
            except OSError:
                continue
            if int(counts.get("max", 0)) or int(counts.get("oom_kill", 0)):
                found.add(wall)
        try:
            if int((place / "memory.failcnt").read_text() or 0):
                found.add("memory")
        except (OSError, ValueError):
            pass
    return tuple(sorted(found))


class Bac:
    def __init__(self, walls: Walls = Walls(), *, python: str = sys.executable):
        self.walls, self.python = walls, python
        self.runtime: str | None = None
        self.groups = True
        self.why = self._unavailable()
        self.ready = self.why is None

    @property
    def isolation(self) -> str:
        return "network and filesystem jail" if self.ready else f"UNAVAILABLE: {self.why}"

    def config(self, args, cwd, *, env=None, readable=(), writable=(), name: str = "run") -> dict:
        """The OCI configuration of one run. Pure: it builds, it does not check that the runtime exists."""
        return oci.config(self.walls, args, cwd, env={**BASE_ENV, **(env or {})}, readable=readable,
                          writable=writable, cgroup=f"/{GROUP}/{name}" if self.groups else None)

    def _unavailable(self) -> str | None:
        """Why no runtime can run this very definition, filter and groups included; None once one does."""
        try:
            oci.seccomp()
        except (OSError, ValueError, KeyError, StopIteration) as exc:
            return f"system-call filter unavailable: {exc}"
        found = [path for path in map(shutil.which, RUNTIMES) if path]
        if not found:
            return f"OCI runtime unavailable ({', '.join(RUNTIMES)})"
        refusals = []
        with tempfile.TemporaryDirectory(prefix="bac-check-") as cwd:
            for runtime in found:
                for groups in ((True,) if os.getuid() == 0 else (True, False)):
                    self.runtime, self.groups = runtime, groups
                    ran = self._execute(["/usr/bin/true"], cwd, None, (), (), 30)
                    if ran.code == 0:
                        return None
                    refusals.append(f"{Path(runtime).name}: {ran.out.strip()[-200:]}")
        self.runtime = None
        return "OCI runtime refused the bac: " + "; ".join(refusals)

    def _execute(self, args, cwd, env, readable, writable, timeout) -> Ran:
        name = uuid.uuid4().hex
        state = Path(tempfile.gettempdir(), f"bac-state-{os.getuid()}")
        state.mkdir(mode=0o700, exist_ok=True)
        base = [str(self.runtime), "--root", str(state)]
        if Path(str(self.runtime)).name == "crun":
            base.append(f"--cgroup-manager={'cgroupfs' if self.groups else 'disabled'}")
        with tempfile.TemporaryDirectory(prefix="bac-bundle-") as bundle, tempfile.TemporaryFile() as output:
            rootfs = Path(bundle, "rootfs")
            rootfs.mkdir()
            for path in oci.SYSTEM:
                if Path(path).is_symlink():
                    Path(rootfs, path.lstrip("/")).symlink_to(Path(path).readlink())
            config = self.config(args, cwd, env=env, readable=readable, writable=writable, name=name)
            Path(bundle, "config.json").write_text(json.dumps(config))
            try:
                try:
                    keep = ["--keep"] if Path(str(self.runtime)).name == "runc" else []
                    r = subprocess.run([*base, "run", *keep, "--bundle", bundle, name], stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
                    code, out = r.returncode, None
                except subprocess.TimeoutExpired:
                    subprocess.run([*base, "kill", name, "KILL"], capture_output=True, timeout=30)
                    code, out = TIMED_OUT, f"timeout after {timeout}s"
                limited = _limited(name) if keep and self.groups else (None if self.groups else ())
            except OSError as exc:
                return Ran(REFUSED, f"execution refused: {exc}")
            finally:
                subprocess.run([*base, "delete", "--force", name], capture_output=True, timeout=30)
            if out is None:
                output.seek(0, 2)
                output.seek(max(0, output.tell() - OUTPUT_TAIL))
                out = output.read().decode(errors="replace")
            return Ran(code, out, limited)

    def run(self, args, cwd, *, env=None, readable=(), writable=()) -> Ran:
        if not self.ready:
            return Ran(REFUSED, f"execution refused: {self.why}")
        return self._execute(args, cwd, env, readable, writable, self.walls.timeout_s)


def capability_map(walls: Walls = Walls(), *, groups: bool = True) -> dict:
    """The map of the bac these walls define, computed from its OCI configuration (D69). Runs nothing."""
    config = oci.config(walls, ["<your command>"], "/work", env=BASE_ENV, cgroup=f"/{GROUP}/map" if groups else None)
    return capabilities.describe(config, timeout_s=walls.timeout_s)
