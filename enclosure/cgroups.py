"""Control groups for the bac (D68): the kernel's own limits on processes, memory and CPU for a whole run.

`prlimit` limits each process; a cgroup limits the run as a whole, holds for root (Linux exempts root from
`RLIMIT_NPROC`) and lets the host kill every process a run left behind. One group per run, created under a
writable root, removed afterwards. cgroup v2 is the target; the v1 hierarchies (pids, memory, cpu) are supported
for hosts that still mount them. Which limits were hit comes back from the kernel's own counters.
"""
from __future__ import annotations

import os
import signal
import time
import uuid
from pathlib import Path

ROOT = Path("/sys/fs/cgroup")
NAME = "standard-bac"
PERIOD_US = 100_000


class Hierarchy:
    """Where groups are made: one cgroup v2 directory, or one directory per v1 controller."""

    def __init__(self, v2: Path | None = None, v1: dict[str, Path] | None = None):
        self.v2, self.v1 = v2, dict(v1 or {})

    @classmethod
    def discover(cls, root: Path = ROOT) -> Hierarchy | None:
        configured = os.environ.get("STANDARD_BAC_CGROUP")
        if configured:
            base = Path(configured)
            return cls(v2=base) if (base / "cgroup.subtree_control").exists() else None
        if (root / "cgroup.controllers").exists():
            base = root / NAME
            try:
                base.mkdir(exist_ok=True)
                wanted = {"pids", "memory", "cpu"} & set((root / "cgroup.controllers").read_text().split())
                (root / "cgroup.subtree_control").write_text(" ".join(f"+{c}" for c in sorted(wanted)))
                (base / "cgroup.subtree_control").write_text(" ".join(f"+{c}" for c in sorted(wanted)))
            except OSError:
                return None
            return cls(v2=base)
        found = {}
        for controller in ("pids", "memory", "cpu"):
            base = root / controller / NAME
            try:
                base.mkdir(exist_ok=True)
            except OSError:
                continue
            found[controller] = base
        return cls(v1=found) if {"pids", "memory"} <= set(found) else None

    def group(self, *, processes: int, memory_bytes: int, cpu_percent: int) -> Group:
        name = uuid.uuid4().hex
        if self.v2:
            path = self.v2 / name
            path.mkdir()
            limits = {"pids.max": processes, "memory.max": memory_bytes, "memory.swap.max": 0,
                      "cpu.max": f"{cpu_percent * PERIOD_US // 100} {PERIOD_US}"}
            for file, value in limits.items():
                if (path / file).exists():
                    (path / file).write_text(str(value))
            return Group([path], v2=True)
        paths, limits = [], {"pids": {"pids.max": processes},
                             "memory": {"memory.limit_in_bytes": memory_bytes},
                             "cpu": {"cpu.cfs_period_us": PERIOD_US,
                                     "cpu.cfs_quota_us": cpu_percent * PERIOD_US // 100}}
        for controller, base in self.v1.items():
            path = base / name
            path.mkdir()
            for file, value in limits[controller].items():
                (path / file).write_text(str(value))
            paths.append(path)
        return Group(paths, v2=False)


class Group:
    def __init__(self, paths: list[Path], *, v2: bool):
        self.paths, self.v2 = paths, v2

    def enter(self) -> None:
        """Called in the child before exec: the run and everything it starts belong to this group."""
        for path in self.paths:
            (path / "cgroup.procs").write_text(str(os.getpid()))

    def hit(self) -> tuple[str, ...]:
        """The limits the kernel enforced during the run, from its own event counters."""
        found = set()
        for path in self.paths:
            for file, wall in (("pids.events", "processes"), ("memory.events", "memory")):
                events = path / file
                if events.exists():
                    counts = dict(line.split() for line in events.read_text().splitlines() if line.strip())
                    if int(counts.get("max", 0)) or int(counts.get("oom_kill", 0)):
                        found.add(wall)
            failcnt = path / "memory.failcnt"
            if failcnt.exists() and int(failcnt.read_text() or 0):
                found.add("memory")
        return tuple(sorted(found))

    def close(self) -> None:
        """Kill whatever the run left behind, then remove the group."""
        for path in self.paths:
            if self.v2 and (path / "cgroup.kill").exists():
                (path / "cgroup.kill").write_text("1")
            for _ in range(50):
                pids = [int(p) for p in (path / "cgroup.procs").read_text().split()]
                if not pids:
                    break
                for pid in pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                time.sleep(0.02)
            try:
                path.rmdir()
            except OSError:
                pass
