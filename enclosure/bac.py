"""One bac definition for the agent's precheck, the tests and production (D68).

`Bac.run` executes argv inside Bubblewrap: every namespace unshared (network, processes, IPC, hostname, user,
cgroup), no capabilities, a new session, `/usr` and the system libraries read-only, private `/proc`, `/dev` and
`/tmp`, and only the declared paths mounted (read-only unless declared writable). A seccomp filter refuses the
calls that would change mounts or namespaces or reach the kernel's sensitive interfaces (`enclosure/seccomp.py`).
`prlimit` bounds each process; one control group per run bounds processes, memory and CPU for the run as a whole
and kills what it leaves behind (`enclosure/cgroups.py`); the host bounds wall time. The environment is exactly what
the caller passes on top of a fixed base, never the caller's own.

Fail closed: without Bubblewrap, prlimit or the seccomp filter nothing runs, and as root nothing runs without
control groups, since Linux does not apply the per-process limit on processes to root.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from enclosure import seccomp
from enclosure.cgroups import Hierarchy

BASE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8"}
REFUSED, TIMED_OUT = 126, 124
OUTPUT_TAIL = 20_000


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
    limited: tuple[str, ...] = ()                     # limits the kernel enforced on the run's control group

    @property
    def ok(self) -> bool:
        return self.code == 0


class Bac:
    def __init__(self, walls: Walls = Walls(), *, python: str = sys.executable, groups: bool = True):
        self.walls, self.python = walls, python
        self.filter = seccomp.program()
        self.hierarchy = Hierarchy.discover() if groups else None
        self.why = self._unavailable()
        self.ready = self.why is None

    @property
    def isolation(self) -> str:
        return "network and filesystem jail" if self.ready else f"UNAVAILABLE: {self.why}"

    def command(self, args, cwd, *, readable=(), writable=(), filter_fd: int | None = None) -> list[str]:
        """The argv that runs `args` in the bac. Pure: it builds, it does not check that the jail exists."""
        w = self.walls
        argv = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
                *(["--seccomp", str(filter_fd)] if filter_fd is not None else []),
                "--dir", "/usr", "--ro-bind", "/usr", "/usr", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
        for path in ("/bin", "/lib", "/lib64"):
            source = Path(path)
            if source.is_symlink():
                argv += ["--symlink", str(source.readlink()), path]
            elif source.exists():
                argv += ["--ro-bind", path, path]
        if Path("/etc/alternatives").is_dir():          # Debian's interpreter links resolve through it
            argv += ["--dir", "/etc", "--ro-bind", "/etc/alternatives", "/etc/alternatives"]
        mounts = {Path(cwd).resolve(): "--ro-bind"}
        mounts.update({Path(path).resolve(): "--ro-bind" for path in readable})
        mounts.update({Path(path).resolve(): "--bind" for path in writable})
        runtime = Path(sys.prefix).resolve()
        if not runtime.is_relative_to(Path("/usr")):
            mounts[runtime] = "--ro-bind"
        made = set()
        for path, operation in sorted(mounts.items(), key=lambda item: (len(item[0].parts), str(item[0]))):
            for parent in reversed(path.parents):
                if parent != Path("/") and not parent.is_relative_to(Path("/usr")) and parent not in made:
                    argv += ["--dir", str(parent)]
                    made.add(parent)
            argv += [operation, str(path), str(path)]
        argv += ["--chdir", str(Path(cwd).resolve())]
        argv += ["prlimit", f"--as={w.memory_mb << 20}", f"--nproc={w.processes}", f"--fsize={w.file_bytes}", "--"]
        return argv + [str(a) for a in args]

    def _unavailable(self) -> str | None:
        """Why the bac cannot run, checked by running `true` through this very definition, filter and group included."""
        if not shutil.which("bwrap") or not shutil.which("prlimit") or not Path("/usr/bin/true").exists():
            return "bubblewrap jail unavailable"
        if self.filter is None:
            return "system-call filter unavailable (libseccomp)"
        if self.hierarchy is None and os.getuid() == 0:
            return "control groups unavailable, and the process limit does not hold for root"
        with tempfile.TemporaryDirectory(prefix="bac-check-") as cwd:
            if self._execute(["/usr/bin/true"], cwd, BASE_ENV, (), (), 10).code != 0:
                return "bubblewrap jail unavailable"
        return None

    def _execute(self, args, cwd, env, readable, writable, timeout) -> Ran:
        group = None
        fd = os.memfd_create("bac-filter")
        try:
            os.write(fd, self.filter or b"")
            os.lseek(fd, 0, os.SEEK_SET)
            argv = self.command(args, cwd, readable=readable, writable=writable, filter_fd=fd)
            argv[0] = shutil.which("bwrap") or "bwrap"
            if self.hierarchy:
                w = self.walls
                group = self.hierarchy.group(processes=w.processes, memory_bytes=w.memory_mb << 20,
                                             cpu_percent=w.cpu_percent)
            with tempfile.TemporaryFile() as output:
                try:
                    r = subprocess.run(argv, env=env, stdout=output, stderr=subprocess.STDOUT, pass_fds=(fd,),
                                       timeout=timeout, preexec_fn=group.enter if group else None)
                except subprocess.TimeoutExpired:
                    return Ran(TIMED_OUT, f"timeout after {timeout}s", group.hit() if group else ())
                output.seek(0, 2)
                output.seek(max(0, output.tell() - OUTPUT_TAIL))
                return Ran(r.returncode, output.read().decode(errors="replace"), group.hit() if group else ())
        except (OSError, subprocess.SubprocessError) as exc:
            return Ran(REFUSED, f"execution refused: {exc}")
        finally:
            os.close(fd)
            if group:
                group.close()

    def run(self, args, cwd, *, env=None, readable=(), writable=()) -> Ran:
        if not self.ready:
            return Ran(REFUSED, f"execution refused: {self.why}")
        return self._execute(args, cwd, {**BASE_ENV, **(env or {})}, readable, writable, self.walls.timeout_s)
