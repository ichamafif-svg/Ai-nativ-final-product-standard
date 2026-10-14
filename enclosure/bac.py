"""One bac definition for the agent's precheck, the tests and production (D68).

`Bac.run` executes argv inside Bubblewrap: every namespace unshared (network, processes, IPC, hostname, user,
cgroup), no capabilities, a new session, `/usr` and the system libraries read-only, private `/proc`, `/dev` and
`/tmp`, and only the declared paths mounted (read-only unless declared writable). `prlimit` bounds address space,
processes and file size; the host bounds wall time. The environment is exactly what the caller passes on top of a
fixed base, never the caller's own.

Fail closed: without Bubblewrap and prlimit nothing runs. Walls still to build (seccomp, cgroups v2) are declared in
`MISSING` so their measurement says `absent`, never `held`.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

BASE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8"}
MISSING = ("syscalls", "cgroups")
REFUSED, TIMED_OUT = 126, 124
OUTPUT_TAIL = 20_000


@dataclass(frozen=True)
class Walls:
    """Limits derived from the effective law or the operator's configuration, never chosen by the code inside."""
    timeout_s: int = 600
    memory_mb: int = 2048
    processes: int = 64
    file_bytes: int = 10_485_760


@dataclass(frozen=True)
class Ran:
    code: int
    out: str

    @property
    def ok(self) -> bool:
        return self.code == 0


class Bac:
    def __init__(self, walls: Walls = Walls(), *, python: str = sys.executable):
        self.walls, self.python = walls, python
        self.ready = self._available()

    @property
    def isolation(self) -> str:
        return "network and filesystem jail" if self.ready else "UNAVAILABLE: bubblewrap jail unavailable"

    def command(self, args, cwd, *, readable=(), writable=()) -> list[str]:
        """The argv that runs `args` in the bac. Pure: it builds, it does not check that the jail exists."""
        w = self.walls
        argv = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
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

    def _available(self) -> bool:
        """The jail exists when this very bac definition runs `true`; a different check could pass alone."""
        jail = shutil.which("bwrap")
        if not jail or not shutil.which("prlimit") or not Path("/usr/bin/true").exists():
            return False
        with tempfile.TemporaryDirectory(prefix="bac-check-") as cwd:
            argv = self.command(["/usr/bin/true"], cwd)
            argv[0] = jail
            try:
                return subprocess.run(argv, env=BASE_ENV, capture_output=True, timeout=10).returncode == 0
            except (OSError, subprocess.SubprocessError):
                return False

    def run(self, args, cwd, *, env=None, readable=(), writable=()) -> Ran:
        if not self.ready:
            return Ran(REFUSED, "execution refused: network and filesystem jail unavailable")
        argv = self.command(args, cwd, readable=readable, writable=writable)
        argv[0] = shutil.which("bwrap")
        try:
            with tempfile.TemporaryFile() as output:
                r = subprocess.run(argv, env={**BASE_ENV, **(env or {})}, stdout=output,
                                   stderr=subprocess.STDOUT, timeout=self.walls.timeout_s)
                output.seek(0, 2)
                output.seek(max(0, output.tell() - OUTPUT_TAIL))
                return Ran(r.returncode, output.read().decode(errors="replace"))
        except subprocess.TimeoutExpired:
            return Ran(TIMED_OUT, f"timeout after {self.walls.timeout_s}s")
        except OSError as exc:
            return Ran(REFUSED, f"execution refused: {exc}")
