"""U — candidate execution in a network and filesystem jail, never with the agent's keys mounted.

What the sandbox says helps the agent; it proves nothing. The judge's instruments run elsewhere, under another
identity, on the exact commit: an agent that lies to itself here is still refused there.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Result:
    code: int
    out: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def _can_isolate() -> bool:
    jail = shutil.which("bwrap")
    if not jail or not shutil.which("prlimit") or not Path("/usr/bin/true").exists():
        return False
    try:
        return subprocess.run([jail, "--unshare-all", "--die-with-parent", "--dir", "/usr",
                               "--ro-bind", "/usr", "/usr",
                               "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "/usr/bin/true"],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class Sandbox:
    def __init__(self, *, timeout: int = 600, memory_mb: int = 2048, python: str = sys.executable,
                 cache_roots=(), file_limit: int = 10_485_760):
        self.timeout, self.memory, self.python, self.file_limit = timeout, memory_mb << 20, python, file_limit
        self.cache_roots = frozenset(Path(path).resolve() for path in cache_roots)
        self.isolated = _can_isolate()

    @property
    def isolation(self) -> str:
        return "network and filesystem jail" if self.isolated else "UNAVAILABLE: bubblewrap jail unavailable"

    def run(self, args: list, cwd, *, pythonpath=None, readable=(), writable=()) -> Result:
        if not self.isolated:
            return Result(126, "candidate execution refused: network and filesystem jail unavailable")
        scratch = Path(tempfile.gettempdir()).resolve()
        exposed = (Path(cwd), *map(Path, readable), *map(Path, writable))
        if any((not path.resolve().is_relative_to(scratch) or path.resolve() == scratch)
               and path.resolve() not in self.cache_roots for path in exposed):
            return Result(126, "candidate execution refused: input is outside scratch")
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1",
               "LANG": "C.UTF-8", **({"PYTHONPATH": str(pythonpath)} if pythonpath else {})}
        limit = ["prlimit", f"--as={self.memory}", "--nproc=64", f"--fsize={self.file_limit}", "--"]
        prefix = [shutil.which("bwrap"), "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
                  "--dir", "/usr", "--ro-bind", "/usr", "/usr", "--proc", "/proc", "--dev", "/dev",
                  "--tmpfs", "/tmp"]
        for path in ("/bin", "/lib", "/lib64"):
            source = Path(path)
            if source.is_symlink():
                prefix += ["--symlink", str(source.readlink()), path]
            elif source.exists():
                prefix += ["--ro-bind", path, path]
        mounts = {Path(cwd).resolve(): "--ro-bind"}
        mounts.update({Path(path).resolve(): "--ro-bind" for path in readable})
        mounts.update({Path(path).resolve(): "--bind" for path in writable})
        runtime = Path(sys.prefix).resolve()
        if not runtime.is_relative_to(Path("/usr")):
            mounts[runtime] = "--ro-bind"
        made = set()
        for path, operation in sorted(mounts.items(), key=lambda item: (len(item[0].parts), str(item[0]))):
            for parent in reversed(path.parents):
                if parent != Path("/") and parent != Path("/usr") and not parent.is_relative_to(Path("/usr")) \
                        and parent not in made:
                    prefix += ["--dir", str(parent)]
                    made.add(parent)
            prefix += [operation, str(path), str(path)]
        prefix += ["--chdir", str(Path(cwd).resolve())]
        try:
            with tempfile.TemporaryFile() as output:
                r = subprocess.run(prefix + limit + [str(a) for a in args], env=env, stdout=output,
                                   stderr=subprocess.STDOUT, timeout=self.timeout)
                output.seek(0, 2)
                output.seek(max(0, output.tell() - 20_000))
                return Result(r.returncode, output.read().decode(errors="replace"))
        except subprocess.TimeoutExpired:
            return Result(124, f"timeout after {self.timeout}s")
        except OSError as exc:
            return Result(126, f"candidate execution refused: {exc}")

    def python_module(self, module: str, *args, cwd, pythonpath=None, readable=(), writable=()) -> Result:
        return self.run([self.python, "-m", module, *args], cwd, pythonpath=pythonpath,
                        readable=readable, writable=writable)

    @contextmanager
    def checkout(self, store, commit: str):
        """A detached, throwaway working tree of one commit of the agent's own store."""
        work = Path(tempfile.mkdtemp(prefix="sandbox-tree-")) / "tree"
        subprocess.run(["git", "-C", str(store), "worktree", "add", "-q", "--detach", str(work), commit],
                       check=True, capture_output=True, timeout=300)
        try:
            yield work
        finally:
            subprocess.run(["git", "-C", str(store), "worktree", "remove", "--force", str(work)],
                           capture_output=True, timeout=300)
            shutil.rmtree(work.parent, ignore_errors=True)
