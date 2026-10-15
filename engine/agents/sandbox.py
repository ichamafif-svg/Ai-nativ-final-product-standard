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
from pathlib import Path
from fabric.runtime.bac import Bac, Ran, Walls

Result = Ran


class Sandbox:
    """The agent's view of the one bac (D68): same walls as tests and production, plus a scratch-only policy."""

    def __init__(self, *, timeout: int = 600, memory_mb: int = 2048, python: str = sys.executable,
                 cache_roots=(), file_limit: int = 10_485_760):
        self.bac = Bac(Walls(timeout_s=timeout, memory_mb=memory_mb, file_bytes=file_limit), python=python)
        self.timeout, self.python = timeout, python
        self.cache_roots = frozenset(Path(path).resolve() for path in cache_roots)
        self.isolated = self.bac.ready

    @property
    def isolation(self) -> str:
        return self.bac.isolation

    def run(self, args: list, cwd, *, pythonpath=None, readable=(), writable=()) -> Result:
        if not self.isolated:
            return Result(126, "candidate execution refused: network and filesystem jail unavailable")
        scratch = Path(tempfile.gettempdir()).resolve()
        exposed = (Path(cwd), *map(Path, readable), *map(Path, writable))
        if any((not path.resolve().is_relative_to(scratch) or path.resolve() == scratch)
               and path.resolve() not in self.cache_roots for path in exposed):
            return Result(126, "candidate execution refused: input is outside scratch")
        env = {"PYTHONPATH": str(pythonpath)} if pythonpath else {}
        return self.bac.run(args, cwd, env=env, readable=readable, writable=writable)

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
