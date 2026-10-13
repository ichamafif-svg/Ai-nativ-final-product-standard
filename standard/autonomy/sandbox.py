"""U — the agent's sandbox: where it runs its own code and checks before proposing anything.

Isolation: a new user and network namespace (`unshare -rn`: no network at all), an empty environment with a throwaway
HOME, a memory limit and a timeout, a detached checkout that is deleted afterwards. What runs here holds no key, reaches
no service and sees no secret the agent does not already hold.

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
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class Sandbox:
    def __init__(self, *, timeout: int = 600, memory_mb: int = 2048, python: str = sys.executable):
        self.timeout, self.memory, self.python = timeout, memory_mb << 20, python
        self.isolated = _can_isolate()

    @property
    def isolation(self) -> str:
        return "no network, empty environment" if self.isolated else "UNISOLATED: unshare unavailable on this host"

    def run(self, args: list, cwd, *, pythonpath=None) -> Result:
        home = tempfile.mkdtemp(prefix="sandbox-home-")
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home, "PYTHONDONTWRITEBYTECODE": "1",
               "LANG": "C.UTF-8", **({"PYTHONPATH": str(pythonpath)} if pythonpath else {})}
        limit = ["prlimit", f"--as={self.memory}", "--"] if shutil.which("prlimit") else []
        prefix = (["unshare", "-rn"] if self.isolated else []) + limit
        try:
            r = subprocess.run(prefix + [str(a) for a in args], cwd=cwd, env=env, capture_output=True,
                               timeout=self.timeout)
            return Result(r.returncode, (r.stdout + r.stderr).decode(errors="replace")[-20_000:])
        except subprocess.TimeoutExpired:
            return Result(124, f"timeout after {self.timeout}s")
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def python_module(self, module: str, *args, cwd, pythonpath=None) -> Result:
        return self.run([self.python, "-m", module, *args], cwd, pythonpath=pythonpath)

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
