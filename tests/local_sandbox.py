"""Unconfined executor for functional tests only; it is never imported by product code."""
import os
import subprocess
import sys
import tempfile

from standard.autonomy.sandbox import Result, Sandbox


class LocalSandbox(Sandbox):
    def __init__(self, **_):
        self.python, self.timeout, self.isolated = sys.executable, 30, True

    @property
    def isolation(self):
        return "unconfined test fixture"

    def prepare_environment(self, requirements, cache):
        return sys.executable

    def run(self, args, cwd, *, pythonpath=None, readable=(), writable=()):
        with tempfile.TemporaryDirectory(prefix="standard-test-home-") as home:
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home,
                   "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8"}
            if pythonpath:
                env["PYTHONPATH"] = str(pythonpath)
            try:
                result = subprocess.run([str(a) for a in args], cwd=cwd, env=env, capture_output=True,
                                        timeout=self.timeout)
            except subprocess.TimeoutExpired:
                return Result(124, "test fixture timed out")
        return Result(result.returncode, (result.stdout + result.stderr).decode(errors="replace")[-20_000:])
