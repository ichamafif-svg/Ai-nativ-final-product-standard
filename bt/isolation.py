"""T06 — running code the trusted side does not trust: a contribution's code and tests (D33).

Measuring `tests` means executing a contributor's code. That code must never run as the guard: the guard reads the
installation's keys and writes the journal. With `[tests] runner_user` set, the instrument runs it as that user (an
account with no key, no group of the guard, nothing writable but its scratch directory), through
`sudo -n -u <user> env -i …`, inside a new user and network namespace (`unshare -rn`: no network at all), under a
memory limit and a deadline. The tree it runs on is a fresh copy, world-readable, and its only writable place is the
output directory. Installing dependencies is a separate step, as the same user, with network, from wheels only.

This boundary does not yet confine the runner's filesystem, and installation of candidate dependencies is a
separate networked step. The host refuses candidate jobs while this is incomplete; `isolated` means user separation
only, not a complete candidate-code jail. Qualification must not report T06 as complete on this implementation.

Fail closed: without a runner user the host refuses candidate code as well. `unconfined=True` is the only way to run
candidate code in the trusted process's own account, and exists for functional tests and explicit demos: it gives the
candidate every key that process can read, so it is never inferred from a missing setting.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path


class Isolation:
    def __init__(self, user: str | None = None, *, memory_mb: int = 2048, unconfined: bool = False):
        if unconfined and user:
            raise ValueError("a runner user and an unconfined executor are exclusive")
        self.user, self.memory, self.unconfined = user, memory_mb << 20, unconfined is True

    @property
    def isolated(self) -> bool:
        return bool(self.user)

    @property
    def candidate_fs_confined(self) -> bool:
        return False

    @property
    def may_run_candidates(self) -> bool:
        """Candidate code runs only in a complete jail, or where an operator explicitly accepted no jail at all."""
        return self.candidate_fs_confined or self.unconfined

    def open_to_runner(self, *paths) -> None:
        """Make the copies the runner reads world-readable (code is not secret), and give it one writable place."""
        if not self.user:
            return
        for root in paths:
            for dirpath, dirs, files in os.walk(root):
                os.chmod(dirpath, 0o755)
                for name in files:
                    p = Path(dirpath, name)
                    if not p.is_symlink():
                        p.chmod(0o755 if p.stat().st_mode & 0o100 else 0o644)

    def writable(self, path: Path) -> Path:
        path.mkdir(parents=True, exist_ok=True)
        if self.user:
            path.chmod(0o1777)
        return path

    def command(self, args: list, env: dict, *, network: bool = False) -> list:
        """The argv that runs `args` as the runner, without network unless asked, under the memory limit."""
        env_args = [f"{k}={v}" for k, v in env.items()]
        jail = [] if network else ["unshare", "-rn"]
        limit = ["prlimit", f"--as={self.memory}", "--"] if shutil.which("prlimit") else []
        if not self.user:
            return ["env", "-i", *env_args, *limit, *[str(a) for a in args]]
        return ["sudo", "-n", "-u", self.user, "--", "/usr/bin/env", "-i", *env_args, *jail, *limit,
                *[str(a) for a in args]]
