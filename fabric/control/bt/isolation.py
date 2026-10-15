"""T06 — running code the trusted side does not trust: a contribution's code and tests (D33, D68).

Measuring `tests` means executing a contributor's code. That code must never run as the guard: the guard reads the
installation's keys and writes the journal. Two walls, one inside the other:

    - the account: with `[tests] runner_user` set, the code runs as that user (no key, no group of the guard,
      nothing writable but its scratch), through `sudo -n -u <user> -- /usr/bin/env -i …`;
    - the bac (`enclosure/`, D68): inside that account, the same OCI enclosure as everywhere else, with no network,
      a read-only system, only the run's own directory mounted, no capability, the allow-list system-call filter
      and the per-process limits. The account's ids are root inside, nobody outside.

`candidate_fs_confined` is true only when this very bac runs under that account here; until then the host refuses
candidate jobs. Installing candidate dependencies is a separate step, with network, from wheels only, as the runner
without the bac (it runs no candidate code). The enclosure enters the trust base with this (D68): it is small,
pinned, and has no AI.

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
        self._bac = None

    @property
    def isolated(self) -> bool:
        return bool(self.user)

    @property
    def bac(self):
        """The enclosure under the runner account, checked once (it runs `true` through this very definition)."""
        if self._bac is None and self.user:
            from fabric.runtime.bac import Bac, Walls
            try:
                self._bac = Bac(Walls(timeout_s=3600, memory_mb=self.memory >> 20), as_user=self.user)
            except KeyError:                                 # no such account
                self._bac = False
        return self._bac or None

    @property
    def candidate_fs_confined(self) -> bool:
        return bool(self.bac and self.bac.ready)

    def run_confined(self, args: list, env: dict, *, cwd, stdin: bytes, readable=(), writable=()):
        """Run in the bac under the runner account; (code, stdout, stderr). Only when `candidate_fs_confined`."""
        if not self.candidate_fs_confined:
            raise RuntimeError("candidate filesystem isolation unavailable")
        ran = self.bac.run(args, cwd, env=env, readable=readable, writable=writable, stdin=stdin, split=True)
        return ran.code, ran.out.encode(), ran.err.encode()

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
