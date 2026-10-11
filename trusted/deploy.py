"""T07/T08 — the release adapter for `deploy` and `rollback` (D30): which commit of main runs in production.

The live release is a symbolic link `current -> releases/<commit>` in a directory the guard owns. Both operations are
the same compare-and-swap: switch `current` from exactly `from` to `to` (the commit exported from the canonical
repository, never from the agent's store), by an atomic rename of a new link over the old one, under a lock: if
`current` is no longer `from`, nothing moves. The product picks the new release up by itself (it watches the link) or
through the configured restart command; a restart that fails leaves the effect `unknown`, for the readback to settle.

Every switch is appended to history.jsonl: the instrument reads it to know which release came before, and which were
rolled back (those are never offered again: no deploy/rollback loop).
"""
from __future__ import annotations

import fcntl
import io
import json
import os
import re
import subprocess
import tarfile
import time
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}")
OPS = ("deploy", "rollback")


class Releases:
    def __init__(self, repo, root, restart=None, branch: str = "main", clock=None):
        self.repo, self.root, self.restart, self.branch = Path(repo), Path(root), restart, branch
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.link, self.dir, self.log = self.root / "current", self.root / "releases", self.root / "history.jsonl"

    def current(self) -> str | None:
        try:
            name = Path(os.readlink(self.link)).name
        except OSError:
            return None
        return name if SHA.fullmatch(name) else None

    def history(self) -> list:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def _export(self, commit: str) -> Path:
        target = self.dir / commit
        if target.is_dir():
            return target
        archive = subprocess.run(["git", "-C", str(self.repo), "archive", "--format=tar", commit],
                                 capture_output=True, timeout=300, check=True).stdout
        tmp = self.dir / f".{commit}.tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(tmp, filter="data")
        for path in [tmp, *tmp.rglob("*")]:                 # code is public to the product's user: read, never write
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o100 else 0o644)
        tmp.rename(target)
        return target

    def switch(self, resource: str, args: dict, reservation_key: str) -> str:
        """deploy (run:release:all/{from}/{to}) and rollback (run:service:all/{from}/{to})."""
        frm, to = args["from"], args["to"]
        if not SHA.fullmatch(to) or not (frm == "none" or SHA.fullmatch(frm)):
            return "failed"                                  # nothing sent: the arguments cannot name commits
        op = "rollback" if resource.startswith("run:service:") else "deploy"
        if op == "deploy" and subprocess.run(
                ["git", "-C", str(self.repo), "merge-base", "--is-ancestor", to, f"refs/heads/{self.branch}"],
                capture_output=True, timeout=120).returncode != 0:
            return "failed"                                  # only a commit of main is ever deployed
        for d in (self.root, self.dir):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o755)
        with open(self.root / ".lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            live = self.current()
            if live == to:
                return "ok"                                  # already applied (a retry after an unknown)
            if live != (None if frm == "none" else frm):
                return "failed"                              # the compare-and-swap refused: production moved
            try:
                self._export(to)
            except (OSError, subprocess.SubprocessError, tarfile.TarError):
                return "failed"                              # nothing switched
            tmp = self.root / f".current-{reservation_key}"
            tmp.unlink(missing_ok=True)
            os.symlink(f"releases/{to}", tmp)
            os.replace(tmp, self.link)                       # atomic: production is `from` or `to`, never between
            with open(self.log, "a") as f:
                f.write(json.dumps({"at": self.clock(), "op": op, "from": frm, "to": to}) + "\n")
            self.log.chmod(0o644)
        if self.restart:
            try:
                ok = subprocess.run(self.restart, capture_output=True, timeout=120).returncode == 0
            except (OSError, subprocess.SubprocessError):
                ok = False
            if not ok:
                return "unknown"                             # switched, but did the product restart? readback says
        return "ok"

    def applied(self, to: str) -> bool:
        return self.current() == to
