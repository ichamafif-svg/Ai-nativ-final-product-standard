"""T07/T08 — the release adapter for `deploy`, `rollback` and `restart` (D30, D31): which commit of main runs.

The live release is a symbolic link `current -> releases/<commit>` in a directory the guard owns. Both operations are
the same compare-and-swap: switch `current` from exactly `from` to `to` (the commit exported from the canonical
repository, never from the agent's store), by an atomic rename of a new link over the old one, under a lock: if
`current` is no longer `from`, nothing moves. The product picks the new release up by itself (it watches the link) or
through the configured restart command; a restart that fails leaves the effect `unknown`, for the readback to settle.

Every switch is appended to history.jsonl: the instrument reads it to know which release came before, and which were
rolled back (those are never offered again: no deploy/rollback loop). A rollback only goes to a release that was live
before; a restart asks the product's runner, through a file it watches, to start the same release again.

Applied (T08) means production *serves* the release, not only that the link points to it: when the product exposes
`build_info{version}`, the readback compares it, and a restart is applied once the process started after the request.
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
OPS = ("deploy", "rollback", "restart", "canary", "abort")


class Releases:
    def __init__(self, repo, root, restart=None, branch: str = "main", clock=None, served=None, canary_percent=None):
        self.repo, self.root, self.restart, self.branch = Path(repo), Path(root), restart, branch
        self.canary_percent = canary_percent or (lambda: 10)
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.served = served or (lambda: {"version": None, "started": None})   # what answers, from the metrics
        self.link, self.dir, self.log = self.root / "current", self.root / "releases", self.root / "history.jsonl"

    def canary(self) -> str | None:
        """The release on a share of traffic beside the live one, if any (D32)."""
        try:
            name = Path(os.readlink(self.root / "canary")).name
        except OSError:
            return None
        return name if SHA.fullmatch(name) else None

    def _log(self, op: str, frm: str, to: str, **extra) -> None:
        with open(self.log, "a") as f:
            f.write(json.dumps({"at": self.clock(), "op": op, "from": frm, "to": to, **extra}) + "\n")
        self.log.chmod(0o644)

    def _link(self, name: str, target: str | None, key: str) -> None:
        if target is None:
            (self.root / name).unlink(missing_ok=True)
            return
        tmp = self.root / f".{name}-{key}"
        tmp.unlink(missing_ok=True)
        os.symlink(f"releases/{target}", tmp)
        os.replace(tmp, self.root / name)                    # atomic

    def canary_switch(self, resource: str, args: dict, reservation_key: str) -> str:
        """canary (run:canary:all/{from}/{to}): start `to`, a commit of main, on a share of traffic beside `from`.
        abort (run:canary:abort/{from}/{to}): take the canary `to` out; it is never offered again."""
        frm, to = args["from"], args["to"]
        if not SHA.fullmatch(to) or not (frm == "none" or SHA.fullmatch(frm)):
            return "failed"
        abort = resource.startswith("run:canary:abort/")
        if not abort and subprocess.run(
                ["git", "-C", str(self.repo), "merge-base", "--is-ancestor", to, f"refs/heads/{self.branch}"],
                capture_output=True, timeout=120).returncode != 0:
            return "failed"
        with open(self.root / ".lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if self.current() != (None if frm == "none" else frm):
                return "failed"                              # production moved
            if abort:
                if self.canary() != to:
                    return "ok" if any(h.get("op") == "abort" and h.get("to") == to for h in self.history()) else "failed"
                self._link("canary", None, reservation_key)
                self._log("abort", frm, to)
                return "ok"
            if self.canary() == to:
                return "ok"
            if self.canary() is not None:
                return "failed"                              # one canary at a time
            try:
                self._export(to)
            except (OSError, subprocess.SubprocessError, tarfile.TarError):
                return "failed"
            weight = self.root / ".canary_weight.tmp"
            weight.write_text(f"{int(self.canary_percent())}\n")
            weight.chmod(0o644)
            os.replace(weight, self.root / "canary_weight")
            self._link("canary", to, reservation_key)
            self._log("canary", frm, to, percent=int(self.canary_percent()))
        return "ok"

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
        if op == "rollback" and to not in {h["to"] for h in self.history()}:
            return "failed"                                  # only back to a release that was live before
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
            if self.canary() is not None and (self.canary() == to or op == "rollback"):
                self._link("canary", None, reservation_key)  # promoted, or stepping back ends any canary
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

    def request_restart(self, resource: str, args: dict, reservation_key: str) -> str:
        """restart (run:process:all/{release}/{n}): only the live release, through the runner's request file."""
        release = args["release"]
        if not SHA.fullmatch(release) or not re.fullmatch(r"[0-9]{1,6}", args["n"]):
            return "failed"
        with open(self.root / ".lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if self.current() != release:
                return "failed"                              # production moved: restarting it is not what was judged
            tmp = self.root / f".restart-{reservation_key}"
            tmp.write_text(f"{release} {args['n']} {reservation_key}\n")
            tmp.chmod(0o644)
            os.replace(tmp, self.root / "restart")
            with open(self.log, "a") as f:
                f.write(json.dumps({"at": self.clock(), "op": "restart", "from": release, "to": release,
                                    "n": args["n"]}) + "\n")
        return "ok"

    def applied(self, it: dict) -> bool:
        served = self.served()
        if it["op"] == "canary":
            return self.canary() == it["args"]["to"] or self.current() == it["args"]["to"]
        if it["op"] == "abort":
            return self.canary() != it["args"]["to"]
        if it["op"] == "restart":
            asked = next((h["at"] for h in self.history() if h.get("op") == "restart" and h.get("n") == it["args"]["n"]
                          and h.get("to") == it["args"]["release"]), None)
            return (asked is not None and served["started"] is not None and served["started"] * 1000 >= asked
                    and served["version"] in (None, it["args"]["release"]))
        to = it["args"]["to"]
        return self.current() == to and served["version"] in (None, to)
