"""T07/T08 — release registers (D30-D32, D37): what production runs is a few named values moved by compare-and-swap.

    current        the commit of main that serves              deploy, rollback: from -> to
    canary         the commit on a share of traffic, or empty   canary: empty -> to; abort: to -> empty
    canary_weight  that share, in percent                       written with canary
    restart        "<release> <n> <key>": the n-th restart      restart: only of the current release

Each register is a small file in a directory the guard owns, replaced atomically under one lock; every move is first
appended to history.jsonl with its reservation key, then made. The guard never builds or exports a release: the
product's runner reads the commit from the canonical repository by its hash (tools/run_release.py).

D38, as boundary transactions: deploy, rollback, canary and abort are `cas` effects on the registers themselves:
applied when this key's move is in the history and the registers show it; not_applied when the key never reached the
history (the move runs to completion under the lock, nothing can still land). A restart is `observable`: the guard
only writes the request; the runner restarts; it is applied when the production program sees a process of that
release started after the request, never not_applied once the request was written. Serving the release is the
purpose, proven separately (`satisfied`): the version the product reports is the one switched to.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import time
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}")


class Registers:
    def __init__(self, repo, root, *, clock=None, served=None, canary_percent=None, branch: str = "main"):
        self.repo, self.root, self.branch = Path(repo), Path(root), branch
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.served = served or (lambda: {"version": None, "started": None})
        self.canary_percent = canary_percent or (lambda: 10)
        self.log = self.root / "history.jsonl"

    def get(self, name: str) -> str | None:
        try:
            value = (self.root / name).read_text().strip()
        except OSError:
            return None
        return value or None

    def current(self) -> str | None:
        return self.get("current")

    def canary(self) -> str | None:
        return self.get("canary")

    def history(self) -> list:
        return [json.loads(x) for x in self.log.read_text().splitlines() if x.strip()] if self.log.exists() else []

    def read(self) -> dict:
        return {"current": self.current(), "canary": self.canary(), "history": self.history()}

    def _sync_dir(self) -> None:
        fd = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _set(self, name: str, value: str | None, key: str) -> None:
        tmp = self.root / f".{name}-{key}"
        with open(tmp, "w") as f:
            f.write(f"{value or ''}\n")
            f.flush()
            os.fsync(f.fileno())
        tmp.chmod(0o644)
        tmp.replace(self.root / name)                       # atomic
        self._sync_dir()                                    # durable before the move is reported

    def _shows(self, writes: dict) -> bool:
        return all(self.get(n) == (v or None) for n, v in writes.items())

    def _move(self, op: str, frm: str, to: str, key: str, writes: dict, expect: dict, **extra) -> str:
        """History first and durable, then the registers, durable: a key absent from the history never moved, and a
        key in it either shows in the registers or is completed here, under the same lock, if nothing moved since."""
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o755)
        with open(self.root / ".lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if self.moved(key):
                if self._shows(writes):
                    return "ok"                             # this very move, already made
                if any(self.get(n) != v for n, v in expect.items()):
                    return "unknown"                        # recorded, interrupted, and production moved since
                for name, value in writes.items():          # recorded then interrupted: finish exactly this move
                    self._set(name, value, key)
                return "ok"
            if any(self.get(n) != v for n, v in expect.items()):
                return "failed"                             # the compare-and-swap refused: production moved
            with open(self.log, "a") as f:
                f.write(json.dumps({"at": self.clock(), "op": op, "from": frm, "to": to, "key": key, **extra}) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.log.chmod(0o644)
            self._sync_dir()
            for name, value in writes.items():
                self._set(name, value, key)
        return "ok"

    def moved(self, key: str) -> bool:
        return any(h.get("key") == key for h in self.history())

    def effects(self) -> dict:
        """The effect adapters of the boundary port and of RESOLVE, one per operation."""
        return {op: RegisterEffect(self, op) for op in ("deploy", "rollback", "canary", "abort", "restart")}

    def _on_main(self, commit: str) -> bool:
        return subprocess.run(["git", "-C", str(self.repo), "merge-base", "--is-ancestor", commit,
                               f"refs/heads/{self.branch}"], capture_output=True, timeout=120).returncode == 0

    # ---- effect ports -----------------------------------------------------------------------------------------------
    def switch(self, resource: str, args: dict, key: str) -> str:
        """deploy (run:release:all/{from}/{to}) and rollback (run:service:all/{from}/{to})."""
        frm, to = args["from"], args["to"]
        if not SHA.fullmatch(to) or not (frm == "none" or SHA.fullmatch(frm)):
            return "failed"                                 # nothing sent: the arguments cannot name commits
        op = "rollback" if resource.startswith("run:service:") else "deploy"
        if (op == "rollback" and to not in {h["to"] for h in self.history()}) or (op == "deploy" and not self._on_main(to)):
            return "failed"                                 # back only to a release that was live; forward only to main
        canary = self.canary()
        writes = {"current": to, **({"canary": None} if canary is not None and (canary == to or op == "rollback") else {})}
        return self._move(op, frm, to, key, writes, {"current": None if frm == "none" else frm})

    def canary_switch(self, resource: str, args: dict, key: str) -> str:
        """canary (run:canary:all/{from}/{to}) and abort (run:canary:abort/{from}/{to})."""
        frm, to = args["from"], args["to"]
        if not SHA.fullmatch(to) or not SHA.fullmatch(frm):
            return "failed"
        if resource.startswith("run:canary:abort/"):
            return self._move("abort", frm, to, key, {"canary": None}, {"current": frm, "canary": to})
        if not self._on_main(to):
            return "failed"
        percent = max(1, min(50, int(self.canary_percent())))
        return self._move("canary", frm, to, key, {"canary": to, "canary_weight": str(percent)},
                          {"current": frm, "canary": None}, percent=percent)

    def request_restart(self, resource: str, args: dict, key: str) -> str:
        """restart (run:process:all/{release}/{n}): only the live release."""
        release, n = args["release"], args["n"]
        if not SHA.fullmatch(release) or not re.fullmatch(r"[0-9]{1,6}", n):
            return "failed"
        return self._move("restart", release, release, key, {"restart": f"{release} {n} {key}"}, {"current": release},
                          n=n)

    def started_after(self, release: str, n: str) -> bool:
        served, asked = self.served(), next((h["at"] for h in self.history() if h.get("op") == "restart"
                                             and h.get("n") == n and h.get("to") == release), None)
        return (asked is not None and served["started"] is not None and served["started"] * 1000 >= asked
                and served["version"] in (None, release))


class RegisterEffect:
    """One operation on the registers, as the boundary sees it: its profile, how it leaves, how it is read back."""

    def __init__(self, registers: Registers, op: str):
        self.r, self.op = registers, op
        self.profile = "observable" if op == "restart" else "cas"
        self.perform = {"deploy": registers.switch, "rollback": registers.switch, "canary": registers.canary_switch,
                        "abort": registers.canary_switch, "restart": registers.request_restart}[op]

    def read(self, it: dict, key: str) -> str | None:
        a = it["args"]
        if self.op == "restart":
            if not self.r.moved(key):
                return "not_sent"                           # the request never left: nothing can happen
            return "applied" if self.r.started_after(a["release"], a["n"]) else None
        if not self.r.moved(key):
            return "not_applied"
        shown = {"deploy": self.r.current() == a["to"], "rollback": self.r.current() == a["to"],
                 "canary": a["to"] in (self.r.canary(), self.r.current()), "abort": self.r.canary() != a["to"]}[self.op]
        return "applied" if shown else None

    def satisfied(self, it: dict) -> bool:
        a, served = it["args"], self.r.served()
        if self.op == "restart":
            return self.r.started_after(a["release"], a["n"])
        if self.op in ("deploy", "rollback"):
            return self.r.current() == a["to"] and served["version"] in (None, a["to"])
        if self.op == "canary":
            return a["to"] in (self.r.canary(), self.r.current())
        return self.r.canary() != a["to"]
