"""T07/T08 — release registers (D30-D32, D37): what production runs is a few named values moved by compare-and-swap.

    current        the commit of main that serves              deploy, rollback: from -> to
    canary         the commit on a share of traffic, or empty   canary: empty -> to; abort: to -> empty
    canary_weight  that share, in percent                       written with canary
    restart        "<release> <n> <key>": the n-th restart      restart: only of the current release

Each register is a small file in a directory the guard owns, replaced atomically under one lock, and every move is
appended to history.jsonl. The guard never builds or exports a release: the product's runner reads the commit from
the canonical repository by its hash (tools/run_release.py). Applied (T08) means production *serves* it: the readback
compares the served version the production program read from the product's own metrics.
"""
from __future__ import annotations

import fcntl
import json
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

    def _set(self, name: str, value: str | None, key: str) -> None:
        tmp = self.root / f".{name}-{key}"
        tmp.write_text(f"{value or ''}\n")
        tmp.chmod(0o644)
        tmp.replace(self.root / name)                       # atomic

    def _move(self, op: str, frm: str, to: str, key: str, writes: dict, expect: dict, **extra) -> str:
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o755)
        with open(self.root / ".lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if any(h.get("key") == key for h in self.history()):
                return "ok"                                 # this very move, already made (a retry after an unknown)
            if any(self.get(n) != v for n, v in expect.items()):
                return "failed"                             # the compare-and-swap refused: production moved
            for name, value in writes.items():
                self._set(name, value, key)
            with open(self.log, "a") as f:
                f.write(json.dumps({"at": self.clock(), "op": op, "from": frm, "to": to, "key": key, **extra}) + "\n")
            self.log.chmod(0o644)
        return "ok"

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

    def applied(self, it: dict) -> bool:
        served, args = self.served(), it["args"]
        if it["op"] == "canary":
            return args["to"] in (self.canary(), self.current())
        if it["op"] == "abort":
            return self.canary() != args["to"]
        if it["op"] == "restart":
            asked = next((h["at"] for h in self.history() if h.get("op") == "restart" and h.get("n") == args["n"]
                          and h.get("to") == args["release"]), None)
            return (asked is not None and served["started"] is not None and served["started"] * 1000 >= asked
                    and served["version"] in (None, args["release"]))
        return self.current() == args["to"] and served["version"] in (None, args["to"])
