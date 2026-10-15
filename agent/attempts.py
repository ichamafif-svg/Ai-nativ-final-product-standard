"""How often a candidate passes the agent's own precheck on its first attempt (D70): the measure of whether the
context given before coding is enough. One line per task outcome; a diagnostic, never a fact or a permission."""
from __future__ import annotations

import json
import time
from pathlib import Path


def record(path, kind: str, task: str, attempts: int, passed: bool) -> None:
    line = {"at": int(time.time() * 1000), "kind": kind, "task": task, "attempts": attempts, "passed": passed}
    with Path(path).open("a", encoding="utf-8") as out:
        out.write(json.dumps(line, sort_keys=True) + "\n")


def first_pass(path) -> dict:
    """Over every recorded task outcome: how many passed, how many on the first attempt, and the rate."""
    try:
        rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    except FileNotFoundError:
        rows = []
    passed = [r for r in rows if r.get("passed")]
    first = [r for r in passed if r.get("attempts") == 1]
    return {"tasks": len(rows), "passed": len(passed), "first_attempt": len(first),
            "rate": round(len(first) / len(rows), 3) if rows else None}
