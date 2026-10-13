"""U03 — the Work Engine: durable leases and retries for projected tasks (ARCHITECTURE.md §11.3).

SQLite holds scheduling only. The obligation and its due date belong to K: this store keeps the earliest due it has
seen, never a later one; a lease confers no right; a task disappears only when a new constitutional view no longer
shows its obligation. Completing an attempt frees the lease and sets the next try; it never closes anything.
"""
from __future__ import annotations

import json
import sqlite3
from urllib.parse import quote
from contextlib import closing
from pathlib import Path


class WorkError(ValueError):
    pass


class WorkEngine:
    def __init__(self, path):
        self.path = Path(path)
        with closing(self._db()) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS tasks (
                mode TEXT NOT NULL, id TEXT NOT NULL, obligation TEXT NOT NULL, need TEXT NOT NULL,
                resource TEXT NOT NULL, due INTEGER NOT NULL, state TEXT NOT NULL, task TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL DEFAULT 0,
                lease_until INTEGER NOT NULL DEFAULT 0, basis TEXT NOT NULL, PRIMARY KEY (mode, id))""")
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, at INTEGER NOT NULL, mode TEXT NOT NULL, task_id TEXT NOT NULL,
                obligation TEXT NOT NULL, basis TEXT NOT NULL, main TEXT, attempt INTEGER NOT NULL,
                route TEXT, outcome TEXT NOT NULL, reason_code TEXT NOT NULL, detail TEXT NOT NULL)""")

    def _db(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=15)
        db.execute("PRAGMA busy_timeout=15000")
        return db

    def sync(self, projection: dict) -> None:
        mode, basis = projection["mode"], json.dumps(projection["basis"], sort_keys=True)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                current = set()
                for t in projection["tasks"]:
                    current.add(t["id"])
                    old = db.execute("SELECT due FROM tasks WHERE mode=? AND id=?", (mode, t["id"])).fetchone()
                    due = min(old[0], t["due"]) if old else t["due"]
                    db.execute("""INSERT INTO tasks (mode, id, obligation, need, resource, due, state, task, basis)
                        VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT (mode, id) DO UPDATE SET due=excluded.due,
                        state=excluded.state, task=excluded.task, basis=excluded.basis,
                        attempts=CASE WHEN tasks.basis=excluded.basis THEN tasks.attempts ELSE 0 END,
                        next_at=CASE WHEN tasks.basis=excluded.basis THEN tasks.next_at ELSE 0 END,
                        lease_until=CASE WHEN tasks.basis=excluded.basis THEN tasks.lease_until ELSE 0 END""",
                               (mode, t["id"], t["obligation"], t["need"], t["resource"], due, t["state"],
                                json.dumps(t, sort_keys=True), basis))
                for (ident,) in db.execute("SELECT id FROM tasks WHERE mode=?", (mode,)).fetchall():
                    if ident not in current:
                        db.execute("DELETE FROM tasks WHERE mode=? AND id=?", (mode, ident))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def claim(self, *, mode: str, now: int, lease_ms: int = 600_000, needs=None):
        """Lease the most urgent ready task (optionally of given needs)."""
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                rows = db.execute("""SELECT id, task, attempts, due FROM tasks WHERE mode=? AND state='AVAILABLE'
                    AND next_at<=? AND lease_until<=? ORDER BY due, id""", (mode, now, now)).fetchall()
                row = next((r for r in rows if needs is None or json.loads(r[1])["need"] in needs), None)
                if row:
                    db.execute("UPDATE tasks SET lease_until=?, attempts=attempts+1 WHERE mode=? AND id=?",
                               (now + lease_ms, mode, row[0]))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        if row is None:
            return None
        return {**json.loads(row[1]), "attempt": row[2] + 1, "due": row[3], "lease_until": now + lease_ms}

    def complete_attempt(self, *, mode: str, task_id: str, lease_until: int, next_at: int) -> None:
        with closing(self._db()) as db:
            changed = db.execute("UPDATE tasks SET next_at=?, lease_until=0 WHERE mode=? AND id=? AND lease_until=?",
                                 (next_at, mode, task_id, lease_until)).rowcount
        if changed != 1:
            raise WorkError("stale lease")

    def tasks(self, mode: str = "RUN") -> list:
        with closing(self._db()) as db:
            return [{**json.loads(task), "attempts": attempts, "due": due} for task, attempts, due in
                    db.execute("SELECT task, attempts, due FROM tasks WHERE mode=? ORDER BY due, id", (mode,))]

    def record(self, *, at: int, mode: str, task: dict, basis: dict, main: str | None,
               outcome: str, reason_code: str, detail: str = "") -> None:
        with closing(self._db()) as db:
            db.execute("""INSERT INTO events
                (at, mode, task_id, obligation, basis, main, attempt, route, outcome, reason_code, detail)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                       (at, mode, task["id"], task["obligation"], json.dumps(basis, sort_keys=True), main,
                        task.get("attempt", 0), next((r["route"] for r in task.get("routes", [])
                                                       if r["state"] == "AVAILABLE"), None),
                        outcome, reason_code, detail[:2000]))

    def progress(self, mode: str = "RUN") -> dict:
        """Only a current, available obligation abandoned by U is a confirmed progress failure."""
        with closing(self._db()) as db:
            rows = self._progress_rows(db, mode)
        return self._progress_report(rows, mode)

    @staticmethod
    def read_progress(path, mode: str = "RUN") -> dict:
        path = Path(path)
        if not path.exists():
            return {"schema": "standard-progress/v1", "mode": mode, "status": "unavailable"}
        try:
            with closing(sqlite3.connect(f"file:{quote(str(path.resolve()))}?mode=ro", uri=True)) as db:
                rows = WorkEngine._progress_rows(db, mode)
        except sqlite3.DatabaseError:
            return {"schema": "standard-progress/v1", "mode": mode, "status": "unavailable"}
        return WorkEngine._progress_report(rows, mode)

    @staticmethod
    def _progress_rows(db, mode):
        return db.execute("""SELECT t.id, t.obligation, t.need, t.state, e.outcome, e.reason_code
                FROM tasks t LEFT JOIN events e ON e.id = (
                    SELECT MAX(id) FROM events WHERE mode=t.mode AND task_id=t.id AND basis=t.basis)
                WHERE t.mode=? ORDER BY t.due, t.id""", (mode,)).fetchall()

    @staticmethod
    def _progress_report(rows, mode):
        failures = [{"task": ident, "obligation": obligation, "reason": reason}
                    for ident, obligation, need, state, outcome, reason in rows
                    if need == "repair" and state == "AVAILABLE" and outcome == "progress_failure"]
        waiting = [{"task": ident, "obligation": obligation, "state": state}
                   for ident, obligation, need, state, _, _ in rows if state != "AVAILABLE"]
        return {"schema": "standard-progress/v1", "mode": mode, "pf": len(failures),
                "failures": failures, "waiting": waiting, "active": len(rows),
                "authority": "U scheduling only; current constitutional debt remains in the journal"}
