"""Work derived from constitutional needs: one queue, durable leases and retries, never authority.

Obligations retain their ids and earliest deadlines. Completing an attempt releases a lease, not a debt.
The former BUILD/RUN scheduling partitions are collapsed transactionally when an existing store is opened.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import quote


class WorkError(ValueError):
    pass


class WorkEngine:
    def __init__(self, path):
        self.path = Path(path)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                legacy = "mode" in {r[1] for r in db.execute("PRAGMA table_info(tasks)")}
                if legacy:
                    db.execute("ALTER TABLE tasks RENAME TO partitioned_tasks")
                    db.execute("ALTER TABLE events RENAME TO partitioned_events")
                db.execute("""CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, obligation TEXT NOT NULL, need TEXT NOT NULL, resource TEXT NOT NULL,
                    due INTEGER NOT NULL, state TEXT NOT NULL, task TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    next_at INTEGER NOT NULL DEFAULT 0, lease_until INTEGER NOT NULL DEFAULT 0, basis TEXT NOT NULL)""")
                db.execute("""CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY, at INTEGER NOT NULL, task_id TEXT NOT NULL, obligation TEXT NOT NULL,
                    basis TEXT NOT NULL, main TEXT, attempt INTEGER NOT NULL, route TEXT, outcome TEXT NOT NULL,
                    reason_code TEXT NOT NULL, detail TEXT NOT NULL)""")
                if legacy:
                    for row in db.execute(
                        "SELECT id, obligation, need, resource, due, state, task, attempts, next_at, "
                        "lease_until, basis FROM partitioned_tasks ORDER BY rowid"
                    ).fetchall():
                        db.execute(
                            """INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                            obligation=excluded.obligation, need=excluded.need, resource=excluded.resource,
                            due=MIN(tasks.due,excluded.due), state=excluded.state, task=excluded.task,
                            attempts=tasks.attempts+excluded.attempts, next_at=MAX(tasks.next_at,excluded.next_at),
                            lease_until=MAX(tasks.lease_until,excluded.lease_until), basis=excluded.basis""",
                            row,
                        )
                    db.execute("""INSERT INTO events SELECT id,at,task_id,obligation,basis,main,attempt,route,
                                  outcome,reason_code,detail FROM partitioned_events""")
                    db.execute("DROP TABLE partitioned_tasks")
                    db.execute("DROP TABLE partitioned_events")
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _db(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=15)
        db.execute("PRAGMA busy_timeout=15000")
        return db

    def sync(self, projection: dict) -> None:
        basis = json.dumps(projection["basis"], sort_keys=True)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                current = set()
                for t in projection["tasks"]:
                    current.add(t["id"])
                    db.execute(
                        """INSERT INTO tasks (id,obligation,need,resource,due,state,task,basis)
                        VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET due=MIN(tasks.due,excluded.due),
                        state=excluded.state, task=excluded.task, basis=excluded.basis,
                        attempts=CASE WHEN tasks.basis=excluded.basis THEN tasks.attempts ELSE 0 END,
                        next_at=CASE WHEN tasks.basis=excluded.basis THEN tasks.next_at ELSE 0 END,
                        lease_until=CASE WHEN tasks.basis=excluded.basis THEN tasks.lease_until ELSE 0 END""",
                        (
                            t["id"],
                            t["obligation"],
                            t["need"],
                            t["resource"],
                            t["due"],
                            t["state"],
                            json.dumps(t, sort_keys=True),
                            basis,
                        ),
                    )
                for (ident,) in db.execute("SELECT id FROM tasks").fetchall():
                    if ident not in current:
                        db.execute("DELETE FROM tasks WHERE id=?", (ident,))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def claim(self, *, now: int, lease_ms: int = 600_000, needs=None):
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                rows = db.execute(
                    """SELECT id,task,attempts,due FROM tasks WHERE state='AVAILABLE'
                    AND next_at<=? AND lease_until<=? ORDER BY due,id""",
                    (now, now),
                ).fetchall()
                row = next((r for r in rows if needs is None or json.loads(r[1])["need"] in needs), None)
                if row:
                    db.execute(
                        "UPDATE tasks SET lease_until=?,attempts=attempts+1 WHERE id=?", (now + lease_ms, row[0])
                    )
                db.commit()
            except BaseException:
                db.rollback()
                raise
        if row is None:
            return None
        return {**json.loads(row[1]), "attempt": row[2] + 1, "due": row[3], "lease_until": now + lease_ms}

    def complete_attempt(self, *, task_id: str, lease_until: int, next_at: int) -> None:
        with closing(self._db()) as db:
            changed = db.execute(
                "UPDATE tasks SET next_at=?,lease_until=0 WHERE id=? AND lease_until=?", (next_at, task_id, lease_until)
            ).rowcount
        if changed != 1:
            raise WorkError("stale lease")

    def tasks(self) -> list:
        with closing(self._db()) as db:
            return [
                {**json.loads(task), "attempts": attempts, "due": due}
                for task, attempts, due in db.execute("SELECT task,attempts,due FROM tasks ORDER BY due,id")
            ]

    def record(
        self, *, at: int, task: dict, basis: dict, main: str | None, outcome: str, reason_code: str, detail: str = ""
    ) -> None:
        with closing(self._db()) as db:
            db.execute(
                """INSERT INTO events (at,task_id,obligation,basis,main,attempt,route,outcome,reason_code,detail)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    at,
                    task["id"],
                    task["obligation"],
                    json.dumps(basis, sort_keys=True),
                    main,
                    task.get("attempt", 0),
                    next((r["route"] for r in task.get("routes", []) if r["state"] == "AVAILABLE"), None),
                    outcome,
                    reason_code,
                    detail[:2000],
                ),
            )

    def progress(self) -> dict:
        with closing(self._db()) as db:
            return self._progress_report(self._progress_rows(db))

    @staticmethod
    def read_progress(path) -> dict:
        path = Path(path)
        if not path.exists():
            return {"schema": "standard-progress/v1", "status": "unavailable"}
        try:
            with closing(sqlite3.connect(f"file:{quote(str(path.resolve()))}?mode=ro", uri=True)) as db:
                if "mode" in {r[1] for r in db.execute("PRAGMA table_info(tasks)")}:
                    return {"schema": "standard-progress/v1", "status": "unavailable", "reason": "work store awaiting migration"}
                rows = WorkEngine._progress_rows(db)
        except sqlite3.DatabaseError:
            return {"schema": "standard-progress/v1", "status": "unavailable"}
        return WorkEngine._progress_report(rows)

    @staticmethod
    def _progress_rows(db):
        return db.execute("""SELECT t.id,t.obligation,t.need,t.state,e.outcome,e.reason_code FROM tasks t
            LEFT JOIN events e ON e.id=(SELECT MAX(id) FROM events WHERE task_id=t.id AND basis=t.basis)
            ORDER BY t.due,t.id""").fetchall()

    @staticmethod
    def _progress_report(rows):
        failures = [
            {"task": i, "obligation": o, "reason": reason}
            for i, o, need, state, outcome, reason in rows
            if need == "repair" and state == "AVAILABLE" and outcome == "progress_failure"
        ]
        waiting = [
            {"task": i, "obligation": o, "state": state} for i, o, _, state, _, _ in rows if state != "AVAILABLE"
        ]
        return {
            "schema": "standard-progress/v1",
            "pf": len(failures),
            "failures": failures,
            "waiting": waiting,
            "active": len(rows),
            "authority": "U scheduling only; current constitutional debt remains in the journal",
        }


NEEDS = ("cover", "observe", "repair", "prove", "human", "witness", "investigate")
CONTRACTS = tuple(f"T{i:02}" for i in range(1, 10))
STATES = ("AVAILABLE", "TRUST_BLOCKED", "NO_ROUTE", "HUMAN_REVIEW")


class ProjectionError(ValueError):
    pass


@dataclass(frozen=True)
class Route:
    """An installed way to serve a need on matching resources: reuse, wrap, complete or create a tool."""

    id: str
    resource: str  # fnmatch pattern
    needs: frozenset
    required_t: frozenset = frozenset()
    target_ids: frozenset | None = None

    def __post_init__(self):
        if (
            not self.id
            or not self.resource
            or not self.needs
            or not set(self.needs) <= set(NEEDS)
            or not set(self.required_t) <= set(CONTRACTS)
        ):
            raise ProjectionError(f"invalid route {self.id}")

    def serves(self, resource: str, need: str, target_id=None) -> bool:
        return (
            need in self.needs
            and fnmatchcase(resource, self.resource)
            and (self.target_ids is None or target_id in self.target_ids)
        )


def minimum_trust(law: dict, resource: str, need: str) -> set:
    """What the law itself requires for this need; a route may add contracts, never remove these."""
    if need in ("cover", "observe", "prove"):
        return {"T06"}
    if need == "repair":
        need_t = {"T06", "T07", "T08"}
        for target in law["targets"]:
            if target["resource"] == resource and target.get("repair"):
                need_t |= set(law["ops"][target["repair"]].get("trusted", []))
        return need_t
    return set()


def _tasks_of(item: dict, law: dict) -> list:
    """(resource, need) pairs one open obligation asks for."""
    kind = item.get("type")
    if kind == "target":
        target = next(t for t in law["targets"] if t["id"] == item["target"])
        out = []
        for need in item.get("needs", []):
            if need == "repair" and target.get("human"):
                need = "human"
            out.append((target["resource"], need))
        return out
    if kind == "protocol" and item.get("stage") == "proof":
        return [("intent:" + item["intent"], "prove")]
    if kind in ("clock", "clock_gap"):
        return [("ledger:time", "witness")]
    if kind == "violation":
        return [("law:" + item["declaration"], "human")]
    return []  # pending, unredeemed, reconcile: the operator's own passes (T)


def project(view: dict, routes, qualify) -> dict:
    """qualify(contracts) raises when the installed T boundary cannot serve them right now."""
    law, health = view["law"]["effective"], view["health"]
    tasks = []
    for item in [*health["open"], *health["escalated"]]:
        missing_needs = []
        for resource, need in _tasks_of(item, law):
            choices = []
            for route in sorted(
                (r for r in routes if r.serves(resource, need, item.get("target"))), key=lambda r: r.id
            ):
                required = set(route.required_t) | minimum_trust(law, resource, need)
                try:
                    qualify(sorted(required))
                    state = "AVAILABLE"
                except Exception:
                    state = "TRUST_BLOCKED"
                choices.append({"route": route.id, "state": state, "required_t": sorted(required)})
            if need in ("human", "witness"):
                state = "HUMAN_REVIEW"
            elif any(c["state"] == "AVAILABLE" for c in choices):
                state = "AVAILABLE"
            else:
                state = "TRUST_BLOCKED" if choices else "NO_ROUTE"
            if state == "NO_ROUTE" and need in ("cover", "observe", "repair", "prove"):
                missing_needs.append(need)
            tasks.append(
                {
                    "id": f"{item['obligation']}:{need}",
                    "obligation": item["obligation"],
                    "need": need,
                    "resource": resource,
                    "target": item.get("target"),
                    "opened": item["opened"],
                    "due": item["due"],
                    "escalated": "escalated_to" in item,
                    "state": state,
                    "routes": choices,
                }
            )
        if missing_needs:
            target = next((t for t in law["targets"] if t["id"] == item.get("target")), None)
            resource = target["resource"] if target else "intent:" + item.get("intent", "unknown")
            choices = [
                {"route": r.id, "state": "AVAILABLE", "required_t": []}
                for r in routes
                if r.serves(resource, "investigate", item.get("target"))
            ]
            if choices:
                tasks.append(
                    {
                        "id": f"{item['obligation']}:investigate",
                        "obligation": item["obligation"],
                        "need": "investigate",
                        "for_needs": sorted(set(missing_needs)),
                        "resource": resource,
                        "target": item.get("target"),
                        "opened": item["opened"],
                        "due": item["due"],
                        "escalated": "escalated_to" in item,
                        "state": "AVAILABLE",
                        "routes": choices,
                    }
                )
    tasks.sort(key=lambda t: (t["due"], t["id"]))
    return {"basis": view["prefix"], "law": view["law"]["digest"], "state": health["state"], "tasks": tasks}


def installed_routes(scopes=(), *, model=True, recipes=True, scanner=True):
    """Actual registered targets, rather than pretending repo:* implements any client requirement."""
    from engine.verification.probes import PROBES
    from engine.catalog import categories
    from engine.verification.scope import REPAIR

    rule_targets = {f"rules-{category}" for category in categories()}
    repair = set(REPAIR) | {"actions"} | rule_targets | set(scopes) if model else ({"sbom", "vulns", "actions"} if recipes else set())
    routes = [
        Route("agent-remediate", "repo:*", frozenset({"repair"}), target_ids=frozenset(repair)),
        Route("agent-investigate", "*", frozenset({"investigate"})),
    ]
    if scanner:
        routes.append(
            Route(
                "scanner",
                "*",
                frozenset({"observe", "cover", "prove"}),
                target_ids=frozenset({*PROBES, *rule_targets, "inventory", "run-sources", "run-slo", "run-live"}),
            )
        )
        routes.append(Route("oracle", "intent:*", frozenset({"prove"}), frozenset({"T08"})))
    return routes
