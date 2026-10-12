"""U02 — project the law's debts onto work (ARCHITECTURE.md §11.1–§11.2).

Input: the constitutional view (law + health at one prefix) and the routes the operator installed. Output: tasks with
stable ids, their original due date, the route that could serve them and the T contracts that route needs. Nothing
here grants a right, closes a debt or proves that a provider exists: a route is a declaration until it qualifies.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

NEEDS = ("cover", "observe", "repair", "prove", "review", "witness")
CONTRACTS = tuple(f"T{i:02}" for i in range(1, 10))
STATES = ("AVAILABLE", "TRUST_BLOCKED", "NO_ROUTE", "HUMAN_REVIEW")


class ProjectionError(ValueError):
    pass


@dataclass(frozen=True)
class Route:
    """An installed way to serve a need on matching resources: reuse, wrap, complete or create a tool."""
    id: str
    mode: str                          # BUILD, RUN or BOTH
    resource: str                      # fnmatch pattern
    needs: frozenset
    required_t: frozenset = frozenset()

    def __post_init__(self):
        if (not self.id or self.mode not in ("BUILD", "RUN", "BOTH") or not self.resource or not self.needs
                or not set(self.needs) <= set(NEEDS) or not set(self.required_t) <= set(CONTRACTS)):
            raise ProjectionError(f"invalid route {self.id}")

    def serves(self, mode: str, resource: str, need: str) -> bool:
        return self.mode in (mode, "BOTH") and need in self.needs and fnmatchcase(resource, self.resource)


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
                need = "review"
            out.append((target["resource"], need))
        return out
    if kind == "protocol" and item.get("stage") == "proof":
        return [("intent:" + item["intent"], "prove")]
    if kind in ("clock", "clock_gap"):
        return [("ledger:time", "witness")]
    if kind == "violation":
        return [("law:" + item["declaration"], "review")]
    return []                          # pending, unredeemed, reconcile: the operator's own passes (T)


def project(view: dict, routes, qualify, *, mode: str = "RUN") -> dict:
    """qualify(contracts) raises when the installed T boundary cannot serve them right now."""
    if mode not in ("BUILD", "RUN"):
        raise ProjectionError("mode is BUILD or RUN")
    law, health = view["law"]["effective"], view["health"]
    tasks = []
    for item in [*health["open"], *health["escalated"]]:
        for resource, need in _tasks_of(item, law):
            choices = []
            for route in sorted((r for r in routes if r.serves(mode, resource, need)), key=lambda r: r.id):
                required = set(route.required_t) | minimum_trust(law, resource, need)
                try:
                    qualify(sorted(required))
                    state = "AVAILABLE"
                except Exception:
                    state = "TRUST_BLOCKED"
                choices.append({"route": route.id, "state": state, "required_t": sorted(required)})
            if need in ("review", "witness"):
                state = "HUMAN_REVIEW"
            elif any(c["state"] == "AVAILABLE" for c in choices):
                state = "AVAILABLE"
            else:
                state = "TRUST_BLOCKED" if choices else "NO_ROUTE"
            tasks.append({"id": f"{item['obligation']}:{need}", "obligation": item["obligation"], "need": need,
                          "resource": resource, "target": item.get("target"), "opened": item["opened"],
                          "due": item["due"], "escalated": "escalated_to" in item, "state": state,
                          "routes": choices})
    tasks.sort(key=lambda t: (t["due"], t["id"]))
    return {"mode": mode, "basis": view["prefix"], "law": view["law"]["digest"], "state": health["state"],
            "tasks": tasks}
