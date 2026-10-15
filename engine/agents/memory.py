"""U — what the agent remembers of its own attempts, and when it stops.

One record per obligation (a target): every attempt with its base, candidate, route, outcome and why. The agent reads
it before trying again, so that it does not repeat what already failed. A budget bounds the attempts on one base of
main; past it the agent stops and leaves a dossier for people. Stopping is visible (`surface tasks` shows it) but it
is not a fact of the ledger: the obligation still escalates to the root humans when it falls due, whatever the agent
says. Memory is the agent's own file: it helps, it authorizes nothing.
"""
from __future__ import annotations

import json
from pathlib import Path


class Memory:
    def __init__(self, path, *, budget: int = 3):
        self.path, self.budget = Path(path), budget
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {}

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True))
        tmp.replace(self.path)

    def attempts(self, target: str, base: str | None = None) -> list:
        return [a for a in self.data.get(target, {}).get("attempts", []) if base is None or a["base"] == base]

    def record(self, target: str, *, at: int, base: str, outcome: str, why: str = "", head: str | None = None,
               route: str | None = None) -> None:
        entry = self.data.setdefault(target, {"attempts": []})
        entry["attempts"] = (entry["attempts"] + [{"at": at, "base": base, "head": head, "route": route,
                                                   "outcome": outcome, "why": why[:2000]}])[-30:]
        self._save()

    def exhausted(self, target: str, base: str) -> bool:
        return len([a for a in self.attempts(target, base) if a["outcome"] not in ("admitted", "crafted")]) >= self.budget

    def abandon(self, target: str, base: str, dossier: str) -> None:
        self.data.setdefault(target, {"attempts": []})["abandoned"] = {"base": base, "dossier": dossier[:8000]}
        self._save()

    def abandoned(self, target: str, base: str) -> str | None:
        a = self.data.get(target, {}).get("abandoned")
        return a["dossier"] if a and a["base"] == base else None

    def lessons(self, target: str, limit: int = 5) -> str:
        """The last failures, for the agent's next attempt: what was tried and why it did not pass."""
        failed = [a for a in self.attempts(target) if a["outcome"] not in ("admitted", "crafted")][-limit:]
        return "\n".join(f"- attempt on {a['base'][:12]} ({a['route']}): {a['outcome']}: {a['why']}" for a in failed)
