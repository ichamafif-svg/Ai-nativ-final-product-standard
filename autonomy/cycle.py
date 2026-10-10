"""U06 — one RUN pass of autonomous maintenance (ARCHITECTURE.md §9.1, §13.2).

    view → project → sync the Work Engine → for each ready repair: craft a commit (recipe or model) → submit the
    intent once independent instruments have observed the exact transition → the kernel decides.

The pass holds no credential but the agent's own key and reaches K/T only through the admission service (`view`,
`qualify`, `admit`). A refusal is information, not failure: the task stays, its due date does not move.
"""
from __future__ import annotations

import json
from pathlib import Path

from .agent import Agent, AgentError
from .projection import project
from .work import WorkEngine


class Cycle:
    def __init__(self, service, engine: WorkEngine, agent: Agent, routes, *, clock, main, state_path,
                 backoff_ms: int = 60_000):
        """main(): the maintained repository's current main commit (read-only). state_path: U's own notes."""
        self.service, self.engine, self.agent, self.routes = service, engine, agent, tuple(routes)
        self.clock, self.main, self.notes, self.backoff_ms = clock, main, Path(state_path), backoff_ms

    def _proposals(self) -> dict:
        return json.loads(self.notes.read_text()) if self.notes.exists() else {}

    def _remember(self, proposals: dict) -> None:
        self.notes.write_text(json.dumps(proposals, indent=2, sort_keys=True))

    def run(self, mode: str = "RUN") -> dict:
        view = self.service.view()
        plan = project(view, self.routes, self.service.qualify, mode=mode)
        self.engine.sync(plan)
        law = view["law"]["effective"]
        targets = {t["id"]: t for t in law["targets"]}
        proposals, report = self._proposals(), {"state": plan["state"], "crafted": {}, "submitted": {}}
        now = self.clock()
        while (task := self.engine.claim(mode=mode, now=now, needs=("repair",))) is not None:
            target = targets[task["target"]]
            _, area, item = target["resource"].split(":", 2)
            base = self.main()
            key = f"{task['target']}@{base}"
            try:
                if key not in proposals:
                    head, route = self.agent.craft(task["target"], base)
                    proposals[key] = {"target": task["target"], "area": area, "item": item, "base": base,
                                      "head": head, "route": route, "submitted": False}
                    report["crafted"][task["target"]] = proposals[key]
                p = proposals[key]
                if not p["submitted"]:
                    at = max(now, view["health"]["as_of"] + 1)
                    self.service.admit(self.agent.intent(view["prefix"]["genesis"], at, area, item, base, p["head"],
                                                         p["route"]))
                    p["submitted"] = True
                    report["submitted"][task["target"]] = "admitted"
            except AgentError as exc:
                report["submitted"][task["target"]] = f"agent: {exc}"
            except Exception as exc:                       # a refusal leaves the debt and its due date in place
                report["submitted"][task["target"]] = getattr(exc, "code", None) or str(exc.args[0] if exc.args else exc)
            self.engine.complete_attempt(mode=mode, task_id=task["id"], lease_until=task["lease_until"],
                                         next_at=now + self.backoff_ms + 1)   # never twice in one pass
        self._remember(proposals)
        return report
