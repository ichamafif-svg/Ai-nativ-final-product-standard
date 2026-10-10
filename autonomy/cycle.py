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
from .memory import Memory
from .projection import project
from .work import WorkEngine


class Cycle:
    def __init__(self, service, engine: WorkEngine, agent: Agent, routes, *, clock, main, state_path,
                 backoff_ms: int = 60_000, findings=None, memory: Memory | None = None):
        """main(): the maintained repository's current main commit (read-only). state_path: U's own notes.
        findings: the instruments' published findings (information, not facts). memory: the agent's attempts."""
        self.service, self.engine, self.agent, self.routes = service, engine, agent, tuple(routes)
        self.clock, self.main, self.notes, self.backoff_ms = clock, main, Path(state_path), backoff_ms
        self.findings_path = Path(findings) if findings else None
        self.memory = memory or Memory(self.notes.with_name("memory.json"))

    def _proposals(self) -> dict:
        return json.loads(self.notes.read_text()) if self.notes.exists() else {}

    def _remember(self, proposals: dict) -> None:
        self.notes.write_text(json.dumps(proposals, indent=2, sort_keys=True))

    def _findings(self) -> dict:
        try:
            return json.loads(self.findings_path.read_text()) if self.findings_path else {}
        except (OSError, ValueError):
            return {}

    def run(self, mode: str = "RUN") -> dict:
        view = self.service.view()
        plan = project(view, self.routes, self.service.qualify, mode=mode)
        self.engine.sync(plan)
        law = view["law"]["effective"]
        targets = {t["id"]: t for t in law["targets"]}
        findings = self._findings()
        proposals, report = self._proposals(), {"state": plan["state"], "crafted": {}, "submitted": {}}
        now = self.clock()
        while (task := self.engine.claim(mode=mode, now=now, needs=("repair",))) is not None:
            tid = task["target"]
            target = targets[tid]
            _, area, item = target["resource"].split(":", 2)
            base = self.main()
            key = f"{tid}@{base}"
            try:
                if self.memory.abandoned(tid, base) is not None:
                    report["submitted"][tid] = "abandoned: waiting for people"
                elif key not in proposals and self.memory.exhausted(tid, base):
                    self.memory.abandon(tid, base, f"{self.memory.budget} attempts on {base} did not pass:\n"
                                                   f"{self.memory.lessons(tid)}")
                    report["submitted"][tid] = "abandoned: waiting for people"
                else:
                    if key not in proposals:
                        head, route = self.agent.craft(tid, base, targets=targets, lessons=self.memory.lessons(tid),
                                                       finding=findings.get(f"{target['resource']}|{target['property']}"))
                        proposals[key] = {"target": tid, "area": area, "item": item, "base": base,
                                          "head": head, "route": route, "submitted": False}
                        report["crafted"][tid] = proposals[key]
                    p = proposals[key]
                    if not p["submitted"]:
                        self._submit(view, now, p, findings, proposals, key, report)
            except AgentError as exc:
                self.memory.record(tid, at=now, base=base, outcome="agent", why=str(exc))
                report["submitted"][tid] = f"agent: {exc}"
            self.engine.complete_attempt(mode=mode, task_id=task["id"], lease_until=task["lease_until"],
                                         next_at=now + self.backoff_ms + 1)   # never twice in one pass
        self._remember(proposals)
        return report

    def _submit(self, view, now, p, findings, proposals, key, report) -> None:
        """Submit once the judge may have measured; a red verdict is a lesson and the next pass crafts again."""
        tid, transition = p["target"], f"repo:{p['area']}:{p['item']}/{p['base']}/{p['head']}"
        try:
            at = max(now, view["health"]["as_of"] + 1)
            self.service.admit(self.agent.intent(view["prefix"]["genesis"], at, p["area"], p["item"], p["base"],
                                                 p["head"], p["route"]))
            p["submitted"] = True
            self.memory.record(tid, at=now, base=p["base"], head=p["head"], route=p["route"], outcome="admitted")
            report["submitted"][tid] = "admitted"
        except Exception as exc:                           # a refusal leaves the debt and its due date in place
            code = getattr(exc, "code", None) or str(exc.args[0] if exc.args else exc)
            verdict = findings.get(f"{transition}|tests", {})
            if verdict.get("status") not in (None, "green"):
                why = f"the judge measured main's tests {verdict['status']}: " + " | ".join(verdict["details"][:3])
                self.memory.record(tid, at=now, base=p["base"], head=p["head"], route=p["route"],
                                   outcome="judge", why=why)
                del proposals[key]                          # the next pass crafts again, with this lesson
                code = f"{code} (tests {verdict['status']}: recorded, will craft again)"
            elif verdict.get("status") == "green" and p["route"] == "review":
                code = f"{code} (tests green: awaiting a signed human review)"
            report["submitted"][tid] = code
