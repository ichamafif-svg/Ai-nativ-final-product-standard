"""U06 — one RUN pass of autonomous maintenance (ARCHITECTURE.md §9.1, §13.2).

    view → project → sync the Work Engine → for each ready repair: craft a commit (recipe or model) → submit the
    intent once independent instruments have observed the exact transition → the kernel decides.

The pass holds no credential but the agent's own key and reaches K/T only through the admission service (`view`,
`qualify`, `admit`). A refusal is information, not failure: the task stays, its due date does not move.
"""
from __future__ import annotations

import json
from pathlib import Path
from dataclasses import replace

from .agent import Agent, AgentError, WRITE_SCOPE
from .memory import Memory
from .projection import Route
from .context import model_packet, task_context
from .read_model import ReadModel
from .work import WorkEngine


class Cycle:
    def __init__(self, service, engine: WorkEngine, agent: Agent, routes, *, clock, main, state_path,
                 backoff_ms: int = 60_000, findings=None, memory: Memory | None = None, settings=lambda: {}):
        """main(): the maintained repository's current main commit (read-only). state_path: U's own notes.
        findings: the instruments' published findings (information, not facts). memory: the agent's attempts."""
        self.service, self.engine, self.agent, self.routes = service, engine, agent, tuple(routes)
        if isinstance(agent, Agent):
            supported = set(agent.scopes) | set(WRITE_SCOPE) \
                if agent.llm else {"sbom", "vulns", "actions"}
            self.routes = tuple(replace(r, target_ids=frozenset(supported))
                                if r.id == "agent-remediate" and r.target_ids is None else r for r in self.routes)
        if callable(getattr(agent, "investigate", None)) and not any("investigate" in r.needs for r in self.routes):
            self.routes += (Route("agent-investigate", "BOTH", "*", frozenset({"investigate"})),)
        self.clock, self.main, self.notes, self.backoff_ms = clock, main, Path(state_path), backoff_ms
        self.findings_path = Path(findings) if findings else None
        self.memory = memory or Memory(self.notes.with_name("memory.json"))
        self.settings = settings

    def _proposals(self) -> dict:
        return json.loads(self.notes.read_text()) if self.notes.exists() else {}

    def _remember(self, proposals: dict) -> None:
        self.notes.write_text(json.dumps(proposals, indent=2, sort_keys=True))

    def _findings(self) -> dict:
        try:
            return json.loads(self.findings_path.read_text()) if self.findings_path else {}
        except (OSError, ValueError):
            return {}

    def _record(self, basis: dict, mode: str, task: dict, main: str, outcome: str, reason: str, detail: str = ""):
        record = getattr(self.engine, "record", None)
        if callable(record):
            record(at=self.clock(), mode=mode, task=task, basis=basis, main=main,
                   outcome=outcome, reason_code=reason, detail=detail)

    def run(self, mode: str = "RUN") -> dict:
        view = self.service.view()
        findings, settings = self._findings(), self.settings()
        main = self.main()
        model = ReadModel(view, findings, self.routes, self.service.qualify, settings=settings, main=main)
        plan = {**model.plan(mode), "basis": model.basis}
        self.engine.sync(plan)
        targets = {row["target"]["id"]: row["target"] for row in model.targets()}
        proposals, report = self._proposals(), {"state": plan["state"], "crafted": {}, "submitted": {}, "research": {}}
        now = self.clock()
        while (task := self.engine.claim(mode=mode, now=now, needs=("repair", "investigate"))) is not None:
            tid = task["target"]
            if task.get("need") == "investigate":
                base = main
                memory_key = f"research:{task['id']}:{view['law'].get('digest')}"
                try:
                    if self.memory.exhausted(memory_key, base):
                        report["research"][task["id"]] = {"blocked": "research budget exhausted; operator review needed"}
                    else:
                        report["research"][task["id"]] = self.agent.investigate(view, task, base, findings, settings)
                        self.memory.record(memory_key, at=now, base=base, outcome="research",
                                           why=str(report["research"][task["id"]].get("summary", "proposal recorded")))
                except (AgentError, OSError, ValueError) as exc:
                    report["research"][task["id"]] = {"blocked": str(exc)}
                    self.memory.record(memory_key, at=now, base=base, outcome="research", why=str(exc))
                self._record(model.basis, mode, task, base, "research",
                             "research_blocked" if "blocked" in report["research"][task["id"]] else "proposal_only")
                self.engine.complete_attempt(mode=mode, task_id=task["id"], lease_until=task["lease_until"],
                                             next_at=now + self.backoff_ms + 1)
                continue
            target = targets[tid]
            _, area, item = target["resource"].split(":", 2)
            base = main
            if getattr(getattr(self.agent, "sandbox", None), "isolated", None) is False:
                report["submitted"][tid] = "trust blocked: candidate jail unavailable"
                self._record(model.basis, mode, task, base, "trust_blocked", "candidate_jail_unavailable")
                self.engine.complete_attempt(mode=mode, task_id=task["id"], lease_until=task["lease_until"],
                                             next_at=now + self.backoff_ms + 1)
                continue
            key = f"{tid}@{base}"
            outcome, reason = "attempted", "candidate"
            try:
                if self.memory.abandoned(tid, base) is not None:
                    report["submitted"][tid] = "abandoned: waiting for people"
                    outcome, reason = "progress_failure", "budget_exhausted"
                elif key not in proposals and self.memory.exhausted(tid, base):
                    self.memory.abandon(tid, base, f"{self.memory.budget} attempts on {base} did not pass:\n"
                                                   f"{self.memory.lessons(tid)}")
                    report["submitted"][tid] = "abandoned: waiting for people"
                    outcome, reason = "progress_failure", "budget_exhausted"
                else:
                    if key not in proposals:
                        head, route = self.agent.craft(tid, base, targets=targets, lessons=self.memory.lessons(tid),
                                                       finding=model.finding(target["resource"], target["property"]),
                                                       law_text=model_packet(task_context(view, {**task,
                                                           "need": task.get("need", "repair"),
                                                           "resource": target["resource"]}, findings,
                                                           settings=settings, model=model)))
                        proposals[key] = {"target": tid, "area": area, "item": item, "base": base,
                                          "head": head, "route": route, "submitted": False}
                        report["crafted"][tid] = proposals[key]
                    p = proposals[key]
                    if not p["submitted"]:
                        self._submit(view, now, p, findings, proposals, key, report)
                        outcome, reason = (("admitted", "admitted") if p["submitted"] else
                                           ("refused", "admission_refused"))
            except AgentError as exc:
                self.memory.record(tid, at=now, base=base, outcome="agent", why=str(exc))
                report["submitted"][tid] = f"agent: {exc}"
                outcome, reason = "attempt_failed", "agent_error"
            self._record(model.basis, mode, task, base, outcome, reason, report["submitted"].get(tid, ""))
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
