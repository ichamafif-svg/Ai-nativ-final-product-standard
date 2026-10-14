"""U — the repair producer: debts become candidate commits (ARCHITECTURE.md §9.1, §13.2).

    view → project → sync the Work Engine → for each ready repair: craft a commit (recipe or model) in the agent's
    own store → the scanner measures the exact transition → the loop plays the move if a route of the rules holds.

The producer never submits anything: it only writes commits in the agent's own store. A candidate the scanner refutes
(red tests, a regression, a change outside its scope) becomes a lesson, and the next pass crafts again. The debt and
its due date stay where the kernel put them.
"""
from __future__ import annotations

import json
from pathlib import Path
from dataclasses import replace

from instruments.scope import REPAIR
from standard.floors import FLOORS

from .agent import Agent, AgentError
from .candidate import explain, record as candidate_record
from .memory import Memory
from .moves import judge
from .projection import Route
from .context import task_context
from .read_model import ReadModel
from .rules import Rules
from .work import WorkEngine


RULE_TARGETS = frozenset(t["id"] for t in FLOORS["targets"] if t["id"].startswith("rules-"))


class Repairer:
    name = "repair"

    def __init__(self, service, engine: WorkEngine, agent: Agent, routes, *, clock, state_path,
                 backoff_ms: int = 60_000, findings=None, memory: Memory | None = None):
        """state_path: U's own notes. findings: the instruments' published findings (information, not facts).
        memory: the agent's attempts."""
        self.service, self.engine, self.agent, self.routes = service, engine, agent, tuple(routes)
        if isinstance(agent, Agent):
            supported = set(agent.scopes) | set(REPAIR) | {"actions"} | RULE_TARGETS \
                if agent.llm else {"sbom", "vulns", "actions"}
            self.routes = tuple(replace(r, target_ids=frozenset(supported))
                                if r.id == "agent-remediate" and r.target_ids is None else r for r in self.routes)
        if callable(getattr(agent, "investigate", None)) and not any("investigate" in r.needs for r in self.routes):
            self.routes += (Route("agent-investigate", "BOTH", "*", frozenset({"investigate"})),)
        self.clock, self.notes, self.backoff_ms = clock, Path(state_path), backoff_ms
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

    def _record(self, basis: dict, mode: str, task: dict, main: str, outcome: str, reason: str, detail: str = ""):
        record = getattr(self.engine, "record", None)
        if callable(record):
            record(at=self.clock(), mode=mode, task=task, basis=basis, main=main,
                   outcome=outcome, reason_code=reason, detail=detail)

    def run(self, view: dict, main: str, mode: str = "RUN") -> dict:
        findings = self._findings()
        model = ReadModel(view, findings, self.routes, self.service.qualify, main=main)
        plan = {**model.plan(mode), "basis": model.basis}
        self.engine.sync(plan)
        targets = {row["target"]["id"]: row["target"] for row in model.targets()}
        proposals, report = self._proposals(), {"state": plan["state"], "crafted": {}, "candidates": {}, "research": {}}
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
                        report["research"][task["id"]] = self.agent.investigate(view, task, base, findings)
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
                report["candidates"][tid] = "trust blocked: candidate jail unavailable"
                self._record(model.basis, mode, task, base, "trust_blocked", "candidate_jail_unavailable")
                self.engine.complete_attempt(mode=mode, task_id=task["id"], lease_until=task["lease_until"],
                                             next_at=now + self.backoff_ms + 1)
                continue
            key = f"{tid}@{base}"
            outcome, reason = "attempted", "candidate"
            try:
                if self.memory.abandoned(tid, base) is not None:
                    report["candidates"][tid] = "abandoned: waiting for people"
                    outcome, reason = "progress_failure", "budget_exhausted"
                elif key not in proposals and self.memory.exhausted(tid, base):
                    self.memory.abandon(tid, base, f"{self.memory.budget} attempts on {base} did not pass:\n"
                                                   f"{self.memory.lessons(tid)}")
                    report["candidates"][tid] = "abandoned: waiting for people"
                    outcome, reason = "progress_failure", "budget_exhausted"
                else:
                    self._judged(view, proposals, key, findings, now)
                    if key not in proposals:
                        head, route = self.agent.craft(tid, base, targets=targets, lessons=self.memory.lessons(tid),
                                                       finding=model.finding(target["resource"], target["property"]),
                                                       context=task_context(view, {**task,
                                                           "need": task.get("need", "repair"),
                                                           "resource": target["resource"]}, findings,
                                                           model=model))
                        proposals[key] = {"target": tid, "area": area, "item": item, "base": base,
                                          "head": head, "way": route}
                        stats = getattr(self.agent, "last_candidate", None)
                        self.memory.record(tid, at=now, base=base, head=head, route=route, outcome="crafted",
                                           **({"why": candidate_record(stats)} if stats else {}))
                        report["crafted"][tid] = proposals[key]
                    p = proposals[key]
                    report["candidates"][tid] = p["head"]
                    outcome, reason = "proposed", "candidate"
            except AgentError as exc:
                stats = getattr(self.agent, "last_candidate", None)
                why = str(exc) + ("\n" + candidate_record(stats) if stats else "")
                self.memory.record(tid, at=now, base=base, outcome="agent", why=why)
                report["candidates"][tid] = f"agent: {exc}"
                outcome, reason = "attempt_failed", "agent_error"
            self._record(model.basis, mode, task, base, outcome, reason, str(report["candidates"].get(tid, "")))
            self.engine.complete_attempt(mode=mode, task_id=task["id"], lease_until=task["lease_until"],
                                         next_at=now + self.backoff_ms + 1)   # never twice in one pass
        self._remember(proposals)
        return report

    def _judged(self, view, proposals, key, findings, now) -> None:
        """A candidate the scanner refuted is a lesson: forget it, so this pass crafts again with what failed."""
        p = proposals.get(key)
        if p is None:
            return
        resource = f"repo:{p['area']}:{p['item']}/{p['base']}/{p['head']}"
        move = judge(view, "remediate", resource, {"area": p["area"], "item": p["item"], "base": p["base"],
                                                   "head": p["head"]})
        if move["status"] != "refuted":
            return
        details = [d for prop in ("tests", "regressions", "scoped", "blocks")
                   for d in findings.get(f"{resource}|{prop}", {}).get("details", [])[:3]]
        rules = explain(details, Rules(view["law"]["effective"]).values())
        why = "the scanner refuted it: " + ", ".join(move["refuted"]) + (" | " + " | ".join(details) if details else "") \
            + (f"\nThe rules behind it:\n{rules}" if rules else "")
        self.memory.record(p["target"], at=now, base=p["base"], head=p["head"], route=p["way"], outcome="judge",
                           why=why[:2000])
        del proposals[key]
