"""U04 — the repair crafter: turn one repair task into one candidate commit (§11.1, §11.4).

What a model writes is hostile data: it never reaches a working tree, a git process's configuration or a shell. The
commit is built with git plumbing in the agent's own proposals store, from a map {path: bytes} whose paths must lie in
the target's write scope (instruments/scope.py, the same definition the scanner judges `scoped` with). The agent never
writes to the maintained repository. Whether the commit lands is the rules' call, from facts the scanner measures on
this exact transition: a recipe's output is `reproduced`; a model's change lands alone when main's tests pass, nothing
regresses and it stays in scope, unless the rules keep that route for the human.

Sending repository context to a model is itself an effect of data egress (§7.4, R15): a detected secret never leaves.
For the secrets target the model sees the files with every detected value replaced by a redaction mark, and a reply
that still contains the mark is refused.
"""

from __future__ import annotations
import re
import json
import os
from pathlib import Path
from instruments.tree import Snapshot
from instruments.data import EMPTY
from instruments.recipes import recipes_for
from instruments.scope import relative, repair as in_scope
from agent.candidate import AgentError, commit_files, CandidateWorkflow
from agent.research import Research, ResearchError
from dataclasses import replace
from instruments.scope import REPAIR
from catalog.floors import FLOORS
from agent.candidate import explain, record as candidate_record
from agent.memory import Memory
from context.moves import judge
from agent.work import Route
from context.missions import task_context
from context.model import ReadModel
from context.policy import Rules
from agent.work import WorkEngine

MODEL = os.environ.get("STANDARD_AGENT_MODEL", "claude-sonnet-5-5")
REDACTED = b"<REDACTED>"


FRONTIER = ("sast", "ci", "deps-age")  # judgment-heavy: the frontier tier; the rest: small


def task_of(target_id: str) -> str | None:
    from catalog import instruction
    return instruction(target_id)


def _strength(m: dict) -> str:
    """The mutation sample, for the human who signs tests: what main's tests did not notice."""
    if not m.get("mutants"):
        return ""
    lines = "".join(f"\n  - {s['where']}: {s['change']}" for s in m["survivors"][:6])
    return (f"Tests killed {m['killed']} of {m['mutants']} mutants of the changed lines"
            + (f"; still passing after:{lines}\n" if lines else ".\n"))


def dossier(target: dict, status: str, details: list, files: list, check: dict, title: str, risks: str = "") -> str:
    """The commit message a reviewer reads first: why, what, what was already checked, what may go wrong."""
    where = "\n".join(f"  - {d.splitlines()[0][:200]}" for d in details[:10]) or "  - (no location published)"
    return (f"Standard: {title}\n\n"
            f"Why: {target['resource']} must have {target['property']} = {target['expect']}; "
            f"the instrument reports {status}.\n{where}\n\n"
            f"What: {', '.join(files)}\n\n"
            f"Checked by the agent ({check.get('isolation', '?')}): main's tests {check.get('tests', '?')} on this "
            f"commit; no other floor target regressed; no new ruff or mypy error in the changed files.\n"
            f"Target fixed by the agent's measurement: {check.get('fixed', 'unknown')}. "
            + _strength(check.get("quality", {}).get("mutation", {})) +
            f"These are the agent's own checks: the independent instruments measure this commit again.\n"
            + (f"\nRisks: {risks[:1500]}\n" if risks else "")
            + f"\nStandard-Target: {target['id']}\n")


def admission_feedback(findings: dict, resource: str) -> str:
    """D70: the scanner's refutation at admission reaches the agent through the same dossier, as facts tied to the
    catalog rules its details name."""
    from catalog import load as load_catalog
    from context.feedback import item, render, route
    known = {r["id"] for r in load_catalog()["rules"]}
    items = [item("lesson", f"admission:{prop}", "admission", trust="fact", where=prop, attempt=str(d),
                  rules=[rid for rid in re.findall(r"\b([A-Z][A-Z0-9]+(?:-[A-Z0-9]+)*):", str(d)) if rid in known])
             for prop in ("tests", "regressions", "scoped", "blocks")
             for d in findings.get(f"{resource}|{prop}", {}).get("details", [])[:3]]
    return render(route(items))


class Agent:
    def __init__(self, store, *, data=EMPTY, api_key: str | None = None, ask=None, publish=None, llm=None,
                 sandbox=None, iterations: int = 2, scopes=None, research_sources=None,
                 review=None, research_steps: int = 8):
        """data: the same pinned snapshot the instruments use, so that recipes reproduce. scopes: the write scopes
        the rules give the client's own targets. llm: the egress gate (agent.llm.Gate); `api_key` and
        `ask(prompt, key) -> dict` build one for tests."""
        from agent.llm import Gate, Provider
        from agent.sandbox import Sandbox
        self.store = Path(store)
        self.data, self.iterations = data, iterations
        self.publish = publish or (lambda head: None)   # e.g. push the branch standard/proposals/<head> on GitHub
        if llm is None and api_key:
            transport = (lambda p, prompt: json.dumps(ask(prompt, api_key))) if ask else None
            llm = Gate({"frontier": Provider("anthropic", "anthropic", MODEL, api_key)},
                       self.store.parent / "egress.log", transport=transport)
        self.llm, self.sandbox = llm, sandbox or Sandbox(cache_roots=(self.store.parent / "venvs",))
        self.scopes = dict(scopes or {})
        if any(not isinstance(patterns, list) or not patterns or any(not relative(p) for p in patterns)
               for patterns in self.scopes.values()):
            raise AgentError("custom repair scopes must be configured lists of relative path patterns")
        self.research = Research(self.llm, self.store.parent / "research.jsonl", sources=research_sources, steps=research_steps)
        self.candidate, self.last_candidate = CandidateWorkflow(**(review or {})), None

    def investigate(self, view, task, base, findings=None, *, model=None):
        from context.missions import assemble, task_context
        context = task_context(view, task, findings, model=model)
        tree = Snapshot(self.store, base)
        packet, sources = assemble(context, tree, role="investigate")
        prompt = ("Find a way to serve this missing need. Inspect, research, reuse or experiment with a tool. "
                  "Return a summary and proposed tool files if useful, the required independent verification and any "
                  "operator action. Do not claim the requirement is closed or register a new trusted instrument.\n"
                  + packet)
        try:
            return self.research.dialogue(prompt, tree, key=task["id"], context=sources)
        except ResearchError as exc:
            raise AgentError(str(exc)) from exc

    def _commit(self, base: str, files: dict, message: str) -> str:
        return commit_files(self.store, base, files, message)

    def craft(self, target_id: str, base: str, *, targets: dict | None = None, finding: dict | None = None,
              lessons: str = "", context=None) -> tuple[str, str]:
        """(head, way): "recipe" when the scanner can reproduce it, "model" when a model wrote it.
        Nothing is proposed that the agent's own precheck rejects: it fixes the target, regresses no other one,
        keeps main's tests green and adds no lint or type error."""
        from agent.precheck import precheck, values_in_force
        from context.missions import write_scope
        self.last_candidate = None
        targets = targets or {}
        target = targets.get(target_id, {"id": target_id, "resource": target_id, "property": "?", "expect": "?"})
        finding = finding or {"status": "?", "details": []}
        context = context or {"task": {"id": f"repair:{target_id}", "need": "repair", "target": target_id},
                              "requirement": target, "findings": finding}
        scope = write_scope("repair", target_id, self.scopes)
        focus = [str(d).split(":")[0] for d in finding["details"]]
        tree = Snapshot(self.store, base)
        recipe = recipes_for(self.data).get(target_id)
        files = recipe(tree) if recipe is not None else None
        if files and any(p not in tree.paths() or tree.read(p) != c for p, c in files.items()):
            head = self._commit(base, files, f"Standard: remediate {target_id}\n\nStandard-Target: {target_id}\n")
            check = precheck(self.store, base, head, target_id, targets, self.data, self.sandbox, self.store.parent / "venvs",
                             values=values_in_force(context)) if targets else {}
            if check and not check["ok"]:
                raise AgentError(f"the recipe for {target_id} does not pass the agent's precheck: {check['problems']}")
            self.publish(head)
            return head, "recipe"
        if (task_of(target_id) is None and target_id not in self.scopes) or self.llm is None:
            raise AgentError(f"{target_id}: no applicable recipe and no model route")
        feedback, upgrades = "", ""
        if target_id in ("vulns", "deps-age", "licenses"):
            upgrades = json.dumps({n: {k: v for k, v in p.items() if k in ("latest", "changelog", "releases", "license")}
                                   for n, p in self.data.packages.items()}, indent=1)[:6000]
        where = "\n".join(d[:400] for d in finding["details"][:20]) or "(none published)"
        from agent.attempts import record as record_attempt
        for attempt in range(1, self.iterations + 1):
            instruction = task_of(target_id) or "Serve the client requirement within the write scope the rules give it."
            prompt = (f"Repository maintenance. Target `{target_id}`.\nTask: {instruction}\n"
                      f"Requirement: {target['resource']} must have {target['property']} = {target['expect']}; "
                      f"the independent instrument reports {finding['status']}.\nWhere:\n{where}\n"
                      + (f"Earlier attempts that did not pass:\n{lessons}\n" if lessons else "")
                      + (f"Your previous candidate was rejected by your own checks:\n{feedback}\n" if feedback else "")
                      + (f"Release data of the pinned dependencies:\n{upgrades}\n" if upgrades else "")
                      + "Return JSON {\"title\": str, \"files\": {path: full new content or null to delete}, \"risks\": str}, "
                      "changing as few files as possible.\n")
            tier = "frontier" if target_id in FRONTIER or target_id.startswith("rules-") else "small"
            try:
                reply, stats = self.candidate.run(
                    lambda text, role, **kw: self.research.worker(text, role, key=f"repair:{target_id}", tier=tier, **kw),
                    tree, prompt, focus=focus,
                    scope_ok=lambda path: in_scope(target_id, path, self.scopes), context=context, scope=scope)
                self.last_candidate = stats
                if stats["remaining"]:
                    feedback = "Candidate checks remain incomplete:\n" + "\n".join(stats["remaining"])
                    continue
            except ResearchError as exc:
                self.last_candidate = self.candidate.last_stats
                raise AgentError(str(exc)) from exc
            except ValueError as exc:
                self.last_candidate = self.candidate.last_stats
                raise AgentError(f"the repair of {target_id}: {exc}") from exc
            files = reply.get("files")
            if not isinstance(files, dict) or not files or not all(in_scope(target_id, p, self.scopes) and (c is None or isinstance(c, str))
                                                                    for p, c in files.items()):
                raise AgentError(f"the repair of {target_id} leaves its write scope")
            if any(c is not None and REDACTED.decode() in c for c in files.values()):
                raise AgentError("the reply still carries a redaction mark")
            title = str(reply.get("title", ""))[:200] or f"remediate {target_id}"
            encoded = {p: c.encode() if c is not None else None for p, c in files.items()}
            head = self._commit(base, encoded,
                                f"Standard: {title}\n\nStandard-Target: {target_id}\n")
            check = precheck(self.store, base, head, target_id, targets, self.data, self.sandbox, self.store.parent / "venvs",
                             values=values_in_force(context)) if targets else {
                "ok": True, "isolation": self.sandbox.isolation, "tests": "?"}
            if check["ok"]:
                message = dossier(target, finding["status"], finding["details"], sorted(files), check, title,
                                  str(reply.get("risks", "")))
                head = self._commit(base, encoded, message)
                self.publish(head)
                record_attempt(self.store.parent / "attempts.jsonl", "repair", target_id, attempt, True)
                return head, "model"
            feedback = (check.get("feedback_text") or "\n".join(check["problems"]))[:4000]
        record_attempt(self.store.parent / "attempts.jsonl", "repair", target_id, self.iterations, False)
        raise AgentError(f"no candidate for {target_id} passed the agent's precheck: {feedback[:1500]}")


RULE_TARGETS = frozenset(t["id"] for t in FLOORS["targets"] if t["id"].startswith("rules-"))


class Repairer:
    name = "repair"

    def __init__(
        self,
        service,
        engine: WorkEngine,
        agent: Agent,
        routes,
        *,
        clock,
        state_path,
        backoff_ms: int = 60_000,
        findings=None,
        memory: Memory | None = None,
    ):
        """state_path: U's own notes. findings: the instruments' published findings (information, not facts).
        memory: the agent's attempts."""
        self.service, self.engine, self.agent, self.routes = service, engine, agent, tuple(routes)
        if isinstance(agent, Agent):
            supported = (
                set(agent.scopes) | set(REPAIR) | {"actions"} | RULE_TARGETS
                if agent.llm
                else {"sbom", "vulns", "actions"}
            )
            self.routes = tuple(
                replace(r, target_ids=frozenset(supported)) if r.id == "agent-remediate" and r.target_ids is None else r
                for r in self.routes
            )
        if callable(getattr(agent, "investigate", None)) and not any("investigate" in r.needs for r in self.routes):
            self.routes += (Route("agent-investigate", "*", frozenset({"investigate"})),)
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

    def _record(self, basis: dict, task: dict, main: str, outcome: str, reason: str, detail: str = ""):
        record = getattr(self.engine, "record", None)
        if callable(record):
            record(
                at=self.clock(), task=task, basis=basis, main=main, outcome=outcome, reason_code=reason, detail=detail
            )

    def run(self, view: dict, main: str) -> dict:
        findings = self._findings()
        model = ReadModel(view, findings, self.routes, self.service.qualify, main=main)
        plan = {**model.plan(), "basis": model.basis}
        self.engine.sync(plan)
        targets = {row["target"]["id"]: row["target"] for row in model.targets()}
        proposals, report = self._proposals(), {"state": plan["state"], "crafted": {}, "candidates": {}, "research": {}}
        now = self.clock()
        while (task := self.engine.claim(now=now, needs=("repair", "investigate"))) is not None:
            tid = task["target"]
            if task.get("need") == "investigate":
                base = main
                memory_key = f"research:{task['id']}:{view['law'].get('digest')}"
                try:
                    if self.memory.exhausted(memory_key, base):
                        report["research"][task["id"]] = {
                            "blocked": "research budget exhausted; operator review needed"
                        }
                    else:
                        report["research"][task["id"]] = self.agent.investigate(view, task, base, findings)
                        self.memory.record(
                            memory_key,
                            at=now,
                            base=base,
                            outcome="research",
                            why=str(report["research"][task["id"]].get("summary", "proposal recorded")),
                        )
                except (AgentError, OSError, ValueError) as exc:
                    report["research"][task["id"]] = {"blocked": str(exc)}
                    self.memory.record(memory_key, at=now, base=base, outcome="research", why=str(exc))
                self._record(
                    model.basis,
                    task,
                    base,
                    "research",
                    "research_blocked" if "blocked" in report["research"][task["id"]] else "proposal_only",
                )
                self.engine.complete_attempt(
                    task_id=task["id"], lease_until=task["lease_until"], next_at=now + self.backoff_ms + 1
                )
                continue
            target = targets[tid]
            _, area, item = target["resource"].split(":", 2)
            base = main
            if getattr(getattr(self.agent, "sandbox", None), "isolated", None) is False:
                report["candidates"][tid] = "trust blocked: candidate jail unavailable"
                self._record(model.basis, task, base, "trust_blocked", "candidate_jail_unavailable")
                self.engine.complete_attempt(
                    task_id=task["id"], lease_until=task["lease_until"], next_at=now + self.backoff_ms + 1
                )
                continue
            key = f"{tid}@{base}"
            outcome, reason = "attempted", "candidate"
            try:
                if self.memory.abandoned(tid, base) is not None:
                    report["candidates"][tid] = "abandoned: waiting for people"
                    outcome, reason = "progress_failure", "budget_exhausted"
                elif key not in proposals and self.memory.exhausted(tid, base):
                    self.memory.abandon(
                        tid, base, f"{self.memory.budget} attempts on {base} did not pass:\n{self.memory.lessons(tid)}"
                    )
                    report["candidates"][tid] = "abandoned: waiting for people"
                    outcome, reason = "progress_failure", "budget_exhausted"
                else:
                    self._judged(view, proposals, key, findings, now)
                    if key not in proposals:
                        head, route = self.agent.craft(
                            tid,
                            base,
                            targets=targets,
                            lessons=self.memory.lessons(tid),
                            finding=model.finding(target["resource"], target["property"]),
                            context=task_context(
                                view,
                                {**task, "need": task.get("need", "repair"), "resource": target["resource"]},
                                findings,
                                model=model,
                            ),
                        )
                        proposals[key] = {
                            "target": tid,
                            "area": area,
                            "item": item,
                            "base": base,
                            "head": head,
                            "way": route,
                        }
                        stats = getattr(self.agent, "last_candidate", None)
                        self.memory.record(
                            tid,
                            at=now,
                            base=base,
                            head=head,
                            route=route,
                            outcome="crafted",
                            **({"why": candidate_record(stats)} if stats else {}),
                        )
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
            self._record(model.basis, task, base, outcome, reason, str(report["candidates"].get(tid, "")))
            self.engine.complete_attempt(
                task_id=task["id"], lease_until=task["lease_until"], next_at=now + self.backoff_ms + 1
            )  # never twice in one pass
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
        dossier = admission_feedback(findings, resource)
        why = "the scanner refuted it: " + ", ".join(move["refuted"]) + (f"\n{dossier}" if dossier else "") \
            + (f"\nThe rules behind it:\n{rules}" if rules else "")
        self.memory.record(p["target"], at=now, base=p["base"], head=p["head"], route=p["way"], outcome="judge",
                           why=why[:2000])
        del proposals[key]
