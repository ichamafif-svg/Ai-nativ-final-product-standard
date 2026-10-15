"""U — the build producer: implement what a contracted request asks for (D34).

The human said what the product must do by signing the request's contract (its acceptance tests). For each
contracted request, the agent writes an implementation on the current main: source code only (instruments/scope.py),
plus the contract file itself byte for byte (tests/acceptance/test_<request>.py). Before proposing it, it checks in
its sandbox that the contract passes, main's tests still pass, no floor target gets worse and no new lint error
appears; it iterates on its own failures. The commit (trailer `Standard-Request:`) is a candidate: the scanner
measures acceptance, tests, regressions and scope on it, and the loop plays `implement` when a route of the rules
holds. Once main passes the contract, the producer records the delivery (`deliver`), which the rules admit only on
the scanner's `accepted = yes`.

What the agent cannot do: write or change a test, change the contract. Without a model it proposes nothing and says
so; any contributor may implement the request instead (same trailer).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from instruments.suite import contract_path, load
from instruments.tree import Snapshot
from bt.signing import Signer, envelope

from instruments.scope import feature

from agent.candidate import AgentError, commit_files
from context.missions import task_context, write_scope
from context.moves import judge
from context.model import ReadModel
from agent.research import Research, ResearchError


def in_scope(rid: str, path) -> bool:
    return isinstance(path, str) and path != contract_path(rid) and feature(rid, path)


class Builder:
    name = "build"

    def __init__(self, service, signer: Signer, grant: str, store, requests, *, clock, notes, llm=None,
                 sandbox=None, data=None, iterations: int = 3, backoff_ms: int = 60_000, research_sources=None,
                 review=None, research_steps: int = 8):
        """grant: the agent's capability. store: the agent's proposals store. requests: the request store (contracts
        and specs by digest)."""
        from instruments.data import EMPTY

        from agent.sandbox import Sandbox
        self.service, self.signer, self.grant, self.store = service, signer, grant, Path(store)
        self.requests, self.clock, self.notes = Path(requests), clock, Path(notes)
        self.llm, self.sandbox, self.data = llm, sandbox or Sandbox(
            cache_roots=(self.store.parent / "venvs",)), data or EMPTY
        self.iterations, self.backoff_ms = iterations, backoff_ms
        self.research = Research(llm, self.notes.with_name("build-research.jsonl"), sources=research_sources, steps=research_steps)
        from agent.candidate import CandidateWorkflow
        self.candidate, self.last_candidate = CandidateWorkflow(**(review or {})), None

    # ---- checks in the agent's own sandbox ------------------------------------------------------------------------
    def check(self, base: str, head: str, rid: str, targets: dict) -> list:
        from agent.precheck import precheck

        check = precheck(
            self.store, base, head, None, targets, self.data, self.sandbox, self.store.parent / "venvs", request=rid
        )
        # D70: when the precheck fails, the agent reads its one ordered feedback dossier.
        return [check["feedback_text"] or "\n".join(check["problems"])] if check["problems"] else []

    # ---- crafting -------------------------------------------------------------------------------------------------
    def craft(self, rid: str, title: str, spec: bytes, contract: bytes, base: str, targets: dict, *, context=None) -> str:
        self.last_candidate = None
        if self.llm is None:
            raise AgentError("no model is configured: a contributor may implement it (trailer Standard-Request)")
        tree, feedback = Snapshot(self.store, base), ""
        context = context or {"task": {"id": f"request:{rid}", "need": "implement", "resource": f"build:request/{rid}"}}
        scope = write_scope("build", rid)
        documents = {"specification": spec.decode(errors="replace"), "acceptance": contract.decode(errors="replace")}
        from agent.attempts import record as record_attempt
        for attempt in range(1, self.iterations + 1):
            prompt = (f"Implement a feature request in this repository.\nRequest {rid}: {title}\n\n"
                      f"Specification preview (read full ref=document/specification):\n{documents['specification'][:1200]}\n\n"
                      f"Its acceptance tests, signed by the product owner (they will be added as "
                      f"{contract_path(rid)}; you may not change them, nor any other test):\n"
                      f"Acceptance preview (read full ref=document/acceptance):\n{documents['acceptance'][:1200]}\n\n"
                      + (f"Your previous candidate did not pass:\n{feedback}\n\n" if feedback else "")
                      + "Read the complete specification and acceptance contract before implementing or reviewing. "
                      "Return JSON {\"title\": str, \"files\": {path: full new content or null to delete}, \"risks\": str}: "
                      "source files only, never under tests/, as few as possible.\n")
            try:
                reply, stats = self.candidate.run(
                    lambda text, role, **kw: self.research.worker(text, role, key=f"request:{rid}", **kw),
                    tree, prompt,
                    scope_ok=lambda path: in_scope(rid, path), context=context, scope=scope, documents=documents,
                    fixed_files={contract_path(rid): contract})
                self.last_candidate = stats
                if stats["remaining"]:
                    feedback = "Candidate checks remain incomplete:\n" + "\n".join(stats["remaining"])
                    continue
            except ResearchError as exc:
                self.last_candidate = self.candidate.last_stats
                raise AgentError(str(exc)) from exc
            except ValueError as exc:
                self.last_candidate = self.candidate.last_stats
                raise AgentError(f"the implementation: {exc}") from exc
            files = reply.get("files")
            if not isinstance(files, dict) or not files or not all(in_scope(rid, p) and (c is None or isinstance(c, str))
                                                                    for p, c in files.items()):
                raise AgentError("the implementation leaves its write scope (code only, never tests)")
            blobs = {p: c.encode() if c is not None else None for p, c in files.items()} | {contract_path(rid): contract}
            what = str(reply.get("title", ""))[:200] or title
            message = (f"{what}\n\nImplements request {rid}: {title}\n"
                       f"Files: {', '.join(sorted(files))}\n"
                       f"Checked by the agent ({self.sandbox.isolation}): the contract passes, main's tests pass, no "
                       f"floor target regressed. The independent instruments measure it again.\n"
                       + (f"\nRisks: {str(reply.get('risks', ''))[:1500]}\n" if reply.get("risks") else "")
                       + f"\nStandard-Request: {rid}\n")
            if self.last_candidate:
                from agent.candidate import record
                message += "\nAdvisory workflow: " + record(self.last_candidate) + "\n"
            head = commit_files(self.store, base, blobs, message)
            problems = self.check(base, head, rid, targets)
            if not problems:
                record_attempt(self.store.parent / "attempts.jsonl", "build", rid, attempt, True)
                return head
            feedback = "\n".join(problems)[:5000]
        record_attempt(self.store.parent / "attempts.jsonl", "build", rid, self.iterations, False)
        raise AgentError(f"no implementation of {rid} passed the agent's checks: {feedback[:1500]}")

    # ---- the pass ---------------------------------------------------------------------------------------------------
    def _admit(self, view, kind: str, body: dict) -> str:
        body = {"id": f"{kind}-{uuid.uuid4().hex}", "at": max(self.clock(), view["health"]["as_of"] + 1),
                "author": self.signer.identity, **body}
        try:
            self.service.admit(envelope(view["prefix"]["genesis"], kind, body, [self.signer]))
            return "admitted"
        except Exception as exc:
            return getattr(exc, "code", None) or str(exc)

    def run(self, view: dict, main: str) -> dict:
        now, base = self.clock(), main
        model = ReadModel(view, main=base)
        notes = json.loads(self.notes.read_text()) if self.notes.exists() else {}
        targets = {row["target"]["id"]: row["target"] for row in model.targets()}
        report = {}
        for resource, e in sorted(model.entities("request")):
            if e["state"] != "contracted":
                continue
            rid, note = resource.split("/", 1)[1], notes.setdefault(resource.split("/", 1)[1], {})
            if model.transition(resource).get("accepted") == "yes":
                outcome = self._admit(view, "transition", {
                    "under": self.grant, "resource": resource, "operation": "deliver",
                    "expected": e["expected"], "changes": {}})
                report[rid] = note["state"] = "delivered" if outcome == "admitted" else f"delivery: {outcome}"
                continue
            if note.get("next_at", 0) > now:
                continue
            spec, contract = load(self.requests, e["fields"]["spec"]), load(self.requests, e["fields"]["contract"])
            if contract is None:
                report[rid] = "the contract is not in the request store"
                continue
            if note.get("head") and note.get("base") == base and judge(
                    view, "implement", f"repo:feature:{rid}/{base}/{note['head']}",
                    {"request": rid, "base": base, "head": note["head"]})["status"] == "refuted":
                note["base"] = None                          # the scanner refuted it: implement again
            if note.get("base") != base:                     # main moved: implement again on the new main
                try:
                    note.update(base=base, head=self.craft(rid, e["fields"]["title"], spec or b"", contract, base,
                                targets, context=task_context(view, {"id": f"request:{rid}", "need": "repair",
                                      "op": "implement", "resource": resource, "target": None,
                                      "opened": e.get("created"), "due": None}, model=model)), state="proposed")
                except AgentError as exc:
                    note.update(base=base, head=None, state=f"waiting: {exc}", next_at=now + 10 * self.backoff_ms)
                if self.last_candidate:
                    from agent.candidate import record
                    note["workflow"] = record(self.last_candidate)
            report[rid] = note.get("state")
        self.notes.write_text(json.dumps(notes, indent=2, sort_keys=True))
        return report
