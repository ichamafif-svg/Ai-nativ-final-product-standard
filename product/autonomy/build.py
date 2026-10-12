"""U: build what a contracted request asks for (D34).

For each request whose contract a person signed, the agent writes an implementation on the current main: code only,
never a test, plus the contract file itself byte for byte (tests/acceptance/test_<request>.py). Before proposing it,
it checks in its sandbox that the contract passes, main's tests still pass, no floor target gets worse and no new lint
error appears; it iterates on its own failures. It then proposes the commit (trailer `Standard-Request:`) and asks the
law to `implement` it: refused until the independent scanner measured acceptance, tests and regressions on that exact
commit and a reviewer signed it. Once main passes the contract, it records the delivery (`deliver`), which the law
admits only on the scanner's `accepted = yes`.

What the agent cannot do: write or change a test, change the contract, land anything without a review.
Without a model it proposes nothing and says so; any contributor may implement the request instead (same trailer).
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from instruments.suite import contract_path, load
from instruments.tree import Snapshot
from bt.signing import Signer, envelope

from .agent import AgentError, commit_files, model_context

SCOPE = re.compile(r"(?!tests/)(?!\.github/)(?!standard/)([A-Za-z0-9_][A-Za-z0-9_.-]{0,99}/){0,8}"
                   r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\.(py|md|txt|json|toml|ya?ml|sql|html|css|js)")


def in_scope(path) -> bool:
    return isinstance(path, str) and ".." not in path and SCOPE.fullmatch(path) is not None


class Builder:
    def __init__(self, service, signer: Signer, grants: dict, store, requests, *, main, clock, notes, llm=None,
                 sandbox=None, data=None, iterations: int = 3, backoff_ms: int = 60_000):
        """grants: {"agent_implement": id, "agent_deliver": id}. store: the agent's proposals store. requests: the
        request store (contracts and specs by digest)."""
        from instruments.data import EMPTY

        from .sandbox import Sandbox
        self.service, self.signer, self.grants, self.store = service, signer, grants, Path(store)
        self.requests, self.main, self.clock, self.notes = Path(requests), main, clock, Path(notes)
        self.llm, self.sandbox, self.data = llm, sandbox or Sandbox(), data or EMPTY
        self.iterations, self.backoff_ms = iterations, backoff_ms

    # ---- checks in the agent's own sandbox ------------------------------------------------------------------------
    def check(self, base: str, head: str, rid: str, targets: dict) -> list:
        from instruments.probes import _worse

        from .precheck import measure, suite, tools
        problems = []
        with self.sandbox.checkout(self.store, head) as code:
            r = self.sandbox.python_module("pytest", "-q", "-p", "no:cacheprovider", contract_path(rid), cwd=code,
                                           pythonpath=code)
            if not r.ok:
                problems.append(f"the contract does not pass yet:\n{r.out[-3000:]}")
        status, failures = suite(self.sandbox, self.store, base, head, self.store.parent / "venvs")
        if status != "green":
            problems.append(f"main's tests are {status}: {failures[:3]}")
        before, after = measure(Snapshot(self.store, base), targets, self.data), measure(Snapshot(self.store, head),
                                                                                         targets, self.data)
        problems += [f"{t}: {before[t][0]} -> {after[t][0]}" for t in after
                     if t in before and _worse(targets[t]["expect"], before[t][0], after[t][0])]
        import subprocess
        changed = subprocess.run(["git", "-C", str(self.store), "diff", "--name-only", base, head], capture_output=True,
                                 text=True, timeout=60).stdout.split()
        problems += [f"{n} reports new errors: {e[:10]}" for n, e in tools(self.sandbox, self.store, base, head,
                                                                           changed).items()]
        return problems

    # ---- crafting -------------------------------------------------------------------------------------------------
    def craft(self, rid: str, title: str, spec: bytes, contract: bytes, base: str, targets: dict) -> str:
        if self.llm is None:
            raise AgentError("no model is configured: a contributor may implement it (trailer Standard-Request)")
        from .repomap import RepoMap
        tree, feedback = Snapshot(self.store, base), ""
        for _ in range(self.iterations):
            prompt = (f"Implement a feature request in this repository.\nRequest {rid}: {title}\n\n"
                      f"Specification:\n{spec.decode(errors='replace')[:8000]}\n\n"
                      f"Its acceptance tests, signed by the product owner (they will be added as "
                      f"{contract_path(rid)}; you may not change them, nor any other test):\n"
                      f"{contract.decode(errors='replace')[:8000]}\n\n"
                      + (f"Your previous candidate did not pass:\n{feedback}\n\n" if feedback else "")
                      + f"Repository map:\n{RepoMap(tree).render()}\n\n"
                      f"Return JSON {{\"title\": str, \"files\": {{path: full new content}}, \"risks\": str}}: "
                      f"source files only, never under tests/, as few as possible.\n\n{model_context(tree)}")
            reply = self.llm.ask(prompt, "frontier")
            files = reply.get("files")
            if not isinstance(files, dict) or not files or not all(in_scope(p) and isinstance(c, str)
                                                                    for p, c in files.items()):
                raise AgentError("the implementation leaves its write scope (code only, never tests)")
            blobs = {p: c.encode() for p, c in files.items()} | {contract_path(rid): contract}
            what = str(reply.get("title", ""))[:200] or title
            message = (f"{what}\n\nImplements request {rid}: {title}\n"
                       f"Files: {', '.join(sorted(files))}\n"
                       f"Checked by the agent ({self.sandbox.isolation}): the contract passes, main's tests pass, no "
                       f"floor target regressed. The independent instruments measure it again.\n"
                       + (f"\nRisks: {str(reply.get('risks', ''))[:1500]}\n" if reply.get("risks") else "")
                       + f"\nStandard-Request: {rid}\n")
            head = commit_files(self.store, base, blobs, message)
            problems = self.check(base, head, rid, targets)
            if not problems:
                return head
            feedback = "\n".join(problems)[:5000]
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

    def run(self) -> dict:
        view, now, base = self.service.view(), self.clock(), self.main()
        notes = json.loads(self.notes.read_text()) if self.notes.exists() else {}
        targets = {t["id"]: t for t in view["law"]["effective"]["targets"]}
        report = {}
        for resource, e in sorted(view.get("entities", {}).items()):
            if e["type"] != "request" or e["state"] != "contracted":
                continue
            rid, note = resource.split("/", 1)[1], notes.setdefault(resource.split("/", 1)[1], {})
            if view["transitions"].get(resource, {}).get("accepted") == "yes" and "agent_deliver" in self.grants:
                outcome = self._admit(view, "transition", {
                    "under": self.grants["agent_deliver"], "resource": resource, "operation": "deliver",
                    "expected": e["expected"], "changes": {}})
                report[rid] = note["state"] = "delivered" if outcome == "admitted" else f"delivery: {outcome}"
                continue
            if note.get("next_at", 0) > now:
                continue
            spec, contract = load(self.requests, e["fields"]["spec"]), load(self.requests, e["fields"]["contract"])
            if contract is None:
                report[rid] = "the contract is not in the request store"
                continue
            if note.get("base") != base:                     # main moved: implement again on the new main
                try:
                    note.update(base=base, head=self.craft(rid, e["fields"]["title"], spec or b"", contract, base,
                                                           targets), state="proposed")
                except AgentError as exc:
                    note.update(base=base, head=None, state=f"waiting: {exc}", next_at=now + 10 * self.backoff_ms)
            if note.get("head") and note.get("state") != "landing" and "agent_implement" in self.grants:
                outcome = self._admit(view, "intent", {"under": self.grants["agent_implement"], "op": "implement",
                                                       "args": {"request": rid, "base": base, "head": note["head"]}})
                note["state"] = "landing" if outcome == "admitted" else f"proposed: {outcome}"
                if outcome != "admitted":
                    note["next_at"] = now + self.backoff_ms
            report[rid] = note.get("state")
        self.notes.write_text(json.dumps(notes, indent=2, sort_keys=True))
        return report
