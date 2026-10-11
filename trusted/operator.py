"""The operator's own passes on the trusted side (T06 instruments, T07 departures, T08 readback, proof of effect).

They run in the operator process with their own identities and keys, never an agent's. Each pass admits signed
statements through the same journal and service as anyone else: nothing here bypasses the kernel.
"""
from __future__ import annotations

import json
import re
import subprocess
import uuid
from pathlib import Path

from . import build, instruments
from .adapters import applied
from .data import EMPTY
from .recipes import recipes_for
from .signing import Signer, envelope

MAIN_OPS = ("remediate", "integrate", "implement")                 # the operations that move main, by the same compare-and-swap
AUTHOR = re.compile(r"refs/heads/([a-z0-9][a-z0-9_-]{0,63})/[^\s]+")
REMEASURE_MS = 12 * 3_600_000


class Instruments:
    """T06: measure main's floor targets, and every proposed transition whose base is main.

    A proposal that a recipe reproduces gets `tests` and `reproduced`; any other proposal naming a remediable target
    (its `Standard-Target:` trailer, untrusted, used only to name the resource) gets `tests` alone and waits for a
    signed human review."""

    def __init__(self, service, instrument: instruments.Instrument, repo, proposals, *, data=EMPTY, world=None,
                 anchor: str | None = None, install: bool = False, inbox=None, findings=None, requests=None):
        self.service, self.instrument, self.repo, self.proposals = service, instrument, Path(repo), Path(proposals)
        self.requests, self.cache = requests, {}            # D34: the request store; measures per (commit, contract)
        self.inbox, self.measured, self.findings_path = inbox, {}, findings
        self.data, self.world, self.install = data, world, install
        clock = instrument.clock                          # statements never fall behind the ledger's last instant
        instrument.clock = lambda: max(clock(), service.journal.snapshot()["last_at"] + 1)
        self.anchor = anchor or self._main()

    def _main(self) -> str:
        return instruments.git(self.repo, "rev-parse", "refs/heads/main").strip()

    def _judged(self, state) -> set:
        """Heads of remediate effects the line shows applied: the only commits allowed on main since the anchor."""
        return {it["args"]["head"] for i, it in state["intents"].items()
                if it["op"] in MAIN_OPS and state["line"].get(i, {}).get("state") == "proving"}

    def _admit(self, envelope) -> int:
        self.service.admit(envelope)
        return 1

    def measure(self) -> dict:
        view = self.service.view()
        domain, law = view["prefix"]["genesis"], view["law"]["effective"]
        targets = {t["id"]: t for t in law["targets"]}
        main = self._main()
        ctx = {"data": self.data, "world": self.world, "anchor": self.anchor,
               "judged": self._judged(self.service.journal.snapshot())}
        admitted = sum(self._admit(env) for env in self.instrument.measure_targets(domain, self.repo, main, targets, ctx))
        recipes = recipes_for(self.data)
        listed = instruments.git(self.repo, "ls-remote", str(self.proposals), "refs/standard/proposals/*")
        for ref in listed.split()[::2]:                     # never run git inside U's store: its config is U's
            subprocess.run(["git", "-C", str(self.repo), "fetch", "-q", "--no-tags", str(self.proposals), ref],
                           capture_output=True, timeout=300)
            parents = instruments.git(self.repo, "rev-list", "--parents", "-n", "1", ref).split()
            if parents[1:] != [main]:
                continue                                    # only transitions from the current main are measured
            head = instruments.git(self.repo, "rev-parse", ref).strip()
            rid = build.claimed(self.repo, head)
            if rid is not None:                             # D34: an implementation of a contracted request
                admitted += self.feature(domain, main, head, rid, targets)
                continue
            facts, tid = {}, None
            for name, recipe in recipes.items():
                if name in targets and instruments.reproduced(self.repo, main, ref, recipe) == "yes":
                    tid, facts = name, {"reproduced": "yes"}
                    break
            if tid is None:
                claimed = re.search(r"(?m)^Standard-Target: ([a-z-]+)$",
                                    instruments.git(self.repo, "log", "-1", "--format=%B", ref))
                tid = claimed[1] if claimed else None
            if tid not in targets or targets[tid].get("repair") != "remediate":
                continue
            _, area, item = targets[tid]["resource"].split(":", 2)
            resource = f"repo:{area}:{item}/{main}/{ref}"
            facts["tests"], details = instruments.tests_report(self.repo, main, ref, install=self.install)
            self.instrument.findings[f"{resource}|tests"] = {"status": facts["tests"], "details": details}
            admitted += sum(self._admit(self.instrument.observation(domain, resource, p, v)) for p, v in facts.items())
        admitted += self.contributions(domain, main)
        admitted += self.contracts(domain, main)
        self.publish()
        return {"admitted": admitted, "main": main}

    def _request(self, rid: str):
        """(state, contract bytes) of a request, or None when it is unknown or its contract is not in the store."""
        e = self.service.journal.snapshot()["entities"].get(f"build:request/{rid}")
        if e is None or e["type"] != "request" or self.requests is None:
            return None
        contract = build.load(self.requests, e["fields"]["contract"])
        return (e["state"], contract) if contract is not None else None

    def _once(self, key, measure):
        if key not in self.cache:
            self.cache[key] = measure()
        return self.cache[key]

    def feature(self, domain: str, main: str, head: str, rid: str, targets: dict) -> int:
        """tests, regressions and acceptance on repo:feature:{request}/{main}/{head}, for a contracted request."""
        known = self._request(rid)
        if known is None or known[0] != "contracted":
            return 0
        resource = f"repo:feature:{rid}/{main}/{head}"
        facts = {
            "acceptance": self._once((head, rid, "acceptance"),
                                     lambda: build.acceptance_on(self.repo, head, rid, known[1])),
            "tests": self._once((main, head, "tests"),
                                lambda: instruments.tests_report(self.repo, main, head, install=self.install)),
            "regressions": self._once((main, head, "regressions"), lambda: instruments.regressions(
                self.repo, main, head, targets, {"data": self.data}, frozenset(recipes_for(self.data)))),
        }
        admitted = 0
        for prop, (status, details) in facts.items():
            self.instrument.findings[f"{resource}|{prop}"] = {"status": status, "details": details}
            admitted += self._admit(self.instrument.observation(domain, resource, prop, status))
        return admitted

    def contracts(self, domain: str, main: str) -> int:
        """`contract` on every proposed request (red on main?), `accepted` on every contracted one (main passes?)."""
        admitted = 0
        for resource, e in self.service.journal.snapshot()["entities"].items():
            if e["type"] != "request" or e["state"] not in ("proposed", "contracted"):
                continue
            rid = resource.split("/", 1)[1]
            known = self._request(rid)
            if known is None:
                self.instrument.findings[f"{resource}|contract"] = {
                    "status": "uncovered:store", "details": ["the contract is not in the request store"]}
                continue
            if e["state"] == "proposed":
                prop, (status, details) = "contract", self._once(
                    (main, rid, "contract"), lambda: build.contract_on(self.repo, main, rid, known[1]))
            else:
                status, details = self._once((main, rid, "accepted"),
                                             lambda: build.acceptance_on(self.repo, main, rid, known[1]))
                prop, status = "accepted", "yes" if status == "green" else "no"
            self.instrument.findings[f"{resource}|{prop}"] = {"status": status, "details": details}
            admitted += self._admit(self.instrument.observation(domain, resource, prop, status))
        if len(self.cache) > 2000:
            self.cache.clear()
        return admitted

    def publish(self) -> None:
        """Findings for whoever repairs (agent, human), readable by the agent's group. Information, never a fact."""
        if self.findings_path is None:
            return
        tmp = Path(f"{self.findings_path}.tmp")
        tmp.write_text(json.dumps(self.instrument.findings, indent=1, sort_keys=True))
        tmp.chmod(0o640)
        tmp.replace(self.findings_path)

    def contributions(self, domain: str, main: str) -> int:
        """`tests` and `regressions` for every inbox branch whose head is a direct child of main, on
        repo:contrib:{author}/{main}/{head}. The author is the inbox branch's first segment, which the gate's hook binds
        to the pushing key. Main's own suite runs against the contribution's code, so a contribution cannot weaken the
        tests that judge it; every floor probe runs on main and on the contribution, so it cannot open a new gap."""
        if not self.inbox:
            return 0
        admitted, now = 0, self.instrument.clock()
        listed = instruments.git(self.repo, "ls-remote", str(self.inbox), "refs/heads/*")
        for line in listed.splitlines():                    # read from outside: the inbox's config is the gate's
            head, ref = line.split("\t")
            author = AUTHOR.fullmatch(ref)
            resource = f"repo:contrib:{author[1]}/{main}/{head}" if author else None
            if resource is None or now - self.measured.get(resource, -REMEASURE_MS) < REMEASURE_MS:
                continue
            subprocess.run(["git", "-C", str(self.repo), "fetch", "-q", "--no-tags", str(self.inbox), head],
                           capture_output=True, timeout=300)
            parents = instruments.git(self.repo, "rev-list", "--parents", "-n", "1", head).split()
            if parents[1:] != [main]:
                continue                                    # not on the current main: the author rebases
            self.measured[resource] = now
            status, details = instruments.tests_report(self.repo, main, head, install=self.install)
            self.instrument.findings[f"{resource}|tests"] = {"status": status, "details": details}
            admitted += self._admit(self.instrument.observation(domain, resource, "tests", status))
            targets = {t["id"]: t for t in self.service.view()["law"]["effective"]["targets"]}
            status, details = instruments.regressions(self.repo, main, head, targets, {"data": self.data},
                                                      frozenset(recipes_for(self.data)))
            self.instrument.findings[f"{resource}|regressions"] = {"status": status, "details": details}
            admitted += self._admit(self.instrument.observation(domain, resource, "regressions", status))
            rid = build.claimed(self.repo, head)
            known = self._request(rid) if rid else None
            if known is not None and known[0] == "contracted":   # D34: a contribution that answers a request
                status, details = build.acceptance_on(self.repo, head, rid, known[1])
                self.instrument.findings[f"{resource}|acceptance"] = {"status": status, "details": details}
                admitted += self._admit(self.instrument.observation(domain, resource, "acceptance", status))
        return admitted


class Prover:
    """Proof of application: an independent oracle attests that an applied intent's head is on main, or that
    production runs the release it switched to."""

    def __init__(self, service, repository, signer: Signer, capability: str, clock, releases=None):
        self.service, self.repository, self.signer, self.capability, self.clock = (
            service, repository, signer, capability, clock)
        self.releases = releases

    def prove_due(self) -> dict:
        state = self.service.journal.snapshot()
        out = {}
        for name, ob in sorted(state["obligations"].items()):
            if ob["stage"] != "proof":
                continue
            it = state["intents"][ob["intent"]]
            if not applied(it, self.repository, self.releases):
                continue
            body = {"id": f"proof-{uuid.uuid4().hex}", "at": max(self.clock(), state["last_at"] + 1),
                    "author": self.signer.identity, "under": self.capability, "resource": it["resource"],
                    "subject": it["id"], "level": "real"}
            out[name] = self.service.admit(envelope(state["domain"], "evidence", body, [self.signer]))
        return out
