"""The operator's own passes on the trusted side (T06 instruments, T07 departures, T08 readback, proof of effect).

They run in the operator process with their own identities and keys, never an agent's. Each pass admits signed
statements through the same journal and service as anyone else: nothing here bypasses the kernel.
"""
from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

from . import instruments
from .recipes import RECIPES
from .signing import Signer, envelope


class Instruments:
    """T06: measure main's floor targets, and every proposed transition whose base is main."""

    def __init__(self, service, instrument: instruments.Instrument, repo, proposals, *, install: bool = False):
        self.service, self.instrument, self.repo, self.proposals = service, instrument, Path(repo), Path(proposals)
        self.install = install

    def _main(self) -> str:
        return instruments.git(self.repo, "rev-parse", "refs/heads/main").strip()

    def measure(self) -> dict:
        view = self.service.view()
        domain, law = view["prefix"]["genesis"], view["law"]["effective"]
        targets = {t["id"]: t for t in law["targets"]}
        main = self._main()
        admitted = 0
        for env in self.instrument.measure_targets(domain, self.repo, main, targets):
            self.service.admit(env)
            admitted += 1
        for ref in instruments.git(self.proposals, "for-each-ref", "--format=%(objectname)",
                                   "refs/standard/proposals/").split():
            subprocess.run(["git", "-C", str(self.repo), "fetch", "-q", "--no-tags", str(self.proposals), ref],
                           capture_output=True, timeout=300)
            parents = instruments.git(self.repo, "rev-list", "--parents", "-n", "1", ref).split()
            if parents[1:] != [main]:
                continue                                    # only transitions from the current main are measured
            for tid, recipe in RECIPES.items():            # which reproducible repair this proposal is
                t = targets.get(tid)
                if t is None or t.get("repair") != "remediate":
                    continue
                if instruments.reproduced(self.repo, main, ref, recipe) != "yes":
                    continue
                _, area, item = t["resource"].split(":", 2)
                resource = f"repo:{area}:{item}/{main}/{ref}"
                facts = {"tests": instruments.tests(self.repo, main, ref, install=self.install), "reproduced": "yes"}
                for prop, status in facts.items():
                    self.service.admit(self.instrument.observation(domain, resource, prop, status))
                    admitted += 1
                break
        return {"admitted": admitted, "main": main}


class Prover:
    """Proof of application: an independent oracle attests that an applied intent's head is on main."""

    def __init__(self, service, repository, signer: Signer, capability: str, clock):
        self.service, self.repository, self.signer, self.capability, self.clock = (
            service, repository, signer, capability, clock)

    def prove_due(self) -> dict:
        state = self.service.journal.snapshot()
        out = {}
        for name, ob in sorted(state["obligations"].items()):
            if ob["stage"] != "proof":
                continue
            it = state["intents"][ob["intent"]]
            if it["op"] != "remediate" or not self.repository.applied(it["args"]["head"]):
                continue
            body = {"id": f"proof-{uuid.uuid4().hex}", "at": max(self.clock(), state["last_at"] + 1),
                    "author": self.signer.identity, "under": self.capability, "resource": it["resource"],
                    "subject": it["id"], "level": "real"}
            out[name] = self.service.admit(envelope(state["domain"], "evidence", body, [self.signer]))
        return out
