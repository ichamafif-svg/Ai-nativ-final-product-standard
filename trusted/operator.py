"""The operator's own passes on the trusted side (T06 instruments, T07 departures, T08 readback, proof of effect).

They run in the operator process with their own identities and keys, never an agent's. Each pass admits signed
statements through the same journal and service as anyone else: nothing here bypasses the kernel.
"""
from __future__ import annotations

import re
import subprocess
import uuid
from pathlib import Path

from . import instruments
from .data import EMPTY
from .recipes import recipes_for
from .signing import Signer, envelope


class Instruments:
    """T06: measure main's floor targets, and every proposed transition whose base is main.

    A proposal that a recipe reproduces gets `tests` and `reproduced`; any other proposal naming a remediable target
    (its `Standard-Target:` trailer, untrusted, used only to name the resource) gets `tests` alone and waits for a
    signed human review."""

    def __init__(self, service, instrument: instruments.Instrument, repo, proposals, *, data=EMPTY, world=None,
                 anchor: str | None = None, install: bool = False):
        self.service, self.instrument, self.repo, self.proposals = service, instrument, Path(repo), Path(proposals)
        self.data, self.world, self.install = data, world, install
        clock = instrument.clock                          # statements never fall behind the ledger's last instant
        instrument.clock = lambda: max(clock(), service.journal.snapshot()["last_at"] + 1)
        self.anchor = anchor or self._main()

    def _main(self) -> str:
        return instruments.git(self.repo, "rev-parse", "refs/heads/main").strip()

    def _judged(self, state) -> set:
        """Heads of remediate effects the line shows applied: the only commits allowed on main since the anchor."""
        return {it["args"]["head"] for i, it in state["intents"].items()
                if it["op"] == "remediate" and state["line"].get(i, {}).get("state") == "proving"}

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
            facts["tests"] = instruments.tests(self.repo, main, ref, install=self.install)
            admitted += sum(self._admit(self.instrument.observation(domain, resource, p, v)) for p, v in facts.items())
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
