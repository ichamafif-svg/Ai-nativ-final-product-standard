"""T — Boundary Transactions (D38): the one way Standard meets the world outside the ledger.

Every claim that enters and every effect that leaves is a boundary transaction under a contract the floors declare
(floors.CONTRACTS). A transaction is a record, kept by digest in the evidence store and listed in transactions.jsonl:

    kind        observe | effect | resolve
    identity    who: the scanner, the guard, the oracle (never an agent)
    subject     what exactly: a job and the resources it spoke of, or the judged resource
    authority   under what: the contract, the capability, the reservation key
    contract    how it is justified: reproducible, attested or composite (observe); cas or observable (effect)
    material    what was read or sent, by digest: the run record, the canonical request, what was read back
    causality   the genesis, the ledger head and the law it happened under, and the transactions it answers
    outcome     established | refused (observe); ok | failed | unknown (effect); applied | not_applied | unknown

OBSERVE   the host runs a job of the pinned programs; only what the job's contract allows it to say is signed, as a
          measurement whose method names the contract (`programs@<digest>/suite`): the kernel admits `tests` from
          the suite contract alone. What the job says outside its contract is refused and recorded, never signed.
EFFECT    the guard's port: the operation's adapter must have the physical profile the contract requires, or the
          route is unqualified and nothing leaves. What left, with which key, and the answer, are recorded.
RESOLVE   after an uncertain or expired effect, the oracle reads the provider back. A `cas` effect is decided by
          the state itself: applied, or not_applied when the move did not happen and no request can still land; an
          `observable` effect is applied only when an observation shows it, and never not_applied once requested.
          Timeouts, lost answers and silence prove nothing. That an effect applied is not that its purpose holds:
          the proof (an observation of the result, D30) stays a separate step.

This module knows no provider and no measure: adapters bring `profile`, `perform`, `read`, `satisfied`; programs
bring their answers. Adding either adds no line here.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from kernel import digest

from .guard import EffectPort, NotDispatched
from .signing import Signer, envelope

PROFILES = ("cas", "observable")


def _matches(resource: str, prefixes) -> bool:
    return any(resource.startswith(p) for p in prefixes)


class Boundary:
    def __init__(self, evidence, index, contracts: dict, programs: str, clock, ledger=lambda: {}):
        """evidence: trusted.host.Evidence; index: the transactions list (jsonl); contracts: floors.CONTRACTS;
        programs: `programs@<digest>`; ledger(): {"genesis", "head", "law"} at this moment."""
        self.evidence, self.index, self.contracts = evidence, Path(index), contracts
        self.programs, self.clock, self.ledger = programs, clock, ledger
        self.jobs = {job: name for name, c in contracts["observe"].items() for job in c["jobs"]}
        if any(profile not in PROFILES for profile in contracts["effect"].values()):
            raise ValueError(f"an effect contract names a profile outside {PROFILES}")

    def record(self, kind: str, identity: str, subject, authority, contract, material, outcome, answers=()) -> str:
        bt = {"bt": kind, "id": f"bt-{uuid.uuid4().hex}", "at": self.clock(), "identity": identity, "subject": subject,
              "authority": authority, "contract": contract, "material": material,
              "causality": {**self.ledger(), "answers": list(answers)}, "outcome": outcome}
        ref = self.evidence.put(json.dumps(bt, sort_keys=True).encode())
        with open(self.index, "a") as f:
            f.write(json.dumps({"at": bt["at"], "bt": kind, "ref": ref, "subject": subject if isinstance(subject, str)
                                else subject.get("job"), "key": authority.get("key"), "outcome": outcome}) + "\n")
        return ref

    def effect_of(self, key: str) -> list:
        """The effect transactions a reservation produced, for RESOLVE to answer."""
        if not key or not self.index.exists():
            return []
        rows = (json.loads(line) for line in self.index.read_text().splitlines() if line.strip())
        return [r["ref"] for r in rows if r["bt"] == "effect" and r.get("key") == key]

    # ---- OBSERVE --------------------------------------------------------------------------------------------------
    def observe(self, host, identity: str, job: str, inputs: dict, *, network=False, cache=True, answers=()) -> dict:
        """Run one job through the host; keep what its contract lets it say. -> {"facts": [(resource, property,
        status, details)], "method", "ref", "refused", "extra"} or {"error"}."""
        name = self.jobs.get(job)
        if name is None and job != "plan":
            return {"error": f"no observation contract names the job {job}"}
        out, run = host.call(job, inputs, network=network, cache=cache)
        if "error" in out:
            return {"error": out["error"], "ref": run}
        c = self.contracts["observe"].get(name, {"form": "reproducible", "properties": [], "resources": []})
        kept, refused = [], []
        for resource, prop, status, details in out.get("facts", []):
            ok = isinstance(resource, str) and isinstance(status, str) and prop in c["properties"] \
                and _matches(resource, c["resources"])
            (kept if ok else refused).append((resource, prop, status, details))
        ref = self.record("observe", identity, {"job": job, "resources": sorted({f[0] for f in kept})},
                          {"contract": name or "plan"},
                          {"form": c["form"], "attested": c.get("attested", [])},
                          {"run": run, "programs": host.method}, "refused" if refused else "established", answers)
        return {"facts": kept, "refused": refused, "method": f"{self.programs}/{name}", "ref": ref,
                "extra": out.get("extra", {}), "jobs": out.get("jobs")}

    def capture(self, identity: str, points: list) -> str | None:
        """What the declared sources returned, recorded before any program reads it (attested material)."""
        if not points:
            return None
        return self.record("observe", identity, {"job": "capture", "resources": sorted({p[0] for p in points})},
                           {"contract": "capture"}, {"form": "attested", "attested": self.contracts["observe"]
                                                     ["capture"]["attested"]},
                           {"points": [list(p) for p in points]}, "established")


class BoundaryPort(EffectPort):
    """EFFECT: the guard's port; each operation reaches only an adapter whose profile is the contract's."""

    def __init__(self, boundary: Boundary, adapters: dict):
        super().__init__({op: a.perform for op, a in adapters.items()})
        self.boundary, self.adapters = boundary, dict(adapters)

    def perform(self, judged: dict, expected: bytes, reservation_key: str):
        op, required = judged["op"], self.boundary.contracts["effect"].get(judged["op"])
        profile = getattr(self.adapters.get(op), "profile", None)
        authority, material = {"key": reservation_key, "op": op}, {"request": digest(judged)}
        if profile is None or profile != required:
            self.boundary.record("effect", "guard", judged["resource"], authority,
                                 {"profile": required, "adapter": profile}, material, "failed:unqualified")
            raise NotDispatched("no adapter with the physical profile this operation requires")
        result = super().perform(judged, expected, reservation_key)
        self.boundary.record("effect", "guard", judged["resource"], authority, {"profile": profile}, material,
                             result if result in ("ok", "failed", "unknown") else "unknown")
        return result


class Resolve:
    """RESOLVE: T08 and the proof of application, for the oracle's identity."""

    def __init__(self, boundary: Boundary, adapters: dict, signer: Signer, capability: str):
        self.boundary, self.adapters, self.signer, self.capability = boundary, adapters, signer, capability

    def _key(self, state: dict, intent_id: str) -> str | None:
        token = state["token_of"].get(intent_id)
        reserved = state["reserved"].get(token) if token else None
        return digest({"genesis": state["domain"], "reservation": reserved}) if reserved else None

    def readback(self, intent_id: str, state: dict):
        """A signed reconciliation, or None: unknown stays unknown."""
        it = state["intents"][intent_id]
        adapter, key = self.adapters.get(it["op"]), self._key(state, intent_id)
        try:
            seen = adapter.read(it, key) if adapter is not None and key is not None else None
        except Exception:
            seen = None
        if seen == "not_applied" and adapter.profile != "cas":
            seen = None                                     # a request may still land: never absent by silence
        if seen == "not_sent":
            seen = "not_applied"                            # nothing left the guard for this reservation
        outcome = seen if seen in ("applied", "not_applied") else "unknown"
        self.boundary.record("resolve", self.signer.identity, it["resource"], {"key": key, "intent": intent_id},
                             {"profile": getattr(adapter, "profile", None)}, {"read": seen}, outcome,
                             self.boundary.effect_of(key))
        if outcome == "unknown":
            return None
        body = {"id": f"rec-{uuid.uuid4().hex}", "at": max(self.boundary.clock(), state["last_at"] + 1),
                "author": self.signer.identity, "under": self.capability, "intent": intent_id, "result": outcome}
        return envelope(state["domain"], "reconciliation", body, [self.signer])

    def satisfied(self, it: dict) -> bool:
        """The purpose of an applied effect, observed: main contains the head, production serves the release."""
        adapter = self.adapters.get(it["op"])
        try:
            return adapter is not None and bool(adapter.satisfied(it))
        except Exception:
            return False


def ledger_of(journal) -> dict:
    s = journal.snapshot()
    return {"genesis": s["domain"], "head": s["head"], "law": s["law"]["digest"] if s.get("law") else None}


