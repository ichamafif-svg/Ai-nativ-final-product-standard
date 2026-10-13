"""The operator-side service: K and T assembled behind one admission path (ARCHITECTURE.md §10, §13.1).

It runs in its own process, under its own OS account. U reaches it only through the gateway (`view`, `status`,
`qualify`, `admit`); the operator loop calls `dispatch_due`, `reconcile_due` and `deliver_due`. Every operation first
qualifies exactly the T contracts it depends on; a missing contract stops that operation only.
"""
from __future__ import annotations

import threading

from kernel import Accountability, apply, digest, empty
from kernel.accountability import empty as accountability_empty
from kernel.floor0 import line_state
from kernel.identity import IdentityError, open_envelope

from .assessment import BASE, CONTRACTS, TIMED, TrustUnavailable, required_for
from .guard import EffectPort, Guard
from .journal import Journal
from .signing import Signer

EFFECT = TIMED | {"T07", "T08"}


class TrustedService:
    def __init__(self, journal: Journal, *, boundary, clock, effect_port: EffectPort | None = None,
                 guard_signer: Signer | None = None, reconciliation=None, delivery=None):
        if not callable(getattr(boundary, "check", None)) or not callable(clock):
            raise TrustUnavailable("TRUST.BOUNDARY_REQUIRED")
        self.journal, self.boundary, self.clock = journal, boundary, clock
        self.effect_port, self.guard_signer = effect_port, guard_signer
        self.reconciliation, self.delivery = reconciliation, delivery
        self._last_now = -1
        self.accountability = Accountability(journal.kernel)
        self._fold_lock = threading.Lock()                # the gateway thread and the operator loop both read health

    # ---- trust ------------------------------------------------------------------------------------------------------
    def _require(self, need) -> int | None:
        need = frozenset(need)
        now = None
        if "T03" in need:
            try:
                now = self.clock()
            except Exception as exc:
                raise TrustUnavailable("TRUST.CLOCK") from exc
            if type(now) is not int or now < self._last_now:
                raise TrustUnavailable("TRUST.CLOCK_ROLLBACK")
            self._last_now = now
        self.boundary.check(need, release=self.journal.kernel.code, genesis=self.journal.genesis_pin,
                            ledger=str(self.journal.path), now=now)
        if "T07" in need and not isinstance(self.effect_port, EffectPort):
            raise TrustUnavailable("TRUST.EFFECT_PORT")
        if "T08" in need and not callable(getattr(self.reconciliation, "readback", None)):
            raise TrustUnavailable("TRUST.RECONCILIATION_PORT")
        if "T09" in need and not callable(getattr(self.delivery, "deliver_due", None)):
            raise TrustUnavailable("TRUST.DELIVERY_PORT")
        return now

    # ---- the gateway surface ----------------------------------------------------------------------------------------
    def admit(self, envelope) -> dict:
        try:
            kind = open_envelope(envelope)[0]
        except (IdentityError, TypeError, KeyError):
            kind = None                                    # the kernel refuses it below, under the strictest need
        need = required_for(kind) if kind else TIMED
        self._require(need)

        def build(state):
            self._require(need)                            # again, under the write lock
            return {"seq": state["size"], "prev": state["head"], "envelope": envelope}
        _, record = self.journal.transact(build)
        return {"admitted": True, "kind": record["kind"], "id": record["body"]["id"], "law": record["law"]}

    def qualify(self, required) -> None:
        if not isinstance(required, (list, tuple, set, frozenset)) or not set(required) <= set(CONTRACTS):
            raise TrustUnavailable("TRUST.UNKNOWN_CONTRACT")
        self._require(TIMED | set(required))

    def view(self) -> dict:
        """The law and its debts at one checked prefix: data for U, never a permission."""
        now = self._require(TIMED)
        for _ in range(3):
            state = self.journal.snapshot()
            health = self.health(required_at=now)
            if (health["size"], health["head"]) == (state["size"], state["head"]):
                break
        else:
            raise TrustUnavailable("VIEW.PREFIX_CHANGED")
        law = self.journal.kernel.law_of(state)
        transitions = {}                                    # facts on exact transitions: tests, review, regressions…
        for key, ob in state["observations"].items():
            resource, rest = key.split("|", 1)                # a resource and an author never hold "|"
            prop = rest.rsplit("|", 1)[0]
            if "/" in resource:
                transitions.setdefault(resource, {})[prop] = ob["status"]
        return {"prefix": {"size": state["size"], "head": state["head"], "genesis": state["domain"]},
                "law": {"digest": law.digest, "effective": law.raw}, "health": health,
                "assessment": self.assessment(), "transitions": transitions,
                # Public admitted declarations only: visibility of rights is never permission to exercise them.
                "grants": state["grants"],
                # D34: typed resources (requests) with the digest a transition must name as `expected`
                "entities": {r: {**e, "expected": digest(e)} for r, e in state["entities"].items()},
                "facts": sorted(({k: o[k] for k in ("id", "resource", "property", "status", "author", "at")}
                                 for o in state["observations"].values()), key=lambda o: -o["at"])[:500]}

    def assessment(self) -> str:
        """INDEPENDENT only when an independent, pinned assessor qualified this installation (D19)."""
        return "INDEPENDENT" if getattr(self.boundary, "independent", False) else "SELF_ASSESSED"

    def status(self) -> dict:
        """Never raises: a fault is a visible state with what is still known (§9.4)."""
        basis = None
        try:
            self._require(BASE)
            state = self.journal.snapshot()
            basis = {"size": state["size"], "head": state["head"], "genesis": state["domain"]}
        except Exception as exc:
            return {"state": "FAULT", "basis": None, "boundary": "prefix", "reason": type(exc).__name__}
        try:
            verdict = self.health(required_at=self._require(TIMED))
            return {"state": verdict["state"], "basis": basis, "open": len(verdict["open"]),
                    "escalated": len(verdict["escalated"]), "assessment": self.assessment()}
        except Exception as exc:
            return {"state": "FAULT", "basis": basis, "boundary": "audit", "reason": type(exc).__name__}

    def health(self, *, required_at=None) -> dict:
        """The accountability fold, kept across calls: only entries not yet folded are judged again. If the journal
        no longer extends what was folded, the fold restarts from genesis."""
        with self._fold_lock:
            return self._health(required_at)

    def _health(self, required_at) -> dict:
        kernel = self.journal.kernel
        a, ks, n = getattr(self, "_fold", (None, None, 0))
        tail = self.journal.entries(max(n - 1, 0)) if a is not None else []
        if a is None or (n and (not tail or digest(tail[0]) != ks["head"])):
            a, ks, n = accountability_empty(), empty(), 0       # the journal no longer extends the fold
            tail = self.journal.entries()
        else:
            tail = tail[1:] if n else tail
        entries_len = n + len(tail)
        try:
            for entry in tail:
                record, delta = kernel.decide(ks, entry)
                apply(ks, delta)
                self.accountability.feed(a, ks, record)
        except BaseException:
            self._fold = (None, None, 0)                    # a half-applied fold is never reused
            raise
        self._fold = (a, ks, entries_len)
        verdict = self.accountability.health(a, ks, required_at=required_at)
        return {**verdict, "head": ks["head"], "size": ks["size"]}

    # ---- the operator loop ------------------------------------------------------------------------------------------
    def guard(self) -> Guard:
        self._require(EFFECT)
        if self.guard_signer is None:
            raise TrustUnavailable("TRUST.GUARD_SIGNER")
        return Guard(self.journal, self.guard_signer, self.effect_port, self.clock,
                     qualify=lambda trusted: self._require(TIMED | set(trusted)))

    def dispatch_due(self) -> dict:
        guard, results = self.guard(), {}
        state = self.journal.snapshot()
        now = self._require(EFFECT)
        for intent in sorted(state["intents"]):
            phase = line_state(state["line"], intent, now)
            if phase not in ("intended", "tokened"):
                continue
            try:
                token = guard.issue(intent) if phase == "intended" else self.journal.snapshot()["token_of"][intent]
                results[intent] = guard.redeem(token)
            except Exception as exc:
                results[intent] = {"blocked": getattr(exc, "code", type(exc).__name__)}
        return results

    def reconcile_due(self) -> dict:
        """Ask the independent readback (T08) about every uncertain or expired effect; admit its signed answer."""
        now = self._require(TIMED | {"T08"})
        state, results = self.journal.snapshot(), {}
        for intent in sorted(state["intents"]):
            if line_state(state["line"], intent, now) not in ("uncertain", "expired"):
                continue
            try:
                envelope = self.reconciliation.readback(intent, state)
                results[intent] = self.admit(envelope) if envelope is not None else "UNKNOWN"
            except Exception as exc:
                results[intent] = {"blocked": getattr(exc, "code", type(exc).__name__)}
        return results

    def deliver_due(self) -> dict:
        now = self._require(TIMED | {"T09"})
        return self.delivery.deliver_due(self.health(required_at=now))
