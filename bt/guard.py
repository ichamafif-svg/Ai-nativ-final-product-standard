"""T07 — the effect guard (ARCHITECTURE.md §8.2), and the port to the trusted provider adapters.

Reserve durably, re-judge under the journal write lock with both judges, send once while still holding the lock,
await outside it, report. The guard alone holds the provider credentials (inside its adapters); an agent never does.
"""
from __future__ import annotations

import copy
import uuid

from kernel import Refused, canon, digest

from .checker import Disagreement
from .journal import Halted, Journal
from .signing import Signer, entry


class NotDispatched(Exception):
    """Nothing entered a provider adapter: the effect certainly did not leave."""


class EffectPort:
    """Op name -> trusted adapter(resource, args, reservation_key) -> "ok" | "failed" | "unknown" | wait().
    A wait() only awaits a request already sent; it never sends anything."""

    def __init__(self, adapters: dict):
        if not isinstance(adapters, dict) or not adapters or not all(callable(a) for a in adapters.values()):
            raise ValueError("explicit trusted adapters are required")
        self._adapters = dict(adapters)

    def perform(self, judged: dict, expected: bytes, reservation_key: str):
        if canon(judged) != expected:
            raise NotDispatched("the effect differs from the judged bytes")
        adapter = self._adapters.get(judged["op"])
        if adapter is None:
            raise NotDispatched("no trusted adapter for this operation")
        try:
            return adapter(judged["resource"], copy.deepcopy(judged["args"]), reservation_key)
        except Exception:
            return "unknown"                       # inside an adapter, any failure is uncertain


class Guard:
    def __init__(self, journal: Journal, signer: Signer, port: EffectPort, clock, qualify=lambda trusted: None):
        """clock(): trusted time (T03). qualify(trusted): raises if a T contract the op needs is unavailable."""
        if not isinstance(port, EffectPort) or not callable(clock):
            raise ValueError("a trusted effect port and a trusted clock are required")
        self.journal, self.signer, self.port, self.clock, self.qualify = journal, signer, port, clock, qualify

    def _at(self, state) -> int:
        now = self.clock()
        if type(now) is not int or now < 0:
            raise Refused("HIST.TIME", "trusted time is unavailable")
        return max(now, state["last_at"] + 1)

    def _sign(self, state, kind, **fields):
        body = {"id": f"{kind}-{uuid.uuid4().hex}", "at": self._at(state), "author": self.signer.identity, **fields}
        return entry(state, kind, body, [self.signer])

    def issue(self, intent_id: str, cosigners=()) -> str:
        def build(state):
            it = state["intents"].get(intent_id)
            if it is None:
                raise Refused("OBL.NOT_OPEN", "the intent is not in this journal")
            body = {"id": f"token-{uuid.uuid4().hex}", "at": self._at(state), "author": self.signer.identity,
                    "intent": intent_id, "args_digest": digest(it["args"])}
            return entry(state, "token", body, [self.signer, *cosigners])
        return self.journal.transact(build)[1]["body"]["id"]

    def redeem(self, token_id: str) -> str:
        """Reserve, depart once or not at all, report. Returns the reported result."""
        self.journal.transact(lambda s: self._sign(s, "reservation", token=token_id))
        result = self._depart(token_id)
        if callable(result):
            try:
                result = result()
            except Exception:
                result = "unknown"
        result = result if result in ("ok", "failed", "unknown") else "unknown"
        self.journal.transact(lambda s: self._sign(s, "execution", token=token_id, result=result))
        return result

    def _depart(self, token_id: str):
        """Re-judge with both judges and send under the write lock. Once an adapter has been entered, the answer is
        never "failed" by default: only the adapter can say so; any later error is "unknown"."""
        entered = False
        try:
            with self.journal.effect_gate() as state:
                kernel = self.journal.kernel
                now = max(self.clock(), state["last_at"])
                law = kernel.law_of(state)
                it = kernel.judge_dispatch(state, token_id, self.signer.identity, now)
                try:
                    checked = self.journal.checker.dispatch(state, token_id, now, law.raw, law.digest)
                except Disagreement as exc:
                    self.journal._halt(f"departure check: {exc}")
                judged = {"op": it["op"], "resource": it["resource"], "args": copy.deepcopy(it["args"])}
                if canon(judged) != canon(checked):
                    self.journal._halt("the two judges produced different physical effects")
                self.qualify(law.ops[it["op"]]["trusted"])          # every T the op needs, just before departure
                key = digest({"genesis": state["domain"], "reservation": state["reserved"][token_id]})
                expected = canon(judged)
                entered = True
                result = self.port.perform(judged, expected, key)   # sent under the lock
            return result
        except Halted:
            raise
        except NotDispatched:
            return "failed"
        except Exception:
            return "unknown" if entered else "failed"
