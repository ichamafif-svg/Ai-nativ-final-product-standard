"""The trusted side against its contracts (ARCHITECTURE.md §8, §10, §11.6) and the findings register (§17)."""
import base64
import copy
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from fixture import CODE, HOUR, Keys, Ledger, client_law

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from standard.floors import RELEASE
from kernel import Kernel, Refused, canon, digest
from kernel.floor0 import DISPATCH_MS
from bt import (AdmissionGateway, Checker, ClockError, Disagreement, EffectPort, EscalationOutbox,
                     GatewayClient, Halted, Journal, PinStore, SignedAssessment, Signer, TrustUnavailable,
                     TrustedService, WitnessClock, required_for)
from bt.assessment import BASE, PREFIX as ASSESSMENT_PREFIX
from bt.clock import PREFIX as CLOCK_PREFIX
from bt.delivery import PREFIX as RECEIPT_PREFIX
from bt.gateway import answer


def raw_public(sk):
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class Checks(unittest.TestCase):
    """The checker blocks a kernel delta that differs from the signed consequence (F0-2)."""

    def setUp(self):
        self.L = Ledger()
        self.g = self.L.grant("agent", ["effect:inventory-refresh"], ["repo:*"])

    def corrupted(self, kind, author, mutate, signers=None, **fields):
        L = self.L
        body = {"id": f"x-{kind}", "at": L.state["last_at"] + 1, "author": author, **fields}
        entry = L.entry(kind, body, signers or [author])
        record, delta = L.kernel.decide(L.state, entry)
        law = L.kernel.law_by_digest(record["law"])
        with self.assertRaises(Disagreement):
            Checker(RELEASE.floors).check(L.state, record, mutate(copy.deepcopy(delta)), entry, law.raw, law.digest)

    def test_r01_a_restriction_must_be_applied(self):
        self.corrupted("revoke", "h1", lambda d: [op for op in d if op[1] != "revoked"], grant=self.g)
        self.corrupted("freeze", "h1", lambda d: [("put", "frozen", "other:*", op[3]) if op[1] == "frozen" else op
                                                 for op in d], scope="repo:*")

    def test_no_hidden_mutation(self):
        self.corrupted("freeze", "h1", lambda d: d + [("put", "grants", "evil", {"holder": "agent"})], scope="repo:*")

    def test_the_effect_line_moves_only_along_its_table(self):
        self.corrupted("intent", "agent", lambda d: [("put", "line", op[2], {"state": "reserved", "at": op[3]["at"]})
                                                     if op[1] == "line" else op for op in d],
                       under=self.g, op="inventory-refresh", args={"scope": "all"})

    def test_the_checker_reads_the_signed_entry_not_the_record(self):
        L = self.L
        body = {"id": "f", "at": L.state["last_at"] + 1, "author": "h1", "scope": "repo:*"}
        entry = L.entry("freeze", body, ["h1"])
        record, delta = L.kernel.decide(L.state, entry)
        law = L.kernel.law_by_digest(record["law"])
        forged = {**record, "body": {**body, "scope": "x:*"}}
        with self.assertRaises(Disagreement):
            Checker(RELEASE.floors).check(L.state, forged, delta, entry, law.raw, law.digest)


class Durable(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.L = Ledger()
        self.pins = PinStore(os.path.join(self.dir, "pins", "pins.db"), create=True)
        self.path = os.path.join(self.dir, "journal.db")
        self.J = Journal(self.path, self.L.kernel, self.pins, self.L.state["domain"], create=True)
        for e in self.L.entries:
            self.J.append(e)

    def test_replay_from_disk_equals_memory(self):
        other = Journal(self.path, Kernel(RELEASE, CODE), self.pins, self.L.state["domain"])
        self.assertEqual(other.snapshot(), self.L.state)

    def test_f0_10_rollback_is_detected(self):
        self.J.append(self.L.entry("freeze", {"id": "f1", "at": self.L.state["last_at"] + 1, "author": "h1",
                                              "scope": "a:*"}, ["h1"]))
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.execute("DELETE FROM entries WHERE seq = (SELECT MAX(seq) FROM entries)")
        fresh = Journal(self.path, Kernel(RELEASE, CODE), self.pins, self.L.state["domain"])
        with self.assertRaises(Refused) as r:
            fresh.snapshot()
        self.assertEqual(r.exception.code, "HIST.ROLLBACK")

    def test_v6_10_a_crash_between_pin_and_commit_is_recoverable(self):
        state = self.J.snapshot()
        entry = self.L.entry("freeze", {"id": "f2", "at": state["last_at"] + 1, "author": "h1", "scope": "b:*"}, ["h1"])
        self.pins.keep_then_pin(state["size"] + 1, canon(entry))       # the crash: pinned, never committed
        fresh = Journal(self.path, Kernel(RELEASE, CODE), self.pins, state["domain"])
        with self.assertRaises(Refused):
            fresh.snapshot()
        self.assertIn("b:*", fresh.recover_tail()["frozen"])
        self.assertIn("b:*", fresh.snapshot()["frozen"])

    def test_the_genesis_is_externally_pinned(self):
        with self.assertRaises(ValueError):
            Journal(self.path, Kernel(RELEASE, CODE), self.pins, digest("another ledger"))

    def test_a_halt_persists(self):
        self.pins.halt("disagreement")
        with self.assertRaises(Halted):
            Journal(self.path, Kernel(RELEASE, CODE), self.pins, self.L.state["domain"]).snapshot()


class Effects(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.L = L = Ledger()
        self.g = L.grant("agent", ["effect:inventory-refresh"], ["repo:*"])
        self.pins = PinStore(os.path.join(self.dir, "p", "pins.db"), create=True)
        self.J = Journal(os.path.join(self.dir, "j.db"), L.kernel, self.pins, L.state["domain"], create=True)
        self.signer = Signer("guard", L.keys.private["guard"][1])      # the guard's own key, held by T
        for e in L.entries:
            self.J.append(e)
        self.calls = []
        self.now = lambda: self.J.snapshot()["last_at"]

    def intent(self):
        state = self.J.snapshot()
        body = {"id": f"i{len(self.calls)}-{state['size']}", "at": state["last_at"] + 1, "author": "agent",
                "under": self.g, "op": "inventory-refresh", "args": {"scope": "all"}}
        self.L.state = state
        self.J.append(self.L.entry("intent", body, ["agent"]))
        return body["id"]

    def guard(self, adapter):
        from bt import Guard
        return Guard(self.J, self.signer, EffectPort({"inventory-refresh": adapter}), self.now)

    def test_one_departure_under_both_judges(self):
        g = self.guard(lambda resource, args, key: self.calls.append((resource, args, key)) or "ok")
        result = g.redeem(g.issue(self.intent()))
        self.assertEqual(result, "ok")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], "repo:inventory:all")

    def test_an_adapter_failure_after_entry_is_unknown(self):
        def boom(*_):
            raise TimeoutError("lost answer")
        g = self.guard(boom)
        self.assertEqual(g.redeem(g.issue(self.intent())), "unknown")

    def test_a_restriction_before_departure_means_nothing_left(self):
        g = self.guard(lambda *a: self.calls.append(a) or "ok")
        token = g.issue(self.intent())
        g.journal.transact(lambda s: g._sign(s, "reservation", token=token))
        state = self.J.snapshot()
        self.L.state = state
        self.J.append(self.L.entry("revoke", {"id": "rv", "at": state["last_at"], "author": "h1", "grant": self.g},
                                   ["h1"]))
        self.assertEqual(g._depart(token), "failed")
        self.assertEqual(self.calls, [])

    def test_two_judges_disagreeing_on_bytes_halts(self):
        g = self.guard(lambda *a: self.calls.append(a) or "ok")
        token = g.issue(self.intent())
        g.journal.transact(lambda s: g._sign(s, "reservation", token=token))
        original = self.J.checker.dispatch
        self.J.checker.dispatch = lambda *a: {**original(*a), "args": {"scope": "other"}}
        with self.assertRaises(Halted):
            g._depart(token)
        self.assertEqual(self.calls, [])


class Gateway(unittest.TestCase):
    class Service:
        def view(self):
            return {"bytes": b"not json"}          # HK-1: an unserializable result

        def status(self):
            return {"state": "PROVEN"}

        def qualify(self, required):
            raise TrustUnavailable("TRUST.UNVERIFIED:T07")

        def admit(self, envelope):
            raise Refused("CAP.SCOPE", "outside")

    def test_hk1_every_request_gets_a_typed_answer(self):
        s = self.Service()
        for request, error in (({"action": "view"}, "TypeError"), ({"action": "admit", "envelope": {}}, "CAP.SCOPE"),
                               ({"action": "qualify", "required": ["T07"]}, "TrustUnavailable"),
                               ({"action": "drop"}, "REQUEST.SHAPE")):
            reply = json.loads(answer(s, json.dumps(request).encode() + b"\n"))
            self.assertEqual(reply, {"ok": False, "error": error})
        self.assertEqual(json.loads(answer(s, b"x" * 10)), {"ok": False, "error": "REQUEST.SIZE"})

    def test_round_trip_over_the_socket(self):
        path = os.path.join(tempfile.mkdtemp(), "admission.sock")
        server = AdmissionGateway(path, self.Service())
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        self.assertEqual(GatewayClient(path).status(), {"state": "PROVEN"})
        thread.join()
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        with self.assertRaises(Exception) as r:
            GatewayClient(path).admit({})
        self.assertEqual(r.exception.args[0], "CAP.SCOPE")
        thread.join()
        server.server_close()


class Boundary(unittest.TestCase):
    def test_restrictions_need_no_clock_effects_need_the_guard(self):
        self.assertEqual(required_for("freeze"), BASE)
        self.assertIn("T03", required_for("grant"))
        self.assertTrue({"T07", "T08"} <= required_for("reservation"))
        self.assertIn("T06", required_for("evidence"))

    def assessment(self, contracts, **override):
        sk = Ed25519PrivateKey.generate()
        payload = {"schema": SignedAssessment.SCHEMA, "assessor": "lab", "independent": True, "release": CODE,
                   "genesis": "g",
                   "ledger": digest("/ledger"), "issued_at": 10, "expires_at": 1000, "contracts": contracts, **override}
        bundle = {"payload": payload, "signature": base64.b64encode(sk.sign(ASSESSMENT_PREFIX + canon(payload))).decode()}
        return SignedAssessment(bundle, {"lab": raw_public(sk)})

    def test_a_signed_assessment_binds_release_genesis_ledger_and_time(self):
        ok = dict.fromkeys(["T01", "T02", "T03", "T04", "T05"], "VERIFIED")
        b = self.assessment(ok)
        b.check(BASE, release=CODE, genesis="g", ledger="/ledger", now=500)
        b.check(BASE, release=CODE, genesis="g", ledger="/ledger", now=None)      # a restriction, without a clock
        for kwargs in ({"genesis": "h", "now": 500}, {"ledger": "/other", "now": 500}, {"now": 2000}):
            with self.assertRaises(TrustUnavailable):
                b.check(BASE, **{"release": CODE, "genesis": "g", "ledger": "/ledger", **kwargs})
        with self.assertRaises(TrustUnavailable):
            b.check(BASE | {"T07"}, release=CODE, genesis="g", ledger="/ledger", now=500)


class Clock(unittest.TestCase):
    def setUp(self):
        self.keys = {w: Ed25519PrivateKey.generate() for w in ("w1", "w2")}
        self.at = {"w1": 100, "w2": 100}

    def fetch(self, nonce):
        quotes = []
        for w, sk in self.keys.items():
            claim = {"genesis": "g", "nonce": nonce, "witness": w, "at": self.at[w]}
            quotes.append({"claim": claim, "signature": base64.b64encode(sk.sign(CLOCK_PREFIX + canon(claim))).decode()})
        return quotes

    def test_two_witnesses_agree_and_time_never_goes_back(self):
        clock = WitnessClock(genesis="g", public_keys={w: raw_public(k) for w, k in self.keys.items()}, quorum=2,
                             fetch=self.fetch)
        self.assertEqual(clock(), 100)
        self.at["w2"] = 101
        with self.assertRaises(ClockError):
            clock()
        self.at = {"w1": 50, "w2": 50}
        with self.assertRaises(ClockError):
            clock()

    def test_a_bounded_spread_gives_the_latest_quote_and_restarts_never_go_back(self):
        """Review, medium 15: exact agreement of independent clocks, and monotonicity lost at every restart."""
        state = Path(tempfile.mkdtemp()) / "clock.json"
        keys = {w: raw_public(k) for w, k in self.keys.items()}
        clock = WitnessClock(genesis="g", public_keys=keys, quorum=2, fetch=self.fetch, tolerance_ms=50, state=state)
        self.at = {"w1": 100, "w2": 130}
        self.assertEqual(clock(), 130)
        self.at = {"w1": 100, "w2": 300}
        with self.assertRaises(ClockError):
            clock()                                                       # spread beyond the tolerance
        again = WitnessClock(genesis="g", public_keys=keys, quorum=2, fetch=self.fetch, tolerance_ms=50, state=state)
        self.at = {"w1": 120, "w2": 125}
        with self.assertRaises(ClockError):
            again()                                                       # below what was already returned
        with self.assertRaises(ClockError):
            WitnessClock(genesis="g", public_keys=keys, quorum=2, fetch=self.fetch, tolerance_ms=60_000)


class Delivery(unittest.TestCase):
    def test_an_unanswered_send_is_read_back_never_resent(self):
        provider = Ed25519PrivateKey.generate()
        sent, receipts = [], {}

        class Transport:
            def send(self, key, payload):
                sent.append(key)
                raise TimeoutError("lost answer after sending")

            def readback(self, key):
                return receipts.get(key)

        box = EscalationOutbox(os.path.join(tempfile.mkdtemp(), "out.db"), transport=Transport(),
                               provider_keys={"mail": raw_public(provider)}, genesis="g", create=True)
        verdict = {"state": "ESCALATED", "head": "h", "escalated": [
            {"obligation": "target:vulns", "opened": 1, "due": 2, "escalated_to": ["h1", "h2"]}]}
        first = box.deliver_due(verdict)
        self.assertEqual(list(first.values()), ["UNKNOWN"])
        key = next(iter(first))
        payload = {"key": key, "genesis": "g", "head": "h", "obligation": "target:vulns", "opened": 1, "due": 2,
                   "recipients": ["h1", "h2"]}
        claim = {"key": key, "payload_digest": digest(payload), "recipients_digest": digest(["h1", "h2"]),
                 "provider": "mail", "delivered_at": 3}
        receipts[key] = {"claim": claim, "signature": base64.b64encode(provider.sign(RECEIPT_PREFIX + canon(claim))).decode()}
        self.assertEqual(box.deliver_due(verdict), {key: "delivered"})
        self.assertEqual(sent, [key])


class Service(unittest.TestCase):
    def test_status_is_a_visible_fault_when_trust_is_missing(self):
        dir_ = tempfile.mkdtemp()
        L = Ledger()
        pins = PinStore(os.path.join(dir_, "p", "pins.db"), create=True)
        journal = Journal(os.path.join(dir_, "j.db"), L.kernel, pins, L.state["domain"], create=True)
        for e in L.entries:
            journal.append(e)

        class Nothing:
            def check(self, required, **_):
                raise TrustUnavailable("TRUST.UNVERIFIED")

        service = TrustedService(journal, boundary=Nothing(), clock=lambda: 0)
        self.assertEqual(service.status()["state"], "FAULT")
        with self.assertRaises(TrustUnavailable):
            service.admit(L.entry("freeze", {"id": "f", "at": 1, "author": "h1", "scope": "x:*"}, ["h1"])["envelope"])


if __name__ == "__main__":
    unittest.main()
