"""The kernel against its contracts (ARCHITECTURE.md §4–§9) and the findings register (§17)."""
import base64
import copy
import unittest

from fixture import CODE, HOUR, Keys, Ledger, client_law, envelope

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from floors import RELEASE
from kernel import MECHANISMS, Accountability, Kernel, Refused, apply, canon, digest, empty
from kernel.accountability import RETIRED, empty as accountability_empty
from kernel.floor0 import DISPATCH_MS, MAX_AHEAD_MS
from kernel.identity import canonical_public


def health(ledger, required_at=None):
    acc, a, ks = Accountability(ledger.kernel), accountability_empty(), empty()
    for e in ledger.entries:
        record, delta = ledger.kernel.decide(ks, e)
        apply(ks, delta)
        acc.feed(a, ks, record)
    return acc.health(a, ks, required_at=required_at)


class Genesis(unittest.TestCase):
    def test_genesis_pins_root_law_and_code(self):
        L = Ledger()
        self.assertEqual(L.state["code"], CODE)
        self.assertEqual(L.state["law"]["digest"], L.kernel.law_of(L.state).digest)

    def test_f0_1_quorum_needs_k_plus_two_humans(self):
        keys = Keys()
        for h in ("h3", "h4"):
            keys.root["identities"][h]["kind"] = "agent"
        with self.assertRaises(Refused) as r:
            Ledger(keys=keys)
        self.assertEqual(r.exception.code, "TYPE.ROOT")

    def test_genesis_binds_the_code_release(self):
        with self.assertRaises(Refused) as r:
            Ledger(kernel=Kernel(RELEASE, digest({"code": "other"})))
        self.assertEqual(r.exception.code, "HIST.CODE")

    def test_every_refusal_is_one_of_six_mechanisms(self):
        L = Ledger()
        codes = {L.refused("freeze", "agent", scope="repo:*"), L.refused("grant", "agent", holder="agent",
                 actions=["x"], resources=["*"], conditions=[], not_after=10 ** 12),
                 L.refused("checkpoint", "w1", ["w1"], size=L.state["size"], head=L.state["head"])}
        self.assertTrue(all(c.split(".")[0] in MECHANISMS for c in codes), codes)


class Widening(unittest.TestCase):
    def test_widening_needs_quorum_delay_and_activation(self):
        L = Ledger()
        self.assertEqual(L.refused("grant", "h1", ["h1"], holder="agent", actions=["x"], resources=["*"],
                                   conditions=[], not_after=10 ** 12), "CAP.QUORUM")
        pid = L.submit("grant", "h1", ["h1", "h2"], holder="agent", actions=["x"], resources=["*"], conditions=[],
                       not_after=10 ** 12)
        self.assertEqual(L.refused("activate", "h1", ["h1", "h2"], proposal=pid), "CAP.DELAY")
        L.advance(HOUR + 1)
        L.submit("activate", "h1", ["h1", "h2"], proposal=pid)
        self.assertIn(pid, L.state["grants"])

    def test_time_never_grants(self):
        """A far future timestamp is refused: only witnesses advance the anchor (F0-6)."""
        L = Ledger()
        pid = L.submit("grant", "h1", ["h1", "h2"], holder="agent", actions=["x"], resources=["*"], conditions=[],
                       not_after=10 ** 12)
        self.assertEqual(L.refused("activate", "h1", ["h1", "h2"], at=L.state["anchor_at"] + MAX_AHEAD_MS + 1,
                                   proposal=pid), "HIST.AHEAD")

    def test_veto_and_override(self):
        L = Ledger()
        pid = L.submit("grant", "h1", ["h1", "h2"], holder="agent", actions=["x"], resources=["*"], conditions=[],
                       not_after=10 ** 12)
        self.assertEqual(L.refused("veto", "h2", proposal=pid), "CAP.VETO")     # a signer cannot veto
        L.submit("veto", "h3", proposal=pid)
        self.assertNotIn(pid, L.state["proposals"])
        over = L.submit("grant", "h1", ["h1", "h2", "h4"], override=True, holder="agent", actions=["x"],
                        resources=["*"], conditions=[], not_after=10 ** 12)
        self.assertEqual(L.refused("veto", "h3", proposal=over), "CAP.VETO")
        L.advance(HOUR + 1)
        self.assertEqual(L.refused("activate", "h1", ["h1", "h2"], proposal=over), "CAP.DELAY")   # double delay
        L.advance(HOUR + 1)
        L.submit("activate", "h1", ["h1", "h2"], proposal=over)

    def test_proposal_goes_stale_when_the_law_changes(self):
        """V6-§3.2: an old delay cannot be used after a law change."""
        L = Ledger()
        pid = L.submit("grant", "h1", ["h1", "h2"], holder="agent", actions=["x"], resources=["*"], conditions=[],
                       not_after=10 ** 12)
        law = L.submit("law", "h1", ["h1", "h2"], client=client_law(delays={"grant": 2 * HOUR}))
        L.advance(HOUR + 1)
        L.submit("activate", "h1", ["h1", "h2"], proposal=law)
        L.advance(HOUR + 1)
        self.assertEqual(L.refused("activate", "h1", ["h1", "h2"], proposal=pid), "CAP.STALE")


class Restrictions(unittest.TestCase):
    def test_v6_5_a_restriction_may_share_the_last_instant(self):
        L = Ledger()
        ceiling = L.state["anchor_at"] + MAX_AHEAD_MS
        L.submit("freeze", "h3", at=ceiling, scope="repo:a:*")
        L.submit("freeze", "sentinel", at=ceiling, scope="repo:b:*")
        self.assertEqual(L.refused("heartbeat", "agent", at=ceiling, seen=0), "CAP.RESTRICT")
        self.assertEqual(L.refused("grant", "h1", ["h1", "h2"], at=ceiling, holder="agent", actions=["x"],
                                   resources=["*"], conditions=[], not_after=10 ** 12), "HIST.TIME")

    def test_v6_2_a_law_cannot_block_a_restriction(self):
        L = Ledger()
        bad = client_law(obligations=[{"id": "block", "level": "refuse", "due_ms": HOUR, "on_due": "lapse",
                                       "open": [{"kind": "intent", "key": "id"}],
                                       "gate": [{"kind": "freeze", "key": "scope"}]}])
        self.assertEqual(L.refused("law", "h1", ["h1", "h2"], client=bad), "TYPE.LAW")

    def test_freeze_blocks_effects_and_unfreeze_is_a_widening(self):
        L = Ledger()
        g = L.grant("agent", ["effect:inventory-refresh"], ["repo:*"])
        L.submit("freeze", "h3", scope="repo:inventory:*")
        self.assertEqual(L.refused("intent", "agent", under=g, op="inventory-refresh", args={"scope": "all"}),
                         "CAP.FROZEN")
        self.assertEqual(L.refused("unfreeze", "h3", scope="repo:inventory:*"), "CAP.QUORUM")


class Law(unittest.TestCase):
    def test_a_client_only_tightens(self):
        L = Ledger()
        for weaker in (client_law(ttl={"proof": 2 * 86_400_000}), client_law(delays={"grant": 60_000}),
                       client_law(witnesses={"quorum": 1}), client_law(tighten={"targets": {"vulns": {"due_ms": 10 ** 10}}}),
                       client_law(ops={"remediate": {"args": {"x": "segment"}, "resource": "a:{x}", "profile": "capability"}})):
            self.assertEqual(L.refused("law", "h1", ["h1", "h2"], client=weaker), "TYPE.LAW")
        L.submit("law", "h1", ["h1", "h2"], client=client_law(ttl={"proof": 3_600_000}))

    def test_v6_7_client_proof_never_below_the_floor(self):
        L = Ledger()
        weak = client_law(evidence={"weak": {"fields": {"under": "id", "resource": "resource", "subject": "id",
                                                        "level": "str"}}},
                          discharges={"weak": [{"obligation": "proof", "key": "subject", "min_level": "unknown"}]})
        self.assertEqual(L.refused("law", "h1", ["h1", "h2"], client=weak), "TYPE.LAW")

    def test_v6_3_conditions_accept_only_strings_and_integers(self):
        L = Ledger()
        bad = client_law(obligations=[{"id": "forced", "level": "refuse", "due_ms": HOUR, "on_due": "lapse",
                                       "open": [{"kind": "intent", "key": "id", "where": {"args.force": True}}]}])
        self.assertEqual(L.refused("law", "h1", ["h1", "h2"], client=bad), "TYPE.LAW")

    def test_v6_8_an_evidence_kind_cannot_take_a_kernel_name(self):
        L = Ledger()
        for name in ("token", "observation"):
            law = client_law(evidence={name: {"fields": {"under": "id", "resource": "resource"}}})
            self.assertEqual(L.refused("law", "h1", ["h1", "h2"], client=law), "TYPE.LAW")

    def test_autonomy_floor_every_target_has_a_route(self):
        L = Ledger()
        orphan = client_law(targets=[{"id": "uptime", "kind": "property", "coverage": "inventory",
                                      "resource": "svc:api:uptime", "property": "status", "expect": "ok",
                                      "min_level": "real", "fresh_ms": HOUR, "due_ms": HOUR, "owner": "h1",
                                      "sources": ["oracle"]}])
        self.assertEqual(L.refused("law", "h1", ["h1", "h2"], client=orphan), "TYPE.LAW")


class Evidence(unittest.TestCase):
    def setUp(self):
        self.L = Ledger()
        self.agent = self.L.grant("agent", ["effect:remediate"], ["repo:*"], conditions=["remediate-autonomous"])
        self.tester = self.L.grant("tester", ["observe", "certify:real"], ["repo:*"])
        self.repro = self.L.grant("reproducer", ["observe", "certify:real"], ["repo:*"])
        self.args = {"area": "deps", "item": "vulns", "base": "a" * 40, "head": "b" * 40}
        self.resource = "repo:deps:vulns/" + "a" * 40 + "/" + "b" * 40

    def test_tests_alone_never_make_a_repair_autonomous(self):
        L = self.L
        L.submit("observation", "tester", under=self.tester, resource=self.resource, property="tests",
                 status="green", level="real")
        self.assertEqual(L.refused("intent", "agent", under=self.agent, op="remediate", args=self.args),
                         "CAP.CONDITION")
        L.submit("observation", "reproducer", under=self.repro, resource=self.resource, property="reproduced",
                 status="yes", level="real")
        L.submit("intent", "agent", under=self.agent, op="remediate", args=self.args)

    def test_f0_8_the_actor_cannot_attest_its_own_permission(self):
        L = self.L
        self_attest = L.grant("agent", ["observe", "certify:real"], ["repo:*"])
        for prop, status in (("tests", "green"), ("reproduced", "yes")):
            L.submit("observation", "agent", under=self_attest, resource=self.resource, property=prop,
                     status=status, level="real")
        self.assertEqual(L.refused("intent", "agent", under=self.agent, op="remediate", args=self.args),
                         "CAP.CONDITION")

    def test_observations_are_bound_to_the_exact_transition(self):
        """V6-§3.1 / R05: a proof about another head proves nothing about this one."""
        L = self.L
        other = "repo:deps:vulns/" + "a" * 40 + "/" + "c" * 40
        for author, under, prop, status in (("tester", self.tester, "tests", "green"),
                                            ("reproducer", self.repro, "reproduced", "yes")):
            L.submit("observation", author, under=under, resource=other, property=prop, status=status, level="real")
        self.assertEqual(L.refused("intent", "agent", under=self.agent, op="remediate", args=self.args),
                         "CAP.CONDITION")

    def test_certification_needs_the_capability(self):
        L = self.L
        weak = L.grant("scanner", ["observe"], ["repo:*"])
        self.assertEqual(L.refused("observation", "scanner", under=weak, resource="repo:x", property="p",
                                   status="s", level="real"), "NIV.CERTIFY")


class EffectLine(unittest.TestCase):
    def setUp(self):
        L = self.L = Ledger()
        self.agent = L.grant("agent", ["effect:inventory-refresh"], ["repo:*"])
        self.rec = L.grant("oracle", ["reconcile", "evidence", "certify:real"], ["repo:*"])
        self.intent = L.submit("intent", "agent", under=self.agent, op="inventory-refresh", args={"scope": "all"})
        self.token = L.submit("token", "guard", intent=self.intent, args_digest=digest({"scope": "all"}))
        self.res = L.submit("reservation", "guard", token=self.token)

    def test_v6_1_no_reconciliation_while_the_reservation_can_still_leave(self):
        L = self.L
        self.assertEqual(L.refused("reconciliation", "oracle", under=self.rec, intent=self.intent,
                                   result="not_applied"), "OBL.LINE")
        L.kernel.judge_dispatch(L.state, self.token, "guard", L.state["last_at"])
        L.advance(DISPATCH_MS + 1)
        with self.assertRaises(Refused) as r:
            L.kernel.judge_dispatch(L.state, self.token, "guard", L.state["last_at"])
        self.assertEqual(r.exception.code, "OBL.LINE")
        L.submit("reconciliation", "oracle", under=self.rec, intent=self.intent, result="not_applied")

    def test_a_restriction_before_departure_blocks_it(self):
        L = self.L
        L.submit("revoke", "h3", grant=self.agent)
        with self.assertRaises(Refused) as r:
            L.kernel.judge_dispatch(L.state, self.token, "guard", L.state["last_at"])
        self.assertEqual(r.exception.code, "CAP.WITHDRAWN")

    def test_unknown_result_blocks_retry_until_reconciled(self):
        L = self.L
        L.submit("execution", "guard", token=self.token, result="unknown")
        self.assertEqual(L.refused("intent", "agent", under=self.agent, op="inventory-refresh",
                                   args={"scope": "all"}, retry_of=self.intent), "OBL.BLOCKED")
        L.submit("reconciliation", "oracle", under=self.rec, intent=self.intent, result="applied")
        self.assertIn(f"proof:{self.intent}", L.state["obligations"])

    def test_proof_closes_only_on_independent_evidence(self):
        L = self.L
        L.submit("execution", "guard", token=self.token, result="ok")
        own = L.grant("agent", ["evidence", "certify:real"], ["repo:*"])
        self.assertEqual(L.refused("evidence", "agent", under=own, resource="repo:inventory:all",
                                   subject=self.intent, level="real"), "PROV.NOT_INDEPENDENT")
        L.submit("evidence", "oracle", under=self.rec, resource="repo:inventory:all", subject=self.intent,
                 level="real")
        self.assertNotIn(f"proof:{self.intent}", L.state["obligations"])

    def test_a_token_is_single_use(self):
        L = self.L
        L.submit("execution", "guard", token=self.token, result="failed")
        self.assertEqual(L.refused("execution", "guard", token=self.token, result="ok"), "OBL.RESERVATION")


class Identity(unittest.TestCase):
    def test_v6_9_one_passkey_one_encoding(self):
        point = ec.generate_private_key(ec.SECP256R1()).public_key()
        full = base64.b64encode(point.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)).decode()
        short = base64.b64encode(point.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)).decode()
        self.assertTrue(canonical_public("webauthn-es256", full))
        self.assertFalse(canonical_public("webauthn-es256", short))

    def test_v6_env_unsigned_fields_change_nothing(self):
        L = Ledger()
        entry = L.entry("freeze", {"id": "f", "at": L.state["last_at"] + 1, "author": "h3", "scope": "x:*"}, ["h3"])
        entry["envelope"]["extra"] = "unsigned"
        with self.assertRaises(Refused) as r:
            L.kernel.decide(L.state, entry)
        self.assertEqual(r.exception.code, "PROV.ENVELOPE")

    def test_signatures_bind_this_ledger(self):
        a, b = Ledger(), Ledger(keys=None)
        entry = a.entry("freeze", {"id": "f", "at": a.state["last_at"] + 1, "author": "h3", "scope": "x:*"}, ["h3"])
        entry["seq"], entry["prev"] = b.state["size"], b.state["head"]
        with self.assertRaises(Refused) as r:
            b.kernel.decide(b.state, entry)
        self.assertIn(r.exception.code, ("PROV.DOMAIN", "PROV.SIGNATURE"))


class Determinism(unittest.TestCase):
    def test_replay_and_commit_rederive_the_same_state(self):
        L = Ledger()
        L.grant("agent", ["effect:inventory-refresh"], ["repo:*"])
        self.assertEqual(L.kernel.replay(L.entries), L.state)
        entry = L.entry("freeze", {"id": "fz", "at": L.state["last_at"] + 1, "author": "h3", "scope": "a:*"}, ["h3"])
        decision = L.kernel.judge(L.state, entry)
        self.assertEqual(decision.verdict, "ACCEPT")
        self.assertEqual(L.kernel.judge(copy.deepcopy(L.state), entry), decision)
        after = L.kernel.commit(L.state, decision)
        self.assertIn("a:*", after["frozen"])
        self.assertNotIn("a:*", L.state["frozen"])

    def test_hostile_input_is_refused_never_raised(self):
        L = Ledger()
        for junk in (None, 1.5, {"seq": 1}, {"seq": 1, "prev": None, "envelope": {"x": 1}}, [1, 2], "x" * 10):
            self.assertEqual(L.kernel.judge(L.state, junk).verdict, "REJECT")


class Debt(unittest.TestCase):
    def test_v6_6_renaming_a_target_keeps_its_debt(self):
        target = {"id": "uptime", "kind": "property", "coverage": "inventory", "resource": "repo:svc:uptime",
                  "property": "status", "expect": "ok", "min_level": "real", "fresh_ms": HOUR, "due_ms": 10 * HOUR,
                  "owner": "h1", "sources": ["oracle"], "human": True}
        L = Ledger(law=client_law(targets=[target]))
        first = {o["obligation"]: o for o in health(L)["open"]}["target:uptime"]
        L.advance(HOUR)
        renamed = client_law(targets=[{**target, "id": "uptime-v2"}])
        pid = L.submit("law", "h1", ["h1", "h2"], client=renamed)
        L.advance(HOUR + 1)
        L.submit("activate", "h1", ["h1", "h2"], proposal=pid)
        later = {o["obligation"]: o for o in health(L)["open"] + health(L)["escalated"]}["target:uptime-v2"]
        self.assertEqual((later["opened"], later["due"]), (first["opened"], first["due"]))

    def test_retiring_a_target_is_not_a_repair(self):
        target = {"id": "uptime", "kind": "property", "coverage": "inventory", "resource": "repo:svc:uptime",
                  "property": "status", "expect": "ok", "min_level": "real", "fresh_ms": HOUR, "due_ms": 10 * HOUR,
                  "owner": "h1", "sources": ["oracle"], "human": True}
        L = Ledger(law=client_law(targets=[target]))
        pid = L.submit("law", "h1", ["h1", "h2"], client=client_law())
        L.advance(HOUR + 1)
        L.submit("activate", "h1", ["h1", "h2"], proposal=pid)
        self.assertEqual([r["status"] for r in health(L)["retired"]], [RETIRED])

    def test_a_silent_witness_cannot_hold_the_verdict(self):
        L = Ledger()
        verdict = health(L, required_at=L.state["last_at"] + 30 * 86_400_000)
        self.assertEqual(verdict["state"], "ESCALATED")


if __name__ == "__main__":
    unittest.main()
