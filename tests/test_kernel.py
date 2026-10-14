"""The kernel against its contracts (ARCHITECTURE.md §4–§9): one human, one agent, the rules of the game."""
import base64
import copy
import unittest

from fixture import CODE, HOUR, Keys, Ledger, client_law

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from catalog.floors import RELEASE
from kernel import MECHANISMS, Accountability, Kernel, Refused, apply, digest, empty
from kernel.accountability import RETIRED, empty as accountability_empty
from kernel.floor0 import DISPATCH_MS, MAX_AHEAD_MS
from kernel.identity import canonical_public

A, B, C = "a" * 40, "b" * 40, "c" * 40
GRANT = {"holder": "agent", "actions": ["x"], "resources": ["*"], "conditions": [], "not_after": 10 ** 12}


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

    def test_f0_1_exactly_one_human_and_a_witness(self):
        for change in ("second human", "no human", "no witness"):
            keys = Keys()
            if change == "second human":
                keys.add("h2", "human")
            elif change == "no human":
                keys.root["identities"]["h1"]["kind"] = "agent"
            else:
                keys.root["identities"]["w1"]["kind"] = "service"
            with self.assertRaises(Refused) as r:
                Ledger(keys=keys)
            self.assertIn(r.exception.code, ("TYPE.ROOT", "PROV.AUTHOR", "CAP.HUMAN"), change)

    def test_genesis_binds_the_code_release(self):
        with self.assertRaises(Refused) as r:
            Ledger(kernel=Kernel(RELEASE, digest({"code": "other"})))
        self.assertEqual(r.exception.code, "HIST.CODE")

    def test_every_refusal_is_one_of_six_mechanisms(self):
        L = Ledger()
        codes = {L.refused("freeze", "agent", scope="repo:*"), L.refused("grant", "agent", **GRANT),
                 L.refused("checkpoint", "h1", size=L.state["size"], head=L.state["head"])}
        self.assertEqual(codes, {"CAP.RESTRICT", "CAP.HUMAN", "CAP.WITNESS"})
        self.assertTrue(all(c.split(".")[0] in MECHANISMS for c in codes))


class Widening(unittest.TestCase):
    def test_one_human_widens_at_once_and_the_agent_never(self):
        L = Ledger()
        self.assertEqual(L.refused("grant", "agent", **GRANT), "CAP.HUMAN")
        gid = L.submit("grant", "h1", **GRANT)
        self.assertIn(gid, L.state["grants"])

    def test_time_never_grants(self):
        """A far future timestamp is refused: only witnesses advance the anchor (F0-6)."""
        L = Ledger()
        self.assertEqual(L.refused("grant", "h1", at=L.state["anchor_at"] + MAX_AHEAD_MS + 1, **GRANT), "HIST.AHEAD")


class Restrictions(unittest.TestCase):
    def test_v6_5_a_restriction_may_share_the_last_instant(self):
        L = Ledger()
        ceiling = L.state["anchor_at"] + MAX_AHEAD_MS
        L.submit("freeze", "h1", at=ceiling, scope="repo:a:*")
        self.assertEqual(L.refused("freeze", "agent", at=ceiling, scope="repo:b:*"), "CAP.RESTRICT")
        self.assertEqual(L.refused("grant", "h1", at=ceiling, **GRANT), "HIST.TIME")

    def test_v6_2_a_law_cannot_block_a_restriction(self):
        L = Ledger()
        bad = client_law(obligations=[{"id": "block", "level": "refuse", "due_ms": HOUR, "on_due": "lapse",
                                       "open": [{"kind": "intent", "key": "id"}],
                                       "gate": [{"kind": "freeze", "key": "scope"}]}])
        self.assertEqual(L.refused("law", "h1", client=bad), "TYPE.LAW")

    def test_the_human_says_no_by_a_freeze_and_lifts_it_by_a_widening(self):
        L = Ledger()
        g = L.grant("agent", ["effect:inventory-refresh"], ["repo:*"])
        L.submit("freeze", "h1", scope="repo:inventory:*")
        self.assertEqual(L.refused("intent", "agent", under=g, op="inventory-refresh", args={"scope": "all"}),
                         "CAP.FROZEN")
        self.assertEqual(L.refused("unfreeze", "agent", scope="repo:inventory:*"), "CAP.HUMAN")
        L.submit("unfreeze", "h1", scope="repo:inventory:*")
        L.submit("intent", "agent", under=g, op="inventory-refresh", args={"scope": "all"})


class Rules(unittest.TestCase):
    def test_the_rules_never_go_below_the_socle(self):
        L = Ledger()
        human_less = {"args": {"x": "segment"}, "resource": "a:{x}",
                      "routes": {"auto": {"all": [{"prefix": ["resource", "a:"]}]}}}
        for weaker in (client_law(ttl={"proof": 2 * 86_400_000}), client_law(witnesses={"quorum": 2}),
                       client_law(tighten={"targets": {"vulns": {"due_ms": 10 ** 10}}}),
                       client_law(ops={"remediate": {"args": {"x": "segment"}, "resource": "a:{x}",
                                                     "routes": {"human": {"all": [{"prefix": ["x", "a"]}]}}}}),
                       client_law(ops={"mine": human_less}),
                       client_law(settings={"burn_fast": "10"}), client_law(settings={"rollback_horizon_min": 300}),
                       client_law(routes={"deploy": ["human"]}), client_law(routes={"deploy": ["nowhere"]})):
            self.assertEqual(L.refused("law", "h1", client=weaker), "TYPE.LAW")
        L.submit("law", "h1", client=client_law(ttl={"proof": 3_600_000},
                                                 settings={"burn_fast": "20"}, routes={"deploy": []}))
        law = L.kernel.law_of(L.state)
        self.assertEqual(sorted(law.ops["deploy"]["routes"]), ["human"])

    def test_a_client_op_carries_a_human_route(self):
        L = Ledger()
        mine = {"args": {"x": "segment"}, "resource": "app:jobs:{x}",
                "routes": {"auto": {"all": [{"observed": ["ready", "yes", "real"]}]},
                           "human": {"all": [{"observed": ["decision", "approve", "real", "human"]}]}}}
        L.submit("law", "h1", client=client_law(ops={"run-job": mine}))
        self.assertIn("run-job", L.kernel.law_of(L.state).ops)

    def test_v6_7_client_proof_never_below_the_floor(self):
        L = Ledger()
        weak = client_law(evidence={"weak": {"fields": {"under": "id", "resource": "resource", "subject": "id",
                                                        "level": "str"}}},
                          discharges={"weak": [{"obligation": "proof", "key": "subject", "min_level": "unknown"}]})
        self.assertEqual(L.refused("law", "h1", client=weak), "TYPE.LAW")

    def test_v6_3_conditions_accept_only_strings_and_integers(self):
        L = Ledger()
        bad = client_law(obligations=[{"id": "forced", "level": "refuse", "due_ms": HOUR, "on_due": "lapse",
                                       "open": [{"kind": "intent", "key": "id", "where": {"args.force": True}}]}])
        self.assertEqual(L.refused("law", "h1", client=bad), "TYPE.LAW")

    def test_v6_8_an_evidence_kind_cannot_take_a_kernel_name(self):
        L = Ledger()
        for name in ("token", "observation"):
            law = client_law(evidence={name: {"fields": {"under": "id", "resource": "resource"}}})
            self.assertEqual(L.refused("law", "h1", client=law), "TYPE.LAW")

    def test_autonomy_floor_every_target_has_a_route(self):
        L = Ledger()
        orphan = client_law(targets=[{"id": "uptime", "kind": "property", "coverage": "inventory",
                                      "resource": "svc:api:uptime", "property": "status", "expect": "ok",
                                      "min_level": "real", "fresh_ms": HOUR, "due_ms": HOUR, "owner": "h1",
                                      "sources": ["oracle"]}])
        self.assertEqual(L.refused("law", "h1", client=orphan), "TYPE.LAW")


class Routes(unittest.TestCase):
    """F0-12: an effect proceeds only while one route of its op holds; the human route needs a human's decision."""

    def setUp(self):
        L = self.L = Ledger()
        self.agent = L.grant("agent", ["effect:remediate", "effect:integrate"], ["repo:*"])
        self.scanner = L.grant("scanner", ["observe", "certify:real"], ["repo:*"])
        self.human = L.grant("h1", ["observe", "certify:real"], ["repo:*"])
        self.args = {"area": "code", "item": "sast", "base": A, "head": B}
        self.resource = f"repo:code:sast/{A}/{B}"

    def remediate(self):
        return dict(under=self.agent, op="remediate", args=self.args)

    def test_tests_alone_never_make_a_repair_autonomous(self):
        L = self.L
        L.measure("scanner", self.scanner, self.resource, "tests", "green")
        self.assertEqual(L.refused("intent", "agent", **self.remediate()), "CAP.ROUTE")
        L.measure("scanner", self.scanner, self.resource, "reproduced", "yes")
        L.submit("intent", "agent", **self.remediate())

    def test_a_scoped_repair_lands_alone_unless_the_rules_turn_it_off(self):
        L = self.L
        for prop, status in (("tests", "green"), ("regressions", "none"), ("scoped", "yes"), ("blocks", "clean")):
            L.measure("scanner", self.scanner, self.resource, prop, status)
        L.submit("law", "h1", client=client_law(routes={"remediate": ["reproduced"]}))
        self.assertEqual(L.refused("intent", "agent", **self.remediate()), "CAP.ROUTE")
        L.submit("law", "h1", client=client_law())
        L.submit("intent", "agent", **self.remediate())

    def test_only_a_human_decides(self):
        L = self.L
        for prop, status in (("tests", "green"), ("regressions", "none")):
            L.measure("scanner", self.scanner, self.resource, prop, status)
        machine = L.grant("oracle", ["observe", "certify:real"], ["repo:*"])
        L.submit("observation", "oracle", under=machine, resource=self.resource, property="decision",
                 status="approve", level="real")
        self.assertEqual(L.refused("intent", "agent", **self.remediate()), "CAP.ROUTE")   # a machine's yes is none
        L.decide(self.human, self.resource)
        L.submit("intent", "agent", **self.remediate())

    def test_code_from_outside_needs_the_human(self):
        L = self.L
        args, res = {"contributor": "bob", "base": A, "head": B}, f"repo:contrib:bob/{A}/{B}"
        for prop, status in (("tests", "green"), ("regressions", "none"), ("scoped", "yes"), ("blocks", "clean"), ("reproduced", "yes")):
            if prop in ("tests", "regressions"):
                L.measure("scanner", self.scanner, res, prop, status)
        self.assertEqual(L.refused("intent", "agent", under=self.agent, op="integrate", args=args), "CAP.ROUTE")
        L.decide(self.human, res)
        L.submit("intent", "agent", under=self.agent, op="integrate", args=args)

    def test_f0_8_the_actor_cannot_attest_its_own_permission(self):
        L = self.L
        own = L.grant("agent", ["observe", "certify:real"], ["repo:*"])
        self.assertEqual(L.refused("observation", "agent", under=own, resource=self.resource, property="tests",
                                   status="green", level="real"), "PROV.INSTRUMENT")
        at = L.state["last_at"] + 1                                       # nor measure as if it were the scanner
        self.assertEqual(L.refused("measurement", "agent", at=at, under=own, resource=self.resource,
                                   property="tests", status="green", level="real", method="main-suite",
                                   coverage="repo:inventory:all", measured_at=at, artifact="sha256:" + "0" * 64),
                         "PROV.COVERAGE")
        L.submit("observation", "agent", under=own, resource=self.resource, property="decision", status="approve",
                 level="real")
        self.assertEqual(L.refused("intent", "agent", **self.remediate()), "CAP.ROUTE")

    def test_observations_are_bound_to_the_exact_transition(self):
        """V6-§3.1 / R05: a proof about another head proves nothing about this one."""
        L = self.L
        other = f"repo:code:sast/{A}/{C}"
        for prop, status in (("tests", "green"), ("reproduced", "yes")):
            L.measure("scanner", self.scanner, other, prop, status)
        L.decide(self.human, other)
        self.assertEqual(L.refused("intent", "agent", **self.remediate()), "CAP.ROUTE")

    def test_the_human_says_no_after_saying_yes(self):
        L = self.L
        for prop, status in (("tests", "green"), ("regressions", "none")):
            L.measure("scanner", self.scanner, self.resource, prop, status)
        L.decide(self.human, self.resource)
        L.submit("freeze", "h1", scope=self.resource)
        self.assertEqual(L.refused("intent", "agent", **self.remediate()), "CAP.FROZEN")

    def test_certification_needs_the_capability(self):
        L = self.L
        weak = L.grant("scanner", ["observe"], ["repo:*"])
        self.assertEqual(L.refused("observation", "scanner", under=weak, resource="repo:x", property="p",
                                   status="s", level="real"), "NIV.CERTIFY")

    def test_a_route_is_judged_again_at_departure(self):
        """The window fact lives two minutes: a deploy whose window closed in between never leaves."""
        L = self.L
        agent = L.grant("agent", ["effect:deploy"], ["run:*"])
        scanner = L.grant("scanner", ["observe", "certify:real"], ["run:*"])
        res = f"run:release:all/{A}/{B}"
        for prop, status in (("candidate", "yes"), ("window", "open"), ("budget_pct", "80")):
            L.measure("scanner", scanner, res, prop, status)
        intent = L.submit("intent", "agent", under=agent, op="deploy", args={"from": A, "to": B})
        L.advance(3 * 60_000)
        self.assertEqual(L.refused("token", "guard", intent=intent, args_digest=digest({"from": A, "to": B})),
                         "CAP.ROUTE")


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
        L.submit("revoke", "h1", grant=self.agent)
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
        entry = L.entry("freeze", {"id": "f", "at": L.state["last_at"] + 1, "author": "h1", "scope": "x:*"}, ["h1"])
        entry["envelope"]["extra"] = "unsigned"
        with self.assertRaises(Refused) as r:
            L.kernel.decide(L.state, entry)
        self.assertEqual(r.exception.code, "PROV.ENVELOPE")

    def test_signatures_bind_this_ledger(self):
        a, b = Ledger(), Ledger(keys=None)
        entry = a.entry("freeze", {"id": "f", "at": a.state["last_at"] + 1, "author": "h1", "scope": "x:*"}, ["h1"])
        entry["seq"], entry["prev"] = b.state["size"], b.state["head"]
        with self.assertRaises(Refused) as r:
            b.kernel.decide(b.state, entry)
        self.assertIn(r.exception.code, ("PROV.DOMAIN", "PROV.SIGNATURE"))


class Determinism(unittest.TestCase):
    def test_replay_and_commit_rederive_the_same_state(self):
        L = Ledger()
        L.grant("agent", ["effect:inventory-refresh"], ["repo:*"])
        self.assertEqual(L.kernel.replay(L.entries), L.state)
        entry = L.entry("freeze", {"id": "fz", "at": L.state["last_at"] + 1, "author": "h1", "scope": "a:*"}, ["h1"])
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
    TARGET = {"id": "uptime", "kind": "property", "coverage": "inventory", "resource": "repo:svc:uptime",
              "property": "status", "expect": "ok", "min_level": "real", "fresh_ms": HOUR, "due_ms": 10 * HOUR,
              "owner": "h1", "sources": ["oracle"], "human": True}

    def test_v6_6_renaming_a_target_keeps_its_debt(self):
        L = Ledger(law=client_law(targets=[self.TARGET]))
        first = {o["obligation"]: o for o in health(L)["open"]}["target:uptime"]
        L.advance(HOUR)
        L.submit("law", "h1", client=client_law(targets=[{**self.TARGET, "id": "uptime-v2"}]))
        later = {o["obligation"]: o for o in health(L)["open"] + health(L)["escalated"]}["target:uptime-v2"]
        self.assertEqual((later["opened"], later["due"]), (first["opened"], first["due"]))

    def test_retiring_a_target_is_not_a_repair(self):
        L = Ledger(law=client_law(targets=[self.TARGET]))
        L.submit("law", "h1", client=client_law())
        self.assertEqual([r["status"] for r in health(L)["retired"]], [RETIRED])

    def test_a_silent_witness_cannot_hold_the_verdict(self):
        L = Ledger()
        verdict = health(L, required_at=L.state["last_at"] + 30 * 86_400_000)
        self.assertEqual(verdict["state"], "ESCALATED")


class Bounds(unittest.TestCase):
    """D35/D36: the routes compare the scanner's numbers with the settings in force, exactly, in both judges."""

    def test_the_language_compares_decimals_exactly(self):
        from kernel.language import LanguageError, compile_program, evaluate
        atoms = compile_program({"all": [{"compare": ["delta", "le", "0.5", "real"]}]})
        holds = lambda status: evaluate(atoms, request={"resource": "r"}, observations={("r", "delta", status, "real")})
        self.assertTrue(holds("0.5"))
        self.assertTrue(holds("-3"))
        self.assertFalse(holds("0.500001"))
        self.assertFalse(holds("lots"))                                    # a word never compares
        self.assertFalse(holds("1e-9"))                                    # nor an exponent
        for bad in (["delta", "lt", 1, "real"], ["delta", "le", "1.5x", "real"], ["delta", "le", 1]):
            with self.assertRaises(LanguageError):
                compile_program({"all": [{"compare": bad}]})

    def setUp(self):
        L = self.L = Ledger()
        self.agent = L.grant("agent", ["effect:deploy", "effect:rollback"], ["run:*"])
        self.scanner = L.grant("scanner", ["observe", "certify:real"], ["run:*"])

    def test_a_canary_promotion_is_bounded_by_the_settings(self):
        L = self.L
        resource = f"run:release:all/{A}/{B}"
        for prop, status in (("candidate", "yes"), ("canary_error_delta", "0.8"), ("canary_requests", "500"),
                             ("canary_baked_min", "10")):
            L.measure("scanner", self.scanner, resource, prop, status)
        self.assertEqual(L.refused("intent", "agent", under=self.agent, op="deploy", args={"from": A, "to": B}),
                         "CAP.ROUTE")                                      # 0.8 points worse: over the rules' 0.5
        L.submit("law", "h1", client=client_law(settings={"canary_max_error_delta": "1"}))
        L.submit("intent", "agent", under=self.agent, op="deploy", args={"from": A, "to": B})

    def test_the_agent_steps_back_alone_only_on_the_evidence_the_rules_ask_for(self):
        L = self.L
        resource = f"run:service:all/{B}/{A}"
        for prop, status in (("previous", "yes"), ("proven", "yes"), ("switched_min", "3"), ("burn_fast", "9.500"),
                             ("migrations_crossed", "0")):
            L.measure("scanner", self.scanner, resource, prop, status)
        rollback = dict(under=self.agent, op="rollback", args={"from": B, "to": A})
        self.assertEqual(L.refused("intent", "agent", **rollback), "CAP.ROUTE")   # burning, not enough to act alone
        L.measure("scanner", self.scanner, resource, "burn_fast", "20.000")
        L.measure("scanner", self.scanner, resource, "switched_min", "45")
        self.assertEqual(L.refused("intent", "agent", **rollback), "CAP.ROUTE")   # past the rules' 30 min horizon
        L.measure("scanner", self.scanner, resource, "switched_min", "3")
        L.submit("law", "h1", client=client_law(routes={"rollback": []}))
        self.assertEqual(L.refused("intent", "agent", **rollback), "CAP.ROUTE")   # automatic rollback turned off
        L.submit("law", "h1", client=client_law())
        L.submit("intent", "agent", **rollback)


if __name__ == "__main__":
    unittest.main()
