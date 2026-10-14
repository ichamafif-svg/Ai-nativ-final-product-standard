"""Production (D30, D36): the scanner measures the service and signs what is and numbers, the law bounds when the agent
may act alone, the engineers' settings restrain it further; the agent deploys main and rolls back a release that broke
the service, and a release rolled back is never deployed again: that gap goes to people."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import ceremony  # noqa: E402
from test_install import Clock  # noqa: E402
from test_maintenance import FILES, demo_repository  # noqa: E402

import agent.__main__ as agent_process  # noqa: E402
import runtime.operator as daemon  # noqa: E402
import instruments.production as runtime  # noqa: E402
from bt.register import Registers  # noqa: E402
from fixture import client_law  # noqa: E402
from kernel import Kernel  # noqa: E402
from catalog.floors import RELEASE  # noqa: E402
from agent.loop import tactic  # noqa: E402
from context.moves import moves  # noqa: E402
from context.policy import Rules as RulesView, RulesError, change  # noqa: E402
from instruments.production import component_id, evaluate  # noqa: E402
from bt.gateway import AdmissionGateway  # noqa: E402

A, B, C = "a" * 40, "b" * 40, "c" * 40


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


class Metrics:
    """A product's cumulative histogram, advanced by each scrape: `errors` of every 100 requests fail. It says which
    release answers (`version`, by default whatever the link points to) and when its process started."""

    def __init__(self, link=None):
        self.count = self.failed = 0
        self.errors, self.link, self.version, self.started = 0, link, None, 1

    def __call__(self, url):
        self.count, self.failed = self.count + 100, self.failed + self.errors
        ok = self.count - self.failed
        version = self.version
        if version is None and self.link is not None and os.path.exists(self.link):
            version = Path(self.link).read_text().strip() or None
        return "\n".join([
            f'http_server_request_duration_seconds_bucket{{http_route="/orders",http_response_status_code="200",le="0.1"}} {ok}',
            f'http_server_request_duration_seconds_bucket{{http_route="/orders",http_response_status_code="200",le="+Inf"}} {ok}',
            f'http_server_request_duration_seconds_count{{http_route="/orders",http_response_status_code="200"}} {ok}',
            f'http_server_request_duration_seconds_bucket{{http_route="/orders",http_response_status_code="500",le="0.1"}} {self.failed}',
            f'http_server_request_duration_seconds_bucket{{http_route="/orders",http_response_status_code="500",le="+Inf"}} {self.failed}',
            f'http_server_request_duration_seconds_count{{http_route="/orders",http_response_status_code="500"}} {self.failed}',
            f"process_start_time_seconds {self.started}",
            *([f'build_info{{version="{version}"}} 1'] if version else []),
        ])


N = {"burn_fast": 0, "failing_pct": 0, "budget_pct": 80.0}


def facts_of(*args, **kw):
    return {(r, p): s for r, p, s in runtime.release_facts(*args, **kw)}


class Facts(unittest.TestCase):
    """D36: the scanner signs what is, on exact switches, and numbers; it judges nothing the engineers tune."""

    def test_main_is_a_candidate_unless_it_was_stepped_back_from(self):
        f = facts_of(A, B, [], set(), 0, N)
        self.assertEqual(f[("run:release:all", "lag")], "behind")
        self.assertEqual(f[(f"run:release:all/{A}/{B}", "candidate")], "yes")
        self.assertEqual(f[(f"run:release:all/{A}/{B}", "budget_pct")], "80.000")
        self.assertEqual(f[(f"run:release:all/{A}/{B}", "window")], "open")
        self.assertEqual(f[(f"run:canary:all/{A}/{B}", "candidate")], "yes")       # or on a share of traffic first
        f = facts_of(A, B, [{"at": 0, "op": "rollback", "from": B, "to": A}], set(), 0, N)
        self.assertNotIn((f"run:release:all/{A}/{B}", "candidate"), f)
        self.assertEqual(facts_of(B, B, [], set(), 0, N)[("run:release:all", "lag")], "none")
        self.assertEqual(facts_of(B, B, [], set(), 0, N, served=A)[("run:release:all", "lag")], "behind")

    def test_a_previous_release_with_its_numbers_and_whether_it_was_proven(self):
        history = [{"at": 1_000, "op": "deploy", "from": A, "to": B}]
        r = f"run:service:all/{B}/{A}"
        f = facts_of(B, B, history, {A}, 1_000 + 120_000, {**N, "burn_fast": 20.0, "failing_pct": 40.0})
        self.assertEqual({k: f[(r, k)] for k in ("previous", "proven", "switched_min", "burn_fast", "failing_pct")},
                         {"previous": "yes", "proven": "yes", "switched_min": "2", "burn_fast": "20.000",
                          "failing_pct": "40.000"})
        self.assertNotIn((r, "proven"), facts_of(B, B, history, set(), 61_000, N))   # A never met the objective
        self.assertNotIn((r, "previous"), facts_of(B, B, history, {A}, 61_000, N, crossed=lambda live, prev: None))
        f = facts_of(B, B, history, set(), 1_000 + 120_000, N, served=A)            # B never answered: A still does
        self.assertEqual((f[(r, "unanswered_s")], f[(r, "proven")]), ("120", "yes"))

    def test_the_live_release_and_its_restarts_in_the_last_hour(self):
        history = [{"at": 0, "op": "deploy", "from": A, "to": B}]
        late = 10 * 3_600_000
        self.assertEqual(facts_of(B, B, history, {A}, late, N)[(f"run:process:all/{B}/1", "live")], "yes")
        history.append({"at": late - 60_000, "op": "restart", "from": B, "to": B, "n": "1"})
        f = facts_of(B, B, history, {A}, late, N)
        self.assertEqual(f[(f"run:process:all/{B}/2", "restarts_last_hour")], "1")
        self.assertEqual(f[(f"run:process:all/{B}/2", "switched_min")], "600")      # restarts are not switches

    def test_an_unreachable_source_is_uncovered_never_met(self):
        m = runtime.measures({})
        assess = lambda points, now, answers=(): runtime.assess({"metrics-0": points}, list(answers), m, now, 0)
        self.assertEqual(assess([(1, None), (2, None)], 2)["slo"], "uncovered:1")
        self.assertEqual(runtime.assess({}, [], m, 2, 0)["coverage"], "uncovered:1")      # nothing declared
        metrics = Metrics()
        points = [(at, metrics("x")) for at in (1, 31)]
        self.assertEqual(assess(points, 31)["slo"], "met")
        metrics.errors = 50
        points += [(at, metrics("x")) for at in (61, 91)]
        assessed = assess(points, 91)
        self.assertEqual(assessed["slo"], "breached:2")                              # /orders failing, its SLO burning
        self.assertAlmostEqual(assessed["failing_pct"], 100 / 3)                     # 100 failed of 300 in the window

    def test_probes_see_what_the_product_does_not_report(self):
        m = runtime.measures({"base_url": "http://shop",
                              "probes": {"p-a": {"spec": "GET /health 200"}, "p-b": {"spec": "rm -rf /"}}})
        self.assertEqual([tuple(x) for x in m["probes"]], [("p-a", "GET", "/health", 200)])
        metrics = Metrics()
        points = [(at, metrics("x")) for at in (1, 31, 61, 91)]
        answer = lambda status: [["p-a", "GET", "/health", 200, status, 0.01]]
        answers = [(1, answer(200)), (31, answer(200))]
        self.assertEqual(runtime.assess({"m": points[:2]}, answers, m, 31, 0)["slo"], "met")
        answers += [(61, answer(503)), (91, answer(503))]
        assessed = runtime.assess({"m": points}, answers, m, 91, 0)
        self.assertEqual(assessed["slo"], "breached:1")                              # metrics fine, probe failing
        self.assertEqual([c["kind"] for c in assessed["components"] if c["error_rate"]], ["probe"])


class Moves(unittest.TestCase):
    """D36: production moves under the rules in force: the routes decide, the agent's tactics can only hold back."""

    def view(self, facts, now=10_000_000, **rules):
        law = Kernel(RELEASE, "x").load(client_law(**rules)).raw
        return {"law": {"effective": law}, "identities": {"scanner": "service", "h1": "human"}, "now": now,
                "facts": [{"resource": r, "property": p, "status": s, "author": "scanner", "at": now}
                          for r, f in facts.items() for p, s in f.items()],
                "transitions": facts, "played": {}, "frozen": []}

    def move(self, view, resource):
        return next(m for m in moves(view) if m["resource"] == resource)

    def back(self, **facts):
        return {f"run:service:all/{B}/{A}": {"previous": "yes", "proven": "yes", "switched_min": "2", "burn_fast": "0",
                                            "failing_pct": "0", "unanswered_s": "0", "migrations_crossed": "0", **facts}}

    def test_a_rollback_right_after_a_switch_that_broke_the_service(self):
        r = f"run:service:all/{B}/{A}"
        status = lambda facts, **rules: self.move(self.view(self.back(**facts), **rules), r)
        self.assertEqual(status({})["status"], "yours")
        self.assertFalse(status({})["wanted"])                                   # nothing broke: nobody is asked
        self.assertEqual((status({"burn_fast": "20.000"})["status"], status({"burn_fast": "20.000"})["route"]),
                         ("ready", "burn"))
        self.assertEqual(status({"failing_pct": "40"})["route"], "failing")
        self.assertEqual(status({"unanswered_s": "120", "switched_min": "300"})["route"], "unanswered")
        late = status({"failing_pct": "40", "switched_min": "45"})                # past the rules' 30 min horizon
        self.assertEqual((late["status"], late["wanted"]), ("yours", False))
        off = status({"failing_pct": "40"}, routes={"rollback": []})              # the rules keep it for the human
        self.assertEqual((off["status"], off["wanted"], off["turned_off"]), ("yours", True, ["failing"]))
        migrating = status({"failing_pct": "40", "migrations_crossed": "1"}, settings={"rollback_migrations": 0})
        self.assertNotEqual(migrating["status"], "ready")
        self.assertNotEqual(status({"failing_pct": "40", "proven": "no"})["status"], "ready")
        self.assertNotEqual(status({"failing_pct": "6"}, settings={"failing": 10})["status"], "ready")

    def test_a_restart_is_yours_until_the_rules_give_it_and_never_right_after_a_switch(self):
        r = f"run:process:all/{B}/2"
        facts = lambda **f: {r: {"live": "yes", "switched_min": "600", "failing_pct": "40", "burn_fast": "0",
                                 "restarts_last_hour": "0", **f}}
        mine = self.move(self.view(facts()), r)
        self.assertEqual((mine["status"], mine["wanted"]), ("yours", True))      # recommended rules: yours
        on = {"routes": {"restart": ["failing", "burn"]}, "settings": {"restarts_per_hour": 0}}
        self.assertEqual(self.move(self.view(facts(), **on), r)["status"], "ready")
        self.assertNotEqual(self.move(self.view(facts(restarts_last_hour="1"), **on), r)["status"], "ready")
        view = self.view(facts(switched_min="3"), **on)
        self.assertIn("follows a switch", tactic(view, self.move(view, r)))

    def test_deploy_in_the_window_with_budget_left_or_start_a_canary(self):
        r, c = f"run:release:all/{A}/{B}", f"run:canary:all/{A}/{B}"
        facts = lambda **f: {r: {"candidate": "yes", "budget_pct": "10.000", "window": "open", **f},
                             c: {"candidate": "yes", "budget_pct": "10.000", "window": "open", **f}}
        self.assertEqual(self.move(self.view(facts()), r)["route"], "direct")
        self.assertEqual(self.move(self.view(facts(window="closed")), r)["status"], "yours")
        self.assertEqual(self.move(self.view(facts(), settings={"freeze_below": 25}), r)["status"], "yours")
        self.assertEqual(self.move(self.view(facts(), routes={"deploy": []}), r)["status"], "yours")
        view = self.view(facts())
        self.assertEqual(tactic(view, self.move(view, c)), "the rules deploy directly")
        view = self.view(facts(), routes={"deploy": ["promote"]})                 # strategy canary, in the rules
        self.assertIsNone(tactic(view, self.move(view, c)))
        self.assertEqual(self.move(view, c)["status"], "ready")

    def test_a_canary_bakes_and_is_promoted_a_worse_one_is_taken_out(self):
        r, abort = f"run:release:all/{A}/{B}", f"run:canary:abort/{A}/{B}"
        canary = {"routes": {"deploy": ["promote"]}}
        facts = lambda **f: {r: {"candidate": "yes", "canary_error_delta": "0.100", "canary_requests": "500",
                                 "canary_baked_min": "11", "canary_p99_ms": "100", "live_p99_ms": "100", **f},
                             abort: {"running": "yes"}}
        self.assertEqual(self.move(self.view(facts(), **canary), r)["route"], "promote")
        self.assertNotEqual(self.move(self.view(facts(canary_baked_min="3"), **canary), r)["status"], "ready")
        hold = lambda **f: tactic((v := self.view(facts(**f), **canary)), self.move(v, abort))
        self.assertEqual(hold(), "the canary holds")
        self.assertIsNone(hold(canary_error_delta="5.000", canary_baked_min="2", canary_error_pct="5.1",
                               live_error_pct="0.1", live_requests="5000"))
        self.assertEqual(hold(canary_error_delta="1.527", canary_error_pct="3.5", live_error_pct="2.0",
                              canary_requests="301", live_requests="2700", canary_baked_min="2"),
                         "the canary holds")                                     # what a live demo saw by chance
        self.assertIsNone(hold(candidate="no"))                                  # main moved on: taken out


class Rules(unittest.TestCase):
    """The rules of the game: one document in the journal, each value checked, the socle's bounds kept."""

    def test_only_valid_settings_are_drafted(self):
        client = client_law()
        for bad in ({"objective": "120"}, {"deploy_tz": "Mars/Olympus"}, {"deploy_hours": "18-09"}):
            with self.assertRaises(RulesError):
                change(client, settings=bad)
        with self.assertRaises(RulesError):
            change(client, sections={"probes": {"p-x": {"spec": "rm -rf /"}}})
        with self.assertRaises(RulesError):
            change(client, routes={"deploy": ["human"]})                         # the human route is not a choice
        drafted = change(client, settings={"objective": "99.95"}, sections={"silences": {"m-x": {
            "target_of": "all", "until": "99999999999999", "reason": "maintenance"}}})
        law = Kernel(RELEASE, "x").load(drafted).raw
        self.assertEqual(RulesView(law).silences(2_000)["m-x"]["target_of"], "all")
        with self.assertRaises(Exception):                                        # looser than the socle: refused
            Kernel(RELEASE, "x").load(change(client, settings={"canary_max_error_delta": "5"}))

    def test_a_component_override_and_its_counting(self):
        cid = component_id("api", "POST", "/orders")
        law = Kernel(RELEASE, "x").load(client_law(settings={"components": {cid: {"p99_ms": 200, "counted": "off"}}})).raw
        rules = RulesView(law)
        self.assertEqual(rules.limits("api", "POST", "/orders")["p99_ms"], 200)
        self.assertFalse(rules.limits("api", "POST", "/orders")["counted"])
        self.assertEqual(rules.limits("api", "GET", "/health")["p99_ms"], 1000.0)
        self.assertFalse(rules.limits("dependency", "POST", "pay")["counted"])      # outside: shown, not counted
        self.assertFalse(runtime.measures(law["settings"])["counted"][cid])          # the scanner reads the same

    def test_the_window_is_measured_from_the_rules(self):
        m = runtime.measures({"deploy_days": "mon,tue,wed,thu,fri", "deploy_hours": "09-18", "deploy_tz": "Europe/Paris"})
        saturday = 1_791_619_200_000                                                  # 2026-10-10 10:00 Paris
        self.assertEqual(runtime.window(m, saturday), "closed")
        self.assertEqual(runtime.window(m, saturday + 2 * 86_400_000), "open")       # Monday
        self.assertEqual(runtime.window({**m, "deploy_tz": "Nowhere/Else"}, saturday), "closed")


class Migrations(unittest.TestCase):
    def test_stepping_back_across_a_schema_change_needs_a_compatible_migration(self):
        base = {"app.py": [], "migrations/0001_orders.sql": []}
        expand = {**base, "migrations/0002_note.compatible.sql": []}
        drop = {**expand, "migrations/0003_drop.sql": []}
        self.assertEqual(runtime.crossed(expand, base), 1)
        self.assertEqual(runtime.crossed(base, base), 0)
        self.assertIsNone(runtime.crossed(drop, expand))


class Objectives(unittest.TestCase):
    """SLOs with error budgets and multi-window burn rates (D32), as numbers (D36)."""

    def store(self, minutes, bad_share, per_minute=100, start=0, latency_le="0.1"):
        return [(m, "c-000000000001", "api", per_minute, per_minute * bad_share,
                 {"0.05": per_minute * 0.5, "0.1": per_minute * 0.9, "+Inf": per_minute})
                for m in range(start, start + minutes)]

    def slo(self, **kw):
        return {"s-1": {"name": "x", "sli": "availability", "target": 99.9, "window_d": 1, "selector": "counted",
                        "threshold_ms": None, **kw}}

    def test_a_fast_burn_needs_both_windows(self):
        counted = lambda cid, kind: True
        hot = evaluate(self.store(60, 0.02), self.slo(), 59, counted=counted)["s-1"]
        self.assertEqual((hot["burn"]["5m"], hot["fast_burn"]), (20.0, 20.0))         # 2 % bad for 0.1 % allowed
        self.assertLess(hot["budget"], 0)
        store = self.store(55, 0.0)
        store += [(m, "c-000000000001", "api", 100, 2, {"+Inf": 100}) for m in range(55, 60)]
        blip = evaluate(store, self.slo(), 59, counted=counted)["s-1"]
        self.assertGreater(blip["burn"]["5m"], 14.4)                                  # five bad minutes
        self.assertLess(blip["fast_burn"], 14.4)                                      # but not over the hour
        quiet = evaluate(self.store(60, 0.0005), self.slo(), 59, counted=counted)["s-1"]
        self.assertLess(max(quiet["fast_burn"], quiet["slow_burn"]), 1)
        self.assertAlmostEqual(quiet["budget"], 0.5)

    def test_a_latency_sli_counts_requests_under_the_threshold(self):
        got = evaluate(self.store(10, 0.0), self.slo(sli="latency", threshold_ms=100, target=95.0), 9,
                       counted=lambda c, k: True)["s-1"]
        self.assertAlmostEqual(got["compliance"], 0.9)                                # 90 % under 100 ms
        got = evaluate(self.store(10, 0.0), self.slo(sli="latency", threshold_ms=80, target=95.0), 9,
                       counted=lambda c, k: True)["s-1"]
        self.assertAlmostEqual(got["compliance"], 0.5)                                # never rounded up to 100 ms


class Canary(unittest.TestCase):
    def test_the_scanner_signs_the_canary_numbers_beside_the_live_release(self):
        history = [{"at": 0, "op": "deploy", "from": "none", "to": A}, {"at": 60_000, "op": "canary", "from": A, "to": B}]
        stats = {B: {"requests": 500, "error_rate": 0.05, "p99": 120.0}, A: {"requests": 5000, "error_rate": 0.0, "p99": 100.0}}
        f = facts_of(A, B, history, {A}, 60_000 + 11 * 60_000, N, canary=B, canary_stats=lambda rel, since: stats[rel])
        r = f"run:release:all/{A}/{B}"
        self.assertEqual({k: f[(r, k)] for k in ("canary_error_delta", "canary_requests", "canary_baked_min",
                                                 "canary_p99_ms", "live_p99_ms")},
                         {"canary_error_delta": "5.000", "canary_requests": "500", "canary_baked_min": "11",
                          "canary_p99_ms": "120.000", "live_p99_ms": "100.000"})
        self.assertEqual(f[(f"run:canary:abort/{A}/{B}", "running")], "yes")
        self.assertNotIn((f"run:canary:all/{A}/{B}", "candidate"), f)                # one canary at a time

    def test_the_registers_start_promote_and_abort(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, FILES)
        m0 = git("rev-parse", "main", cwd=repo)
        (repo / "app.py").write_text("def add(a, b):\n    return a + b  # v2\n")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "v2", cwd=repo)
        m1 = git("rev-parse", "main", cwd=repo)
        r = Registers(repo, root / "run", canary_percent=lambda: 20)
        r.switch(f"run:release:all/none/{m0}", {"from": "none", "to": m0}, "k0")
        self.assertEqual(r.canary_switch(f"run:canary:all/{m0}/{m1}", {"from": m0, "to": m1}, "k1"), "ok")
        self.assertEqual((r.canary(), r.current()), (m1, m0))
        self.assertEqual(r.get("canary_weight"), "20")
        self.assertEqual(r.canary_switch(f"run:canary:all/{m0}/{m1}", {"from": m0, "to": m1}, "k1"), "ok")  # retry
        self.assertEqual(r.switch(f"run:release:all/{m0}/{m1}", {"from": m0, "to": m1}, "k2"), "ok")    # promote
        self.assertEqual((r.canary(), r.current()), (None, m1))
        self.assertEqual(r.canary_switch(f"run:canary:abort/{m0}/{m1}", {"from": m0, "to": m1}, "k3"), "failed")
        self.assertEqual([h["op"] for h in r.history()], ["deploy", "canary", "deploy"])


class Switch(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp())
        self.repo = demo_repository(root, FILES)
        self.main = git("rev-parse", "main", cwd=self.repo)
        self.served = {"version": None, "started": None}
        self.releases = Registers(self.repo, root / "run", served=lambda: self.served)

    def test_the_live_release_moves_only_from_the_exact_release(self):
        r, main = self.releases, self.main
        self.assertEqual(r.switch(f"run:release:all/{A}/{main}", {"from": A, "to": main}, "k1"), "failed")
        self.assertIsNone(r.current())                                                  # production was not A
        self.assertEqual(r.switch(f"run:release:all/none/{main}", {"from": "none", "to": main}, "k2"), "ok")
        self.assertEqual(r.current(), main)
        self.assertEqual(r.switch(f"run:release:all/none/{main}", {"from": "none", "to": main}, "k2"), "ok")  # retry
        self.assertEqual(r.switch(f"run:release:all/{main}/{C}", {"from": main, "to": C}, "k3"), "failed")  # not main
        self.assertEqual(r.switch(f"run:release:all/{main}/x", {"from": main, "to": "x"}, "k4"), "failed")
        self.assertEqual(r.switch(f"run:service:all/{main}/{A}", {"from": main, "to": A}, "k5"), "failed")  # never live
        self.assertEqual([h["to"] for h in r.history()], [main])

    def test_resolve_reads_the_registers_and_the_purpose_is_the_served_version(self):
        r, main = self.releases, self.main
        effects = r.effects()
        self.assertEqual((effects["deploy"].profile, effects["restart"].profile), ("cas", "observable"))
        deploy = {"op": "deploy", "args": {"from": "none", "to": main}}
        self.assertEqual(effects["deploy"].read(deploy, "k"), "not_applied")          # the key never moved anything
        r.switch(f"run:release:all/none/{main}", deploy["args"], "k")
        self.assertEqual(effects["deploy"].read(deploy, "k"), "applied")              # the register moved
        self.served = {"version": A, "started": 1}
        self.assertFalse(effects["deploy"].satisfied(deploy))                          # but the product serves A
        self.served = {"version": main, "started": 1}
        self.assertTrue(effects["deploy"].satisfied(deploy))
        restart = {"op": "restart", "args": {"release": main, "n": "1"}}
        self.assertEqual(effects["restart"].read(restart, "k6"), "not_sent")
        self.assertEqual(r.request_restart(f"run:process:all/{main}/1", restart["args"], "k6"), "ok")
        self.assertIn(main, r.get("restart"))
        self.assertIsNone(effects["restart"].read(restart, "k6"))                      # asked; same process: unknown
        self.served = {"version": main, "started": 10 ** 10}
        self.assertEqual(effects["restart"].read(restart, "k6"), "applied")
        self.assertEqual(r.request_restart("x", {"release": A, "n": "2"}, "k7"), "failed")   # not the live release


class Production(unittest.TestCase):
    def test_deploy_breach_rollback_and_the_gap_goes_to_people(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, {**FILES, "sbom.json": "{}\n"})
        clock = Clock(1_900_000_000_000)
        ceremony.now = daemon.now_ms = clock
        install = root / "install"
        ceremony.init(argparse.Namespace(dir=str(install), repo=str(repo), github=None, token_file=None, unconfined_tests=True,
                                         pins=str(root / "elsewhere" / "pins.db")))
        with open(install / "standard.toml", "a") as f:
            f.write('\n[run]\nmetrics = ["http://standard/metrics"]\nslo = 99.9\n\n[deploy]\nroot = "run"\n')
        operator = daemon.Installation(install / "standard.toml")
        metrics = Metrics(link=str(install / "run" / "current"))       # the product says which release answers
        operator.host.fetch = metrics
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        try:
            loop, repairer, _, refresh = agent_process.build(install / "standard.toml")
            loop.clock = repairer.clock = clock

            def rounds(n=3):
                for _ in range(n):
                    clock.t += 30_000
                    operator.tick()
                    refresh()
                    clock.t += 61_000                                  # past the agent's backoff
                    loop.run()
                clock.t += 30_000
                operator.tick()

            def obs(key):
                return operator.journal.snapshot()["observations"].get(f"{key}|scanner", {}).get("status")

            m0 = git("rev-parse", "main", cwd=repo)
            rounds()
            self.assertEqual(operator.releases.current(), m0)                 # deployed on its own
            self.assertEqual(obs("run:service:all|slo"), "met")
            self.assertEqual(obs("run:release:all|lag"), "none")
            state = operator.journal.snapshot()
            deploys = [i for i, it in state["intents"].items() if it["op"] == "deploy"]
            self.assertNotIn(f"proof:{deploys[0]}", state["obligations"])     # applied, read back, proven

            (repo / "app.py").write_text("def add(a, b):\n    return a + b  # faster\n")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "change", cwd=repo)
            m1 = git("rev-parse", "main", cwd=repo)
            rounds(1)
            self.assertEqual(operator.releases.current(), m1)                 # main moved: production followed
            metrics.errors = 40                                               # m1 breaks /orders
            rounds()
            self.assertEqual(operator.releases.current(), m0)                 # stepped back on its own
            self.assertEqual([h["op"] for h in operator.releases.history()], ["deploy", "deploy", "rollback"])
            metrics.errors = 0
            rounds()
            self.assertEqual(operator.releases.current(), m0)                 # m1 is never offered again
            self.assertEqual(obs("run:release:all|lag"), "behind")
            self.assertEqual(obs(f"run:release:all/{m0}/{m1}|candidate"), "no")     # withdrawn once it went live
            health = operator.service.view()["health"]
            self.assertIn("run-live", [o.get("target") for o in health["open"]])  # someone's gap, with a due date
            self.assertIn("run-slo", [p["target"] for p in health["proven"]])     # the service itself recovered

            # D51: the human keeps deployment (a change of the rules, in force at once), then says yes to one switch.
            from context.moves import queue
            from surface.human import decide as yes, load_signer, rules
            human = load_signer("human", install / "keys" / "human.key")
            view = operator.service.view()
            operator.service.admit(rules(view, human, change(view["law"]["client"], routes={"deploy": []}),
                                         at=clock()))

            def decide(resource):
                operator.service.admit(yes(operator.service.view(), human, operator.config["grants"]["human"],
                                           resource, at=clock()))

            (repo / "app.py").write_text("def add(a, b):\n    return a + b  # fixed\n")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "fix", cwd=repo)
            m2 = git("rev-parse", "main", cwd=repo)
            rounds(2)
            self.assertEqual(operator.releases.current(), m0)                 # a candidate, not deployed alone
            self.assertEqual(obs(f"run:release:all/{m0}/{m2}|candidate"), "yes")
            self.assertIn(f"run:release:all/{m0}/{m2}",                       # it waits for the human
                          [m["resource"] for m in queue(operator.service.view())])
            decide(f"run:release:all/{m0}/{m2}")
            rounds(1)
            self.assertEqual(operator.releases.current(), m2)                 # the human's yes, by the guard
            decide(f"run:process:all/{m2}/1")                                 # and a restart, by hand
            rounds(1)
            self.assertIn(f"{m2} 1", (install / "run" / "restart").read_text())
            restart = next(i for i, it in operator.journal.snapshot()["intents"].items() if it["op"] == "restart")
            self.assertIn(f"proof:{restart}", operator.journal.snapshot()["obligations"])   # not proven: same process
            metrics.started = clock() // 1000 + 5                             # the runner started it again
            rounds(1)
            self.assertNotIn(f"proof:{restart}", operator.journal.snapshot()["obligations"])

            # D37: every signed measure is a pure function of its run record; anyone can run it again.
            from tools import replay
            config = install / "standard.toml"
            signed = replay.ledger(config, 200)
            recorded = list(signed)
            jobs = {}
            for r in recorded:
                result = replay.replay(replay.host_for(config), r, signed[r])
                self.assertEqual(result["result"], "agrees", result)
                self.assertGreater(result["ledger"], 0)
                jobs[result["job"]] = jobs.get(result["job"], 0) + 1
            lying = replay.replay(replay.host_for(config), recorded[0],     # review, medium 13: the ledger itself
                                  {*signed[recorded[0]], ("run:service:all", "slo", "forged")})
            self.assertEqual(lying["ledger_not_in_record"], [("run:service:all", "slo", "forged")])
            self.assertIn("production", jobs)
            host = replay.host_for(config)                                    # a record whose answer was forged
            bt = json.loads(host.evidence.get(next(r for r in recorded if b'"production"' in host.evidence.get(r))))
            self.assertEqual((bt["bt"], bt["contract"]["form"]), ("observe", "composite"))   # D38: what it rests on
            rec = json.loads(host.evidence.get(bt["material"]["run"]))
            rec["output"]["facts"] = [[r, p, "met" if p == "slo" else s, d] for r, p, s, d in rec["output"]["facts"]]
            rec["output"]["facts"].append([f"run:release:all/{m0}/{m1}", "candidate", "yes", []])   # stepped back from
            forged = host.evidence.put(json.dumps(rec, sort_keys=True).encode())
            self.assertEqual(replay.replay(host, forged)["result"], "disagrees")
        finally:
            gateway.shutdown()
            gateway.server_close()


class CanaryEndToEnd(unittest.TestCase):
    def test_a_canary_bakes_and_is_promoted_a_bad_one_is_taken_out(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, {**FILES, "sbom.json": "{}\n"})
        clock = Clock(1_900_000_000_000)
        ceremony.now = daemon.now_ms = clock
        install = root / "install"
        ceremony.init(argparse.Namespace(dir=str(install), repo=str(repo), github=None, token_file=None, unconfined_tests=True,
                                         pins=str(root / "elsewhere" / "pins.db")))
        with open(install / "standard.toml", "a") as f:
            f.write('\n[run]\nmetrics = ["http://standard/metrics"]\nslo = 99.9\n\n[deploy]\nroot = "run"\n'
                    'runner_metrics = "http://runner/__standard/metrics"\n')
        operator = daemon.Installation(install / "standard.toml")
        metrics, bad = Metrics(link=str(install / "run" / "current")), {}
        seen = {}

        def fetch(url):
            if "runner" not in url:
                return metrics(url)
            lines = []
            for name in ("current", "canary"):
                release = (install / "run" / name).read_text().strip() if (install / "run" / name).exists() else ""
                if release:
                    ok, err = seen.get(release, (0, 0))
                    seen[release] = (ok + 100 - bad.get(release, 0), err + bad.get(release, 0))
            for release, (ok, err) in seen.items():
                lines += [f'standard_release_requests_total{{release="{release}",outcome="ok"}} {ok}',
                          f'standard_release_requests_total{{release="{release}",outcome="error"}} {err}',
                          f'standard_release_duration_seconds_bucket{{release="{release}",le="0.1"}} {ok + err}',
                          f'standard_release_duration_seconds_bucket{{release="{release}",le="+Inf"}} {ok + err}']
            return "\n".join(lines)
        operator.host.fetch = fetch

        def commit_v(text):
            git("reset", "-q", "--hard", cwd=repo)                            # the guard moved main, not this tree
            (repo / "app.py").write_text(text)
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", text[:9], cwd=repo)
            return git("rev-parse", "main", cwd=repo)
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        try:
            loop, repairer, _, refresh = agent_process.build(install / "standard.toml")
            loop.clock = repairer.clock = clock

            def rounds(n):
                for _ in range(n):
                    clock.t += 30_000
                    operator.tick()
                    refresh()
                    clock.t += 61_000
                    loop.run()
                operator.tick()

            from surface.human import load_signer, rules
            human = load_signer("human", install / "keys" / "human.key")
            m0 = git("rev-parse", "main", cwd=repo)
            rounds(2)
            self.assertEqual(operator.releases.current(), m0)                 # a first release: nothing to compare

            # D51: the human turns direct deployment off in the rules: the agent goes through a canary.
            view = operator.service.view()
            operator.service.admit(rules(view, human, change(view["law"]["client"], routes={"deploy": ["promote"]}),
                                         at=clock()))
            agent = load_signer("agent", install / "agent" / "agent.key")
            with self.assertRaises(Exception) as refused:                     # the agent never writes the rules
                operator.service.admit(rules(operator.service.view(), agent, client_law(), at=clock()))
            self.assertEqual(getattr(refused.exception, "code", None), "CAP.HUMAN")
            r1 = commit_v("def add(a, b):\n    return a + b  # v1\n")
            rounds(2)
            self.assertEqual((operator.releases.current(), operator.releases.canary()), (m0, r1))   # on a share
            rounds(9)
            self.assertEqual((operator.releases.current(), operator.releases.canary()), (r1, None))   # promoted

            m1 = r1
            m2 = commit_v("def add(a, b):\n    return a + b  # v2\n")
            bad[m2] = 30                                                      # 30 % of its requests fail
            rounds(4)
            self.assertEqual((operator.releases.current(), operator.releases.canary()), (m1, None))   # taken out
            self.assertIn("abort", [h["op"] for h in operator.releases.history()])

        finally:
            gateway.shutdown()
            gateway.server_close()


if __name__ == "__main__":
    os.chdir(ROOT / "tests")
    unittest.main()
