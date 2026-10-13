"""Production (D30, D36): the scanner measures the service and signs what is and numbers, the law bounds when the agent
may act alone, the engineers' settings restrain it further; the agent deploys main and rolls back a release that broke
the service, and a release rolled back is never deployed again: that gap goes to people."""
import argparse
import hashlib
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

import standard.autonomy.__main__ as agent_process  # noqa: E402
import standard.runtime.daemon as daemon  # noqa: E402
import instruments.production as runtime  # noqa: E402
from bt.register import Registers  # noqa: E402
from standard.autonomy import release  # noqa: E402
from standard.autonomy.policy import Policy, history, law_bounds  # noqa: E402
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
        m = runtime.measures({"global": {"base_url": "http://shop"},
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


class Decide(unittest.TestCase):
    """D36: the agent's restraint, from the engineers' settings, inside the law's bounds."""

    def view(self, **facts):
        return {f"run:service:all/{B}/{A}": {"previous": "yes", "proven": "yes", "switched_min": "2", "burn_fast": "0",
                                            "failing_pct": "0", "unanswered_s": "0", "migrations_crossed": "0", **facts}}

    def test_a_rollback_right_after_a_switch_that_broke_the_service(self):
        decide = lambda facts, doc={}: release.decide(self.view(**facts), Policy(doc), 0)
        self.assertEqual(decide({})[0], [])
        self.assertEqual(decide({"burn_fast": "20.000"})[0],
                         [("rollback", f"run:service:all/{B}/{A}", "agent_rollback")])
        self.assertEqual(decide({"failing_pct": "40"})[0],
                         [("rollback", f"run:service:all/{B}/{A}", "agent_rollback_failing")])
        self.assertEqual(decide({"unanswered_s": "120", "switched_min": "300"})[0][0][2], "agent_rollback_unanswered")
        actions, why = decide({"failing_pct": "40", "switched_min": "45"})
        self.assertEqual((actions, "not attributable" in why["rollback"]), ([], True))      # horizon 30 min
        actions, why = decide({"failing_pct": "40"}, {"global": {"auto_rollback": "off"}})
        self.assertIn("engineer decides", why["rollback"])
        actions, why = decide({"failing_pct": "40", "migrations_crossed": "1"}, {"global": {"compatible_migrations": "off"}})
        self.assertIn("compatible migration", why["rollback"])
        actions, why = decide({"failing_pct": "40", "proven": "no"})
        self.assertIn("known", why["rollback"])
        self.assertEqual(decide({"failing_pct": "6"}, {"global": {"failing": "10"}})[0], [])  # engineers ask for more

    def test_a_restart_only_when_allowed_away_from_a_switch_and_within_budget(self):
        r = f"run:process:all/{B}/2"
        view = lambda **f: {r: {"live": "yes", "switched_min": "600", "failing_pct": "40", "burn_fast": "0",
                                "restarts_last_hour": "0", **f}}
        on = {"global": {"auto_restart": "on", "restarts_per_hour": "1"}}
        self.assertIn("off", release.decide(view(), Policy({}), 0)[1]["restart"])
        self.assertEqual(release.decide(view(), Policy(on), 0)[0], [("restart", r, "agent_restart")])
        self.assertIn("budget", release.decide(view(restarts_last_hour="1"), Policy(on), 0)[1]["restart"])
        self.assertIn("follows a switch", release.decide(view(switched_min="3"), Policy(on), 0)[1]["restart"])

    def test_deploy_in_the_window_unfrozen_with_budget_left_or_start_a_canary(self):
        r = f"run:release:all/{A}/{B}"
        view = {r: {"candidate": "yes", "budget_pct": "10.000"}, f"run:canary:all/{A}/{B}": {"candidate": "yes"}}
        self.assertEqual(release.decide(view, Policy({}), 0)[0], [("deploy", r, "agent_deploy")])
        self.assertIn("approves", release.decide(view, Policy({"global": {"auto_deploy": "off"}}), 0)[1]["deploy"])
        self.assertIn("budget", release.decide(view, Policy({"global": {"freeze_below": "25"}}), 0)[1]["deploy"])
        self.assertEqual(release.decide(view, Policy({"global": {"strategy": "canary"}}), 0)[0],
                         [("canary", f"run:canary:all/{A}/{B}", "agent_canary")])
        policy = Policy({"global": {"deploy_days": "mon,tue,wed,thu,fri", "deploy_hours": "09-18", "deploy_tz": "Europe/Paris"}})
        saturday = 1_791_619_200_000                                                  # 2026-10-10 10:00 Paris
        self.assertIn("window", release.decide(view, policy, saturday)[1]["deploy"])
        self.assertEqual(release.decide(view, policy, saturday + 2 * 86_400_000)[0][0][0], "deploy")   # Monday
        view[r]["approved"] = "yes"
        self.assertEqual(release.decide(view, Policy({"global": {"auto_deploy": "off"}}), 0)[0],
                         [("deploy", r, "agent_deploy_reviewed")])

    def test_a_canary_bakes_and_is_promoted_a_worse_one_is_taken_out(self):
        r, abort = f"run:release:all/{A}/{B}", f"run:canary:abort/{A}/{B}"
        canary = {"global": {"strategy": "canary"}}
        view = lambda **f: {r: {"candidate": "yes", "canary_error_delta": "0.100", "canary_requests": "500",
                                "canary_baked_min": "11", "canary_p99_ms": "100", "live_p99_ms": "100", **f},
                            abort: {"running": "yes"}}
        self.assertEqual(release.decide(view(), Policy(canary), 0)[0], [("deploy", r, "agent_promote")])
        actions, why = release.decide(view(canary_baked_min="3"), Policy(canary), 0)
        self.assertEqual((actions, "baking" in why["canary"]), ([], True))
        self.assertEqual(release.decide(view(canary_error_delta="5.000", canary_baked_min="2"), Policy(canary), 0)[0],
                         [("abort", abort, "agent_abort")])
        noise = view(canary_error_delta="1.527", canary_error_pct="3.5", live_error_pct="2.0", canary_requests="301",
                     live_requests="2700", canary_baked_min="2")              # what the live demo saw by chance
        self.assertEqual(release.decide(noise, Policy(canary), 0)[0], [])
        broken = view(canary_error_delta="28.000", canary_error_pct="30", live_error_pct="2", canary_requests="60",
                      live_requests="600", canary_baked_min="1")
        self.assertEqual(release.decide(broken, Policy(canary), 0)[0], [("abort", abort, "agent_abort")])
        moved = {**view(), r: {"candidate": "no"}}
        self.assertEqual(release.decide(moved, Policy(canary), 0)[0], [("abort", abort, "agent_abort")])


class Settings(unittest.TestCase):
    """The engineers' settings: the rules file on main, within bounds, and signed silences."""

    def test_only_valid_settings_are_read(self):
        policy = Policy({"global": {"objective": "120", "auto_deploy": "off"}, "probes": {"p-x": {"spec": "rm -rf /"}}})
        self.assertEqual((policy.get("objective"), policy.get("auto_deploy")), (99.9, "off"))
        self.assertEqual([i["setting"] for i in policy.ignored], ["global/objective", "p-x/spec"])
        policy = Policy({}, transitions={"run:policy/m-x/until": {"value": "99999999999999"},
                                         "run:policy/m-x/target_of": {"value": "all"}})
        self.assertEqual(policy.silences(2_000)["m-x"]["target_of"], "all")

    def test_a_component_override_and_its_counting(self):
        cid = component_id("api", "POST", "/orders")
        policy = Policy({"components": {cid: {"p99_ms": "200", "counted": "off"}}})
        self.assertEqual(policy.limits("api", "POST", "/orders")["p99_ms"], 200)
        self.assertFalse(policy.limits("api", "POST", "/orders")["counted"])
        self.assertEqual(policy.limits("api", "GET", "/health")["p99_ms"], 1000.0)
        self.assertFalse(policy.limits("dependency", "POST", "pay")["counted"])      # outside: shown, not counted
        self.assertFalse(runtime.measures({"components": {cid: {"counted": "off"}}})["counted"][cid])   # the scanner too

    def test_the_law_bounds_and_the_history_of_the_rules(self):
        from standard.floors import FLOORS
        bounds = law_bounds(FLOORS["conditions"])
        self.assertEqual((bounds["burn_fast"], bounds["rollback_horizon_min"], bounds["restarts_per_hour"]),
                         (("ge", 14.4), ("le", 240.0), ("le", 12.0)))
        changes = history([(1, "h1", {}), (2, "h1", {"global": {"strategy": "canary"}}), (3, "alice", {})])
        self.assertEqual([(c["at"], c["setting"], c["value"]) for c in changes],
                         [(3, "global/strategy", "(retiré)"), (2, "global/strategy", "canary")])


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
        clock.t += 3_600_100
        ceremony.activate(argparse.Namespace(dir=str(install)))
        operator = daemon.Installation(install / "standard.toml")
        metrics = Metrics(link=str(install / "run" / "current"))       # the product says which release answers
        operator.host.fetch = metrics
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        try:
            cycle, refresh = agent_process.build(install / "standard.toml")
            cycle.clock = clock

            def rounds(n=3):
                for _ in range(n):
                    clock.t += 30_000
                    operator.tick()
                    refresh()
                    clock.t += 61_000                                  # past the agent's backoff
                    cycle.run()
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

            # D31: the engineer keeps deployment for himself (stricter: at once), then approves one exact switch.
            from standard.surface.human import load_signer
            from bt.signing import envelope
            h1 = load_signer("h1", install / "keys" / "h1.key")

            def decide(resource, prop, status):
                s = operator.journal.snapshot()
                operator.service.admit(envelope(s["domain"], "observation", {
                    "id": f"h1-{clock()}", "at": max(clock(), s["last_at"] + 1), "author": "h1",
                    "under": operator.config["grants"]["engineer"], "resource": resource, "property": prop,
                    "status": status, "level": "real"}, [h1]))

            (repo / "standard").mkdir(exist_ok=True)                           # D35: the rules file, by git
            (repo / "standard" / "rules.json").write_text(json.dumps({"global": {"auto_deploy": "off"}}))
            git("add", "-A", cwd=repo)
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "rules", cwd=repo)
            (repo / "app.py").write_text("def add(a, b):\n    return a + b  # fixed\n")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "fix", cwd=repo)
            m2 = git("rev-parse", "main", cwd=repo)
            rounds(2)
            self.assertEqual(operator.releases.current(), m0)                 # a candidate, not deployed alone
            self.assertEqual(obs(f"run:release:all/{m0}/{m2}|candidate"), "yes")
            notes = json.loads((install / "agent" / "releases.json").read_text())
            self.assertIn("approves", notes["why"]["deploy"])                  # the agent's restraint, said
            decide(f"run:release:all/{m0}/{m2}", "approved", "yes")
            rounds(1)
            self.assertEqual(operator.releases.current(), m2)                 # the engineer's decision, by the guard
            decide(f"run:process:all/{m2}/1", "requested", "yes")             # and a restart, by hand
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
            recorded = replay.records(config, 200)
            jobs = {}
            for r in recorded:
                result = replay.replay(replay.host_for(config), r)
                self.assertEqual(result["result"], "agrees", result)
                jobs[result["job"]] = jobs.get(result["job"], 0) + 1
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
        clock.t += 3_600_100
        ceremony.activate(argparse.Namespace(dir=str(install)))
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
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        try:
            cycle, refresh = agent_process.build(install / "standard.toml")
            cycle.clock = clock

            def rounds(n):
                for _ in range(n):
                    clock.t += 30_000
                    operator.tick()
                    refresh()
                    clock.t += 61_000
                    cycle.run()
                operator.tick()

            from standard.surface.human import load_signer
            from bt.signing import envelope
            h1 = load_signer("h1", install / "keys" / "h1.key")
            m0 = git("rev-parse", "main", cwd=repo)
            rounds(2)
            self.assertEqual(operator.releases.current(), m0)                 # a first release: nothing to compare

            # D35: the engineer changes the rules from the interface with one signature; the agent commits exactly
            # that file; the scanner checks it; the law lands it.
            doc = json.dumps({"global": {"strategy": "canary"}}, indent=2, sort_keys=True).encode() + b"\n"
            digest = "sha256:" + hashlib.sha256(doc).hexdigest()
            (install / "requests").mkdir(exist_ok=True)
            (install / "requests" / digest[7:]).write_bytes(doc)
            s = operator.journal.snapshot()
            operator.service.admit(envelope(s["domain"], "observation", {
                "id": "h1-rules", "at": max(clock(), s["last_at"] + 1), "author": "h1",
                "under": operator.config["grants"]["engineer"], "resource": f"repo:config:rules/{m0}",
                "property": "rules", "status": digest, "level": "real"}, [h1]))
            rounds(3)
            r1 = git("rev-parse", "main", cwd=repo)
            self.assertNotEqual(r1, m0)
            self.assertEqual(git("show", f"{r1}:standard/rules.json", cwd=repo).encode() + b"\n", doc)
            rounds(2)
            self.assertEqual((operator.releases.current(), operator.releases.canary()), (m0, r1))   # on a share
            rounds(9)
            self.assertEqual((operator.releases.current(), operator.releases.canary()), (r1, None))   # promoted

            def commit(text):
                git("reset", "-q", "--hard", cwd=repo)                        # the guard moved main, not this tree
                (repo / "app.py").write_text(text)
                git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", text[:9], cwd=repo)
                return git("rev-parse", "main", cwd=repo)
            m1 = r1
            m2 = commit("def add(a, b):\n    return a + b  # v2\n")
            bad[m2] = 30                                                      # 30 % of its requests fail
            rounds(4)
            self.assertEqual((operator.releases.current(), operator.releases.canary()), (m1, None))   # taken out
            self.assertIn("abort", [h["op"] for h in operator.releases.history()])

            # D35: a rules commit that changes anything else, or bytes nobody signed, is never `configured`.
            from standard.autonomy.agent import commit_files
            here = git("rev-parse", "main", cwd=repo)
            sneaky = commit_files(cycle.agent.store, here, {"standard/rules.json": doc, "app.py": b"evil = 1\n"},
                                  f"rules\n\nStandard-Rules: {digest}\n")
            unsigned = commit_files(cycle.agent.store, here, {"standard/rules.json": b"{}\n"},
                                    "rules\n\nStandard-Rules: sha256:" + "1" * 64 + "\n")
            operator.tick()
            facts = operator.service.view()["transitions"]
            self.assertEqual(facts[f"repo:config:rules/{here}/{sneaky}"]["configured"], "no")
            self.assertEqual(facts[f"repo:config:rules/{here}/{unsigned}"]["configured"], "no")
        finally:
            gateway.shutdown()
            gateway.server_close()


if __name__ == "__main__":
    os.chdir(ROOT / "tests")
    unittest.main()
