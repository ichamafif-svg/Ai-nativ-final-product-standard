"""Production (D30): the scanner proves the service from its metrics, the agent deploys main and rolls back a release
that broke the objective, and a release rolled back is never deployed again: that gap goes to people."""
import argparse
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import ceremony  # noqa: E402
from test_install import Clock  # noqa: E402
from test_maintenance import FILES, demo_repository  # noqa: E402

import autonomy.__main__ as agent_process  # noqa: E402
import trusted.daemon as daemon  # noqa: E402
from trusted import runtime  # noqa: E402
from trusted.deploy import Releases  # noqa: E402
from trusted.policy import Policy, component_id  # noqa: E402
from trusted.gateway import AdmissionGateway  # noqa: E402

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
        if version is None and self.link is not None and os.path.islink(self.link):
            version = os.path.basename(os.readlink(self.link))
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


class Facts(unittest.TestCase):
    def test_main_is_a_candidate_and_deployable_only_when_engineers_let_it(self):
        facts, _ = runtime.release_facts("met", A, B, [], set(), 0)
        self.assertIn(("run:release:all", "lag", "behind"), facts)
        self.assertIn((f"run:release:all/{A}/{B}", "candidate", "yes"), facts)
        self.assertIn((f"run:release:all/{A}/{B}", "deployable", "yes"), facts)
        policy = Policy(60_000, defaults={"auto_deploy": "off"})
        facts, why = runtime.release_facts("met", A, B, [], set(), 0, policy=policy)
        self.assertIn((f"run:release:all/{A}/{B}", "candidate", "yes"), facts)
        self.assertNotIn("deployable", str(facts))                                   # an engineer approves
        self.assertIn("approves", why["deploy"])
        facts, why = runtime.release_facts("met", A, B, [{"at": 0, "op": "rollback", "from": B, "to": A}], set(), 0)
        self.assertEqual(facts, [("run:release:all", "lag", "behind")])
        self.assertIn("new commit", why["deploy"])
        self.assertEqual(runtime.release_facts("met", B, B, [], set(), 0)[0], [("run:release:all", "lag", "none")])
        self.assertIn("behind", str(runtime.release_facts("met", B, B, [], set(), 0, served=A)[0]))   # not served

    def test_a_rollback_needs_a_fresh_switch_a_release_known_good_and_a_schema_it_can_run_on(self):
        history = [{"at": 1_000, "op": "deploy", "from": A, "to": B}]
        facts, _ = runtime.release_facts("breached:1", B, B, history, {A}, 1_000 + 60_000)
        self.assertIn((f"run:service:all/{B}/{A}", "regressed", "yes"), facts)
        self.assertIn((f"run:service:all/{B}/{A}", "previous", "yes"), facts)          # an engineer may step back
        facts, why = runtime.release_facts("breached:1", B, B, history, set(), 61_000)  # A never proved good
        self.assertNotIn("regressed", str(facts))
        facts, why = runtime.release_facts("breached:1", B, B, history, {A}, 1_000 + 3_600_000)   # too late: people
        self.assertNotIn("regressed", str(facts))
        self.assertIn("not attributable", why["rollback"])
        facts, why = runtime.release_facts("breached:1", B, B, history, {A}, 61_000,
                                           compat=lambda live, prev: (False, "migration not declared compatible"))
        self.assertNotIn("regressed", str(facts))
        self.assertNotIn("previous", str(facts))                                      # not even by hand
        self.assertIn("migration", why["rollback"])
        policy = Policy(60_000, defaults={"auto_rollback": "off"})
        facts, why = runtime.release_facts("breached:1", B, B, history, {A}, 61_000, policy=policy)
        self.assertNotIn("regressed", str(facts))
        self.assertIn("engineer decides", why["rollback"])

    def test_a_release_that_never_answers_is_stepped_back_from(self):
        history = [{"at": 1_000, "op": "deploy", "from": A, "to": B}]
        facts, why = runtime.release_facts("met", B, B, history, set(), 1_000 + 120_000, served=A)
        self.assertIn((f"run:service:all/{B}/{A}", "regressed", "yes"), facts)
        self.assertIn("never answered", why["rollback"])
        facts, _ = runtime.release_facts("met", B, B, history, set(), 1_000 + 30_000, served=A)   # still starting
        self.assertNotIn("regressed", str(facts))

    def test_a_restart_only_when_allowed_and_within_its_budget(self):
        history = [{"at": 0, "op": "deploy", "from": A, "to": B}]
        late = 10 * 3_600_000
        self.assertIn("off", runtime.release_facts("breached:1", B, B, history, {A}, late)[1]["restart"])
        policy = Policy(60_000, defaults={"auto_restart": "on", "restarts_per_hour": 1})
        facts, _ = runtime.release_facts("breached:1", B, B, history, {A}, late, policy=policy)
        self.assertIn((f"run:process:all/{B}/1", "restartable", "yes"), facts)
        history.append({"at": late - 60_000, "op": "restart", "from": B, "to": B, "n": "1"})
        facts, why = runtime.release_facts("breached:1", B, B, history, {A}, late, policy=policy)
        self.assertNotIn("restartable", str(facts))
        self.assertIn("budget", why["restart"])
        facts, why = runtime.release_facts("breached:1", B, B, [{"at": late - 60_000, "op": "deploy", "from": A, "to": B}],
                                           set(), late, policy=policy, compat=lambda live, prev: (False, "migration"))
        self.assertNotIn("restartable", str(facts))                                   # a code fault: not a restart
        self.assertIn("follows a switch", why["restart"])

    def test_an_unreachable_source_is_uncovered_never_met(self):
        production = runtime.Production(["http://x/metrics"], fetch=lambda url: (_ for _ in ()).throw(OSError("down")))
        production.scrape(1)
        production.scrape(2)
        self.assertEqual(production.assess(2)["slo"], "uncovered:1")
        self.assertEqual(runtime.Production([]).assess(2)["coverage"], "uncovered:empty")
        metrics = Metrics()
        production = runtime.Production(["http://x/metrics"], fetch=metrics)
        production.scrape(1)
        production.scrape(31)
        self.assertEqual(production.assess(31)["slo"], "met")
        metrics.errors = 50
        production.scrape(61)
        production.scrape(91)
        assessed = production.assess(91)
        self.assertEqual(assessed["slo"], "breached:1")
        self.assertEqual(assessed["components"][0]["why"]["rule"], "error_rate")


class Settings(unittest.TestCase):
    """What engineers set: stricter applies at once, looser after the law's delay; only the engineer is read."""

    def statement(self, key, value, at, author="h1", n=[0]):
        n[0] += 1
        return {f"run:policy/{key}|value|{author}#{n[0]}": {"id": f"s{n[0]}", "resource": f"run:policy/{key}",
                                                          "property": "value", "status": value, "at": at,
                                                          "author": author}}

    def test_stricter_at_once_looser_after_the_delay(self):
        policy = Policy(60_000)
        policy.update(self.statement("global/objective", "99.95", 1_000), {"h1"}, 1_000)
        self.assertEqual(policy.get("objective"), 99.95)                             # stricter: now
        policy.update(self.statement("global/objective", "99", 2_000), {"h1"}, 2_000)
        self.assertEqual(policy.get("objective"), 99.95)                             # looser: not yet
        self.assertIn("global/objective", policy.published()["pending"])
        policy.update({}, {"h1"}, 62_000)
        self.assertEqual(policy.get("objective"), 99.0)                              # after the delay
        policy.update(self.statement("global/auto_restart", "on", 63_000), {"h1"}, 63_000)
        self.assertEqual(policy.get("auto_restart"), "off")                          # more autonomy waits too
        policy.update(self.statement("global/auto_deploy", "off", 64_000), {"h1"}, 64_000)
        self.assertEqual(policy.get("auto_deploy"), "off")                           # less autonomy: now

    def test_only_the_engineer_within_bounds_is_read(self):
        policy = Policy(60_000)
        policy.update(self.statement("global/objective", "99.99", 1_000, author="agent"), {"h1"}, 1_000)
        self.assertEqual(policy.get("objective"), 99.9)
        policy.update(self.statement("global/objective", "120", 2_000), {"h1"}, 2_000)
        self.assertEqual(policy.get("objective"), 99.9)
        self.assertIn("ignored", policy.published()["history"][0]["outcome"])
        policy.update(self.statement("p-x/spec", "rm -rf /", 3_000), {"h1"}, 3_000)
        self.assertEqual(policy.probes(), [])

    def test_a_component_override_and_its_counting(self):
        policy = Policy(60_000)
        cid = component_id("api", "POST", "/orders")
        policy.update(self.statement(f"{cid}/p99_ms", "200", 1_000), {"h1"}, 1_000)
        self.assertEqual(policy.limits("api", "POST", "/orders")["p99_ms"], 200)    # stricter than 1000: now
        self.assertEqual(policy.limits("api", "GET", "/health")["p99_ms"], 1000.0)
        self.assertFalse(policy.limits("dependency", "POST", "pay")["counted"])      # outside: shown, not counted
        policy.update(self.statement(f"{cid}/counted", "off", 2_000), {"h1"}, 2_000)
        self.assertTrue(policy.limits("api", "POST", "/orders")["counted"])          # uncounting loosens: waits

    def test_probes_see_what_the_product_does_not_report(self):
        policy = Policy(60_000, defaults={"base_url": "http://shop"})
        policy.update(self.statement("p-a/spec", "GET /health 200", 1_000), {"h1"}, 1_000)
        metrics = Metrics()
        answers = iter([200, 200, 503, 503])
        production = runtime.Production(["http://x/metrics"], fetch=metrics, policy=policy,
                                        request=lambda method, url: (next(answers), 0.01))
        for at in (1, 31):
            production.scrape(at)
        self.assertEqual(production.assess(31)["slo"], "met")
        for at in (61, 91):
            production.scrape(at)
        assessed = production.assess(91)
        self.assertEqual(assessed["slo"], "breached:1")                              # metrics fine, probe failing
        self.assertEqual([c["kind"] for c in assessed["components"] if c["state"] == "failing"], ["probe"])


class Migrations(unittest.TestCase):
    def test_stepping_back_across_a_schema_change_needs_a_compatible_migration(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, {**FILES, "migrations/0001_orders.sql": "CREATE TABLE o (id INTEGER);\n"})
        commit = lambda path, text: (Path(repo, path).write_text(text), git("add", "-A", cwd=repo),
                                     git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", path, cwd=repo),
                                     git("rev-parse", "HEAD", cwd=repo))[-1]
        base = git("rev-parse", "HEAD", cwd=repo)
        expand = commit("migrations/0002_note.compatible.sql", "ALTER TABLE o ADD COLUMN note TEXT;\n")
        drop = commit("migrations/0003_drop.sql", "DROP TABLE o;\n")
        self.assertEqual(runtime.compatible(repo, expand, base, True), (True, None))
        self.assertFalse(runtime.compatible(repo, expand, base, False)[0])           # engineers said no
        fits, why = runtime.compatible(repo, drop, expand, True)
        self.assertFalse(fits)
        self.assertIn("0003_drop.sql", why)


class Switch(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp())
        self.repo = demo_repository(root, FILES)
        self.main = git("rev-parse", "main", cwd=self.repo)
        self.served = {"version": None, "started": None}
        self.releases = Releases(self.repo, root / "run", served=lambda: self.served)

    def test_the_live_release_moves_only_from_the_exact_release(self):
        r, main = self.releases, self.main
        self.assertEqual(r.switch(f"run:release:all/{A}/{main}", {"from": A, "to": main}, "k1"), "failed")
        self.assertIsNone(r.current())                                                  # production was not A
        self.assertEqual(r.switch(f"run:release:all/none/{main}", {"from": "none", "to": main}, "k2"), "ok")
        self.assertEqual(r.current(), main)
        self.assertTrue((r.link / "app.py").exists())                                   # main's tree, exported
        self.assertEqual(r.switch(f"run:release:all/none/{main}", {"from": "none", "to": main}, "k2"), "ok")  # retry
        self.assertEqual(r.switch(f"run:release:all/{main}/{C}", {"from": main, "to": C}, "k3"), "failed")  # not main
        self.assertEqual(r.switch(f"run:release:all/{main}/x", {"from": main, "to": "x"}, "k4"), "failed")
        self.assertEqual(r.switch(f"run:service:all/{main}/{A}", {"from": main, "to": A}, "k5"), "failed")  # never live
        self.assertEqual([h["to"] for h in r.history()], [main])

    def test_applied_means_served_and_a_restart_means_a_new_process(self):
        r, main = self.releases, self.main
        r.switch(f"run:release:all/none/{main}", {"from": "none", "to": main}, "k")
        deploy = {"op": "deploy", "args": {"from": "none", "to": main}}
        self.served = {"version": A, "started": 1}
        self.assertFalse(r.applied(deploy))                                            # the link moved, not the code
        self.served = {"version": main, "started": 1}
        self.assertTrue(r.applied(deploy))
        restart = {"op": "restart", "args": {"release": main, "n": "1"}}
        self.assertEqual(r.request_restart(f"run:process:all/{main}/1", restart["args"], "k6"), "ok")
        self.assertIn(main, (r.root / "restart").read_text())
        self.assertFalse(r.applied(restart))                                           # same process
        self.served = {"version": main, "started": 10 ** 10}
        self.assertTrue(r.applied(restart))
        self.assertEqual(r.request_restart("x", {"release": A, "n": "2"}, "k7"), "failed")   # not the live release

    def test_a_restart_command_that_fails_is_unknown(self):
        self.releases.restart = ["false"]
        self.assertEqual(self.releases.switch("r", {"from": "none", "to": self.main}, "k"), "unknown")
        self.assertTrue(self.releases.applied({"op": "deploy", "args": {"to": self.main}}))


class Production(unittest.TestCase):
    def test_deploy_breach_rollback_and_the_gap_goes_to_people(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, {**FILES, "sbom.json": "{}\n"})
        clock = Clock(1_900_000_000_000)
        ceremony.now = daemon.now_ms = clock
        install = root / "install"
        ceremony.init(argparse.Namespace(dir=str(install), repo=str(repo), github=None, token_file=None,
                                         pins=str(root / "elsewhere" / "pins.db")))
        with open(install / "standard.toml", "a") as f:
            f.write('\n[run]\nmetrics = ["http://product/metrics"]\nslo = 99.9\n\n[deploy]\nroot = "run"\n')
        clock.t += 3_600_100
        ceremony.activate(argparse.Namespace(dir=str(install)))
        operator = daemon.Installation(install / "standard.toml")
        metrics = Metrics(link=str(install / "run" / "current"))       # the product says which release answers
        operator.production.production.fetch = metrics
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
            self.assertEqual(obs(f"run:release:all/{m0}/{m1}|deployable"), "no")    # withdrawn once it went live
            health = operator.service.view()["health"]
            self.assertIn("run-live", [o.get("target") for o in health["open"]])  # someone's gap, with a due date
            self.assertIn("run-slo", [p["target"] for p in health["proven"]])     # the service itself recovered

            # D31: the engineer keeps deployment for himself (stricter: at once), then approves one exact switch.
            from surface.human import load_signer
            from trusted.signing import envelope
            h1 = load_signer("h1", install / "keys" / "h1.key")

            def decide(resource, prop, status):
                s = operator.journal.snapshot()
                operator.service.admit(envelope(s["domain"], "observation", {
                    "id": f"h1-{clock()}", "at": max(clock(), s["last_at"] + 1), "author": "h1",
                    "under": operator.config["grants"]["engineer"], "resource": resource, "property": prop,
                    "status": status, "level": "real"}, [h1]))

            decide("run:policy/global/auto_deploy", "value", "off")
            (repo / "app.py").write_text("def add(a, b):\n    return a + b  # fixed\n")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "fix", cwd=repo)
            m2 = git("rev-parse", "main", cwd=repo)
            rounds(2)
            self.assertEqual(operator.releases.current(), m0)                 # a candidate, not deployed alone
            self.assertEqual(obs(f"run:release:all/{m0}/{m2}|candidate"), "yes")
            self.assertIsNone(obs(f"run:release:all/{m0}/{m2}|deployable"))
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
            self.assertEqual(operator.policy.get("auto_deploy"), "off")
        finally:
            gateway.shutdown()
            gateway.server_close()


if __name__ == "__main__":
    os.chdir(ROOT / "tests")
    unittest.main()
