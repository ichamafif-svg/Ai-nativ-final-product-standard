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
from trusted.gateway import AdmissionGateway  # noqa: E402

A, B, C = "a" * 40, "b" * 40, "c" * 40


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


class Metrics:
    """A product's cumulative histogram, advanced by each scrape: `errors` of every 100 requests fail."""

    def __init__(self):
        self.count = self.failed = 0
        self.errors = 0

    def __call__(self, url):
        self.count, self.failed = self.count + 100, self.failed + self.errors
        ok = self.count - self.failed
        return "\n".join([
            f'http_server_request_duration_seconds_bucket{{http_route="/orders",http_response_status_code="200",le="0.1"}} {ok}',
            f'http_server_request_duration_seconds_bucket{{http_route="/orders",http_response_status_code="200",le="+Inf"}} {ok}',
            f'http_server_request_duration_seconds_count{{http_route="/orders",http_response_status_code="200"}} {ok}',
            f'http_server_request_duration_seconds_bucket{{http_route="/orders",http_response_status_code="500",le="0.1"}} {self.failed}',
            f'http_server_request_duration_seconds_bucket{{http_route="/orders",http_response_status_code="500",le="+Inf"}} {self.failed}',
            f'http_server_request_duration_seconds_count{{http_route="/orders",http_response_status_code="500"}} {self.failed}',
        ])


class Facts(unittest.TestCase):
    def test_main_is_deployable_unless_it_was_rolled_back(self):
        facts, _ = runtime.release_facts("met", A, B, [], set(), 0)
        self.assertIn(("run:release:all", "lag", "behind"), facts)
        self.assertIn((f"run:release:all/{A}/{B}", "deployable", "yes"), facts)
        facts, why = runtime.release_facts("met", A, B, [{"at": 0, "op": "rollback", "from": B, "to": A}], set(), 0)
        self.assertEqual(facts, [("run:release:all", "lag", "behind")])
        self.assertIn("new commit", why["deploy"])
        self.assertEqual(runtime.release_facts("met", B, B, [], set(), 0)[0], [("run:release:all", "lag", "none")])

    def test_a_rollback_needs_a_fresh_switch_and_a_release_known_good(self):
        history = [{"at": 1_000, "op": "deploy", "from": A, "to": B}]
        facts, _ = runtime.release_facts("breached:1", B, B, history, {A}, 1_000 + 60_000)
        self.assertIn((f"run:service:all/{B}/{A}", "regressed", "yes"), facts)
        facts, why = runtime.release_facts("breached:1", B, B, history, set(), 61_000)       # A never proved good
        self.assertNotIn("regressed", str(facts))
        facts, why = runtime.release_facts("breached:1", B, B, history, {A}, 1_000 + 3_600_000)   # too late: people
        self.assertNotIn("regressed", str(facts))
        self.assertIn("not attributable", why["rollback"])
        self.assertNotIn("regressed", str(runtime.release_facts("uncovered:1", B, B, history, {A}, 61_000)[0]))

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


class Switch(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp())
        self.repo = demo_repository(root, FILES)
        self.main = git("rev-parse", "main", cwd=self.repo)
        self.releases = Releases(self.repo, root / "run")

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
        self.assertEqual([h["to"] for h in r.history()], [main])

    def test_a_restart_that_fails_is_unknown(self):
        self.releases.restart = ["false"]
        self.assertEqual(self.releases.switch("r", {"from": "none", "to": self.main}, "k"), "unknown")
        self.assertTrue(self.releases.applied(self.main))


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
        metrics = Metrics()
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
        finally:
            gateway.shutdown()
            gateway.server_close()


if __name__ == "__main__":
    os.chdir(ROOT / "tests")
    unittest.main()
