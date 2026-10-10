"""A demo installation, as an operator runs it: ceremony in two phases, the operator process, the agent process.

Time is simulated so that FLOOR-0's one-hour delay passes in the test; nothing else is stubbed.
"""
import argparse
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from test_maintenance import FILES, demo_repository

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import ceremony  # noqa: E402

import autonomy.__main__ as agent_process  # noqa: E402
import trusted.daemon as daemon  # noqa: E402
from trusted.gateway import AdmissionGateway  # noqa: E402


class Clock:
    def __init__(self, start):
        self.t = start

    def __call__(self):
        self.t += 1
        return self.t


class Installation(unittest.TestCase):
    def test_from_ceremony_to_an_autonomous_repair(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, FILES)
        clock = Clock(1_900_000_000_000)
        ceremony.now = daemon.now_ms = clock
        ceremony.init(argparse.Namespace(dir=str(root / "install"), repo=str(repo), github=None, token_file=None,
                                         pins=str(root / "elsewhere" / "pins.db")))
        clock.t += 3_600_100
        ceremony.activate(argparse.Namespace(dir=str(root / "install")))

        operator = daemon.Installation(root / "install" / "standard.toml")
        self.assertEqual(operator.service.status()["assessment"], "SELF_ASSESSED")
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        try:
            cycle, refresh = agent_process.build(root / "install" / "standard.toml")
            cycle.clock, cycle.backoff_ms = clock, 0
            for _ in range(3):
                operator.tick()
                refresh()
                cycle.run()
            operator.tick()
            state = operator.journal.snapshot()
            self.assertEqual(state["observations"]["repo:supply:sbom|state|scanner"]["status"], "current")
            files = __import__("subprocess").run(["git", "-C", str(repo), "ls-tree", "--name-only", "main"],
                                                 capture_output=True, text=True).stdout.split()
            self.assertIn("sbom.json", files)
            self.assertEqual(len([i for i in state["intents"].values() if i["op"] == "remediate"]), 1)
        finally:
            gateway.shutdown()
            gateway.server_close()

    def test_qualification_names_every_premise_a_demo_does_not_hold(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, FILES)
        ceremony.now = Clock(1_900_000_000_000)
        ceremony.init(argparse.Namespace(dir=str(root / "install"), repo=str(repo), github=None, token_file=None,
                                         pins=None))
        import qualify
        report = {p["probe"]: p for p in qualify.qualify(root / "install" / "standard.toml")}
        failed = {name for name, p in report.items() if p["result"] == "FAIL"}
        self.assertTrue({"T04 pins apart from the journal", "T02 humans hold their own keys",
                         "T03 witnesses apart from the operator", "independent assessment",
                         "T07 only the guard moves main"} <= failed)
        self.assertTrue(all(p["does_not_prove"] for p in report.values()))


class GitHubAdapter(unittest.TestCase):
    def github(self, replies):
        from trusted.github import GitHub
        calls = []

        def transport(method, url, token, body=None):
            calls.append((method, url, body))
            return replies.pop(0)
        return GitHub("acme/app", "token", transport=transport), calls

    def test_main_moves_only_from_the_judged_base(self):
        base, head = "a" * 40, "b" * 40
        gh, calls = self.github([(200, {"node_id": "R_1"}), (200, {"data": {"updateRefs": {}}})])
        self.assertEqual(gh.remediate("repo:x:y", {"base": base, "head": head}, "k"), "ok")
        variables = calls[1][2]["variables"]
        self.assertEqual((variables["before"], variables["after"]), (base, head))
        self.assertIn("force: false", calls[1][2]["query"])

    def test_a_refusal_is_failed_a_lost_answer_is_unknown(self):
        args = {"base": "a" * 40, "head": "b" * 40}
        gh, _ = self.github([(200, {"node_id": "R_1"}), (200, {"errors": [{"message": "stale beforeOid"}]})])
        self.assertEqual(gh.remediate("r", args, "k"), "failed")
        gh, _ = self.github([(200, {"node_id": "R_1"}), (502, {})])
        self.assertEqual(gh.remediate("r", args, "k"), "unknown")
        gh, _ = self.github([(500, {})])
        self.assertEqual(gh.remediate("r", args, "k"), "failed")             # nothing was sent

    def test_the_git_route_is_the_same_compare_and_swap(self):
        from trusted.github import GitHub
        root = Path(tempfile.mkdtemp())
        origin = demo_repository(root, FILES)
        git = lambda *a: __import__("subprocess").run(["git", *a], check=True, capture_output=True, text=True).stdout.strip()
        git("-C", str(origin), "config", "receive.denyCurrentBranch", "ignore")
        mirror = root / "mirror"
        git("clone", "-q", "--mirror", str(origin), str(mirror))
        base = git("-C", str(mirror), "rev-parse", "main")
        tree = git("-C", str(mirror), "rev-parse", "main^{tree}")
        head = git("-C", str(mirror), "commit-tree", tree, "-p", base, "-m", "next")
        other = git("-C", str(mirror), "commit-tree", tree, "-p", base, "-m", "other")
        gh = GitHub("acme/app", "token", push_from=mirror)
        self.assertEqual(gh.remediate("r", {"base": other, "head": head}, "k"), "failed")   # main is not that base
        self.assertEqual(gh.remediate("r", {"base": base, "head": head}, "k"), "ok")
        self.assertEqual(git("-C", str(origin), "rev-parse", "main"), head)

    def test_readback_never_concludes_absence(self):
        gh, _ = self.github([(200, {"status": "ahead"}), (200, {"status": "diverged"})])
        self.assertTrue(gh.applied("b" * 40))
        self.assertFalse(gh.applied("b" * 40))


class Refresh(unittest.TestCase):
    def test_a_snapshot_audits_the_fixed_versions_too(self):
        import refresh_data
        answers = {"24.1": [{"id": "GHSA-1", "affected": [{"ranges": [{"events": [{"fixed": "24.2"}]}]}]}], "24.2": []}

        def get(url, body=None):
            if "osv" in url:
                return {"vulns": answers[body["version"]]}
            return {"info": {"version": "25.0", "license_expression": "Apache-2.0", "classifiers": []}}
        refresh_data.get = get
        path = Path(tempfile.mkdtemp()) / "requirements.txt"
        path.write_text("packaging==24.1\n")
        snap = refresh_data.snapshot(path)
        self.assertEqual(snap["advisories"], {"packaging==24.1": [{"id": "GHSA-1", "fix_versions": ["24.2"]}],
                                              "packaging==24.2": []})


if __name__ == "__main__":
    unittest.main()
