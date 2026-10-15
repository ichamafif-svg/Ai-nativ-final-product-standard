"""Candidate suites stay blocked until T06 confines both network and filesystem."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_maintenance import FILES, demo_repository  # noqa: E402

from bt.host import Evidence, Host  # noqa: E402
from bt.isolation import Isolation  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

RUNNER = "standard-runner"


class Isolated(unittest.TestCase):
    def test_the_command_drops_privileges_network_and_environment(self):
        cmd = Isolation("runner").command(["python3", "-m", "pytest"], {"PATH": "/usr/bin"})
        self.assertEqual(cmd[:4], ["sudo", "-n", "-u", "runner"])
        self.assertIn("unshare", cmd)
        self.assertIn("-i", cmd)                                         # nothing of the guard's environment
        self.assertNotIn("unshare", Isolation("runner").command(["pip"], {}, network=True))
        self.assertFalse(Isolation().isolated)
        self.assertFalse(Isolation("no-such-account-here").candidate_fs_confined)

    def test_candidate_job_fails_closed_before_running_any_code(self):
        root = Path(tempfile.mkdtemp())
        marker = root / "executed"
        repo = demo_repository(root, {**FILES, "tests/test_hostile.py":
                               f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"})
        main = subprocess.run(["git", "-C", str(repo), "rev-parse", "main"], capture_output=True, text=True).stdout.strip()
        # A runner account the bac cannot run under here: no candidate code at all.
        host = Host(ROOT, Evidence(root / "evidence"), repo, isolation=Isolation("no-such-account-here"))
        out, _ = host.call("contribution", {"base": {"commit": main}, "head": {"commit": main},
                                            "author": {"value": "eve"}, "targets": {"value": []}})
        self.assertEqual(out, {"error": "candidate filesystem isolation unavailable"})
        self.assertFalse(marker.exists())

    def test_no_runner_user_is_no_candidate_code_never_the_operator_account(self):
        """Falsifier (review, critical 1): without [tests] runner_user, candidate code ran as the operator."""
        root = Path(tempfile.mkdtemp())
        marker = root / "executed"
        repo = demo_repository(root, {**FILES, "tests/test_hostile.py":
                               f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"})
        main = subprocess.run(["git", "-C", str(repo), "rev-parse", "main"], capture_output=True, text=True).stdout.strip()
        host = Host(ROOT, Evidence(root / "evidence"), repo)
        out, _ = host.call("contribution", {"base": {"commit": main}, "head": {"commit": main},
                                            "author": {"value": "eve"}, "targets": {"value": []}})
        self.assertEqual(out, {"error": "candidate filesystem isolation unavailable"})
        self.assertFalse(marker.exists())

    def test_a_contribution_runs_in_the_bac_under_the_runner_account_and_reaches_nothing_else(self):
        """D68: T06 is the bac inside the runner account; the code runs, measured, without keys or network."""
        import pwd
        try:
            pwd.getpwnam(RUNNER)
        except KeyError:
            self.skipTest(f"no {RUNNER} account here")
        isolation = Isolation(RUNNER)
        if not isolation.candidate_fs_confined:
            self.skipTest(f"the bac does not run under {RUNNER} here: {isolation.bac and isolation.bac.why}")
        root = Path(tempfile.mkdtemp())
        secret = root / "guard.key"
        secret.write_text("PRIVATE")
        probe = (f"from pathlib import Path\nimport socket\n"
                 f"def test_reach():\n"
                 f"    assert not Path({str(secret)!r}).exists()\n"
                 f"    try:\n        socket.create_connection(('1.1.1.1', 443), 2)\n        assert False\n"
                 f"    except OSError:\n        pass\n")
        repo = demo_repository(root, {**FILES, "tests/test_reach.py": probe})
        main = subprocess.run(["git", "-C", str(repo), "rev-parse", "main"], capture_output=True, text=True).stdout.strip()
        host = Host(ROOT, Evidence(root / "evidence"), repo, isolation=isolation)
        out, _ = host.call("contribution", {"base": {"commit": main}, "head": {"commit": main},
                                            "author": {"value": "eve"}, "targets": {"value": []}})
        self.assertNotIn("error", out, out)
        facts = {f[1]: f[2] for f in out.get("facts", [])}
        self.assertEqual(facts.get("tests"), "green", out)

    def test_unconfined_is_explicit_and_demo_only(self):
        from runtime.operator import isolation
        self.assertFalse(isolation({}, demo=True).may_run_candidates)
        self.assertTrue(isolation({"tests": {"unconfined": True}}, demo=True).may_run_candidates)
        with self.assertRaises(ValueError):
            isolation({"tests": {"unconfined": True}}, demo=False)
        with self.assertRaises(ValueError):
            Isolation("runner", unconfined=True)


if __name__ == "__main__":
    unittest.main()
