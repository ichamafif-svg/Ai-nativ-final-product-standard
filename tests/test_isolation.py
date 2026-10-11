"""A contribution's code, run by the trusted side to measure `tests`, cannot read the guard's keys nor reach the
network (D33). Runs only where the runner account exists and this process may sudo to it."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_maintenance import FILES, demo_repository  # noqa: E402

from trusted.host import Evidence, Host  # noqa: E402
from trusted.isolation import Isolation  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

RUNNER = "standard-runner"


def can_run_as_runner() -> bool:
    try:
        return subprocess.run(["sudo", "-n", "-u", RUNNER, "--", "/usr/bin/env", "-i", "true"],
                              capture_output=True, timeout=20).returncode == 0
    except OSError:
        return False


class Isolated(unittest.TestCase):
    def test_the_command_drops_privileges_network_and_environment(self):
        cmd = Isolation("runner").command(["python3", "-m", "pytest"], {"PATH": "/usr/bin"})
        self.assertEqual(cmd[:4], ["sudo", "-n", "-u", "runner"])
        self.assertIn("unshare", cmd)
        self.assertIn("-i", cmd)                                         # nothing of the guard's environment
        self.assertNotIn("unshare", Isolation("runner").command(["pip"], {}, network=True))
        self.assertFalse(Isolation().isolated)

    @unittest.skipUnless(can_run_as_runner(), "no runner account on this host")
    def test_a_hostile_contribution_cannot_reach_a_secret_nor_the_network(self):
        root = Path(tempfile.mkdtemp())
        secret = root / "keys"
        secret.mkdir(mode=0o700)
        (secret / "guard.key").write_text("TOP-SECRET")
        hostile = (
            "import urllib.request\n\n\n"
            f"def test_steal():\n    assert open('{secret}/guard.key').read() == 'TOP-SECRET'\n\n\n"
            "def test_call_home():\n    urllib.request.urlopen('http://127.0.0.1:1', timeout=2)\n\n\n"
            "def test_ok():\n    assert True\n")
        repo = demo_repository(root, {**FILES, "tests/test_hostile.py": hostile})
        main = subprocess.run(["git", "-C", str(repo), "rev-parse", "main"], capture_output=True, text=True).stdout.strip()
        host = Host(ROOT, Evidence(root / "evidence"), repo, isolation=Isolation(RUNNER))
        out, _ = host.call("contribution", {"base": {"commit": main}, "head": {"commit": main},
                                            "author": {"value": "eve"}, "targets": {"value": []}})
        tests = next(f for f in out["facts"] if f[1] == "tests")
        failed = " ".join(d.splitlines()[0] for d in tests[3])
        self.assertIn("test_steal", failed)                              # the key file is out of reach
        self.assertIn("test_call_home", failed)                          # no network at all
        self.assertNotIn("test_ok", failed)
        self.assertEqual(tests[2], "found:2")
        self.assertEqual(os.listdir(secret), ["guard.key"])


if __name__ == "__main__":
    unittest.main()
