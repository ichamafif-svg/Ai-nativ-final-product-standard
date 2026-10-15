"""D69: a refusal of the platform in production is a measured defect of the code, and so a task for the agent."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.catalog.floors import FLOORS  # noqa: E402
from engine.verification.production import platform_refusals  # noqa: E402
from engine.verification.scope import repair  # noqa: E402


def lines(*records):
    return "\n".join(json.dumps(r) for r in records)


class ProductionRefusals(unittest.TestCase):
    def test_corrections_and_refusals_are_findings_imposed_and_alarms_are_not(self):
        text = lines({"kind": "correction", "capability": "ingress.cookies", "route": "GET /cart", "attempt": "cookie cart"},
                     {"kind": "refusal", "capability": "egress.destination", "route": "GET api.x", "attempt": "not listed"},
                     {"kind": "imposed", "capability": "ingress.headers", "route": "GET /", "attempt": "csp added"},
                     {"kind": "alarm", "capability": "egress.secret", "route": "GET evil", "attempt": "secret"})
        status, details = platform_refusals([(1, None), (2, text)])
        self.assertEqual(status, "found:2")
        self.assertEqual(len(details), 2)
        self.assertFalse(any("evil" in d or "csp" in d for d in details))

    def test_no_capture_is_uncovered_and_a_clean_record_is_none(self):
        self.assertTrue(platform_refusals([(1, None)])[0].startswith("uncovered"))
        self.assertEqual(platform_refusals([(1, "")])[0], "none")

    def test_the_target_exists_and_the_agent_may_repair_it_in_the_code(self):
        target = next(t for t in FLOORS["targets"] if t["id"] == "run-platform")
        self.assertEqual((target["resource"], target["property"], target["expect"]),
                         ("repo:code:platform", "refusals", "none"))
        self.assertTrue(repair("run-platform", "app/main.py"))
        self.assertFalse(repair("run-platform", "tests/test_x.py"))


if __name__ == "__main__":
    unittest.main()
