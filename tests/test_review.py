"""Falsifiers of the October 2026 code review: each test reproduces a finding and must stay green afterwards."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fixture import Ledger  # noqa: E402
from instruments.data import TrustedData  # noqa: E402
from instruments.recipes import vulns  # noqa: E402


class Files:
    def __init__(self, files):
        self.f = files

    def paths(self):
        return set(self.f)

    def read(self, path):
        return self.f[path]


def snapshot(advisories):
    return TrustedData({"format": "standard-data/1", "taken_at": 1, "advisories": advisories})


class VulnerabilityRecipe(unittest.TestCase):
    """Review, high 3: the smallest fix of every branch was a major downgrade, merged without a human."""

    def test_never_moves_a_pin_backwards_or_to_another_major(self):
        data = snapshot({"django==4.2.0": [{"id": "GHSA-x", "fix_versions": ["3.2.19", "4.1.9", "4.2.1"]}]})
        self.assertEqual(vulns(Files({"requirements.txt": b"django==4.2.0\n"}), data),
                         {"requirements.txt": b"django==4.2.1\n"})

    def test_no_fix_on_the_pin_s_line_is_no_recipe(self):
        data = snapshot({"lib==1.4.0": [{"id": "A", "fix_versions": ["0.9.9", "2.0.0"]}]})
        self.assertIsNone(vulns(Files({"requirements.txt": b"lib==1.4.0\n"}), data))

    def test_every_advisory_is_fixed_and_commit_ids_are_ignored(self):
        data = snapshot({"lib==1.4.0": [{"id": "A", "fix_versions": ["1.4.2", "a" * 40]},
                                        {"id": "B", "fix_versions": ["1.5.0"]}]})
        self.assertEqual(vulns(Files({"requirements.txt": b"lib==1.4.0\n"}), data),
                         {"requirements.txt": b"lib==1.5.0\n"})


class HumanReview(unittest.TestCase):
    """Review, critical 2: a machine holding `observe` on the resource signed `review = approved` for itself."""

    def setUp(self):
        self.L = L = Ledger()
        L.checkpoint()
        self.scanner = L.grant("scanner", ["observe", "certify:real"], ["repo:*", "run:*", "build:*"])
        self.reviewer = L.grant("h3", ["observe", "certify:real"], ["repo:*"])
        self.agent = L.grant("agent", ["effect:remediate"], ["repo:*"], ["remediate-reviewed"])
        self.base, self.head = "a" * 40, "b" * 40
        self.res = f"repo:code:secrets/{self.base}/{self.head}"
        L.measure("scanner", self.scanner, self.res, "tests", "green")

    def intent(self):
        return dict(under=self.agent, op="remediate",
                    args={"area": "code", "item": "secrets", "base": self.base, "head": self.head})

    def test_a_machine_review_opens_nothing(self):
        self.L.submit("observation", "scanner", under=self.scanner, resource=self.res, property="review",
                      status="approved", level="real")
        self.assertEqual(self.L.refused("intent", "agent", **self.intent()), "CAP.CONDITION")

    def test_a_human_review_opens_the_reviewed_route(self):
        self.L.submit("observation", "h3", under=self.reviewer, resource=self.res, property="review",
                      status="approved", level="real")
        self.assertIn(self.L.submit("intent", "agent", **self.intent()), self.L.state["intents"])

    def test_the_author_kind_is_a_closed_list(self):
        from kernel.language import LanguageError, compile_program
        with self.assertRaises(LanguageError):
            compile_program({"all": [{"observed": ["review", "approved", "real", "robot"]}]})


if __name__ == "__main__":
    unittest.main()
