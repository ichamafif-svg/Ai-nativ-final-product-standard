"""Acceptance tests drafted by a separate agent from the specification alone, for the human to sign (D70)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.agents.acceptance import HEADER, DraftError, draft, validate  # noqa: E402


class Research:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def worker(self, prompt, role, **kw):
        self.calls.append((prompt, role, kw))
        return self.reply


class Acceptance(unittest.TestCase):
    def test_a_separate_read_only_agent_drafts_from_the_specification_alone(self):
        research = Research({"tests": "def test_total():\n    assert 1 + 1 == 2\n", "uncovered": ["latency"]})
        result = draft(research, "Totals add up.", tree=object())
        prompt, role, kw = research.calls[0]
        self.assertEqual(role, "acceptance")
        self.assertTrue(kw["read_only"])
        self.assertIn("Totals add up.", prompt)
        self.assertTrue(result["tests"].startswith(HEADER))
        self.assertEqual(result["uncovered"], ["latency"])
        self.assertIn("the human signs", result["authority"])

    def test_a_draft_without_a_parseable_test_is_refused(self):
        for reply in ({}, {"tests": "def broken(:"}, {"tests": "def helper():\n    pass\n"}):
            with self.assertRaises(DraftError):
                validate(reply)


if __name__ == "__main__":
    unittest.main()
