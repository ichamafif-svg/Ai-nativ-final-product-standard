"""The feedback matrix (D70): one way back, keyed by rule; one filter; no rule's strongest source ever weakens."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catalog import load  # noqa: E402
from context.feedback import STRENGTH, item, matrix, render, route  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class Matrix(unittest.TestCase):
    def setUp(self):
        self.m = matrix(load())

    def test_every_rule_has_a_place_and_a_contract_before_coding(self):
        self.assertEqual(len(self.m["rules"]), 156)
        self.assertTrue(all(r["sources"]["before"] == ["contract"] for r in self.m["rules"].values()))
        self.assertEqual(sum(self.m["totals"].values()), 156)

    def test_business_intent_stays_in_review_until_it_is_declared(self):
        for rid in ("DATA-MIN", "VALIDATE-COMBO", "TRANSACTION", "LOCKING", "CONCURRENCY", "MULTI-APPROVAL"):
            self.assertIn(rid, self.m["review_only"])

    def test_a_planned_wall_gives_no_strength(self):
        ssrf = self.m["rules"]["SSRF"]
        self.assertIn("wall", ssrf["sources"]["build"])               # it teaches in the precheck
        self.assertEqual(ssrf["sources"]["run"], ["wall (planned)"])  # it does not yet hold in production
        self.assertNotEqual(ssrf["strength"], "wall")

    def test_no_rule_loses_its_strongest_source(self):
        floor = json.loads((ROOT / "catalog" / "feedback_floor.json").read_text())
        self.assertEqual(set(floor), set(self.m["rules"]), "every rule has a floor; a new rule adds its own")
        weaker = [rid for rid, r in self.m["rules"].items() if STRENGTH[r["strength"]] < STRENGTH[floor[rid]]]
        self.assertEqual(weaker, [], "a source may only be removed when one at least as strong replaces it")


class Filter(unittest.TestCase):
    def test_one_item_per_rule_and_place_whatever_the_sources(self):
        a = item("lesson", "wall", "build", rules=["SSRF"], where="network.outbound", attempt="x")
        b = item("lesson", "wall", "build", rules=["SSRF"], where="network.outbound", attempt="y")
        self.assertEqual(len(route([a, b])["agent"]), 1)

    def test_facts_first_then_what_the_candidate_introduced(self):
        old = item("lesson", "lint", "build", where="a.py", attempt="old", new=False)
        new = item("lesson", "lint", "build", where="b.py", attempt="new")
        fact = item("lesson", "probe:sast", "build", where="sast", trust="fact")
        self.assertEqual([e["attempt"] for e in route([old, new, fact])["agent"]], ["", "new", "old"])

    def test_alarms_never_reach_the_agent_and_needs_go_to_the_human(self):
        dossier = route([item("alarm", "wall", "run", where="escape"), item("need", "wall", "build", where="@hosts")])
        self.assertEqual(dossier["agent"], [])
        self.assertEqual(len(dossier["hidden control"]), 1)
        self.assertEqual(len(dossier["human"]), 1)
        self.assertNotIn("escape", render(dossier))

    def test_nothing_outside_the_one_format_is_said(self):
        entry = item("lesson", "wall", "build", where="filesystem", attempt="x", mechanism="seccomp rule 12")
        self.assertNotIn("mechanism", route([entry])["agent"][0])

    def test_the_budget_keeps_the_first_items_and_says_how_many_wait(self):
        many = [item("lesson", "lint", "build", where=f"f{i}.py", attempt="e" * 200) for i in range(50)]
        dossier = route(many, budget=2000)
        self.assertLess(len(dossier["agent"]), 50)
        self.assertEqual(len(dossier["agent"]) + dossier["deferred_for_agent"], 50)
        self.assertIn("more items", render(dossier))

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(ValueError):
            item("opinion", "patrol", "build")


if __name__ == "__main__":
    unittest.main()
