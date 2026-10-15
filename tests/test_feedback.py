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
        for rid in ("VALIDATE-COMBO", "TRANSACTION", "LOCKING", "CONCURRENCY", "MULTI-APPROVAL"):
            self.assertIn(rid, self.m["review_only"])
        self.assertEqual(self.m["rules"]["DATA-MIN"]["strength"], "measured")   # declared (@field_uses), so probed

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


class Tree:
    def __init__(self, files):
        self.files = {p: c.encode() for p, c in files.items()}

    def paths(self):
        return list(self.files)

    def read(self, path):
        return self.files[path]


class BeforeCoding(unittest.TestCase):
    TREE = Tree({"app/billing.py": "def charge(a):\n    return a\n\n\ndef refund(a):\n    return -a\n",
                 "app/tax.py": "def vat(a):\n    '''Value added tax.'''\n    return a * 0.2\n",
                 "app/api.py": "from app.billing import charge\n\n\ndef pay(x):\n    return charge(x)\n",
                 "tests/test_billing.py": "from app.billing import charge\n\n\ndef test_charge():\n"
                                          "    assert charge(1) == 1\n"})

    def test_touched_definitions_come_with_their_tests_callers_and_neighbours(self):
        from context.repository import RepoMap
        reading = RepoMap(self.TREE).reading(["app/billing.py"])["app/billing.py"]
        charge = reading["definitions"]["def charge(a)"]
        self.assertEqual(charge, {"tests": ["tests/test_billing.py"], "code": ["app/api.py"]})
        self.assertEqual(reading["untested"], ["def refund(a)"])
        self.assertIn("app/tax.py", reading["reuse"])
        self.assertNotIn("tests/test_billing.py", reading["reuse"])

    def test_the_mission_carries_it_before_coding(self):
        from context.missions import assemble
        packet = json.loads(assemble({}, self.TREE, role="build", focus=["app/billing.py"])[0])["packet"]
        self.assertIn("app/billing.py", packet["before_coding"])


class Views(unittest.TestCase):
    def test_the_matrix_and_the_first_pass_rate_are_shown_to_people(self):
        import tempfile
        from agent.attempts import first_pass, record
        from surface.cli import matrix_text
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "attempts.jsonl")
            record(path, "repair", "secrets", 1, True)
            record(path, "repair", "deps", 2, True)
            record(path, "build", "r1", 2, False)
            self.assertEqual(first_pass(path), {"tasks": 3, "passed": 2, "first_attempt": 1, "rate": 0.333})
            text = matrix_text(attempts=path)
        self.assertIn("review only (16)", text)
        self.assertIn("first-attempt passes: 1 of 3", text)
        self.assertIn("held by platform:egress", matrix_text("SSRF"))


class Admission(unittest.TestCase):
    def test_a_refutation_reaches_the_agent_as_facts_tied_to_rules(self):
        from agent.repair import admission_feedback
        resource = "repo:code:x/b/h"
        findings = {f"{resource}|blocks": {"details": ["SSRF: app.py:3:call:requests.get"]},
                    f"{resource}|tests": {"details": ["test_app::test_add failed"]}}
        text = admission_feedback(findings, resource)
        self.assertIn("[admission:blocks] rules SSRF", text)
        self.assertIn("[admission:tests]", text)
        self.assertLess(text.index("admission:blocks"), text.index("admission:tests"))
