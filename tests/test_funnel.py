"""The funnel (standard/autonomy/funnel.py): three prompts, each with only the rules the change can act on, chosen
deterministically; banned APIs left in the draft go back with the block that covers them; a refusal is explained
with the rule's own text."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from standard.autonomy.funnel import JUDGED, Funnel, Overlay, explain, record  # noqa: E402
from standard.catalog import effective, load  # noqa: E402


class Tree:
    def __init__(self, files):
        self.files = {p: c.encode() for p, c in files.items()}

    def paths(self):
        return set(self.files)

    def read(self, p):
        return self.files[p]


BASE = Tree({"shop/main.py": "from fastapi import FastAPI\nfrom standard_blocks.web import secure_app\n"
                             "app = secure_app(FastAPI())\n",
             "shop/util.py": "from standard_blocks.process import run\n\ndef convert(a, b):\n    return run(['convert', a, b])\n"})


class Passes(unittest.TestCase):
    def test_three_prompts_each_with_what_the_draft_triggers(self):
        prompts, replies = [], [
            {"title": "export", "files": {"shop/export.py": "import os\n\ndef export(name):\n    os.system('zip ' + name)\n"}},
            {"files": {"shop/export.py": "from standard_blocks.process import run\n\ndef export(name):\n"
                                         "    run(['zip', name])\n"}}]

        def ask(text, name):
            prompts.append((name, text))
            return replies.pop(0)
        values = effective(load(), None)
        result, stats = Funnel().run(ask, BASE, "Add an export.", values=values, scope_ok=lambda p: p.startswith("shop/"))
        self.assertEqual([n for n, _ in prompts], ["wide", "fine"])            # no surface: no medium pass
        self.assertTrue(stats["passes"][1]["skipped"])
        self.assertTrue(all(JUDGED in t for _, t in prompts))
        fine = prompts[1][1]
        self.assertIn("shop/export.py:4:call:os.system", fine)                      # the banned API, exactly
        self.assertIn("block process", fine)                                        # and the block that covers it
        self.assertIn("shop/util.py:4: return run(['convert', a, b])", fine)        # how this repository does it
        self.assertIn("INJ-CMD", fine)
        self.assertEqual(stats["remaining"], [])
        self.assertIn("run(['zip', name])", result["files"]["shop/export.py"])
        self.assertIn('"pass": "fine"', record(stats))

    def test_a_pass_with_nothing_selected_is_skipped_and_scope_is_kept(self):
        names = []

        def ask(text, name):
            names.append(name)
            return {"files": {"README.md": "docs\n"}}
        _, stats = Funnel().run(ask, BASE, "Fix the docs.", values={}, scope_ok=lambda p: True)
        self.assertEqual(names, ["wide"])
        self.assertTrue(all(p.get("skipped") for p in stats["passes"][1:]))
        with self.assertRaises(ValueError):
            Funnel().run(lambda t, n: {"files": {"tests/x.py": ""}}, BASE, "x", values={},
                         scope_ok=lambda p: not p.startswith("tests/"))

    def test_a_refusal_is_explained_with_the_text_seen_before_coding(self):
        text = explain(["shop/x.py:3:call:hashlib.md5", "rules-authorization: AUTHZ: probe:access-matrix fail"])
        self.assertIn("block crypto", text)
        self.assertIn("AUTHZ  [wide", text)
        self.assertIn("allow(id)", text)
        self.assertEqual(Overlay(BASE, {"a.py": "x"}).read("a.py"), b"x")


class Patrol(unittest.TestCase):
    def test_each_round_reads_one_category_of_ai_rules_in_a_fixed_order(self):
        import tempfile
        from standard.autonomy.patrol import patrol_rules, rotation
        from standard.catalog import categories
        state = Path(tempfile.mkdtemp()) / "rotation.json"
        rounds = [rotation(state) for _ in range(len(categories()) + 1)]
        self.assertEqual(rounds[:-1], categories())
        self.assertEqual(rounds[-1], categories()[0])                              # and again
        rules = patrol_rules("input-and-business-logic", effective(load(), None), ["api", "database"])
        self.assertTrue(any(r.startswith("TRANSACTION") for r in rules))
        self.assertFalse(any(r.startswith("BIZ-LIMITS") for r in rules))          # deterministic and human only


if __name__ == "__main__":
    unittest.main()
