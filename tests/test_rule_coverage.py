"""Coverage of the rule catalog (engine/verification/coverage.py, rule_probes.py): Standard's own probes start the product's
app and tell a product built on the blocks from the same product written the usual way; each category of rules is a
socle target whose debt is the failing and unmeasured rules; a change that breaks a rule is a regression."""
import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine.verification import coverage, probes  # noqa: E402
from engine.verification.tree import verdict  # noqa: E402
from engine.catalog import compact, effective, load  # noqa: E402
from engine.catalog.floors import FLOORS  # noqa: E402

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False

SHOP = ROOT / "examples" / "shop"
BLOCKS = str(ROOT / "blocks" / "python")


class Tree:
    def __init__(self, files, commit):
        self.files, self.commit = files, commit

    @classmethod
    def of(cls, folder):
        return cls({str(p.relative_to(folder)): p.read_bytes() for p in Path(folder).rglob("*.py")}, folder.name)

    def paths(self):
        return set(self.files)

    def read(self, p):
        return self.files[p]


@unittest.skipUnless(HAVE, "the blocks' dependencies")
class Coverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = load()
        cls.values = effective(cls.cat, {"app": "shop.main:app", "upload_types": ["image/png"],
                                         "access": {"orders.read": ["clerk"], "orders.create": ["clerk"],
                                                    "files.upload": ["clerk"]}})
        cls.ctx = {"rules": {"catalog": compact(cls.cat), "values": cls.values, "paths": [BLOCKS]}}
        cls.good, cls.bad = Tree.of(SHOP / "good"), Tree.of(SHOP / "bad")
        cls.states = {name: probes.rule_states(tree, cls.ctx) for name, tree in (("good", cls.good), ("bad", cls.bad))}

    def test_the_product_on_blocks_holds_what_the_usual_one_breaks(self):
        good, bad = Counter(s["state"] for s in self.states["good"].values()), \
            Counter(s["state"] for s in self.states["bad"].values())
        self.assertEqual(good["failing"], 0, [r for r, s in self.states["good"].items() if s["state"] == "failing"])
        self.assertGreater(bad["failing"], 20)
        for rule in ("AUTHZ", "HASH", "CSPRNG", "PATH-SAFE", "UPLOAD-LIMITS", "METHODS", "ERROR-GENERIC",
                     "MASS-ASSIGN", "LOG-METADATA"):
            self.assertEqual(self.states["bad"][rule]["state"], "failing", rule)
        self.assertEqual(self.states["bad"]["CANON"]["state"], "uncovered")         # no input block: a debt to adopt it
        for rule in ("AUTHZ", "CORS", "UPLOAD-LIMITS", "SESSION-ROTATE", "MASS-ASSIGN"):
            self.assertIn(self.states["good"][rule]["state"], ("measured", "partial"), rule)
        probe = self.states["good"]["SESSION-ROTATE"]["checks"]["probe:session-rotation"]
        self.assertEqual(probe[0], "pass")                             # signed in twice through a fake provider
        self.assertEqual(self.states["bad"]["UPLOAD-LIMITS"]["checks"]["probe:upload-limits"][0], "fail")

    def test_each_category_is_a_target_whose_debt_is_failing_or_unmeasured_rules(self):
        targets = {t["id"]: t for t in FLOORS["targets"] if t["id"].startswith("rules-")}
        self.assertEqual(len(targets), 17)
        for tid, target in targets.items():
            good = verdict(target["expect"], probes.probe_for(tid)(self.good, self.ctx))
            self.assertEqual(good, "none", (tid, probes.probe_for(tid)(self.good, self.ctx).details))
        bad = probes.probe_for("rules-authorization")(self.bad, self.ctx)
        self.assertNotEqual(verdict("none", bad), "none")
        self.assertIn("AUTHZ", bad.findings)                                     # failing: the probe saw it
        undeclared = {"rules": {**self.ctx["rules"], "values": {k: v for k, v in self.values.items() if k != "app"}}}
        unmeasured = verdict("none", probes.probe_for("rules-browser")(self.good, undeclared))
        self.assertTrue(unmeasured.startswith("uncovered:"), unmeasured)          # declare @app: a product debt

    def test_a_change_that_goes_around_a_block_is_a_regression(self):
        targets = {t["id"]: t for t in FLOORS["targets"]}
        worse = Tree({**self.good.files, "shop/extra.py": b"import hashlib\nhashlib.md5(b'x')\n"}, "worse")
        status, details = probes.regressions(self.good, worse, targets, self.ctx)
        self.assertNotEqual(status, "none")
        self.assertTrue(any(d.startswith("rules-cryptography") for d in details), details)
        same, _ = probes.regressions(self.good, Tree(dict(self.good.files), "same"), targets, self.ctx)
        self.assertEqual(same, "none")

    def test_patrolled_and_gap_rules_are_visible_never_debt(self):
        states = self.states["good"]
        self.assertEqual(states["TRANSACTION"]["state"] if "TRANSACTION" in states else "n/a", "n/a")  # no database
        self.assertEqual(states["VALIDATE-COMBO"]["state"], "patrolled")
        self.assertEqual(states["AUTH-PATHS"]["state"], "partial")                  # a probe, and the patrol
        measure = coverage.category_measure(states, compact(self.cat), "input-and-business-logic")
        self.assertNotIn("VALIDATE-COMBO", measure.universe)


if __name__ == "__main__":
    unittest.main()
