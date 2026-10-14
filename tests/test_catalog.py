"""The rule catalog (standard/catalog): every ASVS 5.0 requirement accounted for, every name defined, one text for the
agent before coding and in a refusal, and a deterministic choice of what each funnel pass shows."""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from standard.catalog import (CatalogError, applicable, check_value, effective, load, render,  # noqa: E402
                              select, validate)


class Catalog(unittest.TestCase):
    def setUp(self):
        self.cat = load()

    def test_every_asvs_requirement_is_carried_once_or_set_aside_with_a_reason(self):
        levels, aside = self.cat["asvs"]["levels"], self.cat["asvs"]["set_aside"]
        carried = [a for r in self.cat["rules"] for a in r["asvs"]]
        self.assertEqual(len(levels), 345)
        self.assertEqual(len(carried), len(set(carried)))
        self.assertEqual(set(carried) | set(aside), set(levels))
        self.assertEqual({k: sum(v == k for v in aside.values()) for k in ("doc", "infra", "socle")},
                         {"doc": 33, "infra": 9, "socle": 2})

    def test_no_rule_keeps_a_vague_word_and_every_value_is_named(self):
        vague = ("sensitive data", "critical function", "appropriate", "trusted source", "high-value")
        for r in self.cat["rules"]:
            text = (r["do"] + " " + r.get("never", "")).lower()
            for word in vague:
                self.assertNotIn(word, text, r["id"])

    def test_a_broken_catalog_is_refused(self):
        def broken(change):
            cat = copy.deepcopy(self.cat)
            change(cat)
            with self.assertRaises(CatalogError):
                validate(cat)
        broken(lambda c: c["rules"][0].update(when=["construct:teleport"]))
        broken(lambda c: c["rules"][0].update(asvs=c["rules"][0]["asvs"] + ["1.2.5"]))      # carried twice
        broken(lambda c: c["rules"].pop())                                                    # ASVS left over
        broken(lambda c: c["rules"][0].update(do="Refuse above @nowhere"))
        broken(lambda c: c["rules"][0].update(check=["probe:mind-reading"]))
        broken(lambda c: c["rules"][0].update(block="", absorb="full"))
        broken(lambda c: c["rules"][0].update(check=["patrol"], who=["det"]))
        broken(lambda c: c["blocks"]["web"]["bans"].append("rm -rf /"))

    def test_team_only_rules_wait_for_a_team(self):
        one = {r["id"] for r in applicable(self.cat, ["api", "high-value"])}
        team = {r["id"] for r in applicable(self.cat, ["api", "high-value", "team"])}
        self.assertNotIn("MULTI-APPROVAL", one)
        self.assertIn("MULTI-APPROVAL", team)

    def test_each_pass_shows_only_what_the_change_triggers(self):
        features = ["api", "web", "database", "oidc", "upload", "crypto", "outbound-http", "lang:python"]
        wide = [r["id"] for r in select(self.cat, features, ["surface:endpoint"], "wide")]
        self.assertIn("NO-OWN-AUTH", wide)
        self.assertNotIn("PWD-POLICY", wide)                   # the identity provider's, checked by probes
        self.assertNotIn("NO-OWN-AUTH", [r["id"] for r in select(self.cat, features, [], "wide")])
        self.assertEqual(select(self.cat, features, [], "fine"), [])                    # nothing touched
        fine = [r["id"] for r in select(self.cat, features, ["construct:sql-call"], "fine")]
        self.assertEqual(fine, ["INJ-SQL"])
        medium = [r["id"] for r in select(self.cat, features, ["surface:upload-endpoint"], "medium")]
        self.assertIn("UPLOAD-LIMITS", medium)
        self.assertNotIn("INJ-SQL", medium)
        again = [r["id"] for r in select(self.cat, list(reversed(features)), ["surface:upload-endpoint"], "medium")]
        self.assertEqual(medium, again)                                                  # deterministic
        typical = applicable(self.cat, features)
        text = [r for r in typical if r["absorb"] == "none"]
        self.assertLess(len(text), 20)                       # what the AI keeps as text for a typical product

    def test_the_rule_text_resolves_values_and_says_when_one_is_missing(self):
        upload = next(r for r in self.cat["rules"] if r["id"] == "UPLOAD-LIMITS")
        values = effective(self.cat, {"upload_max_bytes": 2_000_000})
        block = render(upload, values)
        self.assertIn("@upload_max_bytes=2000000", block)
        self.assertIn("@archive_max_files=100", block)                                  # strict default
        self.assertIn("py ok", block)
        self.assertTrue(render(upload, values, full=False).startswith("UPLOAD-LIMITS"))
        retention = next(r for r in self.cat["rules"] if r["id"] == "RETENTION")
        self.assertIn("not set: uncovered", render(retention, effective(self.cat, {})))   # no default that destroys

    def test_values_are_checked_before_anyone_signs_them(self):
        self.assertEqual(check_value(self.cat, "origins", ["https://a.example"]), ["https://a.example"])
        for name, bad in (("origins", "https://a.example"), ("upload_max_bytes", -1), ("mfa", "nobody"),
                          ("nonexistent", 1), ("access", {"orders.read": 3.5})):
            with self.assertRaises(CatalogError):
                check_value(self.cat, name, bad)

    def test_the_catalog_is_part_of_the_release(self):
        from standard.runtime import CATALOG_DATA, code_digest
        import tempfile, shutil
        root = Path(tempfile.mkdtemp())
        for part in ("kernel", "bt", "standard"):
            shutil.copytree(ROOT / part, root / part, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(ROOT / "requirements.hashes", root / "requirements.hashes")
        before = code_digest(root)
        rule = root / "standard" / "catalog" / "rules" / "injection.toml"
        rule.write_text(rule.read_text().replace("bound parameter", "parameter"))
        self.assertNotEqual(code_digest(root), before)
        self.assertIn("values.toml", CATALOG_DATA)


if __name__ == "__main__":
    unittest.main()
