"""The rule catalog (catalog): every ASVS 5.0 requirement accounted for, every name defined, one text for the
agent before coding and in a refusal, and a deterministic choice of what each candidate workflow pass shows."""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catalog import (CatalogError, applicable, check_value, effective, load, render,  # noqa: E402
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
        broken(lambda c: c["rules"][0].update(held_by="the wall, somehow"))
        broken(lambda c: c["rules"][0].pop("held_by"))
        broken(lambda c: c["rules"][0].update(check=["patrol"], who=["det"]))
        broken(lambda c: c["blocks"]["web"]["stacks"]["nextjs"]["bans"].append("rm -rf /"))
        broken(lambda c: c["blocks"]["web"]["stacks"].update(rails={"module": "x", "use": "x", "bans": []}))

    def test_every_rule_says_who_holds_it_and_blocks_left_in_code_stay_with_their_rules(self):
        holders = {r["id"]: r["held_by"] for r in self.cat["rules"]}
        self.assertEqual(len(holders), 156)
        for r in self.cat["rules"]:
            if r["block"] in ("access", "render", "front") and r["held_by"].startswith("code:"):
                self.assertEqual(r["held_by"], f"code:{r['block']}")
        self.assertEqual({r["held_by"] for r in self.cat["rules"] if r["block"] == "idp"}, {"idp"})

    def test_team_only_rules_wait_for_a_team(self):
        one = {r["id"] for r in applicable(self.cat, ["api", "high-value"])}
        team = {r["id"] for r in applicable(self.cat, ["api", "high-value", "team"])}
        self.assertNotIn("MULTI-APPROVAL", one)
        self.assertIn("MULTI-APPROVAL", team)

    def test_selection_uses_applicability_and_touched_surfaces_without_passes(self):
        features = ["api", "web", "database", "oidc", "upload", "crypto", "outbound-http", "lang:python"]
        endpoint = [r["id"] for r in select(self.cat, features, ["surface:endpoint"])]
        self.assertIn("NO-OWN-AUTH", endpoint)
        self.assertNotIn("PWD-POLICY", endpoint)
        self.assertNotIn("NO-OWN-AUTH", [r["id"] for r in select(self.cat, features, [])])
        sql = [r["id"] for r in select(self.cat, features, ["construct:sql-call"])]
        self.assertIn("INJ-SQL", sql)
        upload = [r["id"] for r in select(self.cat, features, ["surface:upload-endpoint"])]
        self.assertIn("UPLOAD-LIMITS", upload)
        self.assertNotIn("INJ-SQL", upload)
        self.assertEqual(upload, [r["id"] for r in select(self.cat, list(reversed(features)), ["surface:upload-endpoint"])])
        self.assertTrue(all("pass" not in r for r in self.cat["rules"]))

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

    def test_catalog_compiles_the_same_targets_and_policy_used_by_the_law_and_editor(self):
        from catalog import targets, policy_values, instruction, definition
        from catalog.floors import FLOORS, RECOMMENDED
        from context.policy import SCHEMA, change
        self.assertEqual(targets(self.cat), FLOORS["targets"])
        self.assertEqual(policy_values("floor"), FLOORS["settings"])
        self.assertEqual(SCHEMA.keys(), self.cat["policy"]["parameter"].keys())
        self.assertEqual(policy_values("recommended")["objective"], RECOMMENDED["settings"]["objective"])
        self.assertIn("never by weakening tests", instruction("ci"))
        self.assertTrue(all("instruction" not in t for t in FLOORS["targets"]))
        self.assertEqual(definition({"id": "client-custom", "resource": "repo:custom"})["origin"],
                         "client law; no catalog mapping")
        with self.assertRaises(ValueError):
            change({}, settings={"canary_percent": 51})
        with self.assertRaises(ValueError):
            change({}, settings={"research_steps": 10})

    def test_contracts_preserve_exact_policy_and_separate_absorption_from_evidence(self):
        from catalog import contracts, render_contracts
        values = effective(self.cat, {"access": {"orders.read": ["buyer"]}})
        packet = contracts(self.cat, ["api"], values, ids={"AUTHZ"}, stacks=["nextjs"])
        text = render_contracts(packet)
        self.assertIn('"orders.read": ["buyer"]', text)
        self.assertIn("access.route", text)
        self.assertIn("unauthenticated", text)
        self.assertIn("critical", packet["parameters"])
        self.assertIn("public", packet["parameters"])
        self.assertIn("partial", text)
        self.assertIn("not evidence", text)
        self.assertEqual(packet["rules"][0]["checks"], next(r["check"] for r in self.cat["rules"] if r["id"] == "AUTHZ"))

    def test_python_primitives_and_framework_integrations_have_one_resolved_contract(self):
        import tomllib
        from catalog import compact, contracts, implementation, render_contracts
        from instruments.coverage import adoptable, evaluate
        from instruments.surfaces import scan
        from test_surfaces import Tree

        declared = tomllib.loads((ROOT / "catalog/blocks.toml").read_text())["block"]
        generic = {"crypto", "outbound", "parse", "process", "input", "data", "render", "log", "runtime"}
        for name in generic:
            self.assertIn("python", declared[name])
            self.assertNotIn("fastapi", declared[name])    # one definition, inherited by the supported framework
            self.assertEqual(implementation(self.cat, name, "python"), implementation(self.cat, name, "fastapi"))
            for stack in ("python", "fastapi"):
                self.assertEqual(adoptable(compact(self.cat)["blocks"][name], stack),
                                 implementation(self.cat, name, stack)["module"])
        for name in ("web", "session", "access", "files"):
            self.assertIsNone(implementation(self.cat, name, "python"))
            self.assertIsNotNone(implementation(self.cat, name, "fastapi"))

        tree = Tree({"agent.py": "from standard_blocks.outbound import request\n"
                                "request('GET', 'docs', endpoints=endpoints, values=values)\n"})
        product = scan(tree)
        self.assertEqual(product["stacks"], ["python"])
        text = render_contracts(contracts(self.cat, product["features"], effective(self.cat, {}),
                                         ids={"RUN-TIMEOUTS"}, stacks=product["stacks"]))
        self.assertIn("python: standard_blocks.outbound", text)
        self.assertNotIn("fastapi:", text)
        for source, stack in ((tree.read("agent.py"), "python"),
                              (b"from fastapi import FastAPI\n" + tree.read("agent.py"), "fastapi")):
            candidate = Tree({"agent.py": source})
            self.assertEqual(scan(candidate)["stacks"], [stack])
            states = evaluate(candidate, compact(self.cat), effective(self.cat, {}), probes={}, bandit={})
            self.assertEqual(states["RUN-TIMEOUTS"]["checks"]["blocks"][0], "pass")
            bare = Tree({"agent.py": ("from fastapi import FastAPI\n" if stack == "fastapi" else "") +
                                    "import httpx\nhttpx.get(url)\n"})
            self.assertEqual(evaluate(bare, compact(self.cat), effective(self.cat, {}), probes={}, bandit={})
                             ["RUN-TIMEOUTS"]["checks"]["blocks"][0], "fail")

    def test_malformed_maintenance_and_policy_declarations_are_refused(self):
        for mutate in (lambda c: c["targets"][0].update(fresh_ms=0),
                       lambda c: c["targets"].append(c["targets"][0]),
                       lambda c: c["policy"]["parameter"]["objective"].update(bounds=["99", "50"]),
                       lambda c: c["policy"]["section"]["slos"].update(fields=["unregistered"])):
            cat = copy.deepcopy(self.cat)
            mutate(cat)
            with self.assertRaises(CatalogError):
                validate(cat)

    def test_the_catalog_is_part_of_the_release(self):
        from runtime import CATALOG_DATA, code_digest
        import tempfile, shutil
        root = Path(tempfile.mkdtemp())
        for part in ("kernel", "bt", "runtime", "catalog", "blocks"):
            shutil.copytree(ROOT / part, root / part, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(ROOT / "requirements.hashes", root / "requirements.hashes")
        before = code_digest(root)
        rule = root / "catalog" / "rules" / "injection.toml"
        rule.write_text(rule.read_text().replace("bound parameter", "parameter"))
        self.assertNotEqual(code_digest(root), before)
        self.assertIn("values.toml", CATALOG_DATA)
        for name in ("maintenance.toml", "policy.toml"):
            self.assertIn(name, CATALOG_DATA)
            source = root / "catalog" / name
            baseline = code_digest(root)
            source.write_text(source.read_text() + "\n# pin check\n")
            self.assertNotEqual(code_digest(root), baseline)


if __name__ == "__main__":
    unittest.main()
