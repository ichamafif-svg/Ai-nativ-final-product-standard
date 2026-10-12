"""Refactoring must keep trust boundaries enforced and pin privileged product assembly."""
import tempfile
import unittest
from pathlib import Path

from bt.release import code_digest as core_digest
from standard.runtime import SOURCES, code_digest as installation_digest
from tools.check_layers import ALLOWED, imports, violations
from tools.coverage import inventory


class Structure(unittest.TestCase):
    def test_coverage_does_not_invent_an_instrument_for_a_declared_target(self):
        rows = {r["target"]: r for r in inventory()}
        self.assertEqual(rows["ci"]["measurement"], "REGISTERED")
        self.assertEqual(rows["ci"]["repair"], "model + human review")
        unknown = {"id": "unknown", "resource": "repo:code:new", "property": "safe"}
        self.assertEqual(inventory([unknown])[0]["measurement"], "MISSING")

    def test_coverage_distinguishes_recipes_attestations_and_conditional_production(self):
        rows = {r["target"]: r for r in inventory()}
        self.assertEqual({tid for tid, r in rows.items() if r["repair"] == "recipe + review fallback"},
                         {"sbom", "vulns", "actions"})
        self.assertEqual(rows["backup"]["measurement"], "MANUAL")
        self.assertEqual(rows["run-slo"]["measurement"], "CONDITIONAL")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for layer in ALLOWED:
            path = self.root / layer
            if path.suffix == ".py":
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("")
            else:
                path.mkdir(parents=True, exist_ok=True)
                (path / "__init__.py").write_text("")

    def write(self, name, source):
        path = self.root / name
        path.write_text(source)
        return path

    def test_product_cannot_reach_the_privileged_runtime_or_guard(self):
        self.write("standard/autonomy/agent.py", "from ..runtime import daemon\nfrom bt import Guard\n")
        problems = violations(self.root)
        self.assertTrue(any("standard.runtime" in p for p in problems), problems)
        self.assertTrue(any("imports bt:" in p for p in problems), problems)

    def test_kernel_and_programs_cannot_import_physical_effects(self):
        self.write("kernel/judge.py", "import socket\n")
        self.write("instruments/jobs.py", "from bt.signing import Signer\n")
        problems = violations(self.root)
        self.assertTrue(any("kernel/judge.py imports socket" in p for p in problems), problems)
        self.assertTrue(any("instruments/jobs.py imports bt.signing" in p for p in problems), problems)

    def test_second_judge_cannot_reuse_the_first_or_reach_it_indirectly(self):
        self.write("kernel/judge.py", "")
        self.write("bt/service.py", "")
        self.write("bt/checker.py", "from kernel import judge\nfrom . import service\n")
        problems = violations(self.root)
        self.assertTrue(any("second judge" in p and "kernel.judge" in p for p in problems), problems)
        self.assertTrue(any("second judge" in p and "bt.service" in p for p in problems), problems)

    def test_relative_imports_of_packages_resolve_within_the_correct_role(self):
        path = self.write("standard/autonomy/__init__.py", "from . import agent\nfrom bt.gateway import GatewayClient\n")
        self.write("standard/autonomy/agent.py", "")
        self.assertIn("standard.autonomy.agent", imports(path, self.root))
        self.assertEqual(violations(self.root), [])

    def test_privileged_product_code_stays_bound_to_the_installation(self):
        for source in SOURCES:
            path = self.root / source
            if path.suffix == ".py":
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            else:
                path.mkdir(parents=True, exist_ok=True)
                (path / "__init__.py").touch()
        core, installed = core_digest(self.root), installation_digest(self.root)
        runtime = self.write("standard/runtime/operator.py", "VERSION = 1\n")
        self.assertEqual(core_digest(self.root), core)
        self.assertNotEqual(installation_digest(self.root), installed)
        bound = installation_digest(self.root)
        runtime.write_text("VERSION = 2\n")
        self.assertNotEqual(installation_digest(self.root), bound)
        (self.root / "standard/floors.py").unlink()
        with self.assertRaises(FileNotFoundError):
            installation_digest(self.root)


if __name__ == "__main__":
    unittest.main()
