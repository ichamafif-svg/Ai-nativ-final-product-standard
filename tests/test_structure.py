"""Refactoring must keep trust boundaries enforced and pin privileged product assembly."""
import tempfile
import unittest
from pathlib import Path

from bt.release import code_digest as core_digest
from product.runtime import SOURCES, code_digest as installation_digest
from tools.check_layers import ALLOWED, imports, violations


class Structure(unittest.TestCase):
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
        self.write("product/autonomy/agent.py", "from ..runtime import daemon\nfrom bt import Guard\n")
        problems = violations(self.root)
        self.assertTrue(any("product.runtime" in p for p in problems), problems)
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
        path = self.write("product/autonomy/__init__.py", "from . import agent\nfrom bt.gateway import GatewayClient\n")
        self.write("product/autonomy/agent.py", "")
        self.assertIn("product.autonomy.agent", imports(path, self.root))
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
        runtime = self.write("product/runtime/operator.py", "VERSION = 1\n")
        self.assertEqual(core_digest(self.root), core)
        self.assertNotEqual(installation_digest(self.root), installed)
        bound = installation_digest(self.root)
        runtime.write_text("VERSION = 2\n")
        self.assertNotEqual(installation_digest(self.root), bound)
        (self.root / "product/floors.py").unlink()
        with self.assertRaises(FileNotFoundError):
            installation_digest(self.root)


if __name__ == "__main__":
    unittest.main()
