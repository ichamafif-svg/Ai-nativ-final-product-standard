"""Refactoring must keep trust boundaries enforced and pin privileged product assembly."""
import tempfile
import unittest
import shutil
from pathlib import Path

from bt.release import code_digest as core_digest
from standard.runtime import SOURCES, code_digest as installation_digest
from tools.check_layers import ALLOWED, imports, violations
from tools.coverage import inventory
from standard.autonomy.read_model import compliance_reading, human_target, work_role
from standard.autonomy.work import WorkEngine
from tomllib import loads as parse_toml


class Structure(unittest.TestCase):
    def test_progress_failures_exclude_required_stops_and_closed_debt(self):
        with tempfile.TemporaryDirectory() as root:
            engine = WorkEngine(Path(root) / "work.db")
            task = {"id": "o:repair", "obligation": "o", "need": "repair", "resource": "repo:code:x",
                    "due": 5, "state": "AVAILABLE", "routes": [{"route": "agent", "state": "AVAILABLE"}]}
            projection = {"mode": "RUN", "basis": {"head": "h"}, "tasks": [task]}
            engine.sync(projection)
            engine.record(at=6, mode="RUN", task=task, basis=projection["basis"], main="m",
                          outcome="progress_failure", reason_code="budget_exhausted")
            self.assertEqual(WorkEngine.read_progress(engine.path)["pf"], 1)
            engine.sync({**projection, "tasks": [{**task, "state": "TRUST_BLOCKED"}]})
            self.assertEqual(engine.progress()["pf"], 0)
            self.assertEqual(len(engine.progress()["waiting"]), 1)
            engine.sync({**projection, "tasks": []})
            self.assertEqual(engine.progress()["pf"], 0)

    def test_new_basis_releases_old_retry_and_lease(self):
        with tempfile.TemporaryDirectory() as root:
            engine = WorkEngine(Path(root) / "work.db")
            task = {"id": "o:repair", "obligation": "o", "need": "repair", "resource": "repo:code:x",
                    "due": 5, "state": "AVAILABLE", "routes": []}
            projection = {"mode": "RUN", "basis": {"head": "old"}, "tasks": [task]}
            engine.sync(projection)
            claimed = engine.claim(mode="RUN", now=10)
            engine.complete_attempt(mode="RUN", task_id=task["id"], lease_until=claimed["lease_until"],
                                    next_at=999)
            self.assertIsNone(engine.claim(mode="RUN", now=11))
            engine.sync({**projection, "basis": {"head": "new"}})
            self.assertEqual(engine.claim(mode="RUN", now=11)["attempt"], 1)

    def test_human_work_is_declared_not_inferred_from_resource_prefix(self):
        target = {"id": "client-org", "resource": "org:client:custom", "repair": "remediate"}
        self.assertFalse(human_target(target))
        self.assertEqual(work_role(target)["level"], "supervised")
        self.assertTrue(human_target({**target, "human": True}))

    def test_coarse_compliance_never_claims_satisfaction(self):
        target = {"id": "isms", "resource": "org:isms:policy"}
        held = compliance_reading(target, "held", "HEALTHY")
        self.assertTrue(held)
        self.assertTrue(all(row["status"] == "partial" and not row["certifies"] for row in held))
        self.assertTrue(all(row["status"] == "fault" for row in compliance_reading(target, "held", "FAULT")))

    def test_installation_toml_uses_a_complete_parser(self):
        self.assertEqual(parse_toml('name = "a#b"\n[agent]\nscopes = ["code", "tests"]'),
                         {"name": "a#b", "agent": {"scopes": ["code", "tests"]}})

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

    def test_every_privileged_source_changes_the_release_digest(self):
        for source in SOURCES:
            source_path = Path(__file__).resolve().parents[1] / source
            path = self.root / source
            if source_path.is_file():
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, path)
            else:
                shutil.copytree(source_path, path, dirs_exist_ok=True)
        original = installation_digest(self.root)
        for source in SOURCES:
            path = self.root / source
            files = [path] if path.is_file() else sorted(path.rglob("*.py"))
            for file in files:
                previous = file.read_text()
                file.write_text(previous + "y = 2\n")
                self.assertNotEqual(installation_digest(self.root), original, file)
                file.write_text(previous)


if __name__ == "__main__":
    unittest.main()
