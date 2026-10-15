"""Refactoring must keep trust boundaries enforced and pin privileged product assembly."""

import tempfile
import unittest
import shutil
from pathlib import Path

from fabric.control.bt.release import code_digest as core_digest
from fabric.control.runtime import SOURCES, code_digest as installation_digest
from tools.check_layers import ALLOWED, imports, violations
from tools.coverage import inventory
from interface.context.model import human_target, work_role
from engine.catalog.floors import FLOORS
from engine.agents.work import WorkEngine
from tomllib import loads as parse_toml


class Structure(unittest.TestCase):
    def test_progress_failures_exclude_required_stops_and_closed_debt(self):
        with tempfile.TemporaryDirectory() as root:
            engine = WorkEngine(Path(root) / "work.db")
            task = {
                "id": "o:repair",
                "obligation": "o",
                "need": "repair",
                "resource": "repo:code:x",
                "due": 5,
                "state": "AVAILABLE",
                "routes": [{"route": "agent", "state": "AVAILABLE"}],
            }
            projection = {"mode": "RUN", "basis": {"head": "h"}, "tasks": [task]}
            engine.sync(projection)
            engine.record(
                at=6,
                task=task,
                basis=projection["basis"],
                main="m",
                outcome="progress_failure",
                reason_code="budget_exhausted",
            )
            self.assertEqual(WorkEngine.read_progress(engine.path)["pf"], 1)
            engine.sync({**projection, "tasks": [{**task, "state": "TRUST_BLOCKED"}]})
            self.assertEqual(engine.progress()["pf"], 0)
            self.assertEqual(len(engine.progress()["waiting"]), 1)
            engine.sync({**projection, "tasks": []})
            self.assertEqual(engine.progress()["pf"], 0)

    def test_new_basis_releases_old_retry_and_lease(self):
        with tempfile.TemporaryDirectory() as root:
            engine = WorkEngine(Path(root) / "work.db")
            task = {
                "id": "o:repair",
                "obligation": "o",
                "need": "repair",
                "resource": "repo:code:x",
                "due": 5,
                "state": "AVAILABLE",
                "routes": [],
            }
            projection = {"mode": "RUN", "basis": {"head": "old"}, "tasks": [task]}
            engine.sync(projection)
            claimed = engine.claim(now=10)
            engine.complete_attempt(task_id=task["id"], lease_until=claimed["lease_until"], next_at=999)
            self.assertIsNone(engine.claim(now=11))
            engine.sync({**projection, "basis": {"head": "new"}})
            self.assertEqual(engine.claim(now=11)["attempt"], 1)

    def test_who_repairs_follows_the_routes_in_force_not_the_resource_prefix(self):
        target = {"id": "client-thing", "resource": "repo:client:custom", "repair": "remediate"}
        self.assertFalse(human_target(target))
        self.assertEqual(work_role(target, FLOORS)["level"], "autonomous")
        human_only = {
            **FLOORS,
            "ops": {**FLOORS["ops"], "remediate": {**FLOORS["ops"]["remediate"], "routes": {"human": {"all": []}}}},
        }
        self.assertEqual(work_role(target, human_only)["level"], "decision")
        self.assertTrue(human_target({**target, "human": True}))

    def test_installation_toml_uses_a_complete_parser(self):
        self.assertEqual(
            parse_toml('name = "a#b"\n[agent]\nscopes = ["code", "tests"]'),
            {"name": "a#b", "agent": {"scopes": ["code", "tests"]}},
        )

    def test_coverage_does_not_invent_an_instrument_for_a_declared_target(self):
        rows = {r["target"]: r for r in inventory()}
        self.assertEqual(rows["ci"]["measurement"], "REGISTERED")
        self.assertEqual(rows["ci"]["repair"], "model in scope")
        unknown = {"id": "unknown", "resource": "repo:code:new", "property": "safe"}
        self.assertEqual(inventory([unknown])[0]["measurement"], "MISSING")

    def test_coverage_distinguishes_recipes_human_repairs_and_conditional_production(self):
        rows = {r["target"]: r for r in inventory()}
        self.assertEqual(
            {tid for tid, r in rows.items() if r["repair"] == "recipe, else model in scope"},
            {"sbom", "vulns", "actions"},
        )
        self.assertEqual(rows["branch"]["repair"], "human")
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
        self.write("engine/agents/repair.py", "from fabric.control.runtime import operator\nfrom bt import Guard\n")
        problems = violations(self.root)
        self.assertTrue(any("runtime" in p for p in problems), problems)
        self.assertTrue(any("imports bt:" in p for p in problems), problems)

    def test_kernel_and_programs_cannot_import_physical_effects(self):
        self.write("fabric/control/kernel/judge.py", "import socket\n")
        self.write("engine/verification/jobs.py", "from fabric.control.bt.signing import Signer\n")
        problems = violations(self.root)
        self.assertTrue(any("fabric/control/kernel/judge.py imports socket" in p for p in problems), problems)
        self.assertTrue(any("engine/verification/jobs.py imports fabric.control.bt.signing" in p for p in problems), problems)

    def test_second_judge_cannot_reuse_the_first_or_reach_it_indirectly(self):
        self.write("fabric/control/kernel/judge.py", "")
        self.write("fabric/control/bt/service.py", "")
        self.write("fabric/control/bt/checker.py", "from fabric.control.kernel import judge\nfrom . import service\n")
        problems = violations(self.root)
        self.assertTrue(any("second judge" in p and "fabric.control.kernel.judge" in p for p in problems), problems)
        self.assertTrue(any("second judge" in p and "fabric.control.bt.service" in p for p in problems), problems)

    def test_blocks_cannot_reach_authority_and_judges_cannot_import_blocks(self):
        self.write("fabric/control/kernel/judge.py", "from blocks.python.standard_blocks import crypto\n")
        self.write("fabric/control/bt/checker.py", "from standard_blocks.crypto import same\n")
        self.write("blocks/escape.py", "from fabric.control.bt.service import TrustedService\n")
        problems = violations(self.root)
        for path in ("fabric/control/kernel/judge.py", "fabric/control/bt/checker.py", "blocks/escape.py"):
            self.assertTrue(any(p.startswith(path + " imports ") for p in problems), problems)

    def test_relative_imports_of_packages_resolve_within_the_correct_role(self):
        path = self.write("engine/agents/__init__.py", "from . import repair\nfrom fabric.control.bt.gateway import GatewayClient\n")
        self.write("engine/agents/repair.py", "")
        self.assertIn("engine.agents.repair", imports(path, self.root))
        self.assertEqual(violations(self.root), [])

    def test_privileged_product_code_stays_bound_to_the_installation(self):
        for source in SOURCES:
            path = self.root / source
            if path.suffix:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            else:
                path.mkdir(parents=True, exist_ok=True)
                (path / "__init__.py").touch()
        from fabric.control.runtime import CATALOG_DATA

        (self.root / "engine/catalog/rules").mkdir(parents=True, exist_ok=True)
        for name in CATALOG_DATA:
            (self.root / 'engine/catalog' / name).touch()
        core, installed = core_digest(self.root), installation_digest(self.root)
        runtime = self.write("fabric/control/runtime/operator.py", "VERSION = 1\n")
        self.assertEqual(core_digest(self.root), core)
        self.assertNotEqual(installation_digest(self.root), installed)
        bound = installation_digest(self.root)
        runtime.write_text("VERSION = 2\n")
        self.assertNotEqual(installation_digest(self.root), bound)
        (self.root / "engine/catalog/floors.py").unlink()
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

    def test_core_and_program_pins_include_executable_ancestor_packages_and_runtime_profiles(self):
        from fabric.control.bt.release import CORE
        from fabric.control.bt.host import programs_digest
        for source in CORE:
            source_path = Path(__file__).resolve().parents[1] / source
            target = self.root / source
            target.parent.mkdir(parents=True, exist_ok=True)
            if source_path.is_file():
                shutil.copy2(source_path, target)
            else:
                shutil.copytree(source_path, target, dirs_exist_ok=True)
        core = core_digest(self.root)
        for name in ("fabric/control/__init__.py", "fabric/runtime/__init__.py", "fabric/runtime/profiles.py"):
            path = self.root / name
            before = path.read_text()
            path.write_text(before + "\nMUTATION = True\n")
            self.assertNotEqual(core_digest(self.root), core, name)
            path.write_text(before)
        programs = programs_digest(self.root)
        parent = self.root / "engine/__init__.py"
        parent.write_text("MUTATION = True\n")
        self.assertNotEqual(programs_digest(self.root), programs)

    def test_namespace_roots_cannot_reintroduce_runtime_into_the_kernel_import_path(self):
        self.write("fabric/__init__.py", "import os\n")
        self.assertTrue(any("namespace root must remain inert" in p for p in violations(self.root)))


class WorkMigration(unittest.TestCase):
    def test_old_partitions_collapse_without_losing_deadlines_attempts_or_leases(self):
        import json
        import sqlite3
        from engine.agents.work import WorkError

        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "work.db"
            db = sqlite3.connect(path)
            db.execute(
                "CREATE TABLE tasks (mode TEXT,id TEXT,obligation TEXT,need TEXT,resource TEXT,due INTEGER,"
                "state TEXT,task TEXT,attempts INTEGER,next_at INTEGER,lease_until INTEGER,basis TEXT,PRIMARY KEY(mode,id))"
            )
            db.execute(
                "CREATE TABLE events (id INTEGER PRIMARY KEY,at INTEGER,mode TEXT,task_id TEXT,obligation TEXT,"
                "basis TEXT,main TEXT,attempt INTEGER,route TEXT,outcome TEXT,reason_code TEXT,detail TEXT)"
            )
            task = {
                "id": "o:repair",
                "obligation": "o",
                "need": "repair",
                "resource": "repo:code:x",
                "due": 12,
                "state": "AVAILABLE",
                "routes": [],
            }
            basis = json.dumps({"head": "h"}, sort_keys=True)
            for mode, due, attempts, next_at, lease in [("BUILD", 5, 2, 100, 999), ("RUN", 12, 3, 200, 1000)]:
                db.execute(
                    "INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        mode,
                        task["id"],
                        "o",
                        "repair",
                        task["resource"],
                        due,
                        "AVAILABLE",
                        json.dumps(task),
                        attempts,
                        next_at,
                        lease,
                        basis,
                    ),
                )
            db.execute(
                "INSERT INTO events VALUES (1,3,?,?,?,?,?,?,?,?,?,?)",
                ("RUN", "o:repair", "o", basis, "main", 3, "agent", "progress_failure", "budget_exhausted", "detail"),
            )
            db.commit()
            db.close()
            self.assertEqual(WorkEngine.read_progress(path)["status"], "unavailable")
            engine = WorkEngine(path)
            self.assertEqual(len(engine.tasks()), 1)
            self.assertEqual((engine.tasks()[0]["due"], engine.tasks()[0]["attempts"]), (5, 5))
            self.assertEqual(engine.progress()["pf"], 1)
            self.assertIsNone(engine.claim(now=999))
            claimed = engine.claim(now=1001)
            self.assertEqual((claimed["due"], claimed["attempt"]), (5, 6))
            with self.assertRaises(WorkError):
                engine.complete_attempt(task_id=task["id"], lease_until=1000, next_at=0)
            engine.complete_attempt(task_id=task["id"], lease_until=claimed["lease_until"], next_at=2000)
            self.assertIsNone(engine.claim(now=1999))
            self.assertEqual(WorkEngine(path).tasks()[0]["due"], 5)


if __name__ == "__main__":
    unittest.main()
