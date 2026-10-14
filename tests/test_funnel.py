"""Selected rule context, bounded parallel advisory reviews, one writer and exploratory patrol."""
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
    def test_two_read_only_reviewers_share_one_draft_and_run_in_parallel(self):
        import threading
        barrier, seen = threading.Barrier(2), []
        def ask(text, role, *, tree, read_only, deadline=None):
            seen.append((role, tree.commit if hasattr(tree, "commit") else "base", read_only))
            if role == "build":
                return {"title": "export", "files": {"shop/export.py": "def export(): return 1\n"}}
            self.assertIn(JUDGED, text)
            self.assertIn("smallest design", text)
            barrier.wait(timeout=2)
            with self.assertRaises(TypeError):
                tree.files["changed.py"] = b"no"
            return {"findings": []}
        result, stats = Funnel().run(ask, BASE, "Add an export.", values={}, scope_ok=lambda p: p.startswith("shop/"))
        self.assertEqual({r for r, _, _ in seen}, {"build", "correctness", "simplicity"})
        reviews = [(digest, ro) for role, digest, ro in seen if role != "build"]
        self.assertEqual(reviews[0], reviews[1])
        self.assertTrue(reviews[0][1])
        self.assertEqual(len(stats["rounds"]), 1)
        self.assertIn("shop/export.py", result["files"])
        self.assertIn('"authority": "proposal_only"', record(stats))

    def test_corrections_are_reviewed_again_and_new_surfaces_receive_rules(self):
        seen = []
        def ask(text, role, *, tree, read_only, deadline=None):
            seen.append((role, getattr(tree, "commit", None), text))
            if role == "build":
                return {"files": {"shop/export.py": "import os\nos.system(name)\n"}}
            if role == "correct":
                self.assertIn("INJ-CMD", text)
                return {"files": {"shop/export.py": "from standard_blocks.process import run\nrun(['zip'])\n"},
                        "review_responses": [{"id": "correctness:0", "decision": "fixed", "reason": "use the block"}]}
            if role == "correctness" and "os.system" in tree.read("shop/export.py").decode():
                return {"findings": [{"path": "shop/export.py", "issue": "shell injection", "effect": "executes input",
                                      "suggestion": "use the process block"}]}
            return {"findings": []}
        result, stats = Funnel().run(ask, BASE, "Export.", values={}, scope_ok=lambda p: True)
        self.assertEqual(len(stats["rounds"]), 2)
        self.assertNotEqual(stats["rounds"][0]["candidate"], stats["rounds"][1]["candidate"])
        self.assertEqual(stats["remaining"], [])
        self.assertIn("run", result["files"]["shop/export.py"])
        self.assertTrue(all("INJ-CMD" in text for role, _, text in seen if role in ("correctness", "simplicity")))

    def test_a_review_is_not_an_edit_or_authority_and_failure_is_visible(self):
        flow = Funnel()
        def ask(text, role, **kw):
            return {"files": {"shop/a.py": "x = 1"}} if role == "build" else {"allowed": True, "files": {}}
        with self.assertRaisesRegex(ValueError, "REVIEW_UNAVAILABLE"):
            flow.run(ask, BASE, "Task", values={}, scope_ok=lambda p: True)
        self.assertIn("REVIEW_UNAVAILABLE", flow.last_stats["error"])

    def test_no_effect_out_of_scope_and_missing_deletions_are_refused(self):
        for files in ({"tests/x.py": ""}, {"shop/absent.py": None}, {"../x.py": ""}, {}):
            with self.assertRaises(ValueError):
                Funnel().run(lambda *a, **k: {"files": files}, BASE, "Task", values={},
                             scope_ok=lambda p: not p.startswith("tests/"))
        overlay = Overlay(BASE, {"shop/util.py": None, "a.ts": "export const x = 1"})
        self.assertNotIn("shop/util.py", overlay.paths())
        with self.assertRaises(FileNotFoundError):
            overlay.read("shop/util.py")
        self.assertEqual(overlay.read("a.ts"), b"export const x = 1")

    def test_a_refusal_is_explained_with_the_text_seen_before_coding(self):
        text = explain(["shop/x.py:3:call:hashlib.md5", "rules-authorization: AUTHZ: probe:access-matrix fail"])
        self.assertIn("block crypto", text)
        self.assertIn("AUTHZ  [wide", text)
        self.assertIn("allow(id)", text)

    def test_reasoned_disagreement_is_recorded_without_a_reviewer_veto(self):
        def ask(text, role, **kw):
            if role == "build": return {"files": {"shop/a.py": "x = 1"}}
            if role == "correct": return {"files": {}, "review_responses": [
                {"id": "simplicity:0", "decision": "declined", "reason": "the public contract requires this state"}]}
            return {"findings": [{"path": "shop/a.py", "issue": "extra state", "effect": "more concepts",
                                  "suggestion": "remove it"}]} if role == "simplicity" else {"findings": []}
        result, stats = Funnel().run(ask, BASE, "Task", values={}, scope_ok=lambda p: True)
        self.assertEqual(result["files"], {"shop/a.py": "x = 1"})
        self.assertEqual(stats["rounds"][0]["responses"][0]["decision"], "declined")

    def test_last_round_cannot_publish_a_revision_without_review(self):
        def ask(text, role, **kw):
            if role == "build": return {"files": {"shop/a.py": "x = 1"}}
            if role == "correct": return {"files": {"shop/a.py": "x = 2"}, "review_responses": [
                {"id": "correctness:0", "decision": "fixed", "reason": "corrected the value"}]}
            return {"findings": [{"path": "shop/a.py", "issue": "wrong value", "effect": "wrong result",
                                  "suggestion": "use 2"}]} if role == "correctness" else {"findings": []}
        with self.assertRaisesRegex(ValueError, "budget exhausted"):
            Funnel(rounds=1).run(ask, BASE, "Task", values={}, scope_ok=lambda p: True)

    def test_dependency_design_is_examined_before_the_writer(self):
        seen = []
        base = Tree({"requirements.txt": "packaging==24.1"})
        def ask(text, role, **kw):
            seen.append(role)
            return {"files": {"requirements.txt": "packaging==24.2"}} if role == "build" else {"findings": []}
        Funnel().run(ask, base, "Upgrade", values={}, scope_ok=lambda p: True, focus=["requirements.txt"])
        self.assertEqual(seen[:2], ["design", "build"])

    def test_accepted_contract_is_in_the_shared_draft_but_cannot_be_edited(self):
        path = "tests/acceptance/test_r.py"
        def ask(text, role, *, tree, read_only, deadline=None):
            if role == "build":
                return {"files": {"shop/a.py": "x = 1"}}
            self.assertEqual(tree.read(path), b"assert True")
            return {"action": "finish", "findings": []}
        result, _ = Funnel().run(ask, BASE, "Task", values={}, scope_ok=lambda p: True,
                                fixed_files={path: b"assert True"})
        self.assertNotIn(path, result["files"])
        with self.assertRaises(ValueError):
            Funnel().run(lambda *a, **kw: {"files": {path: None}}, BASE, "Task", values={},
                         scope_ok=lambda p: True, fixed_files={path: b"assert True"})

    def test_a_new_feature_is_included_in_the_review_rules(self):
        source = ("from fastapi import FastAPI, UploadFile\napp = FastAPI()\n@app.post('/files')\n"
                  "async def upload(f: UploadFile): return {}\n")
        def ask(text, role, **kw):
            if role == "build": return {"files": {"app.py": source}}
            self.assertIn("UPLOAD-LIMITS", text)
            return {"findings": []}
        Funnel().run(ask, Tree({}), "Task", values={}, scope_ok=lambda p: True)

    def test_review_timeout_is_visible_and_cannot_return_a_candidate(self):
        import threading
        release = threading.Event()
        flow = Funnel(timeout_s=1)
        def ask(text, role, **kw):
            if role == "build": return {"files": {"shop/a.py": "x = 1"}}
            release.wait(timeout=3)
            return {"findings": []}
        try:
            with self.assertRaisesRegex(ValueError, "REVIEW_UNAVAILABLE"):
                flow.run(ask, BASE, "Task", values={}, scope_ok=lambda p: True)
        finally:
            release.set()
        self.assertIn("TimeoutError", flow.last_stats["error"])


class Patrol(unittest.TestCase):
    def test_each_round_reads_one_category_of_ai_rules_in_a_fixed_order(self):
        import tempfile
        from standard.autonomy.patrol import patrol_rules, rotation
        from standard.catalog import categories
        state = Path(tempfile.mkdtemp()) / "rotation.json"
        rounds = [rotation(state) for _ in range(len(categories()) + 2)]
        self.assertEqual(rounds[:-1], ["simplicity", *categories()])
        self.assertEqual(rounds[-1], "simplicity")                              # and again
        rules = patrol_rules("input-and-business-logic", effective(load(), None), ["api", "database"])
        self.assertTrue(any(r.startswith("TRANSACTION") for r in rules))
        self.assertFalse(any(r.startswith("BIZ-LIMITS") for r in rules))          # deterministic and human only

    def test_simplicity_is_a_design_proposal_and_schedule_failures_are_bounded(self):
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        from standard.autonomy.patrol import Patrol as Scheduled, SIMPLICITY
        root = Path(tempfile.mkdtemp())
        cycle = SimpleNamespace(agent=SimpleNamespace(store=root / "store", llm=object()))
        scheduled = Scheduled(cycle, lambda: "base", clock=lambda: 100, interval_ms=60_000)
        with patch("standard.autonomy.patrol.run_patrol", side_effect=ValueError("model unavailable")) as run:
            self.assertEqual(scheduled.run({}, "base")["state"], "unavailable")
            self.assertEqual(scheduled.run({}, "base")["state"], "waiting")
            self.assertEqual(run.call_count, 1)
        self.assertIn("not a law violation", SIMPLICITY)


class MeasurementFailures(unittest.TestCase):
    def test_bandit_failure_empty_output_partial_report_and_bad_schema_are_not_clean(self):
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        from instruments.coverage import bandit_findings
        cases = [(2, b""), (1, b""), (0, b"{}"), (0, b'{"results": [], "errors": ["skipped file"]}'),
                 (1, b'{"results": [], "errors": []}')]
        for status, output in cases:
            with self.subTest(status=status, output=output), tempfile.TemporaryDirectory() as tmp:
                with patch("instruments.coverage._materialise", return_value=Path(tmp)), patch(
                        "instruments.coverage.subprocess.run", return_value=SimpleNamespace(returncode=status, stdout=output)):
                    with self.assertRaises(ValueError):
                        bandit_findings(Tree({"app.py": "x = 1"}))

    def test_bandit_must_account_for_every_requested_file(self):
        import tempfile
        import json
        from types import SimpleNamespace
        from unittest.mock import patch
        from instruments.coverage import bandit_findings
        tree = Tree({"app.py": "x = 1"})
        for metrics in ({}, {"./app.py": {"loc": 1}}):
            with tempfile.TemporaryDirectory() as tmp, patch("instruments.coverage._materialise", return_value=Path(tmp)), patch(
                    "instruments.coverage.subprocess.run", return_value=SimpleNamespace(
                        returncode=0, stdout=json.dumps({"results": [], "errors": [], "metrics": metrics}).encode())):
                if metrics:
                    self.assertEqual(bandit_findings(tree), {})
                else:
                    with self.assertRaisesRegex(ValueError, "omitted"):
                        bandit_findings(tree)

    def test_import_only_does_not_prove_block_wiring(self):
        from instruments.coverage import evaluate
        cat = load()
        tree = Tree({"app.py": "from fastapi import FastAPI\nfrom standard_blocks.web import secure_app\napp = FastAPI()\n"})
        states = evaluate(tree, cat, effective(cat, None), probes={}, bandit={})
        checks = [r["checks"]["blocks"][0] for r in states.values() if "blocks" in r["checks"]]
        self.assertIn("unrun:wire standard_blocks.web", checks)

    def test_broken_bandit_is_unmeasured_in_rule_coverage(self):
        from unittest.mock import patch
        from instruments.coverage import evaluate
        tree = Tree({"app.py": "from cryptography.fernet import Fernet\nx = Fernet(k)\n"})
        with patch("instruments.coverage.bandit_findings", side_effect=ValueError("bad report")) as scan:
            states = evaluate(tree, load(), effective(load(), None), probes={})
        checks = [v[0] for r in states.values() for k, v in r["checks"].items() if k.startswith("bandit:")]
        self.assertIn("unrun:bandit:ValueError", checks)
        self.assertEqual(scan.call_count, 1)

    def test_js_alias_destructuring_and_literal_members_cannot_hide_the_banned_call(self):
        from instruments.bans import uses, blocks_fact
        patterns = ["js-call:request.json"]
        for source in ("const r = request; r.json();", 'const r = request; r["json"]();',
                       "const {json: read} = request; read();"):
            self.assertTrue(uses("app.ts", source.encode(), patterns), source)
        self.assertFalse(uses("app.ts", b'// request.json()\nconst url = "https://request.json()";', patterns))
        for source in ("request[method]();", "const msg = `x ${request.json()}`;"):
            status, details = blocks_fact(Tree({}), Tree({"app.ts": source}), ["app.ts"], {"input": patterns})
            self.assertEqual(status, "uncovered:analysis")
            self.assertTrue(details)

    def test_dynamic_categories_have_real_registered_measures_and_repair_scopes(self):
        from tools.coverage import inventory
        rows = [r for r in inventory() if r["target"].startswith("rules-")]
        self.assertEqual(len(rows), 17)
        self.assertTrue(all(r["measurement"] == "REGISTERED" and r["repair"] == "model in scope" for r in rows))
        unknown = {"id": "rules-invented", "resource": "repo:rules:invented", "property": "failing"}
        self.assertEqual(inventory([unknown])[0]["measurement"], "MISSING")
        from instruments.coverage import category_measure
        with self.assertRaisesRegex(ValueError, "unknown rule category"):
            category_measure({}, load(), "invented")

    def test_candidate_cannot_replace_or_configure_the_sast_scanner(self):
        from importlib.util import find_spec
        if find_spec("bandit") is None:
            self.skipTest("requires the installed scanner (CI installs the pinned dependency)")
        from instruments.probes import sast
        tree = Tree({"bandit.py": "raise RuntimeError('candidate scanner executed')\n",
                     ".bandit": "[bandit]\nexclude = app.py\n",
                     "app.py": "import subprocess\nsubprocess.run(user_input, shell=True)\n"})
        self.assertIn("B602", sast(tree, {}).findings)


class CandidateChanges(unittest.TestCase):
    def test_deletion_round_trip_preserves_the_base_and_executable_modes(self):
        import subprocess
        from test_agent import store_with, git
        from standard.autonomy.agent import commit_files
        from instruments.tree import Snapshot
        store, base = store_with({"keep.py": "x = 1\n", "remove.py": "unused = True\n", "tests/test_x.py": "assert True"})
        head = commit_files(store, base, {"remove.py": None, "added.ts": b"export const x = 1"}, "simplify")
        self.assertNotIn("remove.py", Snapshot(store, head).paths())
        self.assertIn("remove.py", Snapshot(store, base).paths())
        self.assertEqual(Snapshot(store, head).read("tests/test_x.py"), Snapshot(store, base).read("tests/test_x.py"))
        self.assertEqual(git("-C", str(store), "rev-parse", f"{head}^"), base)
        with self.assertRaises(ValueError):
            commit_files(store, base, {"../escape.py": b""}, "bad")
        with self.assertRaises(ValueError):
            commit_files(store, base, {"absent.py": None}, "bad")
        # An existing executable keeps its mode after an ordinary edit.
        blob = git("-C", str(store), "rev-parse", f"{base}:keep.py")
        git("-C", str(store), "read-tree", base)
        git("-C", str(store), "update-index", "--cacheinfo", f"100755,{blob},keep.py")
        executable = git("-C", str(store), "commit-tree", git("-C", str(store), "write-tree"), "-p", base, "-m", "mode")
        edited = commit_files(store, executable, {"keep.py": b"x = 2\n"}, "edit")
        result = subprocess.run(["git", "-C", str(store), "ls-tree", edited, "--", "keep.py"], capture_output=True, check=True)
        self.assertTrue(result.stdout.startswith(b"100755"))

    def test_nextjs_sources_are_visible_and_writable_without_opening_reserved_paths(self):
        from instruments.scope import feature, repair
        from standard.autonomy.agent import model_context
        from standard.autonomy.repomap import RepoMap
        tree = Tree({"app/(shop)/orders/[id]/route.ts": "export const GET = access.route('orders.read', f);"})
        self.assertIn("export const GET", model_context(tree))
        self.assertIn("endpoint GET /orders/:id", RepoMap(tree).render())
        for path in tree.paths():
            self.assertTrue(feature("r1", path))
            self.assertTrue(repair("sast", path))
        for path in ("tests/app.ts", ".github/ci.ts", "standard/rules.ts", "../app.ts"):
            self.assertFalse(feature("r1", path))

    def test_review_research_reads_the_draft_and_cannot_experiment_or_write(self):
        import tempfile
        from unittest.mock import patch
        from standard.autonomy.research import Research, ResearchError
        base = Tree({"a.py": "old"})
        draft = Overlay(base, {"a.py": "new", "gone.py": None})
        research = Research(None, Path(tempfile.mkdtemp()) / "notes")
        self.assertEqual(research.read(draft, "a.py"), b"new")
        with self.assertRaises(ResearchError):
            research.read(draft, "gone.py")
        with patch.object(research, "dialogue", return_value={"findings": []}) as dialogue:
            research.worker("inspect", "simplicity", tree=draft, read_only=True, key="task")
        self.assertEqual(dialogue.call_args.kwargs["allowed_actions"], ("read", "search"))


if __name__ == "__main__":
    unittest.main()
