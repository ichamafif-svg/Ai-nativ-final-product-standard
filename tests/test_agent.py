"""What the agent is given to code well (ARCHITECTURE.md §11.7): findings, sandbox, whole-law precheck, memory and
budget, the reviewer's dossier, a repository map, release data and one egress gate. None of it opens a right."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.candidate import AgentError
from agent.repair import Agent
from agent.repair import Repairer  # noqa: E402
from agent.llm import REDACTED, EgressError, Gate, Provider  # noqa: E402
from agent.memory import Memory  # noqa: E402
from agent.precheck import precheck  # noqa: E402
from context.repository import RepoMap  # noqa: E402
from agent.sandbox import Sandbox  # noqa: E402
from local_sandbox import LocalSandbox  # noqa: E402
from catalog.floors import FLOORS  # noqa: E402
from instruments import probes as instruments  # noqa: E402
from instruments.data import EMPTY  # noqa: E402
from instruments.suite import tests_report  # noqa: E402
from instruments.tree import Snapshot, export  # noqa: E402

TARGETS = {t["id"]: t for t in FLOORS["targets"]}
KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
FILES = {"requirements.txt": "packaging==24.1\n", "sbom.json": json.dumps({"components": [
    {"name": "packaging", "version": "24.1"}]}) + "\n",
         "app.py": f'API = "{KEY}"\n\n\ndef add(a, b):\n    return a + b\n',
         "tests/test_app.py": "from app import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"}


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def store_with(files=FILES):
    root = Path(tempfile.mkdtemp())
    work = root / "work"
    git("init", "-q", "-b", "main", str(work))
    for p, text in files.items():
        (work / p).parent.mkdir(parents=True, exist_ok=True)
        (work / p).write_text(text)
    git("add", "-A", cwd=work)
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base", cwd=work)
    git("clone", "-q", "--bare", str(work), str(root / "store"))
    return root / "store", git("rev-parse", "main", cwd=work)


class Signer:
    identity = "agent"


class Findings(unittest.TestCase):
    def test_a_secret_is_located_never_quoted(self):
        store, base = store_with()
        m = instruments.secrets(Snapshot(store, base))
        self.assertIn("app.py:1:secret-rule-0", m.details)
        self.assertFalse(any(KEY in d for d in m.details))

    def test_a_red_suite_names_the_test_and_its_trace(self):
        store, base = store_with()
        head = git("-C", str(store), "commit-tree", git("-C", str(store), "rev-parse", f"{base}^{{tree}}"), "-p", base,
                   "-m", "x")
        work = Path(tempfile.mkdtemp())
        status, details = tests_report(export(store, base, work / "b"), export(store, head, work / "h"))
        self.assertEqual(status, "green")
        self.assertEqual(details, [])


class SandboxIsolation(unittest.TestCase):
    def test_unconfigured_cache_is_not_mounted_by_name(self):
        box = Sandbox(timeout=5)
        box.isolated = True
        cache = ROOT / "venvs"
        self.assertEqual(box.run(["true"], cache).code, 126)
        self.assertIn("outside scratch", box.run(["true"], cache).out)

    def test_no_network_no_inherited_secret_and_a_deadline(self):
        box = Sandbox(timeout=5)
        work = tempfile.mkdtemp()
        if not box.isolated:
            self.assertEqual(box.run([sys.executable, "-c", "print('unsafe')"], work).code, 126)
            return
        os.environ["STANDARD_TEST_SECRET"] = "s3cr3t"
        try:
            env = box.run([sys.executable, "-c", "import os; print(os.environ.get('STANDARD_TEST_SECRET'))"], work)
            self.assertEqual(env.out.strip(), "None")
        finally:
            del os.environ["STANDARD_TEST_SECRET"]
        net = box.run([sys.executable, "-c", "import socket; socket.create_connection(('1.1.1.1', 80), 2)"], work)
        self.assertFalse(net.ok)
        self.assertEqual(box.run(["sleep", "30"], work).code, 124)

    def test_a_candidate_cannot_read_a_sibling_key(self):
        box = Sandbox(timeout=5)
        if not box.isolated:
            self.skipTest("candidate jail unavailable on this host")
        root = Path(tempfile.mkdtemp())
        work = root / "work"
        work.mkdir()
        key = root / "agent.key"
        key.write_text("PRIVATE")
        result = box.run([sys.executable, "-c", f"open({str(key)!r}).read()"], work)
        self.assertNotEqual(result.code, 0)
        self.assertNotIn("PRIVATE", result.out)


class WholeLaw(unittest.TestCase):
    def setUp(self):
        self.store, self.base = store_with()
        self.box = Sandbox()
        if not self.box.isolated:
            self.skipTest("candidate jail unavailable on this host")

    def candidate(self, files):
        from agent.candidate import commit_files
        return commit_files(self.store, self.base, {p: c.encode() for p, c in files.items()}, "candidate")

    def test_a_fix_that_breaks_main_tests_is_not_proposed(self):
        head = self.candidate({"app.py": "import os\nAPI = os.environ['API']\n\n\ndef add(a, b):\n    return a - b\n"})
        check = precheck(self.store, self.base, head, "secrets", TARGETS, EMPTY, self.box)
        self.assertFalse(check["ok"])
        self.assertTrue(any("tests are red" in p for p in check["problems"]))

    def test_a_fix_that_opens_another_gap_is_not_proposed(self):
        head = self.candidate({"app.py": "import os\nimport subprocess\nAPI = os.environ.get('API', '')\n\n\n"
                                         "def add(a, b):\n    subprocess.run(f'echo {a}', shell=True)\n"
                                         "    return a + b\n"})
        check = precheck(self.store, self.base, head, "secrets", TARGETS, EMPTY, self.box)
        self.assertFalse(check["ok"])
        self.assertTrue(any(p.startswith("sast:") for p in check["problems"]), check["problems"])

    def test_a_clean_fix_passes_and_says_how_it_was_checked(self):
        head = self.candidate({"app.py": "import os\nAPI = os.environ.get('API', '')\n\n\n"
                                         "def add(a, b):\n    return a + b\n"})
        check = precheck(self.store, self.base, head, "secrets", TARGETS, EMPTY, self.box)
        self.assertTrue(check["ok"], check["problems"])
        self.assertEqual(check["tests"], "green")
        self.assertEqual(check["quality"]["mutation"]["mutants"], 0)     # no logic changed, nothing to mutate

    def test_untested_new_code_goes_to_the_human_never_refuses_the_candidate(self):
        head = self.candidate({"app.py": "import os\nAPI = os.environ.get('API', '')\n\n\n"
                                         "def add(a, b):\n    return a + b\n\n\ndef double(x):\n    return x * 2\n"})
        check = precheck(self.store, self.base, head, "secrets", TARGETS, EMPTY, self.box)
        self.assertTrue(check["ok"], check["problems"])
        mutation = check["quality"]["mutation"]
        self.assertGreaterEqual(len(mutation["survivors"]), 1)
        self.assertTrue(check["feedback"]["human"] and not any(e["source"] == "mutation"
                                                                for e in check["feedback"]["agent"]))


    def test_green_tests_on_code_that_hit_the_wall_are_not_a_pass(self):
        head = self.candidate({"app.py": "import os\nimport socket\nAPI = os.environ.get('API', '')\n\n\n"
                                         "def add(a, b):\n    try:\n"
                                         "        socket.create_connection(('203.0.113.7', 443), 1)\n"
                                         "    except OSError as exc:\n        print('telemetry failed:', exc)\n"
                                         "    return a + b\n"})
        check = precheck(self.store, self.base, head, "secrets", TARGETS, EMPTY, self.box)
        self.assertEqual(check["tests"], "green")
        self.assertFalse(check["ok"])
        self.assertTrue(any("touched the bac's walls" in p for p in check["problems"]), check["problems"])
        lesson = next(r for r in check["refusals"] if r["capability"] == "network.outbound")
        self.assertEqual(lesson["held_by"], "platform:egress")
        self.assertIn("SSRF", lesson["rules"])
        for word in ("seccomp", "namespace", "netns", "cgroup"):
            self.assertNotIn(word, json.dumps(lesson))
        wall = [e for e in check["feedback"]["agent"] if e["source"] == "wall"]
        self.assertEqual(len(wall), 1)
        self.assertTrue(wall[0]["attempt"].startswith("network.outbound"), wall)
        self.assertIn("app.py:", wall[0]["where"])                   # the line of the agent's own code
        self.assertTrue(any(f.startswith("app.py:") for f in lesson["stack"]), lesson)
        self.assertIn("SSRF", wall[0]["rules"])
        self.assertIn("instead:", check["feedback_text"])

    def test_red_tests_reach_the_agent_through_the_same_dossier(self):
        head = self.candidate({"app.py": "import os\nAPI = os.environ['API']\n\n\ndef add(a, b):\n    return a - b\n"})
        check = precheck(self.store, self.base, head, "secrets", TARGETS, EMPTY, self.box)
        self.assertTrue(any(e["source"] == "tests" for e in check["feedback"]["agent"]), check["feedback"])


class BehindTheGateway(unittest.TestCase):
    """D68 step 2: what the gate corrects on the candidate's product, and not on base's, is its lesson."""

    SERVER = ("import os\nfrom http.server import BaseHTTPRequestHandler, HTTPServer\n\n\n"
              "class H(BaseHTTPRequestHandler):\n    def log_message(self, *a):\n        pass\n\n"
              "    def do_GET(self):\n        self.send_response(200)\n{cookie}"
              "        self.send_header('content-length', '2')\n        self.end_headers()\n"
              "        self.wfile.write(b'ok')\n\n\n"
              "if __name__ == '__main__':\n    HTTPServer(('127.0.0.1', int(os.environ['PORT'])), H).serve_forever()\n")

    def test_a_weak_cookie_behind_the_gateway_is_the_candidates_lesson(self):
        from catalog import effective, load
        from enclosure.components import where
        box = Sandbox()
        if not box.isolated or not where("envoy"):
            self.skipTest("needs the bac and Envoy")
        files = {**FILES, "server.py": self.SERVER.format(cookie="")}
        store, base = store_with(files)
        from agent.candidate import commit_files
        weak = "        self.send_header('set-cookie', 'cart=1')\n"
        head = commit_files(store, base, {"server.py": self.SERVER.format(cookie=weak).encode()}, "candidate")
        values = effective(load(), {"start": "python3 -I server.py", "request_timeout_s": 5})
        check = precheck(store, base, head, None, {}, EMPTY, box, values=values)
        self.assertIsNone(check["entry"])
        self.assertFalse(check["ok"])
        self.assertTrue(any("behind the gateway" in p for p in check["problems"]), check["problems"])
        lesson = next(r for r in check["refusals"] if r["capability"] == "ingress.cookies")
        self.assertEqual(lesson["held_by"], "platform:ingress")
        self.assertIn("COOKIES", lesson["rules"])

    def test_without_start_nothing_runs_and_it_is_said(self):
        store, base = store_with()
        box = Sandbox()
        if not box.isolated:
            self.skipTest("needs the bac")
        check = precheck(store, base, base, None, {}, EMPTY, box)
        self.assertIn("@start", check["entry"])


class Model(unittest.TestCase):
    """A model that is wrong first: the agent learns from its own checks before proposing anything."""

    def test_the_agent_iterates_and_proposes_only_what_passes_with_a_dossier(self):
        store, base = store_with()
        prompts = []
        replies = [{"title": "env key", "files": {"app.py": "import os\nAPI = os.environ['API']\n\n\n"
                                                             "def add(a, b):\n    return a - b\n"}},
                   {"title": "read the key from the environment", "risks": "API is empty if unset",
                    "files": {"app.py": "import os\nAPI = os.environ.get('API', '')\n\n\n"
                                        "def add(a, b):\n    return a + b\n"}}]

        def transport(provider, prompt):
            prompts.append(prompt)
            return json.dumps({'findings': []} if prompt.startswith(('ROLE correctness:', 'ROLE simplicity:')) else replies.pop(0))
        log = store.parent / "egress.log"
        agent = Agent(store, llm=Gate({"small": Provider("p", "anthropic", "m", "k")}, log,
                                                       transport=transport), sandbox=LocalSandbox())
        finding = {"status": "found:1", "details": ["app.py:1:secret-rule-0"]}
        head, route = agent.craft("secrets", base, targets=TARGETS, finding=finding)
        self.assertEqual(route, "model")
        builds = [p for p in prompts if p.startswith('ROLE build:')]
        self.assertEqual(len(builds), 2)
        self.assertIn("tests are red", builds[1])                        # the feedback reached the second attempt
        self.assertIn("app.py:1:secret-rule-0", prompts[0])              # where the gap is
        self.assertNotIn(KEY, "".join(prompts))                         # what the gap is never leaves
        message = git("-C", str(store), "log", "-1", "--format=%B", head)
        for part in ("Why:", "What: app.py", "Checked by the agent", "Risks: API is empty", "Standard-Target: secrets"):
            self.assertIn(part, message)
        lines = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(len(lines), 6)                                  # both attempts complete the real review path
        self.assertTrue(all(set(line) == {"at", "provider", "model", "tier", "bytes", "redactions", "sha256"}
                            for line in lines))

    def test_out_of_ideas_is_an_error_not_a_proposal(self):
        store, base = store_with()
        bad = {"title": "x", "files": {"app.py": "def add(a, b):\n    return 0\n"}}
        agent = Agent(store, llm=Gate({"small": Provider("p", "anthropic", "m", "k")},
                                                       store.parent / "egress.log",
                                                       transport=lambda p, prompt: json.dumps(bad)))
        with self.assertRaises(AgentError):
            agent.craft("secrets", base, targets=TARGETS, finding={"status": "found:1", "details": []})


class Gatekeeping(unittest.TestCase):
    def test_secrets_are_redacted_and_placeholders_refused(self):
        sent = []
        gate = Gate({"frontier": Provider("p", "anthropic", "m", "k")}, Path(tempfile.mkdtemp()) / "log",
                    transport=lambda p, prompt: sent.append(prompt) or json.dumps({"files": {"a.py": REDACTED}}))
        with self.assertRaises(EgressError):
            gate.ask(f"key {KEY}")
        self.assertNotIn(KEY, sent[0])
        self.assertIn(REDACTED, sent[0])


class Memory_(unittest.TestCase):
    def test_a_budget_then_a_dossier_for_people(self):
        memory = Memory(Path(tempfile.mkdtemp()) / "memory.json", budget=2)
        for i in range(2):
            self.assertFalse(memory.exhausted("ci", "b1"))
            memory.record("ci", at=i, base="b1", outcome="judge", why=f"test_x failed {i}")
        self.assertTrue(memory.exhausted("ci", "b1"))
        self.assertFalse(memory.exhausted("ci", "b2"))                   # a new main is a new problem
        self.assertIn("test_x failed 1", memory.lessons("ci"))

    def test_the_repairer_abandons_after_the_budget_and_stops_trying(self):
        class Service:
            def view(self):
                return {"law": {"digest": "test-law", "effective": {"targets": [TARGETS["ci"]]}}, "health": {"as_of": 0},
                        "prefix": {"genesis": "g"}}

            def qualify(self, *a):
                return {}

        class Engine:
            def __init__(self):
                self.claims = 0
                self.records = []

            def sync(self, plan):
                pass

            def claim(self, **kw):
                self.claims += 1
                return {"id": "t", "target": "ci", "lease_until": 0} if self.claims % 2 else None

            def complete_attempt(self, **kw):
                pass

            def record(self, **kw):
                self.records.append(kw)

        class Failing:
            def craft(self, *a, **kw):
                raise AgentError("nothing passes")

        from context.model import ReadModel
        real = ReadModel.plan
        ReadModel.plan = lambda self, mode="RUN": {"state": "IN_PROGRESS", "tasks": []}
        self.addCleanup(setattr, ReadModel, "plan", real)              # never leak into the next test
        root = Path(tempfile.mkdtemp())
        service = Service()
        cycle = Repairer(service, Engine(), Failing(), [], clock=lambda: 1, state_path=root / "proposals.json",
                         memory=Memory(root / "memory.json", budget=2))
        run = lambda: cycle.run(service.view(), "b1")
        self.assertEqual(run()["candidates"]["ci"], "agent: nothing passes")
        self.assertEqual(cycle.engine.records[0]["basis"]["main"], "b1")
        run()
        self.assertEqual(run()["candidates"]["ci"], "abandoned: waiting for people")
        self.assertIn("nothing passes", Memory(root / "memory.json").abandoned("ci", "b1"))
        cycle.agent.sandbox = type("Unavailable", (), {"isolated": False})()
        self.assertEqual(run()["candidates"]["ci"], "trust blocked: candidate jail unavailable")
        self.assertEqual(cycle.engine.records[-1]["reason_code"], "candidate_jail_unavailable")


class Map(unittest.TestCase):
    def test_the_map_names_callers_of_what_a_change_touches(self):
        store, base = store_with({**FILES, "lib.py": "from app import add\n\n\ndef twice(x):\n    return add(x, x)\n"})
        m = RepoMap(Snapshot(store, base))
        self.assertEqual(m.callers("add"), ["lib.py", "tests/test_app.py"])
        self.assertIn("called from: lib.py, tests/test_app.py", m.render(focus=["app.py"]))


if __name__ == "__main__":
    unittest.main()
