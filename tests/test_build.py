"""Construction (D34): a person writes a request and its acceptance tests; the scanner checks the contract asks for
something main does not do; the person signs it; the agent implements it without touching a test; the law lands it
only with the contract passing, main's tests passing, no regression and a review; main passing the contract delivers
the request."""
import argparse
import hashlib
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import ceremony  # noqa: E402
from test_install import Clock  # noqa: E402
from test_maintenance import FILES, demo_repository  # noqa: E402

import autonomy.__main__ as agent_process  # noqa: E402
import trusted.daemon as daemon  # noqa: E402
from autonomy.agent import AgentError  # noqa: E402
from autonomy.build import Builder, in_scope  # noqa: E402
from autonomy.llm import Gate, Provider  # noqa: E402
from surface.human import load_signer  # noqa: E402
from trusted.gateway import AdmissionGateway  # noqa: E402
from trusted.signing import envelope  # noqa: E402

CONTRACT = b"from app import mul\n\n\ndef test_mul():\n    assert mul(2, 3) == 6\n\n\ndef test_mul_zero():\n    assert mul(7, 0) == 0\n"
ALREADY = b"from app import add\n\n\ndef test_add_again():\n    assert add(1, 1) == 2\n"
IMPLEMENTATION = "def add(a, b):\n    return a + b\n\n\ndef mul(a, b):\n    return a * b\n"


def stored(store: Path, data: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    store.mkdir(parents=True, exist_ok=True)
    (store / digest.split(":")[1]).write_bytes(data)
    return digest


def git(*args, cwd):
    import subprocess
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


class Scope(unittest.TestCase):
    def test_the_agent_writes_code_never_tests(self):
        self.assertTrue(in_scope("app.py"))
        self.assertTrue(in_scope("shop/orders.py"))
        for path in ("tests/test_app.py", "tests/acceptance/test_r1.py", ".github/workflows/ci.yml",
                     "standard/rules.json", "../app.py", "app.sh"):
            self.assertFalse(in_scope(path), path)


class Construction(unittest.TestCase):
    def test_request_contract_implementation_review_delivery(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, {**FILES, "sbom.json": "{}\n"})
        clock = Clock(1_900_000_000_000)
        ceremony.now = daemon.now_ms = clock
        install = root / "install"
        ceremony.init(argparse.Namespace(dir=str(install), repo=str(repo), github=None, token_file=None,
                                         pins=str(root / "elsewhere" / "pins.db")))
        clock.t += 3_600_100
        ceremony.activate(argparse.Namespace(dir=str(install)))
        operator = daemon.Installation(install / "standard.toml")
        store, grants = install / "requests", operator.config["grants"]
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        try:
            cycle, refresh = agent_process.build(install / "standard.toml")
            cycle.clock = clock
            people = {h: load_signer(h, install / "keys" / f"{h}.key") for h in ("h1", "h3")}

            def sign(who, kind, **body):
                s = operator.journal.snapshot()
                operator.service.admit(envelope(s["domain"], kind, {
                    "id": f"{kind}-{clock()}", "at": max(clock(), s["last_at"] + 1), "author": who, **body},
                    [people[who]]))

            def request(rid, contract):
                sign("h1", "resource", under=grants["product"], resource=f"build:request/{rid}", type="request",
                     fields={"title": "Multiply", "spec": stored(store, b"Add mul(a, b)."),
                             "contract": stored(store, contract)})

            def facts(resource):
                return operator.service.view()["transitions"].get(resource, {})

            def entity(rid):
                return operator.service.view()["entities"][f"build:request/{rid}"]

            def contract(rid):
                e = entity(rid)
                sign("h1", "transition", under=grants["product"], resource=f"build:request/{rid}",
                     operation="contract", expected=e["expected"], changes={})

            request("r-already", ALREADY)
            request("r-mul", CONTRACT)
            operator.tick()
            self.assertEqual(facts("build:request/r-already")["contract"], "passes:1")   # promises nothing
            self.assertEqual(facts("build:request/r-mul")["contract"], "red")            # asks for something new
            with self.assertRaises(Exception) as refused:
                contract("r-already")
            self.assertEqual(getattr(refused.exception, "code", None), "CAP.CONDITION")
            contract("r-mul")
            self.assertEqual(entity("r-mul")["state"], "contracted")

            replies = iter([{"title": "Add mul", "files": {"tests/test_app.py": "def test_x():\n    pass\n"}},
                            {"title": "Add mul", "files": {"app.py": IMPLEMENTATION}, "risks": "none"}])
            gate = Gate({"frontier": Provider("fake", "anthropic", "m", "k")}, root / "egress.log",
                        transport=lambda provider, prompt: json.dumps(next(replies)))
            builder = Builder(cycle.service, cycle.agent.signer,
                              {k: grants[k] for k in ("agent_implement", "agent_deliver")}, cycle.agent.store, store,
                              main=lambda: git("rev-parse", "main", cwd=repo), clock=clock,
                              notes=root / "requests.json", llm=gate, backoff_ms=0)
            main = git("rev-parse", "main", cwd=repo)
            refresh()
            with self.assertRaises(AgentError):                                 # a test is out of its reach
                builder.craft("r-mul", "Multiply", b"", CONTRACT, main, {})
            report = builder.run()
            self.assertIn(report["r-mul"], ("proposed: CAP.CONDITION", "landing"))
            head = json.loads((root / "requests.json").read_text())["r-mul"]["head"]
            operator.tick()
            resource = f"repo:feature:r-mul/{main}/{head}"
            self.assertEqual({k: facts(resource).get(k) for k in ("acceptance", "tests", "regressions")},
                             {"acceptance": "green", "tests": "green", "regressions": "none"})
            clock.t += 61_000
            builder.run()
            self.assertEqual(git("rev-parse", "main", cwd=repo), main)          # no review: nothing lands
            sign("h3", "observation", under=grants["reviewer"], resource=resource, property="review",
                 status="approved", level="real")
            clock.t += 61_000
            builder.run()
            operator.tick()
            self.assertEqual(git("rev-parse", "main", cwd=repo), head)          # reviewed: the guard moved main
            operator.tick()                                                     # the scanner reads the new main
            self.assertEqual(facts("build:request/r-mul")["accepted"], "yes")
            builder.run()
            self.assertEqual(entity("r-mul")["state"], "delivered")
            import replay                                                       # D37: the facts replay, isolated
            config = install / "standard.toml"
            results = [replay.replay(replay.host_for(config), r) for r in replay.records(config, 200)]
            self.assertEqual({r["result"] for r in results}, {"agrees"}, results)
            self.assertTrue({"feature", "request"} <= {r["job"] for r in results})
        finally:
            gateway.shutdown()
            gateway.server_close()


if __name__ == "__main__":
    unittest.main()
