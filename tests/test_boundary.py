"""Boundary transactions (D38): a compromised program gains no more authority than its contract; an effect leaves
only through an adapter with the physical profile its operation requires; RESOLVE never turns silence into absence."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fixture import Ledger  # noqa: E402

from standard.floors import CONTRACTS, INSTRUMENTS, PROGRAMS  # noqa: E402
from kernel import canon  # noqa: E402
from bt.guard import NotDispatched  # noqa: E402
from bt.host import Evidence  # noqa: E402
from bt.transactions import Boundary  # noqa: E402

A, B = "a" * 40, "b" * 40


class FakeHost:
    """A host whose programs answer what a compromised package would."""
    method = PROGRAMS

    def __init__(self, evidence, facts):
        self.evidence, self.facts = evidence, facts

    def call(self, job, inputs, network=False, cache=True):
        return {"facts": self.facts, "extra": {}}, self.evidence.put(json.dumps([job, self.facts]).encode())


class Adapter:
    def __init__(self, profile, read=None):
        self.profile, self.sent, self._read = profile, [], read

    def perform(self, resource, args, key):
        self.sent.append((resource, key))
        return "ok"

    def read(self, it, key):
        return self._read

    def satisfied(self, it):
        return False


def boundary(root):
    return Boundary(Evidence(root / "evidence"), root / "transactions.jsonl", CONTRACTS, PROGRAMS, lambda: 1,
                    ledger=lambda: {"genesis": "g", "head": "h", "law": "l"})


class Observe(unittest.TestCase):
    def test_a_job_says_only_what_its_contract_allows(self):
        root = Path(tempfile.mkdtemp())
        b = boundary(root)
        forged = [["run:service:all", "slo", "met", []],
                  [f"repo:contrib:alice/{A}/{B}", "tests", "green", []],          # not production's to say
                  [f"run:release:all/{A}/{B}", "decision", "approve", []]]        # nor a person's fact
        out = b.observe(FakeHost(b.evidence, forged), "scanner", "production", {})
        self.assertEqual([tuple(f[:3]) for f in out["facts"]], [("run:service:all", "slo", "met")])
        self.assertEqual(len(out["refused"]), 2)
        self.assertEqual(out["method"], f"{PROGRAMS}/production")
        bt = json.loads(b.evidence.get(out["ref"]))
        self.assertEqual((bt["bt"], bt["outcome"], bt["contract"]["form"]), ("observe", "refused", "composite"))
        self.assertEqual(bt["causality"]["genesis"], "g")
        self.assertIn("error", b.observe(FakeHost(b.evidence, []), "scanner", "unknown-job", {}))

    def test_the_kernel_admits_a_pinned_property_only_from_its_contract(self):
        L = Ledger()
        scanner = L.grant("scanner", ["observe", "certify:real"], ["repo:*", "run:*"])
        resource = f"repo:contrib:alice/{A}/{B}"
        _, coverage, _ = INSTRUMENTS["tests"]
        at = L.state["last_at"] + 1
        code = L.refused("measurement", "scanner", at=at, under=scanner, resource=resource, property="tests",
                         status="green", level="real", method=f"{PROGRAMS}/production", coverage=coverage,
                         measured_at=at, artifact="sha256:" + "0" * 64)
        self.assertTrue(code.startswith("PROV"), code)                # a production program cannot sign tests
        L.measure("scanner", scanner, resource, "tests", "green")    # the suite contract can


class Effect(unittest.TestCase):
    def judged(self, op):
        j = {"op": op, "resource": f"run:process:all/{A}/1", "args": {"release": A, "n": "1"}}
        return j, canon(j)

    def test_an_effect_leaves_only_through_the_profile_its_contract_requires(self):
        root = Path(tempfile.mkdtemp())
        b = boundary(root)
        liar = Adapter("cas")                                         # a restart is not a compare-and-swap
        port = b.port({"restart": liar})
        with self.assertRaises(NotDispatched):
            port.perform(*self.judged("restart"), "k")
        self.assertEqual(liar.sent, [])
        honest = Adapter("observable")
        self.assertEqual(b.port({"restart": honest}).perform(*self.judged("restart"), "k"), "ok")
        outcomes = [json.loads(x)["outcome"] for x in (root / "transactions.jsonl").read_text().splitlines()]
        self.assertEqual(outcomes, ["failed:unqualified", "ok"])


class Resolve(unittest.TestCase):
    def state(self):
        return {"domain": "g", "last_at": 1, "token_of": {"i": "t"}, "reserved": {"t": "r"},
                "intents": {"i": {"id": "i", "op": "restart", "resource": f"run:process:all/{A}/1",
                                  "args": {"release": A, "n": "1"}}}}

    def resolved(self, profile, read):
        from fixture import Keys
        from bt.signing import Signer
        root = Path(tempfile.mkdtemp())
        keys = Keys()
        r = boundary(root).resolver({"restart": Adapter(profile, read)}, Signer("oracle", keys.private["oracle"][1]),
                                    "grant-oracle")
        return r.readback("i", self.state())

    def test_silence_is_never_absence_for_an_observable_effect(self):
        self.assertIsNone(self.resolved("observable", "not_applied"))   # a request may still land
        self.assertIsNone(self.resolved("observable", None))
        self.assertIsNotNone(self.resolved("observable", "not_sent"))   # nothing ever left the guard
        self.assertIsNotNone(self.resolved("cas", "not_applied"))       # the state itself says so


if __name__ == "__main__":
    unittest.main()
