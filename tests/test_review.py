"""Falsifiers of the October 2026 code review: each test reproduces a finding and must stay green afterwards."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fixture import Ledger  # noqa: E402
from instruments.data import TrustedData  # noqa: E402
from instruments.recipes import vulns  # noqa: E402


class Files:
    def __init__(self, files):
        self.f = files

    def paths(self):
        return set(self.f)

    def read(self, path):
        return self.f[path]


def snapshot(advisories):
    return TrustedData({"format": "standard-data/1", "taken_at": 1, "advisories": advisories})


class VulnerabilityRecipe(unittest.TestCase):
    """Review, high 3: the smallest fix of every branch was a major downgrade, merged without a human."""

    def test_never_moves_a_pin_backwards_or_to_another_major(self):
        data = snapshot({"django==4.2.0": [{"id": "GHSA-x", "fix_versions": ["3.2.19", "4.1.9", "4.2.1"]}]})
        self.assertEqual(vulns(Files({"requirements.txt": b"django==4.2.0\n"}), data),
                         {"requirements.txt": b"django==4.2.1\n"})

    def test_no_fix_on_the_pin_s_line_is_no_recipe(self):
        data = snapshot({"lib==1.4.0": [{"id": "A", "fix_versions": ["0.9.9", "2.0.0"]}]})
        self.assertIsNone(vulns(Files({"requirements.txt": b"lib==1.4.0\n"}), data))

    def test_every_advisory_is_fixed_and_commit_ids_are_ignored(self):
        data = snapshot({"lib==1.4.0": [{"id": "A", "fix_versions": ["1.4.2", "a" * 40]},
                                        {"id": "B", "fix_versions": ["1.5.0"]}]})
        self.assertEqual(vulns(Files({"requirements.txt": b"lib==1.4.0\n"}), data),
                         {"requirements.txt": b"lib==1.5.0\n"})


class HumanDecision(unittest.TestCase):
    """Review, critical 2: a machine holding `observe` on the resource signed a human's decision for itself."""

    def setUp(self):
        self.L = L = Ledger()
        L.checkpoint()
        self.scanner = L.grant("scanner", ["observe", "certify:real"], ["repo:*", "run:*", "build:*"])
        self.human = L.grant("h1", ["observe", "certify:real"], ["repo:*"])
        self.agent = L.grant("agent", ["effect:remediate"], ["repo:*"])
        self.base, self.head = "a" * 40, "b" * 40
        self.res = f"repo:code:secrets/{self.base}/{self.head}"
        L.measure("scanner", self.scanner, self.res, "tests", "green")
        L.measure("scanner", self.scanner, self.res, "regressions", "none")

    def intent(self):
        return dict(under=self.agent, op="remediate",
                    args={"area": "code", "item": "secrets", "base": self.base, "head": self.head})

    def test_a_machine_decision_opens_nothing(self):
        self.L.submit("observation", "scanner", under=self.scanner, resource=self.res, property="decision",
                      status="approve", level="real")
        self.assertEqual(self.L.refused("intent", "agent", **self.intent()), "CAP.ROUTE")

    def test_a_human_decision_opens_the_human_route(self):
        self.L.decide(self.human, self.res)
        self.assertIn(self.L.submit("intent", "agent", **self.intent()), self.L.state["intents"])

    def test_the_author_kind_is_a_closed_list(self):
        from kernel.language import LanguageError, compile_program
        with self.assertRaises(LanguageError):
            compile_program({"all": [{"observed": ["decision", "approve", "real", "robot"]}]})


class Violations(unittest.TestCase):
    """Review, medium 9: one escalate-level violation left the verdict ESCALATED forever."""

    def fold(self, L):
        from kernel import Accountability, apply, empty
        from kernel.accountability import empty as fresh
        acc, a, ks = Accountability(L.kernel), fresh(), empty()
        for entry in L.entries:
            record, delta = L.kernel.decide(ks, entry)
            apply(ks, delta)
            acc.feed(a, ks, record)
        return acc.health(a, ks)

    def setUp(self):
        from fixture import client_law
        law = client_law(obligations=[{"id": "ack", "level": "escalate", "due_ms": 1000, "on_due": "escalate",
                                       "open": [{"kind": "intent", "key": "id"}],
                                       "close": [{"kind": "freeze", "key": "id"}]}])
        self.L = L = Ledger(law=law)
        L.checkpoint()
        self.freeze = L.submit("freeze", "h1", scope="x:*")             # closes nothing open: a violation

    def test_a_human_resolves_a_violation_a_machine_cannot(self):
        L = self.L
        name = f"violation:ack:{self.freeze}"
        self.assertIn(name, [x["obligation"] for x in self.fold(L)["escalated"]])
        human = L.grant("h1", ["observe", "certify:real"], ["law:violation/*"])
        machine = L.grant("scanner", ["observe", "certify:real"], ["law:violation/*"])
        L.submit("observation", "scanner", under=machine, resource=f"law:violation/ack/{self.freeze}",
                 property="decision", status="approve", level="real")
        self.assertIn(name, [x["obligation"] for x in self.fold(L)["escalated"]])
        L.decide(human, f"law:violation/ack/{self.freeze}")
        self.assertNotIn(name, [x["obligation"] for x in self.fold(L)["escalated"]])


class OneEncoding(unittest.TestCase):
    """Review, high 6: one statement had several envelopes, hence several heads."""

    def test_non_canonical_base64_is_refused(self):
        L = Ledger()
        L.checkpoint()
        entry = L.entry("freeze", {"id": "fz", "at": L.state["last_at"] + 1, "author": "h1", "scope": "repo:*"}, ["h1"])
        sig = entry["envelope"]["signatures"][0]["sig"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last = sig.rstrip("=")[-1]
        entry["envelope"]["signatures"][0]["sig"] = sig.rstrip("=")[:-1] + alphabet[alphabet.index(last) ^ 1] + "=="
        from kernel import Refused
        with self.assertRaises(Refused) as r:
            L.kernel.decide(L.state, entry)
        self.assertEqual(r.exception.code, "PROV.SIGNATURE")

    def test_a_passkey_signature_has_one_s(self):
        import base64
        import hashlib
        import json
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from kernel.identity import P256_N, keyid, verify
        u = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        sk = ec.generate_private_key(ec.SECP256R1())
        public = base64.b64encode(sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)).decode()
        key = {"alg": "webauthn-es256", "public": public, "keyid": keyid(public), "rp_id": "standard.local",
               "origins": ["https://standard.local"]}
        message = b"statement"
        auth = hashlib.sha256(b"standard.local").digest() + bytes([0x05]) + b"\0\0\0\1"
        client = json.dumps({"type": "webauthn.get", "origin": "https://standard.local",
                             "challenge": u(hashlib.sha256(message).digest())}).encode()
        r, s_ = decode_dss_signature(sk.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())))
        low, high = min(s_, P256_N - s_), max(s_, P256_N - s_)
        sign = lambda value: {"keyid": key["keyid"], "sig": u(encode_dss_signature(r, value)),
                              "webauthn": {"authenticatorData": u(auth), "clientDataJSON": u(client)}}
        self.assertTrue(verify(key, message, sign(low)))
        self.assertFalse(verify(key, message, sign(high)))
        # As py_webauthn checks: an assertion made inside another site's frame is never a decision.
        for extra in ({"crossOrigin": True}, {"crossOrigin": False, "topOrigin": "https://evil.example"}):
            framed = json.dumps({**json.loads(client), **extra}).encode()
            der = sk.sign(auth + hashlib.sha256(framed).digest(), ec.ECDSA(hashes.SHA256()))
            r2, s2 = decode_dss_signature(der)
            self.assertFalse(verify(key, message, {"keyid": key["keyid"],
                                                   "sig": u(encode_dss_signature(r2, min(s2, P256_N - s2))),
                                                   "webauthn": {"authenticatorData": u(auth),
                                                                "clientDataJSON": u(framed)}}))


class SecondJudgeComposition(unittest.TestCase):
    """Review, high 7: the checker trusted the kernel's composition of the law (G03 on one judge)."""

    def test_a_weakened_floor_halts_even_if_the_kernel_composed_it(self):
        import copy
        from bt.checker import Disagreement, _floors_kept
        L = Ledger()
        law, client, floors = L.kernel.law_of(L.state), L.state["law"]["client"], L.kernel.release.floors
        _floors_kept(copy.deepcopy(law.raw), floors, client)                 # the honest composition passes
        human = lambda w: w["ops"]["integrate"]["routes"]["human"]
        for weaken in (lambda w: human(w)["all"].pop(),                                      # no decision any more
                       lambda w: w["ops"]["integrate"]["routes"].__setitem__("auto", {"all": [
                           {"observed": ["tests", "green", "real"]}]}),                    # a route the socle lacks
                       lambda w: w["ops"]["remediate"]["routes"]["scoped"]["all"].pop(),
                       lambda w: w["settings"].__setitem__("burn_fast", "2"),
                       lambda w: w["settings"].__setitem__("rollback_horizon_min", 999),
                       lambda w: w["targets"][3].__setitem__("due_ms", w["targets"][3]["due_ms"] + 1),
                       lambda w: w["ttl"].__setitem__("proof", w["ttl"]["proof"] * 2),
                       lambda w: w["ops"]["remediate"].__setitem__("resource", "repo:{area}:{item}"),
                       lambda w: w["targets"].pop(5)):
            weak = copy.deepcopy(law.raw)
            weaken(weak)
            with self.assertRaises(Disagreement):
                _floors_kept(weak, floors, client)


class MeasurementOrder(unittest.TestCase):
    """Review, medium 8: an older reading replaced a newer one of the same source."""

    def test_an_older_reading_is_refused(self):
        from catalog.floors import INSTRUMENTS
        L = Ledger()
        L.checkpoint()
        sc = L.grant("scanner", ["observe", "certify:real"], ["repo:*"])
        method, coverage, _ = INSTRUMENTS["tests"]
        res, t = f"repo:code:sast/{'a' * 40}/{'b' * 40}", L.state["last_at"] + 1
        fields = dict(under=sc, resource=res, property="tests", level="real", method=method, coverage=coverage,
                      artifact="sha256:" + "0" * 64)
        L.submit("measurement", "scanner", at=t + 10, status="red", measured_at=t + 10, **fields)
        self.assertEqual(L.refused("measurement", "scanner", at=t + 11, status="green", measured_at=t, **fields),
                         "PROV.STALE")


class DurableRegisters(unittest.TestCase):
    """Review, medium 11: history and registers were not durable, and a recorded key read as 'ok' without its move."""

    def registers(self):
        import json
        import tempfile
        from bt.register import Registers
        root = Path(tempfile.mkdtemp())
        r = Registers(root / "repo", root / "run")
        (root / "run").mkdir()
        (root / "run" / "current").write_text("a" * 40 + "\n")
        r._crash = lambda key, to: (root / "run" / "history.jsonl").write_text(
            json.dumps({"at": 1, "op": "deploy", "from": "a" * 40, "to": to, "key": key}) + "\n")
        return r

    def test_a_recorded_but_interrupted_move_is_finished_once(self):
        r = self.registers()
        r._crash("k1", "b" * 40)                          # crash: history written, register not
        self.assertEqual(r._move("deploy", "a" * 40, "b" * 40, "k1", {"current": "b" * 40}, {"current": "a" * 40}), "ok")
        self.assertEqual(r.current(), "b" * 40)

    def test_a_recorded_move_never_overrides_a_later_one(self):
        r = self.registers()
        r._crash("k1", "b" * 40)
        (r.root / "current").write_text("c" * 40 + "\n")   # production moved since
        self.assertEqual(r._move("deploy", "a" * 40, "b" * 40, "k1", {"current": "b" * 40}, {"current": "a" * 40}),
                         "unknown")
        self.assertEqual(r.current(), "c" * 40)


class HealthFold(unittest.TestCase):
    """Review, medium 12: the gateway thread and the operator loop folded the same state concurrently."""

    def test_concurrent_health_reads_agree(self):
        import threading
        from bt.service import TrustedService

        class Journal:
            def __init__(self, L):
                self.kernel, self.L = L.kernel, L

            def entries(self, start=0):
                return list(self.L.entries[start:])
        L = Ledger()
        for _ in range(40):
            L.checkpoint()
        service = TrustedService.__new__(TrustedService)
        from kernel import Accountability
        service.journal, service.accountability = Journal(L), Accountability(L.kernel)
        service._fold_lock = threading.Lock()
        results, errors = [], []

        def read():
            try:
                results.append(service.health()["size"])
            except Exception as exc:                        # noqa: BLE001
                errors.append(exc)
        threads = [threading.Thread(target=read) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(set(results), {L.state["size"]})


def repository(files: dict, links=()):
    import subprocess
    import tempfile
    root = Path(tempfile.mkdtemp())
    run = lambda *a: subprocess.run(["git", "-C", str(root), *a], check=True, capture_output=True)
    run("init", "-q", "-b", "main")
    for path, data in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(data)
    for link, target in links:
        (root / link).symlink_to(target)
    run("add", "-A")
    run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "c")
    return root


class Instruments(unittest.TestCase):
    """Review, medium 10 and lows: what the subject controls, what a base hides, what blocks forever."""

    def export(self, root):
        import tempfile
        from instruments.tree import export
        return export(root, "main", Path(tempfile.mkdtemp()) / "t")

    def test_gitattributes_cannot_hide_a_file_from_the_instruments(self):
        from instruments import probes
        root = repository({".gitattributes": b"leak.py export-ignore\n",
                           "leak.py": b'token = "ghp_' + b"a" * 36 + b'"\n'})
        self.assertTrue(probes.verdict("none", probes.secrets(self.export(root))).startswith("found:"))

    def test_a_symbolic_link_is_declared_never_a_permanent_gap(self):
        from instruments import probes
        root = repository({"app.py": b"x = 1\n"}, links=[("alias.py", "app.py")])
        m = probes.secrets(self.export(root))
        self.assertEqual(probes.verdict("none", m), "none")
        self.assertIn("alias.py: symbolic link, excluded", m.details)

    def test_an_empty_exact_lock_is_measured(self):
        from instruments import probes
        from instruments.data import EMPTY
        tree = self.export(repository({"requirements.txt": b"# nothing\n"}))
        self.assertEqual(probes.verdict("current", probes.sbom(tree)), "current")
        self.assertEqual(probes.verdict("none", probes.vulns(tree, {"data": EMPTY})), "none")

    def test_swapping_one_finding_for_another_is_a_regression(self):
        from instruments import probes
        key = lambda c: b'token = "ghp_' + bytes([c]) * 36 + b'"\n'
        base = self.export(repository({"a.py": key(97), "b.py": b"x = 1\n"}))
        head = self.export(repository({"a.py": b"x = 1\n", "b.py": key(98)}))
        status, why = probes.regressions(base, head, {"secrets": {"expect": "none"}}, {})
        self.assertEqual(status, "found:1", why)

    def test_an_uncovered_base_does_not_hide_a_new_finding(self):
        from instruments import probes
        base = self.export(repository({"a.py": b"x = 1\n", "big.bin": b"0" * (probes.MAX_FILE + 1)}))
        head = self.export(repository({"a.py": b'token = "ghp_' + b"a" * 36 + b'"\n',
                                       "big.bin": b"0" * (probes.MAX_FILE + 1)}))
        self.assertTrue(probes.verdict("none", probes.secrets(base)).startswith("uncovered"))
        status, why = probes.regressions(base, head, {"secrets": {"expect": "none"}}, {})
        self.assertEqual(status, "found:1", why)

    def test_a_moved_line_is_not_a_new_finding(self):
        from instruments import probes
        key = b'token = "ghp_' + b"a" * 36 + b'"\n'
        base = self.export(repository({"a.py": key}))
        head = self.export(repository({"a.py": b"# moved\n" + key}))
        self.assertEqual(probes.regressions(base, head, {"secrets": {"expect": "none"}}, {})[0], "none")


class WriteCost(unittest.TestCase):
    """Review, medium 14: every read and write deep-copied every statement (10 ms -> 55 ms per write at 4,000)."""

    def test_a_snapshot_shares_immutable_records_and_stays_detached(self):
        from bt.journal import detached
        L = Ledger()
        for _ in range(5):
            L.checkpoint()
        view = detached(L.state)
        some = next(iter(L.state["statements"]))
        self.assertIs(view["statements"][some], L.state["statements"][some])      # shared, not copied
        view["statements"]["x"] = {}
        view["frozen"]["y:*"] = "z"
        self.assertNotIn("x", L.state["statements"])
        self.assertNotIn("y:*", L.state["frozen"])
        L.checkpoint()
        self.assertNotEqual(view["size"], L.state["size"])                         # later admissions do not leak


class ClockConfiguration(unittest.TestCase):
    """F0-1: one human, one agent, the operator's clock; nothing else is accepted."""

    def test_only_the_operator_clock(self):
        import types
        from runtime.operator import Installation
        fake = types.SimpleNamespace(demo=False, config={"ledger": {"genesis": "g"}}, path=Path("/tmp/standard.toml"))
        self.assertTrue(callable(Installation._clock(fake, {"kind": "local"})))
        with self.assertRaises(ValueError):
            Installation._clock(fake, {"kind": "witnesses"})


if __name__ == "__main__":
    unittest.main()
