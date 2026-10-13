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


class HumanReview(unittest.TestCase):
    """Review, critical 2: a machine holding `observe` on the resource signed `review = approved` for itself."""

    def setUp(self):
        self.L = L = Ledger()
        L.checkpoint()
        self.scanner = L.grant("scanner", ["observe", "certify:real"], ["repo:*", "run:*", "build:*"])
        self.reviewer = L.grant("h3", ["observe", "certify:real"], ["repo:*"])
        self.agent = L.grant("agent", ["effect:remediate"], ["repo:*"], ["remediate-reviewed"])
        self.base, self.head = "a" * 40, "b" * 40
        self.res = f"repo:code:secrets/{self.base}/{self.head}"
        L.measure("scanner", self.scanner, self.res, "tests", "green")

    def intent(self):
        return dict(under=self.agent, op="remediate",
                    args={"area": "code", "item": "secrets", "base": self.base, "head": self.head})

    def test_a_machine_review_opens_nothing(self):
        self.L.submit("observation", "scanner", under=self.scanner, resource=self.res, property="review",
                      status="approved", level="real")
        self.assertEqual(self.L.refused("intent", "agent", **self.intent()), "CAP.CONDITION")

    def test_a_human_review_opens_the_reviewed_route(self):
        self.L.submit("observation", "h3", under=self.reviewer, resource=self.res, property="review",
                      status="approved", level="real")
        self.assertIn(self.L.submit("intent", "agent", **self.intent()), self.L.state["intents"])

    def test_the_author_kind_is_a_closed_list(self):
        from kernel.language import LanguageError, compile_program
        with self.assertRaises(LanguageError):
            compile_program({"all": [{"observed": ["review", "approved", "real", "robot"]}]})


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
                                       "open": [{"kind": "freeze", "key": "id"}],
                                       "close": [{"kind": "veto", "key": "proposal"}]}])
        self.L = L = Ledger(law=law)
        L.checkpoint()
        pid = L.submit("grant", "h1", ["h1", "h2"], holder="agent", actions=["observe"], resources=["x:*"],
                       conditions=[], not_after=10 ** 12)
        self.veto = L.submit("veto", "h3", proposal=pid)                # closes nothing open: a violation

    def test_a_human_resolves_a_violation_a_machine_cannot(self):
        L = self.L
        name = f"violation:ack:{self.veto}"
        self.assertIn(name, [x["obligation"] for x in self.fold(L)["escalated"]])
        steward = L.grant("h4", ["observe", "certify:real"], ["law:violation/*"])
        machine = L.grant("scanner", ["observe", "certify:real"], ["law:violation/*"])
        L.submit("observation", "scanner", under=machine, resource=f"law:violation/ack/{self.veto}",
                 property="resolved", status="yes", level="real")
        self.assertIn(name, [x["obligation"] for x in self.fold(L)["escalated"]])
        L.submit("observation", "h4", under=steward, resource=f"law:violation/ack/{self.veto}",
                 property="resolved", status="yes", level="real")
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


class SecondJudgeComposition(unittest.TestCase):
    """Review, high 7: the checker trusted the kernel's composition of the law (G03 on one judge)."""

    def test_a_weakened_floor_halts_even_if_the_kernel_composed_it(self):
        import copy
        from bt.checker import Disagreement, _floors_kept
        L = Ledger()
        law, client, floors = L.kernel.law_of(L.state), L.state["law"]["client"], L.kernel.release.floors
        _floors_kept(copy.deepcopy(law.raw), floors, client)                 # the honest composition passes
        for weaken in (lambda w: w["conditions"].__setitem__("remediate-reviewed",
                                                             {"all": [{"observed": ["tests", "green", "real"]}]}),
                       lambda w: w["targets"][3].__setitem__("due_ms", w["targets"][3]["due_ms"] + 1),
                       lambda w: w["ttl"].__setitem__("proof", w["ttl"]["proof"] * 2),
                       lambda w: w["witnesses"].__setitem__("quorum", 1),
                       lambda w: w["ops"]["remediate"].__setitem__("resource", "repo:{area}:{item}"),
                       lambda w: w["targets"].pop(5)):
            weak = copy.deepcopy(law.raw)
            weaken(weak)
            with self.assertRaises(Disagreement):
                _floors_kept(weak, floors, client)


class MeasurementOrder(unittest.TestCase):
    """Review, medium 8: an older reading replaced a newer one of the same source."""

    def test_an_older_reading_is_refused(self):
        from standard.floors import INSTRUMENTS
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


if __name__ == "__main__":
    unittest.main()
