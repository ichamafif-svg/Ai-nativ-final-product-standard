"""Checkpoints for transparency witnesses (L-04): RFC 6962 trees, C2SP signed notes, against reference vectors."""
import base64
import hashlib
import os
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fixture import Ledger

from bt import transparency as t
from bt.signing import Signer
from kernel import canon


class Note(unittest.TestCase):
    def test_signed_note_matches_the_reference_implementation(self):
        # golang.org/x/mod/sumdb/note's test key and signature: a witness written in Go reads ours.
        seed = base64.b64decode("AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz")[1:]
        signer = Signer("x", Ed25519PrivateKey.from_private_bytes(seed))
        public = base64.b64decode(signer.public)
        self.assertEqual(t.verifier_key("PeterNeumann", public),
                         "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW")
        text = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n"
        sig = t.key_hash("PeterNeumann", public) + base64.b64decode(signer.sign(text.encode())["sig"])
        self.assertEqual(base64.b64encode(sig).decode(), "x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFY"
                                                         "C2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=")

    def test_a_checkpoint_verifies_only_for_its_origin_keys_and_bytes(self):
        clock, other = Signer("clock", Ed25519PrivateKey.generate()), Signer("o", Ed25519PrivateKey.generate())
        L = Ledger()
        L.grant("agent", ["effect:inventory-refresh"], ["repo:*"])
        leaves = [canon(e) for e in L.entries]
        note = t.checkpoint("standard/test", leaves, clock, "standard-clock")
        keys = {"standard-clock": base64.b64decode(clock.public)}
        self.assertEqual(t.verify(note, "standard/test", keys), (len(leaves), t.root(leaves)))
        with self.assertRaises(t.TransparencyError):
            t.verify(note, "standard/other", keys)
        with self.assertRaises(t.TransparencyError):
            t.verify(note.replace(f"\n{len(leaves)}\n", f"\n{len(leaves) - 1}\n"), "standard/test", keys)
        with self.assertRaises(t.TransparencyError):
            t.verify(note, "standard/test", {"standard-clock": base64.b64decode(other.public)})
        both = t.cosign(note, other, "second")
        self.assertEqual(t.verify(both, "standard/test", {**keys, "second": base64.b64decode(other.public)})[0],
                         len(leaves))


class Tree(unittest.TestCase):
    def test_roots_and_proofs_follow_rfc_9162(self):
        self.assertEqual(t.root([]), hashlib.sha256(b"").digest())
        self.assertEqual(t.root([b""]).hex(), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
        for n in range(1, 34):
            leaves = [os.urandom(4) for _ in range(n)]
            root = t.root(leaves)
            for i in range(n):
                self.assertTrue(t.verify_inclusion(leaves[i], i, n, t.inclusion(leaves, i), root))
                self.assertFalse(t.verify_inclusion(leaves[i] + b"x", i, n, t.inclusion(leaves, i), root))
            for m in range(1, n + 1):
                proof = t.consistency(leaves, m)
                self.assertTrue(t.verify_consistency(m, n, proof, t.root(leaves[:m]), root))
                if m < n:
                    forked = t.root([b"fork", *leaves[1:m]])
                    self.assertFalse(t.verify_consistency(m, n, proof, forked, root))


if __name__ == "__main__":
    unittest.main()
