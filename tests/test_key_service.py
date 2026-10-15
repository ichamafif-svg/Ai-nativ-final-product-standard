"""Trust core: a role's key may live in the key service; the kernel accepts what it signs like any Ed25519 key."""
import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from fabric.control.bt.signing import KeyServiceSigner, envelope  # noqa: E402
from fabric.supply_chain.components import where  # noqa: E402
from fabric.control.kernel.identity import pae  # noqa: E402


@unittest.skipUnless(where("openbao"), "needs OpenBao: python -m tools.components fetch")
class KeyService(unittest.TestCase):
    def setUp(self):
        from fabric.identity.keys import dev
        self.state = tempfile.mkdtemp()
        self.bao, self.process = dev(self.state, where("openbao"))
        self.addCleanup(self.process.wait)
        self.addCleanup(self.process.kill)
        self.bao.create_key("guard")

    def test_a_signature_from_the_key_service_verifies_and_the_key_never_left_it(self):
        signer = KeyServiceSigner("guard", self.bao.address, self.bao.token, "guard")
        env = envelope("ledger", "freeze", {"id": "x"}, [signer])
        sig = env["signatures"][0]
        message = pae(base64.b64decode(env["payload"]))
        Ed25519PublicKey.from_public_bytes(base64.b64decode(signer.public)).verify(base64.b64decode(sig["sig"]), message)
        self.assertEqual(sig["keyid"], signer.keyid)
        self.assertFalse(any("private" in k for k in vars(signer)))

    def test_native_egress_token_cannot_reach_another_products_keys_or_secrets(self):
        from fabric.identity.keys import KeyServiceError
        self.bao.put_secret("allowed", "known-only-to-the-proxy")
        self.bao.put_secret("other", "other-product")
        self.bao.create_key("product-a", "aes256-gcm96")
        self.bao.create_key("product-b", "aes256-gcm96")
        child = self.bao.restrict(["allowed"], {"product-a": ["encrypt"]})
        self.assertNotEqual(child.token, self.bao.token)
        self.assertEqual(child.secret("allowed"), "known-only-to-the-proxy")
        sealed = child.product_operation("encrypt", "product-a", {"plaintext": "aGk="},
                                         capabilities={"product-a": ["encrypt"]})
        self.assertIn("ciphertext", sealed)
        # Call native endpoints directly: bypassing the Python adapter still cannot widen the token.
        for method, path, body in [
            ("GET", "secret/data/other", None),
            ("POST", "transit/encrypt/product-b", {"plaintext": "aGk="}),
            ("POST", "transit/decrypt/product-a", {"ciphertext": sealed["ciphertext"]}),
            ("POST", "transit/sign/guard", {"input": "aGk="}),
            ("POST", "auth/token/create", {}),
        ]:
            with self.subTest(path=path), self.assertRaises(KeyServiceError):
                child.call(method, path, body)
        child.revoke()
        with self.assertRaises(KeyServiceError):
            child.secret("allowed")

    def test_the_operator_reads_a_service_key_and_refuses_a_readable_token(self):
        from fabric.control.runtime.operator import key
        keys = Path(self.state, "keys")
        keys.mkdir()
        token = keys / "guard.token"
        token.write_text(self.bao.token)
        token.chmod(0o600)
        (keys / "guard.service").write_text(json.dumps({"address": self.bao.address, "token_file": str(token),
                                                        "key": "guard"}))
        self.assertIsInstance(key(keys, "guard"), KeyServiceSigner)
        os.chmod(token, 0o644)
        with self.assertRaises(PermissionError):
            key(keys, "guard")


if __name__ == "__main__":
    unittest.main()
