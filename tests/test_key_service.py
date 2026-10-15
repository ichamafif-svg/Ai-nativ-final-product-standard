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

from bt.signing import KeyServiceSigner, envelope  # noqa: E402
from enclosure.components import where  # noqa: E402
from kernel.identity import pae  # noqa: E402


@unittest.skipUnless(where("openbao"), "needs OpenBao: python -m tools.components fetch")
class KeyService(unittest.TestCase):
    def setUp(self):
        from enclosure.keys import dev
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

    def test_the_operator_reads_a_service_key_and_refuses_a_readable_token(self):
        from runtime.operator import key
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
