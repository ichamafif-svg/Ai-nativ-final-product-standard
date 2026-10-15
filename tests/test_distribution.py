"""Releases and runs, stated for outside verifiers: SLSA provenance (in-toto, DSSE) and TUF distribution."""
import base64
import functools
import hashlib
import json
import tempfile
import threading
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import fixture  # noqa: F401  (the repository on the path)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bt.signing import Signer
from kernel import parse
from kernel.identity import pae
from tools import provenance

try:
    import tuf
except ImportError:                                       # optional: release distribution only
    tuf = None


class Provenance(unittest.TestCase):
    def test_a_run_record_becomes_a_signed_slsa_statement(self):
        record = json.dumps({"method": "programs@sha256:" + "a" * 64, "job": "tests", "network": False,
                             "inputs": {"code": {"commit": "b" * 40}, "data": {"evidence": "sha256:" + "c" * 64}},
                             "output": {"facts": []}}, sort_keys=True).encode()
        statement = provenance.run_statement(record)
        self.assertEqual(statement["subject"][0]["digest"]["sha256"], hashlib.sha256(record).hexdigest())
        self.assertEqual(statement["predicate"]["buildDefinition"]["resolvedDependencies"],
                         [{"name": "code", "digest": {"gitCommit": "b" * 40}},
                          {"name": "data", "digest": {"sha256": "c" * 64}}])
        signer = Signer("scanner", Ed25519PrivateKey.generate())
        env = provenance.envelope(statement, signer)
        payload = base64.b64decode(env["payload"])
        self.assertEqual(parse(payload), statement)
        signer._key.public_key().verify(base64.b64decode(env["signatures"][0]["sig"]), pae(payload))


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


@unittest.skipIf(tuf is None, "python-tuf is not installed")
class Distribution(unittest.TestCase):
    def test_a_client_gets_only_what_the_release_roles_signed(self):
        from tools import distribute
        work = Path(tempfile.mkdtemp())
        repo, keys = work / "repo", work / "keys"
        distribute.init(repo, keys)
        trusted = work / "trusted-root.json"
        trusted.write_bytes((repo / "metadata" / "1.root.json").read_bytes())
        release = work / "standard-test.tar.gz"
        release.write_bytes(b"release bytes")
        distribute.add(repo, keys, [release])
        server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(repo)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            got = distribute.fetch(url, trusted, "standard-test.tar.gz", work / "out")
            self.assertEqual(got.read_bytes(), b"release bytes")
            (repo / "targets" / "standard-test.tar.gz").write_bytes(b"swapped bytes")      # same length: only the hash tells
            from tuf.api.exceptions import RepositoryError
            with self.assertRaises(RepositoryError):                     # the hash the targets role signed
                distribute.fetch(url, trusted, "standard-test.tar.gz", work / "out2")
            with self.assertRaises(LookupError):
                distribute.fetch(url, trusted, "unsigned.tar.gz", work / "out3")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
