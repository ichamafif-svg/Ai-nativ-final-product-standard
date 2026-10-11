"""The web interface (ARCHITECTURE.md §11.9): a browser signs exactly what the kernel verifies, and the server holds no
key, reads through the gateway and forwards envelopes."""
import argparse
import json
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import ceremony  # noqa: E402
from kernel.canon import canon  # noqa: E402
from kernel.identity import open_envelope, statement, verify  # noqa: E402
from test_install import Clock  # noqa: E402
from test_maintenance import FILES, demo_repository  # noqa: E402

NODE = """
import { envelope, importKeyFile } from "%s";
const [key, domain, body] = process.argv.slice(2);
const signer = await importKeyFile(key);
console.log(JSON.stringify({ env: await envelope(domain, "observation", JSON.parse(body), signer), signer: { keyid: signer.keyid, public: signer.public } }));
"""


def node_sign(key_text: str, domain: str, body: dict) -> dict:
    script = Path(tempfile.mkdtemp()) / "sign.mjs"
    script.write_text(NODE % (ROOT / "surface" / "static" / "sign.js").as_uri())
    r = subprocess.run(["node", str(script), key_text, domain, json.dumps(body)], capture_output=True, text=True,
                       timeout=60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return json.loads(r.stdout)


@unittest.skipUnless(subprocess.run(["which", "node"], capture_output=True).returncode == 0, "node is not installed")
class BrowserSigning(unittest.TestCase):
    def test_the_browser_signs_the_very_bytes_the_kernel_verifies(self):
        from trusted.signing import envelope
        root = Path(tempfile.mkdtemp())
        signer = ceremony.new_key(root / "h3.key")
        body = {"id": "review-1", "at": 1_900_000_000_000, "author": "h3", "under": "grant-reviewer",
                "resource": "repo:contrib:alice/" + "a" * 40 + "/" + "b" * 40, "property": "review",
                "status": "approved", "level": "real", "note": 'é ü " \\ \n \u2028 €'}
        out = node_sign((root / "h3.key").read_text(), "sha256:" + "0" * 64, body)
        self.assertEqual(out["signer"]["public"], signer.public)
        self.assertEqual(out["signer"]["keyid"], signer.keyid)
        kind, opened, message, _ = open_envelope(out["env"])
        self.assertEqual((kind, opened), ("observation", body))
        self.assertTrue(verify(signer.root_key(), message, out["env"]["signatures"][0]))
        self.assertEqual(out["env"], envelope("sha256:" + "0" * 64, "observation", body, [signer]))   # byte for byte


class Server(unittest.TestCase):
    def test_state_dossier_and_admission_through_the_gateway(self):
        import trusted.daemon as daemon
        from surface.web import Installation, handler
        from http.server import ThreadingHTTPServer
        from trusted.gateway import AdmissionGateway
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, FILES)
        clock = Clock(1_900_000_000_000)
        ceremony.now = daemon.now_ms = clock
        ceremony.init(argparse.Namespace(dir=str(root / "install"), repo=str(repo), github=None, token_file=None,
                                         pins=str(root / "elsewhere" / "pins.db")))
        clock.t += 3_600_100
        ceremony.activate(argparse.Namespace(dir=str(root / "install")))
        operator = daemon.Installation(root / "install" / "standard.toml")
        operator.tick()
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        web = ThreadingHTTPServer(("127.0.0.1", 0), handler(Installation(root / "install" / "standard.toml")))
        threading.Thread(target=web.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{web.server_address[1]}"
        try:
            state = json.loads(urllib.request.urlopen(f"{url}/api/state").read())
            self.assertEqual(state["assessment"], "SELF_ASSESSED")
            self.assertIn("sbom", [g["target"] for g in state["run"]["gaps"]])
            self.assertEqual(state["signing"]["grants"]["reviewer"]["holder"], "h3")
            main = state["main"]
            self.assertIn("initial", json.loads(urllib.request.urlopen(f"{url}/api/dossier/{main}").read())["message"])
            page = urllib.request.urlopen(f"{url}/").read().decode()
            self.assertIn('src="/app.js"', page)
            forged = urllib.request.Request(f"{url}/api/admit", data=json.dumps({"payloadType": "x"}).encode(),
                                            headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(forged)
            self.assertEqual(refused.exception.code, 409)
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(f"{url}/api/dossier/..%2f..%2fetc")
        finally:
            web.shutdown()
            web.server_close()
            gateway.shutdown()
            gateway.server_close()


if __name__ == "__main__":
    unittest.main()
