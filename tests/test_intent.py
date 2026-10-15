"""D70: business intent, once the human declares it, is probed (DATA-MIN through @field_uses)."""
import json
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.verification.rule_probes import run_http  # noqa: E402


class Orders(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        rows = [{"id": 1, "total": 10, "card_number": "4111"}] if self.path == "/orders" else {"id": 1, "total": 10}
        body = json.dumps(rows).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FieldUses(unittest.TestCase):
    def setUp(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), Orders)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def probe(self, uses):
        out = run_http({"base_url": f"http://127.0.0.1:{self.port}", "endpoints": ["GET /orders", "GET /order"],
                        "values": {"field_uses": uses, "public": []}})
        return out["field-uses"]

    def test_a_field_beyond_the_declared_use_fails_and_undeclared_intent_is_not_probed(self):
        status, details = self.probe({"GET /orders": ["id", "total"]})
        self.assertEqual(status, "fail")
        self.assertIn("card_number", details[0])
        self.assertEqual(self.probe({"GET /order": ["id", "total"]})[0], "pass")
        self.assertEqual(self.probe({})[0], "na")


if __name__ == "__main__":
    unittest.main()
