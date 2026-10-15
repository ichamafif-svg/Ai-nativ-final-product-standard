"""The entry path (D68 step 2): Envoy from the law, the gate's policy, the product in its bac behind its door."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catalog import effective, load  # noqa: E402
from enclosure import gateway, identity  # noqa: E402
from enclosure.bac import Bac  # noqa: E402
from enclosure.components import where  # noqa: E402
from enclosure.gate import Gate, Records, Refused, canonical  # noqa: E402
from blocks.python.standard_blocks.parse import ParseError  # noqa: E402

FIXTURES = Path(__file__).with_name("fixtures")
VALUES = effective(load(), {"public": ["GET /health"], "request_timeout_s": 2, "origins": ["https://app.example"]})
ENVOY = os.environ.get("STANDARD_ENVOY") or where("envoy")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Policy(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.signer = identity.LocalSigner(Path(self.dir, "key"))
        self.records = Records(Path(self.dir, "records.jsonl"))
        self.gate = Gate(door="/nowhere", values=VALUES, audience="shop", signer=self.signer, records=self.records)

    def read(self):
        return [json.loads(line) for line in Path(self.dir, "records.jsonl").read_text().splitlines()]

    def test_the_product_receives_one_canonical_document(self):
        self.assertEqual(canonical(b'{ "b" : 1, "a" : [1, 2] }', max_depth=32, max_bytes=100), b'{"a":[1,2],"b":1}')
        for bad in (b'{"a": 1, "a": 2}', '{"é": 1, "é": 2}'.encode(), b'{"x": NaN}', b'[' * 40 + b']' * 40,
                    '{"ﬁ": 1, "fi": 2}'.encode()):
            with self.assertRaises(ParseError):
                canonical(bad, max_depth=32, max_bytes=1000)

    def test_identity_headers_from_clients_never_pass_and_the_signed_one_verifies(self):
        headers, _ = self.gate.request("GET", "/", [("X-Standard-Identity", "forged"), ("Accept", "*/*")], b"")
        self.assertNotIn(identity.HEADER, dict(headers))
        headers, _ = self.gate.request("GET", "/", [("x-auth-request-user", "alice"),
                                                    ("x-auth-request-groups", "admin,ops")], b"")
        claims = identity.verify(dict(headers)[identity.HEADER], self.signer.public_pem(), audience="shop")
        self.assertEqual((claims["sub"], claims["groups"]), ("alice", ["admin", "ops"]))
        with self.assertRaises(ValueError):
            identity.verify(dict(headers)[identity.HEADER], self.signer.public_pem(), audience="other")

    def test_a_refusal_is_recorded_and_never_reaches_the_product(self):
        with self.assertRaises(Refused):
            self.gate.request("POST", "/x", [("content-type", "application/json")], b'{"a": 1, "a": 2}')
        with self.assertRaises(Refused):
            self.gate.request("POST", "/x", [("sec-fetch-site", "cross-site"), ("origin", "https://evil.example")], b"")
        self.gate.request("POST", "/x", [("sec-fetch-site", "cross-site"), ("origin", "https://app.example")], b"")
        self.assertEqual([r["capability"] for r in self.read()], ["ingress.json", "ingress.isolation"])

    def test_corrections_are_imposed_and_recorded_once(self):
        for _ in range(2):
            out = dict(self.gate.response("GET /", [("Server", "x/1"), ("Set-Cookie", "theme=dark")]))
        self.assertNotIn("server", out)
        self.assertIn("Secure", out["set-cookie"])
        self.assertIn("default-src", out["content-security-policy"])
        records = self.read()
        self.assertEqual(len(records), len({(r["capability"], r["attempt"]) for r in records}))
        self.assertTrue({"ingress.headers", "ingress.cookies"} <= {r["capability"] for r in records})
        for word in ("dark",):                                  # a record names what was missing, never a value
            self.assertNotIn(word, json.dumps(records))


@unittest.skipUnless(ENVOY, "Envoy is not installed: python -m tools.components fetch")
class EnvoyConfiguration(unittest.TestCase):
    def test_the_configuration_derived_from_the_law_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "envoy.json")
            path.write_text(json.dumps(gateway.config(VALUES, port=free_port(), gate=f"{tmp}/g.sock", oauth2=4180)))
            done = subprocess.run([ENVOY, "--mode", "validate", "-c", str(path)], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr[-800:])
            self.assertNotIn("Deprecated", done.stderr)


@unittest.skipUnless(ENVOY and Bac().ready, "needs Envoy and the bac")
class EntryPath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from enclosure.stack import Stack
        cls.port = free_port()
        cls.stack = Stack(tempfile.mkdtemp(), VALUES, [sys.executable, "-I", str(FIXTURES / "echo_product.py")],
                          cwd=FIXTURES, port=cls.port, envoy=ENVOY).start()

    @classmethod
    def tearDownClass(cls):
        cls.stack.stop()

    def call(self, method, path, body=None, headers=None):
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=body, method=method,
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=15) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def test_the_product_sees_canonical_json_and_no_client_identity(self):
        status, headers, body = self.call("POST", "/x", b'{"b": 1, "a": 2}', {
            "content-type": "application/json", "x-standard-identity": "forged", "x-auth-request-user": "eve"})
        seen = json.loads(body)
        self.assertEqual((status, seen["body"]), (200, '{"a":2,"b":1}'))
        self.assertFalse([k for k in seen["headers"] if "identity" in k or "auth-request" in k or "x-envoy" in k])
        self.assertNotIn("x-powered-by", {k.lower() for k in headers})

    def test_the_walls_of_the_entry_hold(self):
        self.assertEqual(self.call("POST", "/x", '{"é": 1, "é": 2}'.encode(), {"content-type": "application/json"})[0], 400)
        self.assertEqual(self.call("TRACE", "/")[0], 405)
        self.assertEqual(self.call("POST", "/x", b"x" * (VALUES["body_max_bytes"] + 1), {"content-type": "text/plain"})[0], 413)
        started = time.monotonic()
        self.assertEqual(self.call("GET", "/slow")[0], 504)
        self.assertLess(time.monotonic() - started, VALUES["request_timeout_s"] + 1.5)

    def test_what_the_gate_corrected_is_on_record(self):
        self.call("GET", "/page")
        found = {(r["capability"], r["route"]) for r in self.stack.read_records()}
        self.assertIn(("ingress.cookies", "GET /page"), found)
        self.assertIn(("ingress.headers", "GET /page"), found)


@unittest.skipUnless(ENVOY and where("oauth2-proxy") and Bac().ready, "needs Envoy, oauth2-proxy and the bac")
class SignIn(unittest.TestCase):
    """OpenID Connect with PKCE through oauth2-proxy; the product only ever sees the platform's signed identity."""

    def test_a_signed_in_user_reaches_the_product_as_a_verifiable_identity_and_nobody_else_does(self):
        import http.cookiejar
        sys.path.insert(0, str(FIXTURES))
        from fake_idp import Provider as FakeProvider
        from enclosure.signin import Provider, secrets
        from enclosure.stack import Stack

        class LocalHttp(http.cookiejar.DefaultCookiePolicy):     # the test has no TLS; Secure cookies still sent
            def return_ok_secure(self, cookie, request):
                return True

        port, signin, idp_port = free_port(), free_port(), free_port()
        idp = FakeProvider(idp_port)
        server = idp.serve()
        state = tempfile.mkdtemp()
        secrets(Path(state, "signin"))["client"].write_text("test-secret")
        provider = Provider(issuer=idp.issuer, client_id="shop", redirect_url=f"http://127.0.0.1:{port}/oauth2/callback",
                            login_url=f"{idp.issuer}/authorize", redeem_url=f"{idp.issuer}/token",
                            jwks_url=f"{idp.issuer}/jwks")
        stranger = urllib.request.build_opener(type("NoRedirect", (urllib.request.HTTPRedirectHandler,),
                                                    {"redirect_request": lambda *a: None}))
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(LocalHttp())))
        try:
            with Stack(state, VALUES, [sys.executable, "-I", str(FIXTURES / "echo_product.py")], cwd=FIXTURES,
                       port=port, oauth2=signin, provider=provider, audience="shop", envoy=ENVOY):
                with self.assertRaises(urllib.error.HTTPError) as refused:
                    stranger.open(f"http://127.0.0.1:{port}/private", timeout=10)
                self.assertEqual(refused.exception.code, 302)
                self.assertIn("code_challenge_method=S256", refused.exception.headers["location"])
                self.assertEqual(stranger.open(f"http://127.0.0.1:{port}/health", timeout=10).status, 200)
                browser.open(f"http://127.0.0.1:{port}/private", timeout=10)        # sign-in, then redirected
                seen = json.loads(browser.open(f"http://127.0.0.1:{port}/private", timeout=10).read())["headers"]
                self.assertFalse([k for k in seen if k.startswith("x-auth-request")])
                claims = identity.verify(seen[identity.HEADER], Path(state, "identity.pub").read_text(), audience="shop")
                self.assertEqual((claims["sub"], claims["groups"]), ("alice", ["admin"]))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
