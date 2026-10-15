"""The platform's other walls (D68 steps 3-4): the egress, the secret broker, the key service, the data."""
import http.cookiejar
import json
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.catalog import effective, load  # noqa: E402
from fabric.identity import identity# noqa: E402
from fabric.runtime.bac import Bac  # noqa: E402
from fabric.supply_chain.components import where  # noqa: E402
from fabric.data.postgres import PG, Database, available as database_available  # noqa: E402
from fabric.network.egress import mitmdump  # noqa: E402

FIXTURES = Path(__file__).with_name("fixtures")
sys.path.insert(0, str(FIXTURES))
READY = bool(Bac().ready and where("envoy"))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Destination(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.seen_auth = self.headers.get("authorization")
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(READY and mitmdump() and where("openbao"), "needs the bac, Envoy, mitmproxy and OpenBao")
class Egress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fabric.identity.keys import dev
        from fabric.network.stack import Stack
        from tls_destination import serve
        cls.plain, cls.tls = free_port(), free_port()
        cls.http = ThreadingHTTPServer(("127.0.0.2", cls.plain), Destination)
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        cls.https, ca = serve(cls.tls)
        cls.state = tempfile.mkdtemp()
        cls.bao, cls.bao_process = dev(cls.state, where("openbao"))
        cls.bao.put_secret("api", "s3cr3t-value")
        cls.bao.create_key("product-notes", "aes256-gcm96")
        cls.bao.create_key("identity-other", "aes256-gcm96")
        values = effective(load(), {"destinations": [f"127.0.0.2:{cls.plain}", f"127.0.0.2:{cls.tls}",
                                                     f"localhost:{cls.plain}"], "request_timeout_s": 10,
                                    "upload_types": ["text/plain"], "upload_max_bytes": 1000})
        cls.port = free_port()
        cls.stack = Stack(cls.state, values, [sys.executable, "-I", str(FIXTURES / "caller_product.py")], cwd=FIXTURES,
                          port=cls.port, secrets={"api": ["127.0.0.2"]}, bao=cls.bao, upstream_ca=ca,
                          key_capabilities={"product-notes": ["encrypt", "decrypt"]}).start()

    @classmethod
    def tearDownClass(cls):
        cls.stack.stop()
        cls.bao_process.kill()
        cls.bao_process.wait()
        for server in (cls.http, cls.https):
            server.shutdown()
            server.server_close()

    def ask(self, path="/call", **query):
        url = f"http://127.0.0.1:{self.port}{path}?{urllib.parse.urlencode(query)}"
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read())

    def test_a_secret_reaches_its_destination_and_never_the_bac(self):
        for scheme, port in (("http", self.plain), ("https", self.tls)):
            out = self.ask(url=f"{scheme}://127.0.0.2:{port}/", auth="Bearer secret:api")
            self.assertEqual(out["status"], 200)
            self.assertTrue(json.loads(out["body"])["ok"])
            server = self.http if scheme == "http" else self.https
            self.assertEqual(server.seen_auth, "Bearer s3cr3t-value")
            self.assertNotIn("s3cr3t-value", out["body"])
            self.assertFalse(out["env_has_secret"])

    def test_every_other_way_out_is_refused_and_recorded(self):
        self.assertEqual(self.ask(url="http://203.0.113.9/")["status"], 403)               # not a destination
        self.assertEqual(self.ask(url=f"http://localhost:{self.plain}/")["status"], 403)   # a private address
        self.assertEqual(self.ask(url=f"http://127.0.0.2:{self.plain}/", auth="Bearer secret:other")["status"], 403)
        self.assertTrue(self.ask("/direct", host="127.0.0.2", port=self.plain)["direct"].startswith("refused"))
        records = {(r["kind"], r["capability"]) for r in self.stack.read_records()}
        self.assertTrue({("refusal", "egress.destination"), ("refusal", "egress.private"),
                         ("refusal", "egress.secret"), ("alarm", "egress.secret")} <= records)

    def test_the_key_service_serves_the_products_own_keys_only(self):
        sealed = self.ask(url="http://keys.standard/encrypt/product-notes", body=json.dumps({"plaintext": "aGk="}))
        self.assertEqual(sealed["status"], 200)
        ciphertext = json.loads(sealed["body"])["ciphertext"]
        opened = self.ask(url="http://keys.standard/decrypt/product-notes", body=json.dumps({"ciphertext": ciphertext}))
        self.assertEqual(json.loads(opened["body"])["plaintext"], "aGk=")
        refused = self.ask(url="http://keys.standard/encrypt/identity-other", body=json.dumps({"plaintext": "aGk="}))
        self.assertEqual(refused["status"], 403)


    def test_files_are_kept_by_the_platform_within_the_rules(self):
        stored = self.ask("/put", url="http://files.standard/", body="hello", type="text/plain")
        self.assertEqual(stored["status"], 201)
        ident = json.loads(stored["body"])["id"]
        self.assertEqual(self.ask(url=f"http://files.standard/{ident}")["body"], "hello")
        self.assertEqual(self.ask("/put", url="http://files.standard/", body="<svg/>", type="image/svg+xml")["status"], 415)
        self.assertEqual(self.ask("/put", url="http://files.standard/", body="x" * 2000, type="text/plain")["status"], 413)

    def test_the_products_logs_never_hold_a_secret_the_platform_knows(self):
        self.ask(url=f"http://127.0.0.2:{self.plain}/", auth="Bearer secret:api", log="1")
        self.stack.capture.close()
        text = Path(self.state, "product.log").read_text()
        self.assertIn("ok", text)
        self.assertNotIn("s3cr3t-value", text)


@unittest.skipUnless(mitmdump() and where("openbao"), "needs mitmproxy and OpenBao")
class AgentEgress(unittest.TestCase):
    """D68 for the agent's own model calls: the platform injects the provider's key; the agent never holds it."""

    def test_the_agent_calls_its_model_with_a_key_it_never_holds(self):
        from engine.agents.llm import Gate
        from fabric.network.egress import Egress
        from fabric.identity.keys import dev
        from tls_destination import serve
        state, port = Path(tempfile.mkdtemp()), free_port()
        model, ca = serve(port)
        bao, process = dev(state, where("openbao"))
        try:
            bao.put_secret("model", "provider-key-value")
            values = effective(load(), {"destinations": [f"127.0.0.2:{port}"]})
            egress = Egress(state, values, secrets={"model": ["127.0.0.2"]}, bao=bao, upstream_ca=ca).start()
            try:
                section = {"egress": f"http://127.0.0.1:{egress.port}", "egress_ca": str(egress.mount / "ca.pem"),
                           "frontier": {"kind": "openai", "model": "m", "key": "secret:model",
                                        "endpoint": f"https://127.0.0.2:{port}/v1/chat/completions"}}
                gate = Gate.from_config(section, Path, state / "egress.log")
                self.assertEqual(gate.tiers["frontier"].key.reveal(), "secret:model")
                self.assertEqual(gate.ask("hello"), {"ok": True})
                self.assertEqual(model.seen_auth, "Bearer provider-key-value")
                with self.assertRaises(ValueError):            # a raw key next to the platform: refused
                    Gate.from_config({**section, "frontier": {**section["frontier"], "key": "sk-raw"}}, Path,
                                     state / "egress.log")
            finally:
                egress.stop()
        finally:
            process.kill()
            process.wait()
            model.shutdown()
            model.server_close()


@unittest.skipUnless(where("openbao") and where("envoy"), "needs OpenBao and Envoy")
class ServiceTls(unittest.TestCase):
    def test_services_on_other_machines_speak_mutual_tls_with_certificates_from_the_key_service(self):
        import subprocess
        from cryptography import x509
        from fabric.network import gateway
        from fabric.identity.keys import dev, service_certificates
        state = tempfile.mkdtemp()
        bao, process = dev(state, where("openbao"))
        try:
            issued = service_certificates(bao, ["gate", "egress"])
        finally:
            process.kill()
            process.wait()
        cert = x509.load_pem_x509_certificate(issued["gate"]["certificate"].encode())
        self.assertEqual(cert.subject.rfc4514_string(), "CN=gate.standard.internal")
        files = {}
        for name, text in (("ca", issued["ca"]), ("cert", issued["gate"]["certificate"]),
                           ("key", issued["gate"]["private_key"])):
            files[name] = str(Path(state, f"{name}.pem"))
            Path(files[name]).write_text(text)
        config = gateway.config(effective(load(), {}), port=free_port(), gate=f"{state}/g.sock")
        config["static_resources"]["clusters"].append(gateway.mtls_cluster(
            "egress", "egress.standard.internal", 8443, cert=files["cert"], key=files["key"], ca=files["ca"],
            server_name="egress.standard.internal"))
        Path(state, "envoy.json").write_text(json.dumps(config))
        done = subprocess.run([where("envoy"), "--mode", "validate", "-c", str(Path(state, "envoy.json"))],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr[-600:])


@unittest.skipUnless(database_available(), "needs PostgreSQL 16 with PL/Python")
class Data(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp()
        self.signer = identity.LocalSigner(Path(self.state, "key"))
        self.db = Database(self.state).start(audience="shop", public_pem=self.signer.public_pem())
        self.addCleanup(self.db.stop)
        self.sql("CREATE TABLE notes (id serial PRIMARY KEY, owner_id text NOT NULL, body text)")

    def sql(self, statement):
        return self.db.psql(statement, user="product", database="product", check=False)

    def as_(self, who, statement):
        token = identity.mint(self.signer, {"sub": who}, audience="shop")
        return self.sql(f"BEGIN; SELECT standard.act_as('{token}'); {statement}; COMMIT;")

    def test_each_subject_sees_and_writes_only_its_rows(self):
        self.as_("alice", "INSERT INTO notes(owner_id, body) VALUES ('alice', 'a')")
        self.as_("bob", "INSERT INTO notes(owner_id, body) VALUES ('bob', 'b')")
        self.assertEqual(self.as_("bob", "SELECT owner_id FROM notes").split(), ["bob", "bob"])   # act_as, then rows
        self.assertIn("row-level security", self.as_("bob", "INSERT INTO notes(owner_id, body) VALUES ('alice', 'x')"))
        self.as_("bob", "UPDATE notes SET body = 'mine' WHERE owner_id = 'alice'")
        self.assertEqual(self.db.psql("SELECT body FROM notes WHERE owner_id = 'alice'", database="product"), "a")

    def test_the_wall_cannot_be_stated_falsely_forgotten_or_removed(self):
        self.as_("alice", "INSERT INTO notes(owner_id, body) VALUES ('alice', 'a')")
        self.assertEqual(self.sql("SELECT count(*) FROM notes"), "0")                    # no subject, no row
        forged = identity.mint(identity.LocalSigner(Path(self.state, "other")), {"sub": "alice"}, audience="shop")
        self.assertIn("identity refused", self.sql(f"SELECT standard.act_as('{forged}')"))
        self.assertIn("must be owner", self.sql("ALTER TABLE notes DISABLE ROW LEVEL SECURITY"))
        self.assertIn("must be owner", self.sql("DROP POLICY standard_owner ON notes"))
        self.assertIn("permission denied", self.sql("CREATE FUNCTION f() RETURNS int LANGUAGE plpython3u AS $$ return 1 $$"))
        token = identity.mint(self.signer, {"sub": "alice"}, audience="shop")
        later = __import__("subprocess").run(                    # one session, two transactions
            [str(PG / "psql"), "-X", "-q", "-A", "-t", "-h", str(self.db.socket), "-U", "product", "-d", "product",
             "-c", f"SELECT standard.act_as('{token}')", "-c", "SELECT count(*) FROM notes"],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(later.stdout.split(), ["alice", "0"])     # the subject held for its own transaction only


@unittest.skipUnless(READY and where("oauth2-proxy") and database_available(), "needs the whole platform")
class SignedInData(unittest.TestCase):
    """End to end: two people sign in; the product passes on the identity the gateway signed; each sees their own."""

    def test_the_identity_signed_at_the_gateway_is_what_the_database_filters_on(self):
        from fake_idp import Provider as FakeProvider
        from fabric.network.signin import Provider, secrets
        from fabric.network.stack import Stack

        class LocalHttp(http.cookiejar.DefaultCookiePolicy):
            def return_ok_secure(self, cookie, request):
                return True

        port, signin = free_port(), free_port()
        idp = FakeProvider(free_port())
        server = idp.serve()
        state = tempfile.mkdtemp()
        secrets(Path(state, "signin"))["client"].write_text("test-secret")
        provider = Provider(issuer=idp.issuer, client_id="shop", redirect_url=f"http://127.0.0.1:{port}/oauth2/callback",
                            login_url=f"{idp.issuer}/authorize", redeem_url=f"{idp.issuer}/token",
                            jwks_url=f"{idp.issuer}/jwks")
        values = effective(load(), {"request_timeout_s": 10})
        try:
            with Stack(state, values, [sys.executable, "-I", str(FIXTURES / "notes_product.py")], cwd=FIXTURES,
                       port=port, oauth2=signin, provider=provider, audience="shop", database=True, egress=False):
                people = {}
                for who in ("alice", "bob"):
                    idp.user = who
                    people[who] = urllib.request.build_opener(
                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(LocalHttp())))
                    people[who].open(f"http://127.0.0.1:{port}/", timeout=20)       # signs in, comes back to /
                    people[who].open(f"http://127.0.0.1:{port}/setup", timeout=20)

                def get(who, path):
                    return json.loads(people[who].open(f"http://127.0.0.1:{port}{path}", timeout=20).read())

                added = get("alice", "/add?owner=alice")
                self.assertEqual(added[0], 0, added)
                self.assertEqual(get("bob", "/add?owner=bob")[0], 0)
                self.assertNotEqual(get("bob", "/add?owner=alice")[0], 0)              # refused by the database
                self.assertEqual(get("alice", "/list")[1].split(), ["alice", "alice"])
                self.assertEqual(get("bob", "/list")[1].split(), ["bob", "bob"])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
