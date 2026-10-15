"""The building blocks (blocks/python/standard_blocks): each holds its rules whatever the route does, and the scanner's
ban list catches product code that goes around them (engine/verification/bans.py, fact `blocks`)."""
import asyncio
import base64
import io
import struct
import sys
import tempfile
import time
import unittest
import zipfile
import zlib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "blocks" / "python")]

try:
    import fastapi  # noqa: F401
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient
    import httpx
    import jwt
    HAVE = True
except ImportError:                                      # the blocks' own dependencies are not Standard's
    HAVE = False

from engine.verification import bans  # noqa: E402
from engine.catalog import load  # noqa: E402


def need(test):
    return unittest.skipUnless(HAVE, "fastapi, httpx and PyJWT are the blocks' dependencies")(test)


class Tree:
    def __init__(self, files):
        self.files = {p: c.encode() for p, c in files.items()}

    def paths(self):
        return set(self.files)

    def read(self, p):
        return self.files[p]


class Defaults(unittest.TestCase):
    def test_the_blocks_defaults_are_the_catalogs(self):
        sys.path.insert(0, str(ROOT / "blocks" / "python"))
        from standard_blocks._defaults import DEFAULTS
        cat = load()
        self.assertEqual(DEFAULTS, {k: v["default"] for k, v in cat["values"].items() if "default" in v})


class Bans(unittest.TestCase):
    def setUp(self):
        self.bans = {n: b["bans"] for n, b in load()["blocks"].items() if b["bans"]}

    def test_going_around_a_block_is_seen_on_the_syntax_tree(self):
        code = '''import requests
from os import system
import subprocess as sp
from hashlib import md5
import pickle
x = eval(user)
sp.run(cmd, shell=True)
system("ls")
md5(b"x")
conn.execute(f"SELECT {x}")
conn.execute("SELECT 1")
httpx.get(u, verify=False)
open(path)
open("static.txt")
'''
        found = {p for _, p in bans.uses("app.py", code.encode(), [p for b in self.bans.values() for p in b])}
        for p in ("import:requests", "call:os.system", "call-kw:subprocess.run:shell=True", "call:hashlib.md5",
                  "import:pickle", "builtin:eval", "call-dyn:execute:0", "call-kw:*:verify=False", "call-dyn:open:0"):
            self.assertIn(p, found, p)
        lines = {line for line, p in bans.uses("app.py", code.encode(), ["call-dyn:execute:0", "call-dyn:open:0"])}
        self.assertEqual(lines, {10, 13})                      # the literal ones are not uses
        js = 'el.innerHTML = x; // el.innerHTML = y\nconst s = "a.innerHTML = b";\nwindow.addEventListener("message", f)'
        self.assertEqual(bans.uses("a.js", js.encode(), ["attr-set:innerHTML", "js-call:window.addEventListener:message"]),
                         [(1, "attr-set:innerHTML"), (3, "js-call:window.addEventListener:message")])

    def test_the_fact_judges_the_change_not_the_past(self):
        base = Tree({"app.py": "import pickle\n", "lib.py": "x = 1\n"})
        same = Tree({"app.py": "import pickle\n\n", "lib.py": "x = 2\n"})
        worse = Tree({"app.py": "import pickle\n", "lib.py": "import os\nos.system('x')\n"})
        self.assertEqual(bans.blocks_fact(base, same, ["app.py", "lib.py"], self.bans), ("clean", []))
        self.assertEqual(bans.blocks_fact(base, worse, ["lib.py"], self.bans),
                         ("breaks:1", ["lib.py:2:call:os.system"]))
        self.assertEqual(bans.blocks_fact(base, worse, ["lib.py"], {}), ("clean", []))
        copied = Tree({**{k: v.decode() for k, v in base.files.items()}, "vendor/standard_blocks/web.py": "x = 1\n"})
        self.assertEqual(bans.blocks_fact(base, copied, ["vendor/standard_blocks/web.py"], self.bans)[0], "breaks:1")


@need
class Web(unittest.TestCase):
    def app(self, **values):
        from standard_blocks import Values
        from standard_blocks.web import secure_app, set_cookie, redirect_to, client_ip
        from starlette.responses import JSONResponse
        v = Values({"rate_per_minute": 1000, **values})
        app = secure_app(FastAPI(), v)

        @app.get("/items")
        def items():
            return {"items": [1]}

        @app.post("/items")
        def create():
            return {"ok": True}

        @app.get("/boom")
        def boom():
            raise RuntimeError("secret path /etc/x")

        @app.get("/cookie")
        def cookie():
            r = JSONResponse({})
            r.set_cookie("plain", "1")
            set_cookie(r, "prefs", "dark")
            return r

        @app.get("/go")
        def go(next: str, request: fastapi.Request):
            return redirect_to(request, next)

        @app.get("/ip")
        def ip(request: fastapi.Request):
            return {"ip": client_ip(request)}
        return TestClient(app, base_url="https://testserver", raise_server_exceptions=False)

    def test_every_response_leaves_with_the_security_headers_and_without_a_banner(self):
        c = self.app(csp_sources=["https://cdn.example"])
        r = c.get("/items")
        for h in ("strict-transport-security", "content-security-policy", "x-content-type-options",
                  "referrer-policy", "cross-origin-opener-policy"):
            self.assertIn(h, r.headers)
        self.assertIn("frame-ancestors 'none'", r.headers["content-security-policy"])
        self.assertIn("https://cdn.example", r.headers["content-security-policy"])
        self.assertNotIn("server", r.headers)
        self.assertNotIn("cache-control", r.headers)                     # nothing authenticated

    def test_refusals_before_any_route(self):
        c = self.app()
        self.assertEqual(c.request("TRACE", "/items").status_code, 405)
        self.assertEqual(c.get("/items?a=1&a=2").status_code, 400)
        boom = c.get("/boom")
        self.assertEqual(boom.status_code, 500)
        self.assertNotIn("/etc", boom.text)
        self.assertIn("ref", boom.json())

    def test_cors_only_for_listed_origins_and_csrf_on_cookie_sessions(self):
        c = self.app(origins=["https://app.example"])
        ok = c.options("/items", headers={"origin": "https://app.example", "access-control-request-method": "POST"})
        self.assertEqual((ok.status_code, ok.headers["access-control-allow-origin"]), (204, "https://app.example"))
        bad = c.options("/items", headers={"origin": "https://evil.example", "access-control-request-method": "POST"})
        self.assertEqual(bad.status_code, 403)
        self.assertEqual(c.post("/items", headers={"origin": "https://evil.example"}).status_code, 403)
        c.cookies.set("__Host-session", "abc")
        self.assertEqual(c.post("/items").status_code, 403)                # no CSRF token
        r = c.get("/items")
        self.assertEqual(r.headers["cache-control"], "no-store")          # authenticated: never cached
        csrf = c.cookies.get("__Host-csrf")
        self.assertTrue(csrf)
        self.assertEqual(c.post("/items", headers={"x-csrf-token": csrf}).status_code, 200)

    def test_cookie_flags_redirects_proxies_and_rate_limits(self):
        c = self.app(redirect_targets=["pay.example"], trusted_proxies=["10.0.0.0/8"])
        cookies = c.get("/cookie").headers.get_list("set-cookie")
        self.assertTrue(all("Secure" in x and "SameSite" in x and "HttpOnly" in x for x in cookies))
        self.assertTrue(any(x.startswith("__Host-prefs=") for x in cookies))
        self.assertEqual(c.get("/go?next=/orders", follow_redirects=False).headers["location"], "/orders")
        self.assertEqual(c.get("/go?next=https://pay.example/x", follow_redirects=False).headers["location"],
                         "https://pay.example/x")
        for evil in ("https://evil.example", "//evil.example", "/\\evil.example"):
            self.assertEqual(c.get("/go", params={"next": evil}, follow_redirects=False).headers["location"], "/")
        self.assertEqual(c.get("/ip", headers={"x-forwarded-for": "1.2.3.4"}).json()["ip"], "testclient")
        slow = self.app(rate_per_minute=2)
        codes = [slow.post("/items").status_code for _ in range(4)]
        self.assertEqual(codes[-1], 429)


def _rsa():
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = key.public_key().public_numbers()
    b64 = lambda i: base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    return key, {"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": b64(n.n), "e": b64(n.e)}


@need
class Session(unittest.TestCase):
    ISS = "https://idp.example/realms/shop"

    def setUp(self):
        from standard_blocks import Values
        from standard_blocks.session import Oidc
        from standard_blocks.access import Access, route_ids
        self.key, jwk = _rsa()
        self.codes, self.claims = {}, {}

        def idp(request: httpx.Request):
            path = request.url.path
            if path.endswith("/.well-known/openid-configuration"):
                return httpx.Response(200, json={"issuer": self.ISS, "jwks_uri": f"{self.ISS}/certs",
                                                 "authorization_endpoint": f"{self.ISS}/auth",
                                                 "token_endpoint": f"{self.ISS}/token"})
            if path.endswith("/certs"):
                return httpx.Response(200, json={"keys": [jwk]})
            if path.endswith("/token"):
                form = parse_qs(request.content.decode())
                pending = self.codes.pop(form["code"][0], None)
                if pending is None:
                    return httpx.Response(400, json={"error": "invalid_grant"})
                import hashlib
                challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()) \
                    .rstrip(b"=").decode()
                if challenge != pending["challenge"]:
                    return httpx.Response(400, json={"error": "pkce"})
                now = int(time.time())
                claims = {"iss": self.ISS, "aud": "shop", "sub": "u-1", "iat": now, "exp": now + 300,
                          "auth_time": now, "nonce": pending["nonce"], "roles": ["clerk"], "amr": ["pwd", "otp"],
                          **self.claims}
                return httpx.Response(200, json={"id_token": jwt.encode(claims, self.key, "RS256",
                                                                        headers={"kid": "k1"})})
            return httpx.Response(404)
        self.values = Values({"access": {"orders.read": ["clerk"]}, "public": ["GET /hello"], "rate_per_minute": 1000})
        from standard_blocks.web import secure_app
        app = secure_app(FastAPI(), self.values)
        self.oidc = Oidc(self.ISS, "shop", "https://testserver/auth/callback", self.values,
                         transport=httpx.MockTransport(idp))
        access = Access(self.oidc.current_user, self.values)
        app.include_router(self.oidc.router)

        @app.get("/orders/{oid}", dependencies=[Depends(access.allow("orders.read"))])
        def read(oid: int):
            return {"id": oid}

        @app.get("/admin/stats", dependencies=[Depends(access.allow("admin.stats"))])
        def stats():
            return {}

        @app.get("/hello", dependencies=[Depends(access.allow("hello"))])
        def hello():
            return {"hi": True}

        @app.post("/account/email", dependencies=[Depends(self.oidc.fresh(max_age_s=60))])
        def email():
            return {"ok": True}

        @app.get("/open")
        def open_():
            return {}
        self.app, self.route_ids = app, route_ids
        self.c = TestClient(app, base_url="https://testserver")

    def sign_in(self, c=None, **override):
        c = c or self.c
        r = c.get("/auth/login", follow_redirects=False)
        q = parse_qs(urlsplit(r.headers["location"]).query)
        self.assertEqual(q["code_challenge_method"], ["S256"])
        code = "c-" + str(len(self.codes))
        self.codes[code] = {"nonce": override.pop("nonce", q["nonce"][0]), "challenge": q["code_challenge"][0]}
        return c.get("/auth/callback", params={"code": code, "state": override.pop("state", q["state"][0]),
                                               **override}, follow_redirects=False)

    def test_sign_in_rotates_the_session_and_the_access_matrix_decides(self):
        self.assertEqual(self.c.get("/orders/1").status_code, 401)
        self.assertEqual(self.c.get("/hello").status_code, 200)                       # @public
        first = self.sign_in()
        self.assertEqual(first.status_code, 303)
        sid = self.c.cookies.get("__Host-session")
        self.assertEqual(self.c.get("/orders/1").json(), {"id": 1})
        self.assertEqual(self.c.get("/admin/stats").status_code, 403)                 # not in @access: admin only
        self.sign_in()
        self.assertNotEqual(self.c.cookies.get("__Host-session"), sid)               # a new id at every sign-in
        self.assertIsNone(self.oidc.sessions.get(sid, 1e9, 1e9))
        self.values.set("access", {"orders.read": ["auditor"]})                        # applies at once
        self.assertEqual(self.c.get("/orders/1").status_code, 403)
        self.assertEqual(self.route_ids(self.app)["GET /open"], None)                  # the probe sees it
        self.assertEqual(self.route_ids(self.app)["GET /orders/{oid}"], "orders.read")

    def test_a_forged_state_a_wrong_nonce_or_another_issuer_never_sign_in(self):
        self.assertEqual(self.sign_in(state="forged").status_code, 400)
        self.assertEqual(self.sign_in(nonce="other").status_code, 401)
        self.assertEqual(self.sign_in(iss="https://evil.example").status_code, 400)
        self.assertIsNone(self.c.cookies.get("__Host-session"))

    def test_timeouts_logout_and_reauthentication(self):
        self.sign_in()
        csrf = self.c.get("/orders/1") and self.c.cookies.get("__Host-csrf")
        self.assertEqual(self.c.post("/account/email", headers={"x-csrf-token": csrf}).status_code, 200)
        self.claims["auth_time"] = int(time.time()) - 3600
        self.sign_in()
        csrf = self.c.get("/orders/1") and self.c.cookies.get("__Host-csrf")
        stale = self.c.post("/account/email", headers={"x-csrf-token": csrf})
        self.assertEqual((stale.status_code, stale.headers.get("x-reauth")), (401, "/auth/login?prompt=login"))
        self.values.set("session_idle_min", 0)
        self.assertEqual(self.c.get("/orders/1").status_code, 401)                    # idle: gone
        self.values.set("session_idle_min", 15)
        self.sign_in()
        other = TestClient(self.app, base_url="https://testserver")
        self.sign_in(other)
        csrf = self.c.get("/orders/1") and self.c.cookies.get("__Host-csrf")
        out = self.c.post("/auth/logout?everywhere=true", headers={"x-csrf-token": csrf})
        self.assertEqual(out.status_code, 200)
        self.assertEqual(other.get("/orders/1").status_code, 401)                      # ended everywhere


@need
class CryptoParseProcess(unittest.TestCase):
    def test_crypto(self):
        from standard_blocks.crypto import CryptoError, check, derive, key, open_, same, seal, token
        k = key()
        box = seal(k, b"data", b"ctx")
        self.assertEqual(open_(k, box, b"ctx"), b"data")
        self.assertNotEqual(seal(k, b"data"), seal(k, b"data"))                       # a fresh nonce each time
        prefix, body = box.rsplit(".", 1)
        # A different leading base64 character always changes decoded bytes; replacing the tail can be a no-op.
        tampered = prefix + "." + ("B" if body[0] == "A" else "A") + body[1:]
        self.assertNotEqual(tampered, box)
        for bad in (tampered, seal(key(), b"data", b"ctx")):
            with self.assertRaises(CryptoError):
                open_(k, bad, b"ctx")
        with self.assertRaises(CryptoError):
            open_(k, box, b"other")
        self.assertGreaterEqual(len(token()), 43)
        d = derive("recovery-code")
        self.assertTrue(check("recovery-code", d))
        self.assertFalse(check("other", d))
        self.assertTrue(same("a", b"a"))

    def test_parse_and_process(self):
        from standard_blocks.parse import ParseError, csv_row, ldap_escape, pattern, search, xml
        with self.assertRaises(ParseError):
            xml('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
        self.assertEqual(xml("<a><b>1</b></a>").find("b").text, "1")
        self.assertEqual(csv_row(["=1+1", "ok", "-2", "@x"]), "'=1+1,ok,'-2,'@x\r\n")
        with self.assertRaises(ParseError):
            pattern(r"(a+)+$")
        self.assertIsNotNone(search("a.b", "xxa.b", literal=True))
        self.assertIsNone(search("a.b", "axb", literal=True))
        self.assertEqual(ldap_escape("a*(b)"), r"a\2a\28b\29")
        from standard_blocks.process import ProcessError, run
        with self.assertRaises(ProcessError):
            run("echo hi; rm -rf /")
        self.assertEqual(run(["echo", "a; b"]).stdout, b"a; b\n")                     # no shell: a literal


def _png(w, h, text=b""):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    raw = b"".join(b"\x00" + b"\x00" * w * 3 for _ in range(h))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + \
        (chunk(b"tEXt", b"GPS\x0048.85,2.35") if text else b"") + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


@need
class Files(unittest.TestCase):
    def files(self, **values):
        from standard_blocks import Values
        from standard_blocks.files import Files
        return Files(Values({"upload_types": ["image/png", "application/zip"], **values}), tempfile.mkdtemp())

    def upload(self, data):
        class U:
            def __init__(self):
                self.io = io.BytesIO(data)

            async def read(self, n):
                return self.io.read(n)
        return U()

    def test_limits_types_metadata_and_names(self):
        from standard_blocks.files import FileRejected
        f = self.files(upload_max_bytes=100_000, image_max_pixels=10_000)
        run = lambda data, **kw: asyncio.run(f.receive(self.upload(data), owner="u-1", **kw))
        fid = run(_png(10, 10, text=True))
        self.assertNotIn(b"GPS", f.read(fid, owner="u-1"))                            # metadata stripped
        for data, status in ((b"x" * 200_000, 413), (b"%PDF-1.7 ...", 415), (_png(200, 200), 413)):
            with self.assertRaises(FileRejected) as refused:
                run(data)
            self.assertEqual(refused.exception.status, status)
        with self.assertRaises(FileRejected):
            f.read("../../etc/passwd", owner="u-1")
        with self.assertRaises(FileRejected):
            f.read(fid, owner="u-2")                                                    # another owner's file
        served = f.serve(fid, owner="u-1", as_name='rapport "été".png')
        self.assertIn("filename=\"rapport__ete_.png\"", served.headers["content-disposition"])
        self.assertIn("filename*=UTF-8''rapport%20%22%C3%A9t%C3%A9%22.png", served.headers["content-disposition"])

    def test_archives_and_quota(self):
        from standard_blocks.files import FileRejected
        f = self.files(archive_max_files=3, user_quota_bytes=2_000)

        def zipped(entries):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for name, data in entries:
                    z.writestr(name, data)
            return buf.getvalue()
        run = lambda data: asyncio.run(f.receive(self.upload(data), owner="u-1"))
        fid = run(zipped([("a.txt", "a")]))
        self.assertEqual(f.unpack(fid, owner="u-1"), {"a.txt": b"a"})
        for entries in ([("../x", "a")], [("/etc/x", "a")], [(str(i), "a") for i in range(5)]):
            with self.assertRaises(FileRejected):
                run(zipped(entries))
        with self.assertRaises(FileRejected) as quota:
            run(zipped([("big.txt", "x" * 5000)]))
        self.assertEqual(quota.exception.status, 413)


@need
class OutboundRender(unittest.TestCase):
    def test_outbound_calls_listed_services_only_and_never_follows_redirects(self):
        from standard_blocks import Values
        from standard_blocks.outbound import Outbound, OutboundRefused
        seen = []

        def server(request):
            seen.append(str(request.url))
            return httpx.Response(302, headers={"location": "http://169.254.169.254/"})
        out = Outbound({"billing": "https://billing.example", "other": "https://other.example"},
                       Values({"destinations": ["billing.example"]}), transport=httpx.MockTransport(server))
        r = asyncio.run(out.get("billing", "/x"))
        self.assertEqual((r.status_code, seen), (302, ["https://billing.example/x"]))
        for service, path in (("other", "/x"), ("billing", "http://169.254.169.254/"), ("nope", "/x"),
                              ("billing", "//evil.example/")):
            with self.assertRaises(OutboundRefused):
                asyncio.run(out.get(service, path))

    def test_html_from_users_and_urls(self):
        from standard_blocks.render import clean_html, one_line, url
        dirty = '<p onclick="x()">hi<script>alert(1)</script><a href="javascript:alert(1)">x</a>' \
                '<a href="https://ok.example">y</a><img src=x onerror=alert(1)></p>'
        clean = clean_html(dirty)
        for bad in ("script", "onclick", "javascript", "onerror", "<img"):
            self.assertNotIn(bad, clean)
        self.assertIn('href="https://ok.example"', clean)
        self.assertEqual(url("https://shop.example", "a/b", 7, q="x&y=1"), "https://shop.example/a%2Fb/7?q=x%26y%3D1")
        self.assertEqual(one_line("a\r\nBcc: x"), "a Bcc: x")


if __name__ == "__main__":
    unittest.main()
