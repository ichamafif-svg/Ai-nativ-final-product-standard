"""Standard's own probes of the product's application (standard/catalog/blocks.toml, `probes`), filled with the values
in force. They are Standard's, pinned with the release: the agent never writes the probe that judges it.

Run as a separate process with the product's tree as working directory, so importing the product cannot touch the
scanner's state:  python -I rule_probes.py < {"app": "module:attr", "values": {...}, "paths": [...]}  ->  JSON
{probe: [status, details]} with status pass | fail | na (nothing to probe) | unrun:<why>.

The app is driven in-process through httpx's ASGI transport at https://probe.invalid: no socket, no network. Session
probes replace the identity provider by a fake one through the session block's own transport hook.

HTTP mode, for products Standard cannot import (Next.js): `@app` is the URL where the product runs (a CI service, a
preview), {"base_url": "...", "routes": [{"path", "methods"}]} with the routes the scanner read from the tree. Only
the probes that need nothing but HTTP run (HTTP_PROBES, rate-limit last since the product sees one address); the
others are a gap of this release on that stack, never a debt.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import time
import traceback
import zipfile

BASE = "https://probe.invalid"
EVIL = "https://evil.probe.invalid"
HEADERS = ("strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy")
TRACE = re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+")
APP_PROBES = ("headers", "cookies", "cors", "csrf", "methods", "errors", "no-store", "param-pollution", "rate-limit",
              "unknown-field", "unauthenticated", "access-matrix", "health", "no-debug", "shutdown", "upload-limits",
              "upload-type", "zip-slip", "oidc-flow", "session-rotation", "logout", "session-timeout", "reauth",
              "log-redaction")

HTTP_PROBES = ("headers", "cookies", "cors", "csrf", "methods", "errors", "no-store", "param-pollution",
               "unauthenticated", "health", "rate-limit")


def http_routes(endpoints) -> list:
    """Scanner endpoints ("GET /orders/:id", "ANY /api/x", "POST action:y") as probe routes; actions are not URLs."""
    out = {}
    for e in endpoints:
        method, _, path = e.partition(" ")
        if not path.startswith("/"):
            continue
        methods = ["GET", "POST"] if method == "ANY" else [method]
        r = out.setdefault(path, {"path": path, "url": re.sub(r":\w+\*?", "1", path), "methods": [], "uploads": [],
                                  "route": None})
        r["methods"] = sorted(set(r["methods"]) | set(methods) - {"HEAD", "OPTIONS"})
    return [r for _, r in sorted(out.items()) if r["methods"]]


def _routes(app):
    out = []
    for r in getattr(app, "routes", []):
        methods = sorted((getattr(r, "methods", None) or set()) - {"HEAD", "OPTIONS"})
        path = getattr(r, "path", None)
        if not methods or not path or path.startswith(("/docs", "/redoc", "/openapi")):
            continue
        concrete = re.sub(r"\{[^}]+\}", "1", path)
        uploads = []
        for p in getattr(getattr(r, "dependant", None), "body_params", []) or []:
            if "UploadFile" in repr(getattr(p, "type_", None) or getattr(getattr(p, "field_info", None), "annotation", "")):
                uploads.append(p.name)
        out.append({"path": path, "url": concrete, "methods": methods, "uploads": uploads, "route": r})
    return out


class Probe:
    def __init__(self, app, values: dict, *, base_url: str | None = None, routes=None):
        import httpx
        self.app, self.values, self.httpx, self.base_url = app, values, httpx, base_url
        self.routes = routes if routes is not None else _routes(app)
        self.public = set(values.get("public", ["GET /health"]))
        self.callers = 0

    def client(self, cookies=None):
        """A client from a fresh address each time, so one probe's rate limit never answers another's."""
        self.callers += 1
        if self.base_url:
            return self.httpx.AsyncClient(base_url=self.base_url, cookies=cookies or {}, follow_redirects=False,
                                          timeout=10)
        caller = (f"192.0.2.{self.callers % 250 + 1}", 40000 + self.callers)
        return self.httpx.AsyncClient(transport=self.httpx.ASGITransport(app=self.app, raise_app_exceptions=False,
                                                                         client=caller),
                                      base_url=BASE, cookies=cookies or {}, follow_redirects=False)

    def as_user(self, role):
        """Act as a signed-in user with `role` for the access block and the session block's dependency. Returns an
        undo function."""
        from standard_blocks.session import User
        user = User(sub="probe", issuer="probe", roles=(role,), auth_time=time.time())

        async def fake(request=None):
            return user
        access = getattr(self.app.state, "standard_access", None)
        session = getattr(self.app.state, "standard_session", None)
        before = access.current_user if access is not None else None
        if access is not None:
            access.current_user = fake
        if session is not None:
            self.app.dependency_overrides[session.current_user] = fake

        def undo():
            if access is not None:
                access.current_user = before
            if session is not None:
                self.app.dependency_overrides.pop(session.current_user, None)
        return undo

    def is_public(self, method, path):
        return f"{method} {path}" in self.public

    # -- web ----------------------------------------------------------------------------------------------------
    async def headers(self):
        bad = []
        async with self.client() as c:
            for r in self.routes:
                if "GET" in r["methods"]:
                    resp = await c.get(r["url"])
                    missing = [h for h in HEADERS if h not in resp.headers]
                    if "server" in resp.headers or "x-powered-by" in resp.headers:
                        missing.append("banner")
                    if missing:
                        bad.append(f"GET {r['path']}: {', '.join(missing)}")
        return bad, not any("GET" in r["methods"] for r in self.routes)

    async def cookies(self):
        bad, seen = [], 0
        async with self.client() as c:
            for r in self.routes:
                if "GET" in r["methods"]:
                    for raw in (await c.get(r["url"])).headers.get_list("set-cookie"):
                        seen += 1
                        name, low = raw.split("=", 1)[0], raw.lower()
                        flags = [f for f in ("secure", "samesite") if f not in low]
                        if "httponly" not in low and name != "__Host-csrf":
                            flags.append("httponly")
                        if not name.startswith(("__Host-", "__Secure-")):
                            flags.append("prefix")
                        if flags:
                            bad.append(f"{name} on {r['path']}: {', '.join(flags)}")
        return bad, seen == 0

    async def cors(self):
        bad = []
        async with self.client() as c:
            for r in self.routes:
                resp = await c.options(r["url"], headers={"origin": EVIL, "access-control-request-method": r["methods"][0]})
                if resp.headers.get("access-control-allow-origin") in (EVIL, "*"):
                    bad.append(f"{r['path']} allows {EVIL}")
        return bad, not self.routes

    async def csrf(self):
        bad, unsafe = [], [(m, r) for r in self.routes for m in r["methods"] if m not in ("GET",)]
        async with self.client(cookies={"__Host-session": "probe"}) as c:
            for m, r in unsafe:
                resp = await c.request(m, r["url"], json={})
                if resp.status_code < 400:
                    bad.append(f"{m} {r['path']} answered {resp.status_code} without a CSRF token")
        return bad, not unsafe

    async def methods(self):
        bad = []
        async with self.client() as c:
            resp = await c.request("TRACE", "/")
            if resp.status_code != 405:
                bad.append(f"TRACE / answered {resp.status_code}")
            for r in self.routes:
                other = next((m for m in ("DELETE", "PUT", "PATCH") if m not in r["methods"]), None)
                if other and not any(o["url"] == r["url"] and other in o["methods"] for o in self.routes):
                    resp = await c.request(other, r["url"])
                    if resp.status_code < 400:
                        bad.append(f"{other} {r['path']} answered {resp.status_code}")
        return bad, False

    async def errors(self):
        bad = []
        async with self.client() as c:
            for r in self.routes:
                for m in r["methods"]:
                    resp = await c.request(m, r["url"] + "?probe=%00", content=b"\x00{", headers={"content-type": "application/json"})
                    if TRACE.search(resp.text) or (resp.status_code >= 500 and "ref" not in resp.text):
                        bad.append(f"{m} {r['path']} leaks internals ({resp.status_code})")
        return bad, not self.routes

    async def no_store(self):
        bad = []
        async with self.client() as c:
            for r in self.routes:
                if "GET" in r["methods"]:
                    resp = await c.get(r["url"], headers={"authorization": "Bearer probe"})
                    if "no-store" not in resp.headers.get("cache-control", ""):
                        bad.append(f"GET {r['path']} cacheable when authenticated")
        return bad, not any("GET" in r["methods"] for r in self.routes)

    async def param_pollution(self):
        bad = []
        async with self.client() as c:
            for r in self.routes:
                if "GET" in r["methods"]:
                    resp = await c.get(r["url"] + "?probe=1&probe=2")
                    if resp.status_code != 400:
                        bad.append(f"GET {r['path']} accepted a repeated parameter ({resp.status_code})")
        return bad, not any("GET" in r["methods"] for r in self.routes)

    async def rate_limit(self):
        unsafe = [(m, r) for r in self.routes for m in r["methods"] if m != "GET"]
        if not unsafe:
            return [], True
        m, r = unsafe[0]
        limit = int(self.values.get("rate_per_minute", 60))
        async with self.client() as c:
            codes = [(await c.request(m, r["url"], json={})).status_code for _ in range(limit + 2)]
        return ([] if 429 in codes else [f"{m} {r['path']}: {limit + 2} calls, no 429"]), False

    async def unknown_field(self):
        try:
            schema = self.app.openapi()
        except Exception as exc:
            return [f"openapi: {type(exc).__name__}"], False
        comps, bad, seen = schema.get("components", {}).get("schemas", {}), [], 0
        for path, ops in schema.get("paths", {}).items():
            for method, op in ops.items():
                content = (op.get("requestBody") or {}).get("content", {}).get("application/json")
                if not content:
                    continue
                seen += 1
                ref = content.get("schema", {}).get("$ref", "")
                body = comps.get(ref.rsplit("/", 1)[-1], content.get("schema", {}))
                if body.get("additionalProperties") is not False:
                    bad.append(f"{method.upper()} {path} accepts unknown fields")
        return bad, seen == 0

    # -- access -------------------------------------------------------------------------------------------------
    async def unauthenticated(self):
        bad = []
        async with self.client() as c:
            for r in self.routes:
                for m in r["methods"]:
                    if self.is_public(m, r["path"]):
                        continue
                    resp = await c.request(m, r["url"], json={})
                    if resp.status_code < 400:
                        bad.append(f"{m} {r['path']} answered {resp.status_code} to nobody")
        return bad, not self.routes

    async def access_matrix(self):
        access = getattr(getattr(self.app, "state", None), "standard_access", None)
        if access is None:
            return ["the app does not expose its Access (Access(...).bind(app))"], False
        from standard_blocks.access import route_ids
        ids, bad = route_ids(self.app), []
        for key, rid in sorted(ids.items()):
            method, path = key.split(" ", 1)
            if rid is None and not self.is_public(method, path) and path != "/health" and not path.startswith("/auth/"):
                bad.append(f"{key} declares no access id")
        matrix = self.values.get("access", {})
        for key, rid in sorted(ids.items()):
            if rid is None or self.is_public(*key.split(" ", 1)):
                continue
            method, path = key.split(" ", 1)
            allowed = matrix.get(rid, ["admin"])
            allowed = allowed if isinstance(allowed, list) else [allowed]
            for role in sorted(set(allowed) | {"probe-nobody"}):
                undo = self.as_user(role)
                try:
                    async with self.client() as c:
                        status = (await c.request(method, re.sub(r"\{[^}]+\}", "1", path), json={})).status_code
                finally:
                    undo()
                want_ok = role in allowed or "*" in allowed
                if want_ok and status == 403 or not want_ok and status != 403:
                    bad.append(f"{key} as {role}: {status}")
        return bad, False

    # -- runtime ------------------------------------------------------------------------------------------------
    async def health(self):
        async with self.client() as c:
            resp = await c.get("/health")
        return ([] if resp.status_code in (200, 503) and "status" in resp.text else ["GET /health is missing"]), False

    async def no_debug(self):
        return (["the app runs with debug"] if getattr(self.app, "debug", False) else []), False

    async def shutdown(self):
        hooks = getattr(getattr(self.app, "router", None), "on_shutdown", []) or []
        return ([] if hooks else ["no shutdown hook (runtime.install)"]), False

    async def log_redaction(self):
        try:
            from standard_blocks import log
        except ImportError:
            return ["the log block is not installed"], False
        out = log.event("probe", password="hunter2", note="AKIAABCDEFGHIJKLMNOP")
        return ([] if "hunter2" not in json.dumps(out) and "AKIA" not in json.dumps(out) else ["a secret reached the log"]), False

    # -- files --------------------------------------------------------------------------------------------------
    async def _uploads(self, make):
        targets = [(m, r) for r in self.routes for m in r["methods"] if r["uploads"] and m != "GET"]
        if not targets:
            return [], True
        signed = getattr(self.app.state, "standard_access", None) or getattr(self.app.state, "standard_session", None)
        ids = {}
        if getattr(self.app.state, "standard_access", None) is not None:
            from standard_blocks.access import route_ids
            ids = route_ids(self.app)
        bad = []
        for m, r in targets:
            allowed = self.values.get("access", {}).get(ids.get(f"{m} {r['path']}"), ["admin"])
            role = (allowed if isinstance(allowed, list) else [allowed] or ["admin"])[0]
            undo = self.as_user(role) if signed else (lambda: None)
            try:
                async with self.client() as c:
                    name, data, mime, want = make()
                    resp = await c.request(m, r["url"], files={r["uploads"][0]: (name, data, mime)})
                    if resp.status_code not in want:
                        bad.append(f"{m} {r['path']}: {name} answered {resp.status_code}")
            finally:
                undo()
        return bad, False

    async def upload_limits(self):
        n = int(self.values.get("upload_max_bytes", 10_485_760)) + 1
        return await self._uploads(lambda: ("big.png", b"\x89PNG\r\n\x1a\n" + b"0" * n, "image/png", (413,)))

    async def upload_type(self):
        return await self._uploads(lambda: ("x.png", b"#!/bin/sh\necho owned\n", "image/png", (415, 422)))

    async def zip_slip(self):
        if "application/zip" not in self.values.get("upload_types", []):
            return [], True
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../../escape.txt", "x")
        return await self._uploads(lambda: ("a.zip", buf.getvalue(), "application/zip", (415, 422)))

    # -- sessions -----------------------------------------------------------------------------------------------
    def _idp(self, oidc):
        import httpx
        import jwt
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        nums = key.public_key().public_numbers()
        b64 = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()
        jwk = {"kty": "EC", "crv": "P-256", "kid": "probe", "x": b64(nums.x), "y": b64(nums.y)}
        codes, iss = {}, oidc.issuer

        def handler(request):
            p = request.url.path
            if p.endswith("/.well-known/openid-configuration"):
                return httpx.Response(200, json={"issuer": iss, "jwks_uri": f"{iss}/probe-certs",
                                                 "authorization_endpoint": f"{iss}/probe-auth",
                                                 "token_endpoint": f"{iss}/probe-token"})
            if p.endswith("/probe-certs"):
                return httpx.Response(200, json={"keys": [jwk]})
            if p.endswith("/probe-token"):
                from urllib.parse import parse_qs
                form = parse_qs(request.content.decode())
                pend = codes.pop(form.get("code", [""])[0], None)
                if not pend:
                    return httpx.Response(400, json={"error": "invalid_grant"})
                now = int(time.time())
                claims = {"iss": iss, "aud": oidc.client_id, "sub": "probe-user", "iat": now, "exp": now + 300,
                          "auth_time": pend.get("auth_time", now), "nonce": pend["nonce"], "roles": ["admin"],
                          "amr": ["pwd", "otp"]}
                return httpx.Response(200, json={"id_token": jwt.encode(claims, key, "ES256", headers={"kid": "probe"})})
            return httpx.Response(404)
        oidc.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        oidc._meta = oidc._jwks = None
        return codes

    async def _sign_in(self, c, codes, **override):
        from urllib.parse import parse_qs, urlsplit
        r = await c.get("/auth/login")
        q = parse_qs(urlsplit(r.headers.get("location", "")).query)
        if q.get("code_challenge_method") != ["S256"] or "state" not in q or "nonce" not in q:
            return None, "login does not use PKCE S256 with state and nonce"
        code = f"probe-{len(codes)}-{time.time_ns()}"
        codes[code] = {"nonce": override.pop("nonce", q["nonce"][0]), **override.pop("pend", {})}
        resp = await c.get("/auth/callback", params={"code": code, "state": override.pop("state", q["state"][0]),
                                                     **override})
        return resp, None

    async def _session(self, body):
        oidc = getattr(getattr(self.app, "state", None), "standard_session", None)
        if oidc is None:
            return [], True
        codes = self._idp(oidc)
        async with self.client() as c:
            return await body(oidc, codes, c), False

    async def oidc_flow(self):
        async def body(oidc, codes, c):
            bad = []
            resp, why = await self._sign_in(c, codes, state="forged")
            if why:
                return [why]
            if resp.status_code < 400:
                bad.append("a forged state signed in")
            resp, _ = await self._sign_in(c, codes, nonce="other")
            if resp.status_code < 400:
                bad.append("a wrong nonce signed in")
            resp, _ = await self._sign_in(c, codes, iss="https://another.probe.invalid")
            if resp.status_code < 400:
                bad.append("another issuer signed in")
            return bad
        return await self._session(body)

    async def session_rotation(self):
        async def body(oidc, codes, c):
            await self._sign_in(c, codes)
            first = c.cookies.get("__Host-session")
            await self._sign_in(c, codes)
            second = c.cookies.get("__Host-session")
            if not first or not second:
                return ["no session after sign-in"]
            return ["the session id did not change at sign-in"] if first == second else []
        return await self._session(body)

    async def logout(self):
        async def body(oidc, codes, c):
            await self._sign_in(c, codes)
            sid = c.cookies.get("__Host-session")
            csrf = (await c.get("/auth/sessions")) and c.cookies.get("__Host-csrf") or ""
            await c.post("/auth/logout", headers={"x-csrf-token": csrf})
            after = await self.httpx.AsyncClient(transport=self.httpx.ASGITransport(app=self.app), base_url=BASE,
                                                 cookies={"__Host-session": sid or "x"}).get("/auth/sessions")
            return [] if after.status_code == 401 else ["the session survived logout"]
        return await self._session(body)

    async def session_timeout(self):
        async def body(oidc, codes, c):
            await self._sign_in(c, codes)
            sid = c.cookies.get("__Host-session")
            if not sid:
                return ["no session after sign-in"]
            idle = float(self.values.get("session_idle_min", 15)) * 60
            if not oidc.sessions.backdate(sid, idle + 1):
                return ["no server-side session"]
            return [] if (await c.get("/auth/sessions")).status_code == 401 else ["an idle session stayed open"]
        return await self._session(body)

    async def reauth(self):
        sensitive = [r for r in self.routes for m in r["methods"]
                     if any(re.fullmatch(p.replace("*", ".*"), f"{m}:{r['path'].strip('/').split('/')[0]}")
                            for p in self.values.get("sensitive_actions", []))]
        if not sensitive:
            return [], True

        async def body(oidc, codes, c):
            await self._sign_in(c, codes, pend={"auth_time": int(time.time()) - 3600})
            csrf = (await c.get("/auth/sessions")) and c.cookies.get("__Host-csrf") or ""
            bad = []
            for r in sensitive:
                for m in r["methods"]:
                    resp = await c.request(m, r["url"], json={}, headers={"x-csrf-token": csrf})
                    if resp.status_code != 401:
                        bad.append(f"{m} {r['path']} ran on an old sign-in ({resp.status_code})")
            return bad
        return await self._session(body)


def run_http(payload: dict) -> dict:
    values = payload.get("values", {})
    probe = Probe(None, values, base_url=payload["base_url"], routes=http_routes(payload.get("endpoints", [])))
    out = {p: ["gap", ["needs the app in-process (FastAPI); over HTTP not yet"]] for p in APP_PROBES
           if p not in HTTP_PROBES}
    for name in HTTP_PROBES:
        try:
            bad, empty = asyncio.run(getattr(probe, name.replace("-", "_"))())
            out[name] = ["na", []] if empty else ["fail", bad[:30]] if bad else ["pass", []]
        except Exception as exc:
            out[name] = [f"unrun:{type(exc).__name__}", [traceback.format_exception_only(exc)[-1].strip()[:200]]]
    return out


def run(payload: dict) -> dict:
    if payload.get("base_url"):
        return run_http(payload)
    sys.path[:0] = [os.getcwd(), *payload.get("paths", [])]
    os.environ["STANDARD_VALUES"] = json.dumps(payload.get("values", {}))
    os.environ.setdefault("STANDARD_FILES_DIR", tempfile.mkdtemp())
    os.environ.pop("STANDARD_ENV", None)
    module, _, attr = payload["app"].partition(":")
    try:
        import importlib
        app = getattr(importlib.import_module(module), attr or "app")
    except Exception as exc:
        return {p: [f"unrun:import {type(exc).__name__}", [str(exc)[:200]]] for p in APP_PROBES}
    probe, out = Probe(app, payload.get("values", {})), {}
    for name in payload.get("probes", APP_PROBES):
        try:
            bad, empty = asyncio.run(getattr(probe, name.replace("-", "_"))())
            out[name] = ["na", []] if empty else ["fail", bad[:30]] if bad else ["pass", []]
        except Exception as exc:
            out[name] = [f"unrun:{type(exc).__name__}", [traceback.format_exception_only(exc)[-1].strip()[:200]]]
    return out


def digest_of(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


if __name__ == "__main__":
    real, sys.stdout = sys.stdout, sys.stderr        # whatever the product prints never mixes with the verdicts
    verdicts = run(json.loads(sys.stdin.read()))
    real.write(json.dumps(verdicts))
