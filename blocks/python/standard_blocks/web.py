"""The web layer (CONTENT-TYPE, COOKIES, HSTS, CORS, SEC-HEADERS, CSRF, METHODS, HTTPS-REDIRECT, TRUSTED-HEADERS,
REDIRECT, NO-VERSION-LEAK, NO-CACHE-SENSITIVE, ERROR-GENERIC, PARAM-POLLUTION, ANTI-AUTOMATION, XSSI).

    app = secure_app(FastAPI(), values)

One ASGI middleware in front of the whole application: whatever a route does, its response leaves with these
headers, cookie flags and limits. Values are read on every request, so a signed change applies at once.
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from urllib.parse import parse_qsl, urlsplit

from . import Values
from . import log
from .crypto import same, token

SESSION_COOKIE, CSRF_COOKIE, CSRF_HEADER = "__Host-session", "__Host-csrf", "x-csrf-token"
SAFE = {"GET", "HEAD", "OPTIONS"}
REFUSED_METHODS = {"TRACE", "TRACK", "CONNECT"}
HSTS = "max-age=31536000; includeSubDomains; preload"


def production() -> bool:
    return os.environ.get("STANDARD_ENV", "") == "production"


def csp(values: Values) -> str:
    extra = " ".join(s for s in values["csp_sources"] if " " not in s and ";" not in s)
    src = f"'self' {extra}".strip()
    return (f"default-src {src}; script-src {src}; style-src {src}; img-src {src} data:; connect-src {src}; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; report-to standard")


def _ip(scope) -> str:
    return (scope.get("client") or ("0.0.0.0", 0))[0]


def _trusted(values: Values, peer: str) -> bool:
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for net in values["trusted_proxies"]:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def client_ip(request) -> str:
    """The caller's address: the forwarded one only when the peer is in @trusted_proxies."""
    values = request.app.state.standard_values
    peer = _ip(request.scope)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and _trusted(values, peer):
        return forwarded.split(",")[0].strip()
    return peer


def redirect_to(request, target: str, status: int = 303):
    """A redirect inside the app (a path), or to a host in @redirect_targets. Anything else goes home."""
    from starlette.responses import RedirectResponse as _Redirect
    values = request.app.state.standard_values
    parts = urlsplit(target)
    inside = target.startswith("/") and not target.startswith("//") and not parts.scheme and not parts.netloc \
        and "\\" not in target
    outside = parts.scheme == "https" and parts.hostname in values["redirect_targets"]
    if not (inside or outside):
        log.security("redirect.refused", route=request.url.path)
        target = "/"
    return _Redirect(target, status_code=status)


def set_cookie(response, name: str, value: str, *, max_age: int | None = None, readable: bool = False) -> None:
    """A cookie with the __Host- prefix, Secure, SameSite=Lax, HttpOnly unless a script must read it."""
    if not name.startswith("__Host-"):
        name = "__Host-" + name
    if len(name) + len(value) > 4000:
        raise ValueError("a cookie stays under 4 KB")
    response.set_cookie(name, value, max_age=max_age, path="/", secure=True, httponly=not readable, samesite="lax")


class _Buckets:
    def __init__(self):
        self.lock, self.state = threading.Lock(), {}

    def take(self, key, per_minute: int) -> bool:
        now = time.monotonic()
        with self.lock:
            tokens, at = self.state.get(key, (per_minute, now))
            tokens = min(per_minute, tokens + (now - at) * per_minute / 60)
            if tokens < 1:
                self.state[key] = (tokens, now)
                return False
            self.state[key] = (tokens - 1, now)
            if len(self.state) > 100_000:
                self.state.clear()
            return True


class Guard:
    """Pure ASGI middleware: refuses what must not reach a route, and dresses every response."""

    def __init__(self, app, values: Values):
        self.app, self.values, self.buckets = app, values, _Buckets()

    async def _send_json(self, send, status: int, body: dict, headers=()):
        data = json.dumps(body).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json; charset=utf-8"),
                                (b"content-length", str(len(data)).encode()), *self._security(None, False), *headers]})
        await send({"type": "http.response.body", "body": data})

    def _security(self, content_type, authenticated: bool):
        h = [(b"strict-transport-security", HSTS.encode()), (b"x-content-type-options", b"nosniff"),
             (b"referrer-policy", b"strict-origin-when-cross-origin"), (b"cross-origin-opener-policy", b"same-origin"),
             (b"x-frame-options", b"DENY"), (b"content-security-policy", csp(self.values).encode()),
             (b"reporting-endpoints", b'standard="/.well-known/csp-report"')]
        if authenticated:
            h.append((b"cache-control", b"no-store"))
        return h

    def _cors(self, origin: str | None, host: str | None):
        if not origin:
            return None
        o = urlsplit(origin)
        if o.netloc and o.netloc == host:
            return "same"
        return origin if origin in self.values["origins"] else "refused"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        method = scope["method"].upper()
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        cookies = dict(p.strip().split("=", 1) for p in headers.get("cookie", "").split(";") if "=" in p)
        authenticated = SESSION_COOKIE in cookies or "authorization" in headers
        if method in REFUSED_METHODS:
            return await self._send_json(send, 405, {"error": "method not allowed"})
        query = parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
        keys = [k for k, _ in query]
        if len(keys) != len(set(keys)):
            return await self._send_json(send, 400, {"error": "a parameter appears twice"})
        if production():
            proto = headers.get("x-forwarded-proto") if _trusted(self.values, _ip(scope)) else None
            if (proto or scope.get("scheme")) == "http":
                if method == "GET" and "text/html" in headers.get("accept", ""):
                    location = f"https://{headers.get('host', '')}{scope.get('raw_path', b'/').decode('latin-1')}"
                    return await self._send_json(send, 308, {"error": "https only"},
                                                 [(b"location", location.encode("latin-1"))])
                return await self._send_json(send, 403, {"error": "https only"})
        allowed = self._cors(headers.get("origin"), headers.get("host"))
        cors_headers = []
        if allowed not in (None, "same", "refused"):
            cors_headers = [(b"access-control-allow-origin", allowed.encode("latin-1")), (b"vary", b"Origin"),
                            (b"access-control-allow-credentials", b"true")]
        if method == "OPTIONS" and "access-control-request-method" in headers:
            if allowed in (None, "refused"):
                return await self._send_json(send, 403, {"error": "origin not allowed"})
            await send({"type": "http.response.start", "status": 204, "headers": [
                *cors_headers, (b"access-control-allow-methods", b"GET, POST, PUT, PATCH, DELETE"),
                (b"access-control-allow-headers", b"content-type, x-csrf-token, authorization"),
                (b"access-control-max-age", b"600"), *self._security(None, False)]})
            return await send({"type": "http.response.body", "body": b""})
        if method not in SAFE:
            if allowed == "refused":
                return await self._send_json(send, 403, {"error": "origin not allowed"})
            if SESSION_COOKIE in cookies and "authorization" not in headers:
                if not same(headers.get(CSRF_HEADER, "") or "-", cookies.get(CSRF_COOKIE, "") or "+"):
                    log.security("csrf.refused", route=scope.get("path", ""))
                    return await self._send_json(send, 403, {"error": "csrf"})
            if not self.buckets.take((_ip(scope), scope.get("path", "")), int(self.values["rate_per_minute"])):
                return await self._send_json(send, 429, {"error": "too many requests"}, [(b"retry-after", b"60")])
        started = {"done": False}

        async def dressed(message):
            if message["type"] == "http.response.start":
                started["done"] = True
                hs = [(k, v) for k, v in message.get("headers", []) if k.lower() not in
                      (b"server", b"x-powered-by", b"access-control-allow-origin")]
                names = {k.lower() for k, _ in hs}
                hs = [(k, _cookie_flags(v)) if k.lower() == b"set-cookie" else (k, v) for k, v in hs]
                if b"content-type" not in names and message.get("status", 200) not in (204, 304):
                    hs.append((b"content-type", b"application/octet-stream"))
                sets_cookie = b"set-cookie" in names
                hs = [h for h in hs if not (h[0].lower() == b"cache-control" and (authenticated or sets_cookie))]
                hs += self._security(None, authenticated or sets_cookie) + cors_headers
                if SESSION_COOKIE in cookies and CSRF_COOKIE not in cookies:
                    hs.append((b"set-cookie", f"{CSRF_COOKIE}={token(16)}; Path=/; Secure; SameSite=Lax".encode()))
                message = {**message, "headers": hs}
            await send(message)
        try:
            await self.app(scope, receive, dressed)
        except Exception as exc:                            # ERROR-GENERIC: details to the log, a reference out
            ref = token(16)
            log.event("error.unhandled", ref=ref, route=scope.get("path", ""), kind=type(exc).__name__,
                      level=40)
            if not started["done"]:
                await self._send_json(send, 500, {"error": "internal error", "ref": ref})


def _cookie_flags(value: bytes) -> bytes:
    text = value.decode("latin-1")
    low = text.lower()
    name = text.split("=", 1)[0].strip()
    if "; secure" not in low:
        text += "; Secure"
    if "samesite" not in low:
        text += "; SameSite=Lax"
    if "httponly" not in low and name != CSRF_COOKIE:
        text += "; HttpOnly"
    if "path=" not in low:
        text += "; Path=/"
    return text.encode("latin-1")


def secure_app(app, values: Values | None = None):
    """Put the guard in front of `app` and keep the values on app.state. Returns the app."""
    values = values or Values.from_env()
    app.state.standard_values = values
    app.add_middleware(Guard, values=values)
    if production() and getattr(app, "debug", False):
        raise RuntimeError("debug is off in production (NO-DEBUG)")
    return app
