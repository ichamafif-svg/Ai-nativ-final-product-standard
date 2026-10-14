"""The web layer (CONTENT-TYPE, COOKIES, HSTS, CORS, SEC-HEADERS, CSRF, METHODS, HTTPS-REDIRECT, TRUSTED-HEADERS,
REDIRECT, NO-VERSION-LEAK, NO-CACHE-SENSITIVE, ERROR-GENERIC, PARAM-POLLUTION, ANTI-AUTOMATION, XSSI, DOS-HEAVY).

    app = secure_app(FastAPI(), values)

One ASGI middleware in front of the whole application: whatever a route does, its request was bounded and its
response leaves with these headers, cookie flags and limits. Values are read on every request, so a signed change
applies at once. Beyond the checklists, the guard:

    - bounds everything before the app sees it: URL, headers, body (413 as soon as the limit is crossed, chunked or
      not), the time until the response starts (@request_timeout_s, 503);
    - reads JSON bodies once, strictly (no duplicate key, no NaN, no lone surrogate, depth @json_max_depth), so no
      two parsers ever read two different documents;
    - isolates resources with Fetch Metadata: a cross-site request that is not a top-level navigation is refused
      unless its origin is in @origins (CSRF, XSSI, cross-site leaks), before and besides the CSRF token;
    - answers only to @hosts (Host header injection, poisoned reset links);
    - limits per address and route and per address overall, in a store shared by every worker, evicting the least
      recent entries (never a reset an attacker can trigger);
    - accepts product checks only as refusals (`refuse=`): a hook can make the guard stricter, never looser.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
from urllib.parse import parse_qsl, urlsplit

from . import Values
from . import log
from .crypto import same, token
from .parse import ParseError, strict_json

SESSION_COOKIE, CSRF_COOKIE, CSRF_HEADER = "__Host-session", "__Host-csrf", "x-csrf-token"
SAFE = {"GET", "HEAD", "OPTIONS"}
REFUSED_METHODS = {"TRACE", "TRACK", "CONNECT"}
HSTS = "max-age=63072000; includeSubDomains; preload"
MAX_URL = 8192
# A CSP source the human may add: a host (with scheme, port, path, wildcard subdomain) or a hash. Never a keyword
# that reopens injection ('unsafe-inline', 'unsafe-eval', data:, *), never a separator.
SOURCE = re.compile(r"(https://)?(\*\.)?[a-z0-9.-]+(:\d{1,5})?(/[\w./-]*)?|'sha(256|384|512)-[A-Za-z0-9+/]+=*'")
MAX_HEADERS, MAX_HEADER_BYTES = 100, 32_768
MULTIPART_SLACK = 65_536
PERMISSIONS = ("accelerometer=(), ambient-light-sensor=(), autoplay=(), bluetooth=(), browsing-topics=(), camera=(), "
               "display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), hid=(), "
               "identity-credentials-get=(), idle-detection=(), interest-cohort=(), local-fonts=(), magnetometer=(), "
               "microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(self), "
               "screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()")


def production() -> bool:
    return os.environ.get("STANDARD_ENV", "") == "production"


def csp(values: Values) -> str:
    extra = " ".join(s for s in values["csp_sources"] if SOURCE.fullmatch(s))
    src = f"'self' {extra}".strip()
    policy = (f"default-src {src}; script-src {src}; style-src {src}; img-src {src} data:; font-src {src}; "
              f"connect-src {src}; media-src {src}; worker-src 'self'; manifest-src 'self'; object-src 'none'; "
              "base-uri 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'self'; "
              "upgrade-insecure-requests; report-to standard")
    if values.get("trusted_types", "enforce") == "enforce":
        policy += "; require-trusted-types-for 'script'"
    return policy


def security_headers(values: Values, *, sensitive: bool = False) -> list[tuple[str, str]]:
    """Every header the guard adds, for responses the guard does not see (static files served elsewhere)."""
    h = [("strict-transport-security", HSTS), ("x-content-type-options", "nosniff"),
         ("referrer-policy", "strict-origin-when-cross-origin"), ("cross-origin-opener-policy", "same-origin"),
         ("cross-origin-resource-policy", "same-origin"), ("x-frame-options", "DENY"),
         ("x-permitted-cross-domain-policies", "none"), ("permissions-policy", PERMISSIONS),
         ("content-security-policy", csp(values)), ("reporting-endpoints", 'standard="/.well-known/csp-report"'),
         ("origin-agent-cluster", "?1")]
    if values.get("trusted_types", "enforce") == "report":
        h.append(("content-security-policy-report-only", "require-trusted-types-for 'script'; report-to standard"))
    if sensitive:
        h.append(("cache-control", "no-store"))
    return h


def _peer(scope) -> str:
    return (scope.get("client") or ("0.0.0.0", 0))[0]


def _in(nets, addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.strip().strip("[]"))
    except ValueError:
        return False
    for net in nets:
        try:
            if ip in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def address(values: Values, peer: str, forwarded: str | None) -> str:
    """The caller's address. X-Forwarded-For counts only when the peer is a trusted proxy, and then only from the
    right: the first hop not in @trusted_proxies is the caller (the left end is whatever the client wrote)."""
    trusted = values["trusted_proxies"]
    if not forwarded or not _in(trusted, peer):
        return peer
    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    while hops and _in(trusted, hops[-1]):
        hops.pop()
    return hops[-1] if hops else peer


def client_ip(request) -> str:
    values = request.app.state.standard_values
    return address(values, _peer(request.scope), request.headers.get("x-forwarded-for"))


def redirect_to(request, target: str, status: int = 303):
    """A redirect inside the app (a path), or to a host in @redirect_targets. Anything else goes home."""
    from starlette.responses import RedirectResponse as _Redirect
    values = request.app.state.standard_values
    target = str.__str__(target) if isinstance(target, str) else ""
    parts = urlsplit(target)
    bad = any(c in target for c in "\\\r\n\t\x00") or target.startswith(("//", "/\\"))
    inside = not bad and target.startswith("/") and not parts.scheme and not parts.netloc
    outside = not bad and parts.scheme == "https" and parts.hostname in values["redirect_targets"] \
        and not parts.username and not parts.password
    if not (inside or outside):
        log.security("redirect.refused", route=request.url.path)
        target = "/"
    return _Redirect(target, status_code=status)


def set_cookie(response, name: str, value: str, *, max_age: int | None = None, readable: bool = False) -> None:
    """A cookie with the __Host- prefix, Secure, SameSite=Lax, HttpOnly unless a script must read it."""
    if not name.startswith("__Host-"):
        name = "__Host-" + name
    if any(c in name + value for c in ";,\r\n \t\x00") or len(name) + len(value) > 4000:
        raise ValueError("a cookie is one token under 4 KB")
    response.set_cookie(name, value, max_age=max_age, path="/", secure=True, httponly=not readable, samesite="lax")


class _TooLarge(Exception):
    pass


class Guard:
    """Pure ASGI middleware: refuses what must not reach a route, bounds what may, and dresses every response."""

    def __init__(self, app, values: Values, store=None, refuse=()):
        from .store import from_env
        self.app, self.values, self.store, self.refuse = app, values, store or from_env(), tuple(refuse)

    async def _send_json(self, send, status: int, body: dict, headers=()):
        data = json.dumps(body).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json; charset=utf-8"),
                                (b"content-length", str(len(data)).encode()), *self._security(False), *headers]})
        await send({"type": "http.response.body", "body": data})

    def _security(self, sensitive: bool):
        return [(k.encode(), v.encode()) for k, v in security_headers(self.values, sensitive=sensitive)]

    def _cors(self, origin: str | None, host: str | None):
        if not origin:
            return None
        o = urlsplit(origin)
        if o.netloc and o.netloc == host and o.scheme in ("https", "http" if not production() else "https"):
            return "same"
        return origin if origin in self.values["origins"] else "refused"

    def _isolated(self, method: str, headers: dict, allowed) -> bool:
        """Fetch Metadata resource isolation: True when the request must be refused."""
        site = headers.get("sec-fetch-site")
        if site in (None, "same-origin", "none") or allowed not in (None, "refused", "same"):
            return False
        navigation = method in ("GET", "HEAD") and headers.get("sec-fetch-mode") == "navigate" \
            and headers.get("sec-fetch-dest") not in ("object", "embed", "iframe", "frame")
        return not navigation

    def _host_ok(self, scope, headers) -> bool:
        hosts = self.values.get("hosts")
        if not hosts:
            return True
        host = headers.get("host", "")
        if _in(self.values["trusted_proxies"], _peer(scope)) and headers.get("x-forwarded-host"):
            host = headers["x-forwarded-host"].split(",")[-1].strip()
        name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        return name.lower().rstrip(".") in {h.lower() for h in hosts}

    def _limit(self, headers) -> int:
        if headers.get("content-type", "").startswith("multipart/form-data"):
            return int(self.values["upload_max_bytes"]) + MULTIPART_SLACK
        return int(self.values["body_max_bytes"])

    async def _read_json(self, receive, limit: int):
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return None
            body = message.get("body", b"")
            size += len(body)
            if size > limit:
                raise _TooLarge
            chunks.append(body)
            if not message.get("more_body"):
                return b"".join(chunks)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        method = scope["method"].upper()
        raw_headers = scope.get("headers", [])
        if len(raw_headers) > MAX_HEADERS or sum(len(k) + len(v) for k, v in raw_headers) > MAX_HEADER_BYTES:
            return await self._send_json(send, 431, {"error": "headers too large"})
        headers = {}
        for k, v in raw_headers:
            name = k.decode("latin-1").lower()
            if name in headers and name in ("host", "content-length", "content-type", "authorization", "origin",
                                            "transfer-encoding", CSRF_HEADER, "sec-fetch-site"):
                return await self._send_json(send, 400, {"error": "a header appears twice"})
            headers[name] = v.decode("latin-1")
        if len(scope.get("raw_path", b"")) + len(scope.get("query_string", b"")) > MAX_URL:
            return await self._send_json(send, 414, {"error": "URL too long"})
        if method in REFUSED_METHODS:
            return await self._send_json(send, 405, {"error": "method not allowed"})
        if not self._host_ok(scope, headers):
            log.security("host.refused", route=scope.get("path", ""))
            return await self._send_json(send, 421, {"error": "unknown host"})
        cookies = dict(p.strip().split("=", 1) for p in headers.get("cookie", "").split(";") if "=" in p)
        authenticated = SESSION_COOKIE in cookies or "authorization" in headers
        query = parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
        keys = [k for k, _ in query]
        if len(keys) != len(set(keys)):
            return await self._send_json(send, 400, {"error": "a parameter appears twice"})
        if production():
            proto = headers.get("x-forwarded-proto") if _in(self.values["trusted_proxies"], _peer(scope)) else None
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
                (b"access-control-max-age", b"600"), *self._security(False)]})
            return await send({"type": "http.response.body", "body": b""})
        if self._isolated(method, headers, allowed):
            log.security("fetch_metadata.refused", route=scope.get("path", ""))
            return await self._send_json(send, 403, {"error": "cross-site request refused"})
        for check in self.refuse:                           # product hooks: they may only refuse
            try:
                reason = check(scope, headers)
            except Exception:
                reason = "check failed"                     # a hook that breaks refuses, it never lets through
            if reason:
                log.security("hook.refused", route=scope.get("path", ""))
                return await self._send_json(send, 403, {"error": str(reason)[:100]})
        caller = address(self.values, _peer(scope), headers.get("x-forwarded-for"))
        if method not in SAFE:
            if allowed == "refused":
                return await self._send_json(send, 403, {"error": "origin not allowed"})
            if SESSION_COOKIE in cookies and "authorization" not in headers:
                if not same(headers.get(CSRF_HEADER, "") or "-", cookies.get(CSRF_COOKIE, "") or "+"):
                    log.security("csrf.refused", route=scope.get("path", ""))
                    return await self._send_json(send, 403, {"error": "csrf"})
            rate = int(self.values["rate_per_minute"])
            if not self.store.take(f"rl:{caller}:{scope.get('path', '')}", rate) or \
                    not self.store.take(f"rl:{caller}", rate * 10):
                log.security("rate.limited", route=scope.get("path", ""))
                return await self._send_json(send, 429, {"error": "too many requests"}, [(b"retry-after", b"60")])
        limit = self._limit(headers)
        declared = headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            return await self._send_json(send, 413 if declared.isdigit() else 400, {"error": "body too large"})
        if "transfer-encoding" in headers and declared is not None:
            return await self._send_json(send, 400, {"error": "length and chunking together"})

        if method not in ("GET", "HEAD") and headers.get("content-type", "").split(";")[0].strip().lower() in \
                ("application/json", "application/merge-patch+json", "application/problem+json"):
            try:
                body = await self._read_json(receive, limit)
                if body:
                    strict_json(body, max_depth=int(self.values["json_max_depth"]), max_bytes=limit)
            except _TooLarge:
                return await self._send_json(send, 413, {"error": "body too large"})
            except ParseError as exc:
                return await self._send_json(send, 400, {"error": f"invalid JSON: {exc}"})
            replayed = {"done": False}

            async def bounded():                            # the app reads the same bytes, once
                if replayed["done"]:
                    return await receive()
                replayed["done"] = True
                return {"type": "http.request", "body": body or b"", "more_body": False}
        else:
            seen = {"bytes": 0}

            async def bounded():
                message = await receive()
                if message["type"] == "http.request":
                    seen["bytes"] += len(message.get("body", b""))
                    if seen["bytes"] > limit:
                        raise _TooLarge
                return message

        started = {"done": False}
        first = asyncio.Event()

        async def dressed(message):
            if message["type"] == "http.response.start":
                started["done"] = True
                first.set()
                hs = [(k, v) for k, v in message.get("headers", []) if k.lower() not in
                      (b"server", b"x-powered-by", b"x-aspnet-version", b"access-control-allow-origin")]
                names = {k.lower() for k, _ in hs}
                hs = [(k, _cookie_flags(v)) if k.lower() == b"set-cookie" else (k, v) for k, v in hs]
                if b"content-type" not in names and message.get("status", 200) not in (204, 304):
                    hs.append((b"content-type", b"application/octet-stream"))
                sets_cookie = b"set-cookie" in names
                sensitive = authenticated or sets_cookie
                own = {k.decode("latin-1") for k, _ in self._security(sensitive)}
                hs = [h for h in hs if h[0].lower().decode("latin-1") not in own]
                hs += self._security(sensitive) + cors_headers
                if SESSION_COOKIE in cookies and CSRF_COOKIE not in cookies:
                    hs.append((b"set-cookie", f"{CSRF_COOKIE}={token(16)}; Path=/; Secure; SameSite=Lax".encode()))
                message = {**message, "headers": hs}
            await send(message)

        async def deadline(task):
            try:
                await asyncio.wait_for(first.wait(), float(self.values["request_timeout_s"]))
            except asyncio.TimeoutError:
                if not started["done"]:
                    task.cancel()

        task = asyncio.ensure_future(self.app(scope, bounded, dressed))
        watch = asyncio.ensure_future(deadline(task))
        try:
            await task
        except asyncio.CancelledError:
            if task.cancelled() and not started["done"]:
                log.security("request.timeout", route=scope.get("path", ""))
                await self._send_json(send, 503, {"error": "took too long"}, [(b"retry-after", b"5")])
            else:
                raise
        except _TooLarge:
            if not started["done"]:
                await self._send_json(send, 413, {"error": "body too large"})
        except Exception as exc:                            # ERROR-GENERIC: details to the log, a reference out
            too_large = isinstance(exc.__cause__ or exc.__context__, _TooLarge)
            if too_large and not started["done"]:
                return await self._send_json(send, 413, {"error": "body too large"})
            ref = token(16)
            log.event("error.unhandled", ref=ref, route=scope.get("path", ""), kind=type(exc).__name__,
                      level=40)
            if not started["done"]:
                await self._send_json(send, 500, {"error": "internal error", "ref": ref})
        finally:
            watch.cancel()


def _cookie_flags(value: bytes) -> bytes:
    text = value.decode("latin-1")
    low = text.lower()
    name = text.split("=", 1)[0].strip()
    if "; secure" not in low:
        text += "; Secure"
    if "samesite" not in low:
        text += "; SameSite=Lax"
    elif "samesite=none" in low and name != CSRF_COOKIE:
        text = text.replace("SameSite=None", "SameSite=Lax").replace("samesite=none", "SameSite=Lax")
    if "httponly" not in low and name != CSRF_COOKIE:
        text += "; HttpOnly"
    if "path=" not in low:
        text += "; Path=/"
    return text.encode("latin-1")


def secure_app(app, values: Values | None = None, *, store=None, refuse=()):
    """Put the guard in front of `app` and keep the values on app.state. `refuse`: product checks
    (scope, headers) -> reason or None; they can only refuse. Returns the app."""
    values = values or Values.from_env()
    app.state.standard_values = values
    app.add_middleware(Guard, values=values, store=store, refuse=refuse)
    if production() and getattr(app, "debug", False):
        raise RuntimeError("debug is off in production (NO-DEBUG)")
    if production() and not values.get("hosts"):
        log.security("hosts.unset", outcome="every host name is answered: set @hosts")
    return app
