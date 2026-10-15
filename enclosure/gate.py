"""The gate (D68): Standard's own policy between the gateway (Envoy) and the product's door.

Envoy does what a general proxy does well: TLS, HTTP framing and normalisation, header and body limits, timeouts,
CORS, CSRF, rate limits and the sign-in through oauth2-proxy. The gate does what only Standard does, and records it:

    - identity: every identity header a client sent is gone (Envoy removed it before anything ran); the identity
      oauth2-proxy established becomes one short token signed by the key service (`enclosure/identity.py`);
    - JSON: a JSON body is read strictly (no duplicate key, no NaN, no lone surrogate, bounded depth, and no two keys
      equal after Unicode normalisation) and the product receives it re-written in one canonical form, never the
      client's bytes: no two parsers can read two documents;
    - isolation: a cross-site request a browser marks as such (Fetch Metadata) is refused unless it is a top-level
      navigation or comes from an origin in @origins (CSRF, XSSI, cross-site leaks), as the web block did;
    - time: one deadline covers the whole exchange with the product;
    - responses: the security headers and cookie flags of the rules of the game are imposed; banner headers removed.

What the gate corrects is never silent (D69): every correction and refusal is a record, read back as a lesson for the
code that needed it. Records name the capability, the route and what was missing, never a value.

    python -m enclosure.gate --listen GATE.sock --door DOOR.sock --values values.json --audience APP
                             --key identity.key --records records.jsonl
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import socketserver
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler

from blocks.python.standard_blocks.parse import ParseError, strict_json
from blocks.python.standard_blocks.web import _cookie_flags, security_headers
from enclosure import identity

HELD_BY = "platform:ingress"
# Set by Envoy after the sign-in, removed by Envoy from every client request before any filter ran.
AUTH_HEADERS = {"x-auth-request-user": "sub", "x-auth-request-email": "email", "x-auth-request-groups": "groups"}
HOP = {"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
       "content-length", "host"}
BANNERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
JSON_TYPES = ("application/json", "+json")


class Refused(Exception):
    def __init__(self, status: int, capability: str, reason: str):
        super().__init__(reason)
        self.status, self.capability, self.reason = status, capability, reason


def collisions(value, path="$") -> None:
    """Refuse two keys of one object that are the same text once Unicode-normalised (NFC and NFKC)."""
    if isinstance(value, dict):
        seen = {}
        for key in value:
            for form in ("NFC", "NFKC"):
                norm = (form, unicodedata.normalize(form, key))
                if norm in seen and seen[norm] != key:
                    raise ParseError(f"two keys are one key once normalised at {path}")
                seen[norm] = key
        for key, item in value.items():
            collisions(item, f"{path}.{key[:32]}")
    elif isinstance(value, list):
        for item in value:
            collisions(item, path)


def canonical(body: bytes, *, max_depth: int, max_bytes: int) -> bytes:
    """The one form the product receives: strict reading, collision refusal, sorted keys, no insignificant space."""
    value = strict_json(body, max_depth=max_depth, max_bytes=max_bytes)
    collisions(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class DoorConnection(http.client.HTTPConnection):
    """The product's door: a Unix socket path, or `host:port` when the release runner stands behind the gate."""

    def __init__(self, door: str, timeout: float):
        super().__init__("product", timeout=timeout)
        self.door = door

    def connect(self):
        if self.door.startswith("/"):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect(self.door)
        else:
            host, _, port = self.door.rpartition(":")
            self.sock = socket.create_connection((host, int(port)), timeout=self.timeout)


class Records:
    """What the gate corrected or refused, once per (kind, capability, route, what): a lesson, not a traffic log."""

    def __init__(self, path):
        self.path, self.lock, self.seen = path, threading.Lock(), set()

    def add(self, kind: str, capability: str, route: str, attempt: str) -> None:
        key = (kind, capability, route, attempt[:240])
        with self.lock:
            if key in self.seen:
                return
            self.seen.add(key)
            line = json.dumps({"kind": kind, "capability": capability, "held_by": HELD_BY, "route": route,
                               "attempt": attempt[:240], "at": int(time.time())}, sort_keys=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


class Gate:
    def __init__(self, *, door: str, values: dict, audience: str, signer, records: Records):
        self.door, self.values, self.audience, self.signer, self.records = door, values, audience, signer, records

    def request(self, method: str, path: str, headers: list, body: bytes) -> tuple[list, bytes]:
        route = f"{method} {path.split('?', 1)[0][:120]}"
        lower = [(k.lower(), v) for k, v in headers]
        if self.cross_site(method, dict(lower)):
            self.records.add("refusal", "ingress.isolation", route, "a cross-site request from an origin not in @origins")
            raise Refused(403, "ingress.isolation", "cross-site request refused")
        found = {AUTH_HEADERS[k]: v for k, v in lower if k in AUTH_HEADERS}
        out = [(k, v) for k, v in lower if k not in AUTH_HEADERS and k != identity.HEADER and k not in HOP
               and not k.startswith("x-envoy-")]                 # the gateway's own bookkeeping stays with it
        if found.get("sub"):
            if "groups" in found:
                found["groups"] = [g for g in found["groups"].split(",") if g]
            out.append((identity.HEADER, identity.mint(self.signer, found, audience=self.audience)))
        kind = dict(lower).get("content-type", "").split(";")[0].strip()
        if body and (kind in JSON_TYPES or kind.endswith(JSON_TYPES[1])):
            try:
                body = canonical(body, max_depth=int(self.values["json_max_depth"]),
                                 max_bytes=int(self.values["body_max_bytes"]))
            except ParseError as exc:
                self.records.add("refusal", "ingress.json", route, str(exc))
                raise Refused(400, "ingress.json", str(exc)) from None
            out = [(k, v) for k, v in out if k != "content-type"] + [("content-type", "application/json")]
        return out, body

    def cross_site(self, method: str, headers: dict) -> bool:
        """Fetch Metadata resource isolation: True when the request must be refused."""
        site = headers.get("sec-fetch-site")
        if site in (None, "same-origin", "none") or headers.get("origin") in self.values.get("origins", []):
            return False
        navigation = method in ("GET", "HEAD") and headers.get("sec-fetch-mode") == "navigate" \
            and headers.get("sec-fetch-dest") not in ("object", "embed", "iframe", "frame")
        return not navigation

    def response(self, route: str, headers: list, *, authenticated: bool = False) -> list:
        """Impose the security headers and cookie flags; every change is a recorded correction."""
        out = []
        for key, value in headers:
            k = key.lower()
            if k in HOP:
                continue
            if k in BANNERS:
                self.records.add("correction", "ingress.headers", route, f"removed the {k} header")
                continue
            if k == "set-cookie":
                fixed = _cookie_flags(value.encode("latin-1")).decode("latin-1")
                if fixed != value:
                    name = value.split("=", 1)[0].strip()[:64]
                    self.records.add("correction", "ingress.cookies", route,
                                     f"cookie {name} lacked Secure, HttpOnly, SameSite or Path")
                value = fixed
            out.append((k, value))
        # As the web block decides: a response to a signed-in user, or one that sets a cookie, is not cached.
        sensitive = authenticated or any(k == "set-cookie" for k, _ in out)
        for key, value in security_headers(self.values, sensitive=sensitive):
            current = [v for k, v in out if k == key]
            if current != [value]:
                # A weaker value is the code's defect (a correction); a missing one is the platform's job (imposed).
                if current:
                    self.records.add("correction", "ingress.headers", route, f"{key} was weaker than the rules")
                else:
                    self.records.add("imposed", "ingress.headers", route, f"{key} added")
                out = [(k, v) for k, v in out if k != key] + [(key, value)]
        return out

    def forward(self, method: str, path: str, headers: list, body: bytes) -> tuple[int, list, bytes]:
        route = f"{method} {path.split('?', 1)[0][:120]}"
        deadline = time.monotonic() + int(self.values["request_timeout_s"])
        connection = DoorConnection(self.door, timeout=int(self.values["request_timeout_s"]))
        try:
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("host", "product")
            for key, value in headers:
                connection.putheader(key, value)
            connection.putheader("content-length", str(len(body)))
            connection.endheaders(body)
            reply = connection.getresponse()
            chunks = []
            while chunk := reply.read(65536):
                chunks.append(chunk)
                if time.monotonic() > deadline:
                    raise TimeoutError
            signed_in = any(k == identity.HEADER for k, _ in headers)
            return reply.status, self.response(route, reply.getheaders(), authenticated=signed_in), b"".join(chunks)
        except (TimeoutError, socket.timeout):
            self.records.add("refusal", "ingress.time", route, "the product did not answer within the time limit")
            raise Refused(504, "ingress.time", "the product did not answer in time") from None
        except OSError:
            raise Refused(502, "ingress.door", "the product is not answering") from None
        finally:
            connection.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    gate: Gate

    def address_string(self):
        return "gateway"

    def log_message(self, *_):
        pass

    def _answer(self, status: int, headers: list, body: bytes):
        self.send_response_only(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        try:
            self._serve()
        except (BrokenPipeError, ConnectionResetError):
            pass                                            # the gateway gave up first (its own deadline)

    def _serve(self):
        try:
            length = int(self.headers.get("content-length") or 0)
            if length > int(self.gate.values["body_max_bytes"]):
                raise Refused(413, "ingress.size", "body too large")
            body = self.rfile.read(length) if length else b""
            headers, body = self.gate.request(self.command, self.path, list(self.headers.items()), body)
            status, out, reply = self.gate.forward(self.command, self.path, headers, body)
            self._answer(status, out, reply)
        except Refused as refused:
            route = f"{self.command} {self.path.split('?', 1)[0][:120]}"
            payload = json.dumps({"error": refused.reason}).encode()
            self._answer(refused.status, self.gate.response(route, [("content-type", "application/json")]), payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve(listen: str, gate: Gate) -> Server:
    if os.path.exists(listen):
        os.unlink(listen)
    handler = type("BoundHandler", (Handler,), {"gate": gate})
    server = Server(listen, handler)
    os.chmod(listen, 0o660)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ("listen", "door", "values", "audience", "key", "records"):
        p.add_argument(f"--{name}", required=True)
    a = p.parse_args(argv)
    with open(a.values, encoding="utf-8") as f:
        values = json.load(f)
    server = serve(a.listen, Gate(door=a.door, values=values, audience=a.audience,
                                  signer=identity.LocalSigner(a.key), records=Records(a.records)))
    try:
        threading.Event().wait()
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
