"""Measure the platform's walls beyond the bac (D68 steps 2-4): the entry, the way out, the data.

Like `walls.py`, every wall is measured by trying what it must refuse, from where an attacker would stand: a client
in front of the gateway, the product's own code inside the bac, the product's database role. Each wall is `held`,
`broken` or `unmeasured` (its component is not installed here). Nothing is held by declaration.

    python -m tools.platform_walls     -> JSON {wall: status}, with the values in force (the catalog's defaults)
"""
from __future__ import annotations

import json
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PRODUCT = r'''
import json, os, socket, urllib.request, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_any(self):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        body = self.rfile.read(int(self.headers.get("content-length") or 0)).decode("utf-8", "replace")
        out = {"body": body, "identity": [k for k in self.headers if "identity" in k.lower() or "auth-request" in k.lower()]}
        if self.path.startswith("/slow"):
            import time; time.sleep(5)
        if self.path.startswith("/call"):
            try:
                with urllib.request.urlopen(q["url"], timeout=5) as r: out["call"] = r.status
            except urllib.error.HTTPError as e: out["call"] = e.code
            except OSError as e: out["call"] = "error"
        if self.path.startswith("/direct"):
            try: socket.create_connection(("1.1.1.1", 443), timeout=2).close(); out["direct"] = "connected"
            except OSError: out["direct"] = "refused"
        data = json.dumps(out).encode()
        self.send_response(200); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)
    do_GET = do_POST = do_any
ThreadingHTTPServer(("127.0.0.1", int(os.environ["PORT"])), H).serve_forever()
'''

ENTRY = ("entry.identity", "entry.canonical", "entry.json", "entry.time", "entry.methods", "entry.size")
EGRESS = ("egress.destination", "egress.private", "egress.direct")
DATA = ("data.forgotten", "data.forged", "data.cross", "data.owner")
WALLS = (*ENTRY, *EGRESS, *DATA)


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _call(port, method, path, body=None, headers=None, timeout=15):
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def entry_and_egress(values: dict) -> dict:
    from enclosure.bac import Bac
    from enclosure.components import where
    from enclosure.egress import mitmdump
    from enclosure.stack import Stack
    out = {w: "unmeasured" for w in (*ENTRY, *EGRESS)}
    if not (where("envoy") and Bac().ready):
        return out
    folder = Path(tempfile.mkdtemp(prefix="walls-"))
    (folder / "product.py").write_text(PRODUCT)
    values = {**values, "request_timeout_s": 2, "destinations": [f"localhost:{_port()}"]}
    port = _port()
    with Stack(folder / "state", values, [sys.executable, "-I", str(folder / "product.py")], cwd=folder, port=port,
               egress=bool(mitmdump())) as stack:
        held = lambda ok: "held" if ok else "broken"
        status, body = _call(port, "POST", "/x", b'{"b": 1, "a": 2}', {"content-type": "application/json",
                                                                        "x-standard-identity": "forged",
                                                                        "x-auth-request-user": "eve"})
        seen = json.loads(body) if status == 200 else {}
        out["entry.identity"] = held(status == 200 and not seen.get("identity"))
        out["entry.canonical"] = held(seen.get("body") == '{"a":2,"b":1}')
        out["entry.json"] = held(_call(port, "POST", "/x", '{"é": 1, "é": 2}'.encode(),
                                       {"content-type": "application/json"})[0] == 400)
        started = time.monotonic()
        out["entry.time"] = held(_call(port, "GET", "/slow")[0] == 504 and time.monotonic() - started < 4.5)
        out["entry.methods"] = held(_call(port, "TRACE", "/")[0] == 405)
        out["entry.size"] = held(_call(port, "POST", "/x", b"x" * (int(values["body_max_bytes"]) + 1),
                                       {"content-type": "text/plain"})[0] == 413)
        direct = json.loads(_call(port, "GET", "/direct")[1])
        out["egress.direct"] = held(direct.get("direct") == "refused")
        if stack.egress:
            ask = lambda url: json.loads(_call(port, "GET", "/call?" + urllib.parse.urlencode({"url": url}))[1])["call"]
            out["egress.destination"] = held(ask("http://203.0.113.9/") == 403)
            out["egress.private"] = held(ask(values["destinations"][0].join(("http://", "/"))) == 403)
    return out


def data() -> dict:
    from enclosure import identity
    from enclosure.data import Database, available
    out = {w: "unmeasured" for w in DATA}
    if not available():
        return out
    state = Path(tempfile.mkdtemp(prefix="walls-data-"))
    signer = identity.LocalSigner(state / "key")
    db = Database(state).start(audience="probe", public_pem=signer.public_pem())
    try:
        sql = lambda s: db.psql(s, user="product", database="product", check=False)
        token = lambda who, s=signer: identity.mint(s, {"sub": who}, audience="probe")
        sql("CREATE TABLE probe_rows (id serial PRIMARY KEY, owner_id text NOT NULL)")
        sql(f"BEGIN; SELECT standard.act_as('{token('a')}'); INSERT INTO probe_rows(owner_id) VALUES ('a'); COMMIT;")
        held = lambda ok: "held" if ok else "broken"
        out["data.forgotten"] = held(sql("SELECT count(*) FROM probe_rows") == "0")
        other = identity.LocalSigner(state / "other")
        out["data.forged"] = held("identity refused" in sql(f"SELECT standard.act_as('{token('a', other)}')"))
        out["data.cross"] = held("row-level security" in sql(
            f"BEGIN; SELECT standard.act_as('{token('b')}'); INSERT INTO probe_rows(owner_id) VALUES ('a'); COMMIT;"))
        out["data.owner"] = held("must be owner" in sql("ALTER TABLE probe_rows DISABLE ROW LEVEL SECURITY"))
    finally:
        db.stop()
    return out


def measure(values: dict) -> dict:
    """values: the named values in force (only the limits are read); the probe narrows time and destinations."""
    return {**entry_and_egress(values), **data()}
