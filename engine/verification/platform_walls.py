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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PRODUCT = r'''
import json, os, socket, urllib.request, urllib.parse
SECRET = "probe-secret-value"
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
        out["env_has_secret"] = any(SECRET in v for v in os.environ.values())
        if self.path.startswith("/call"):
            headers = {k: q[k] for k in ("authorization", "content-type") if k in q}
            data = q["body"].encode() if "body" in q else None
            request = urllib.request.Request(q["url"], data=data, headers=headers, method=q.get("method"))
            try:
                with urllib.request.urlopen(request, timeout=5) as r: out["call"], out["answer"] = r.status, r.read().decode()
            except urllib.error.HTTPError as e: out["call"], out["answer"] = e.code, e.read().decode()
            except OSError as e: out["call"] = "error"
            if q.get("log"): print("answered", out.get("answer"), flush=True)
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
SERVICES = ("secrets.injected", "secrets.held", "keys.own", "files.rules", "logs.redacted")
DATA = ("data.forgotten", "data.forged", "data.cross", "data.owner")
WALLS = (*ENTRY, *EGRESS, *SERVICES, *DATA)
SECRET = "probe-secret-value"
# The part of the platform each wall measures (`held_by` in the catalog): a part counts as running in production
# (interface/context/feedback.RUNNING) only if every one of its walls is measured here or in the bac's own walls.
HOLDS = {"platform:ingress": ENTRY, "platform:egress": EGRESS, "platform:secrets": ("secrets.injected", "secrets.held"),
         "platform:keys": ("keys.own",), "platform:files": ("files.rules",), "platform:logs": ("logs.redacted",),
         "platform:data": DATA}
# The catalog rules a wall enforces by itself, whatever the product's code does (`interface/context/feedback.py`). A rule its
# holder only partly enforces (types and sizes, but no scan; a key service, but the product may still hash by hand)
# is not listed: it keeps its other sources.
COVERS = {"CANON": ("entry.canonical", "entry.json"), "SECRETS-MGMT": ("secrets.injected", "secrets.held"),
          "SSRF": EGRESS, "LOG-NO-SECRETS": ("logs.redacted",), "UPLOAD-TYPE": ("files.rules",),
          "UPLOAD-LIMITS": ("files.rules",), "AUTHZ-SUBJECT": DATA}


class _Destination(BaseHTTPRequestHandler):
    """An allowed destination: it answers with the authorization it received."""
    def log_message(self, *_):
        pass

    def do_GET(self):
        body = json.dumps({"authenticated": self.headers.get("authorization") == f"Bearer {SECRET}"}).encode()
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
    from fabric.runtime.bac import Bac
    from fabric.supply_chain.components import where
    from fabric.network.egress import mitmdump
    out = {w: "unmeasured" for w in (*ENTRY, *EGRESS, *SERVICES)}
    if not (where("envoy") and Bac().ready):
        return out
    folder = Path(tempfile.mkdtemp(prefix="walls-"))
    (folder / "product.py").write_text(PRODUCT)
    destination = ThreadingHTTPServer(("127.0.0.2", 0), _Destination)
    threading.Thread(target=destination.serve_forever, daemon=True).start()
    allowed = f"127.0.0.2:{destination.server_address[1]}"
    values = {**values, "request_timeout_s": 2, "destinations": [f"localhost:{_port()}", allowed],
              "upload_types": ["text/plain"], "upload_max_bytes": 100}
    port = _port()
    bao = process = None
    if mitmdump() and where("openbao"):
        from fabric.identity.keys import dev
        bao, process = dev(folder, where("openbao"))
        bao.put_secret("probe", SECRET)
        bao.create_key("product-probe", "aes256-gcm96")
        bao.create_key("standard-probe", "aes256-gcm96")
    try:
        _measure(out, folder, values, port, allowed, bao)
    finally:
        destination.shutdown()
        destination.server_close()
        if process:
            process.kill()
            process.wait()
    return out


def _measure(out, folder, values, port, allowed, bao) -> None:
    from fabric.network.egress import mitmdump
    from fabric.network.stack import Stack
    with Stack(folder / "state", values, [sys.executable, "-I", str(folder / "product.py")], cwd=folder, port=port, key_capabilities={"product-probe": ["encrypt"]},
               egress=bool(mitmdump()), bao=bao, secrets={"probe": ["127.0.0.2"]} if bao else None) as stack:
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
        if stack.egress and bao is not None:
            call = lambda **q: json.loads(_call(port, "GET", "/call?" + urllib.parse.urlencode(q))[1])
            got = call(url=f"http://{allowed}/", authorization="Bearer secret:probe", log="1")
            out["secrets.injected"] = held(got.get("call") == 200 and json.loads(got["answer"])["authenticated"] is True and not got["env_has_secret"])
            out["secrets.held"] = held(call(url="http://203.0.113.9/", authorization="Bearer secret:probe")["call"]
                                       == 403)
            sealed = call(url="http://keys.standard/encrypt/product-probe", body=json.dumps({"plaintext": "aGk="}))
            other = call(url="http://keys.standard/encrypt/standard-probe", body=json.dumps({"plaintext": "aGk="}))
            out["keys.own"] = held(sealed.get("call") == 200 and other.get("call") == 403)
            put = lambda body, kind: call(url="http://files.standard/", body=body, method="PUT",
                                          **{"content-type": kind})["call"]
            out["files.rules"] = held(put("hello", "text/plain") == 201 and put("<svg/>", "image/svg+xml") == 415
                                      and put("x" * 101, "text/plain") == 413)
            stack.capture.close()
            log = (folder / "state" / "product.log").read_text()
            out["logs.redacted"] = held("answered" in log and SECRET not in log)


def data() -> dict:
    from fabric.identity import identity
    from fabric.data.postgres import Database, available
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
