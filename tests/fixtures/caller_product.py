"""A product that calls out: through the proxy settings like any SDK (urllib honours HTTPS_PROXY), or directly."""
import json
import os
import socket
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Caller(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        out = {"env_has_secret": any("s3cr3t" in v for v in os.environ.values())}
        if self.path.startswith("/direct"):
            try:
                socket.create_connection((q["host"], int(q["port"])), timeout=2).close()
                out["direct"] = "connected"
            except OSError as exc:
                out["direct"] = f"refused: {exc}"
        else:
            headers = {"authorization": q["auth"]} if "auth" in q else {}
            if "type" in q:
                headers["content-type"] = q["type"]
            data = q["body"].encode() if "body" in q else None
            method = "PUT" if self.path.startswith("/put") else "POST" if data else "GET"
            request = urllib.request.Request(q["url"], data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(request, timeout=10) as r:
                    out.update(status=r.status, body=r.read().decode())
            except urllib.error.HTTPError as e:
                out.update(status=e.code, body=e.read().decode())
            except OSError as e:
                out.update(status=None, body=str(e))
            if q.get("log"):
                print("destination answered", out.get("body"), flush=True)   # a careless product logs it all
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(("127.0.0.1", int(os.environ["PORT"])), Caller).serve_forever()
