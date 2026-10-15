"""A product that does nothing right: no security headers, a weak cookie, a banner, a slow route. It echoes what it
received, so tests see exactly what crossed the gateway."""
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def _reply(self):
        if self.path.startswith("/slow"):
            time.sleep(5)
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        out = json.dumps({"method": self.command, "path": self.path, "body": body.decode("utf-8", "replace"),
                          "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("x-powered-by", "echo/1.0")
        self.send_header("set-cookie", "theme=dark")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_DELETE = _reply


ThreadingHTTPServer(("127.0.0.1", int(os.environ["PORT"])), Echo).serve_forever()
