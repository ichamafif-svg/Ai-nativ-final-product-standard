"""Run the live release of a product without downtime, and follow the guard's switches and restarts (D30, D31).

    python tools/run_release.py /srv/standard/deploy/current 9000 [--health /health] [--data /srv/standard/data]

The runner listens on PORT and forwards every request to the release that currently serves. When the guard switches
the `current` link, or asks for a restart (the `restart` file beside it), the runner starts the new process on a
private port, with STANDARD_RELEASE set to its commit, and waits until its health path answers 200. Only then does
traffic move to it and the old process stop: a release that never becomes healthy never receives a request, and the
previous one keeps serving (the instrument sees which version answers and Standard steps back). The product's own
process, without any privilege over the guard.
"""
from __future__ import annotations

import argparse
import http.client
import os
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding",
       "upgrade", "content-length"}


class Runner:
    def __init__(self, link: str, port: int, health: str, data: str | None, ready_s: float = 30.0):
        self.link, self.port, self.health, self.data, self.ready_s = link, port, health, data, ready_s
        self.child, self.child_port, self.running, self.lock = None, None, (None, None), threading.Lock()

    def wanted(self) -> tuple:
        try:
            target = os.readlink(self.link)
        except OSError:
            target = None
        try:
            with open(os.path.join(os.path.dirname(self.link), "restart")) as f:
                restart = f.read().strip()
        except OSError:
            restart = None
        return target, restart

    def start(self, target: str):
        release = os.path.join(os.path.dirname(self.link), target)
        port = self.port + 1 if self.child_port != self.port + 1 else self.port + 2
        env = {**os.environ, "STANDARD_RELEASE": os.path.basename(target)}
        if self.data:
            env["STANDARD_DATA"] = self.data
        child = subprocess.Popen([sys.executable, os.path.join(release, "service.py"), str(port)], cwd=release, env=env)
        deadline = time.time() + self.ready_s
        while time.time() < deadline and child.poll() is None:
            try:
                if urllib.request.urlopen(f"http://127.0.0.1:{port}{self.health}", timeout=2).status == 200:
                    return child, port
            except Exception:
                pass
            time.sleep(0.3)
        child.kill()
        child.wait()
        return None, None

    def follow(self) -> None:
        while True:
            wanted = self.wanted()
            dead = self.child is not None and self.child.poll() is not None
            if wanted != self.running or dead:
                target = wanted[0]
                child, port = self.start(target) if target else (None, None)
                if child is not None:
                    with self.lock:
                        old, self.child, self.child_port = self.child, child, port
                    print(f"serving {os.path.basename(target)} on :{port}", flush=True)
                    if old is not None and old.poll() is None:
                        time.sleep(2)                       # let in-flight requests finish
                        old.terminate()
                        try:
                            old.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            old.kill()
                elif target:
                    print(f"{os.path.basename(target)} did not become healthy: still serving the previous release",
                          flush=True)
                self.running = wanted
            time.sleep(1)

    def handler(self):
        runner = self

        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _forward(self):
                with runner.lock:
                    port = runner.child_port
                if port is None:
                    self.send_error(503, "no release serves")
                    return
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                    conn.request(self.command, self.path, body or None,
                                 {k: v for k, v in self.headers.items() if k.lower() not in HOP})
                    r = conn.getresponse()
                    data = r.read()
                except OSError:
                    self.send_error(502, "the release did not answer")
                    return
                self.send_response(r.status)
                for k, v in r.getheaders():
                    if k.lower() not in HOP:
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _forward

        return Proxy


def main(argv=None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("link")
    parser.add_argument("port", type=int)
    parser.add_argument("--health", default="/health")
    parser.add_argument("--data")
    a = parser.parse_args(argv)
    runner = Runner(a.link, a.port, a.health, a.data)
    threading.Thread(target=runner.follow, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", a.port), runner.handler()).serve_forever()


if __name__ == "__main__":
    main()
