"""Run the live release of a product without downtime, and follow the guard's switches, restarts and canaries
(D30, D31, D32).

    python runtime/runner.py /srv/standard/deploy 9000 --repo /srv/standard/hosting/repos/app.git
                                [--releases DIR] [--health /health] [--data /srv/standard/data]

The guard only moves registers, small files in the deploy directory holding commits (D37: bt/register.py). The
runner builds what it runs: it exports the commit a register names from the canonical repository, by its hash, into
its own releases directory. It listens on PORT and forwards every request to the release that serves. When the guard
moves `current`, or asks for a restart (the `restart` register), the runner starts the new process on a private
port, with STANDARD_RELEASE set to its commit, and waits until its health path answers 200. Only then does traffic
move to it and the old process stop: a release that never becomes healthy never receives a request.

When the guard sets the `canary` register (and `canary_weight`, a percentage), the runner starts that release beside the
live one and sends it that share of requests (never `/metrics`, which stays the live release's). It measures what
each release answers, from in front of them, at `/__standard/metrics` (standard_release_requests_total{release,
outcome} and standard_release_duration_seconds_bucket{release,le}): the instrument compares them. When the link
goes, the canary stops; when `current` becomes the canary, it simply becomes the live process.

The product's own process, without any privilege over the guard.

D68: each release runs in the bac (`enclosure/`), started through its door: no network of its own, a read-only
tree, the data directory as its one writable place, the platform's limits. The runner reaches it only through the
door's Unix socket, for health and for traffic; in production the gateway (Envoy and the gate) stands in front of
the runner. Without a bac nothing is started, unless `--unconfined` says so explicitly (demonstrations only).
"""
from __future__ import annotations

import argparse
import http.client
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding",
       "upgrade", "content-length"}
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


PRODUCT_PORT = 8000


class DoorConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("release", timeout=timeout)
        self.door = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.door)


class Process:
    def __init__(self, release: str, child, port: int | None, door: str | None = None, service=None):
        self.release, self.child, self.port, self.door, self.service = release, child, port, door, service

    def alive(self) -> bool:
        return self.service.running() if self.service else self.child.poll() is None

    def connect(self, timeout: float) -> http.client.HTTPConnection:
        if self.door:
            return DoorConnection(self.door, timeout)
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)

    def stop(self, drain: float = 2.0) -> None:
        if self.alive():
            time.sleep(drain)                               # let in-flight requests finish
        if self.service:
            self.service.stop()
            return
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.child.kill()


class Runner:
    def __init__(self, root: str, port: int, health: str, data: str | None, repo: str, releases: str,
                 ready_s: float = 30.0, bac=None, records=()):
        self.root, self.port, self.health, self.data, self.ready_s = root, port, health, data, ready_s
        self.repo, self.releases, self.bac, self.records = repo, releases, bac, tuple(records)
        self.live = self.canary = None
        self.weight, self.restart_seen, self.ports = 0, None, iter(range(port + 1, port + 1000))
        self.lock, self.counts = threading.Lock(), {}      # release -> {"ok", "error", "buckets"}

    def _read(self, name: str):
        try:
            with open(os.path.join(self.root, name)) as f:
                return f.read().strip() or None
        except OSError:
            return None

    def export(self, release: str) -> str | None:
        """The release's tree, from the canonical repository by its exact commit; built once."""
        if not re.fullmatch(r"[0-9a-f]{40}", release):
            return None
        path = os.path.join(self.releases, release)
        if not os.path.isdir(path):
            tmp = f"{path}.tmp{os.getpid()}"
            os.makedirs(tmp)
            tree = subprocess.run(["git", "-c", "safe.directory=*", "--git-dir", self.repo, "archive", "--format=tar", release],
                                  capture_output=True, timeout=300)
            if tree.returncode != 0 or subprocess.run(["tar", "-x", "-C", tmp], input=tree.stdout,
                                                      capture_output=True).returncode != 0:
                shutil.rmtree(tmp, ignore_errors=True)
                return None
            os.replace(tmp, path)
        return path

    def start(self, release: str) -> Process | None:
        path = self.export(release)
        if path is None:
            print(f"{release} cannot be read from the repository: it receives no traffic", flush=True)
            return None
        if self.bac is not None:
            process = self._start_in_bac(release, path)
        else:
            port = next(self.ports)
            env = {**os.environ, "STANDARD_RELEASE": release}
            if self.data:
                env["STANDARD_DATA"] = self.data
            child = subprocess.Popen([sys.executable, os.path.join(path, "service.py"), str(port)], cwd=path, env=env)
            process = Process(release, child, port)
        deadline = time.time() + self.ready_s
        while time.time() < deadline and process.alive():
            try:
                conn = process.connect(2)
                conn.request("GET", self.health)
                if conn.getresponse().status == 200:
                    conn.close()
                    return process
                conn.close()
            except Exception:
                pass
            time.sleep(0.3)
        process.stop(drain=0)
        print(f"{release} did not become healthy: it receives no traffic", flush=True)
        return None

    def _start_in_bac(self, release: str, path: str) -> Process:
        from enclosure.bac import Service
        from enclosure.stack import DOOR
        door = os.path.join(self.releases, f"{release}.door")
        os.makedirs(door, exist_ok=True)
        os.chmod(door, 0o777)
        sock = os.path.join(door, "http.sock")
        env = {"STANDARD_RELEASE": release, **({"STANDARD_DATA": self.data} if self.data else {})}
        service = Service(self.bac, [self.bac.python, "-I", str(DOOR), sock, str(PRODUCT_PORT), "--",
                                     self.bac.python, os.path.join(path, "service.py"), str(PRODUCT_PORT)],
                          path, env=env, readable=(str(DOOR.parent),),
                          writable=(door, *([self.data] if self.data else [])))
        return Process(release, service.process, None, door=sock, service=service)

    def follow(self) -> None:
        while True:
            current, canary, restart = self._read("current"), self._read("canary"), self._read("restart")
            weight = self._read("canary_weight")
            self.weight = int(weight) if weight and weight.isdigit() else 0
            live_dead = self.live is not None and not self.live.alive()
            if current and (self.live is None or self.live.release != current or live_dead
                            or (restart and restart != self.restart_seen and restart.startswith(current))):
                if self.canary is not None and self.canary.release == current and self.canary.alive():
                    fresh, self.canary = self.canary, None  # promoted: the canary is already warm
                else:
                    fresh = self.start(current)
                if fresh is not None:
                    with self.lock:
                        old, self.live = self.live, fresh
                    print(f"serving {current} on {fresh.door or fresh.port}", flush=True)
                    if old is not None:
                        threading.Thread(target=old.stop, daemon=True).start()
                self.restart_seen = restart
            if canary != (self.canary.release if self.canary else None):
                old = self.canary
                with self.lock:
                    self.canary = None
                if old is not None:
                    threading.Thread(target=old.stop, daemon=True).start()
                if canary and canary != current:
                    started = self.start(canary)
                    with self.lock:
                        self.canary = started
                    if started:
                        print(f"canary {canary} on {started.door or started.port} for {self.weight} %", flush=True)
            time.sleep(1)

    def record(self, release: str, failed: bool, seconds: float) -> None:
        with self.lock:
            c = self.counts.setdefault(release, {"ok": 0, "error": 0, "buckets": [0] * len(BUCKETS)})
            c["error" if failed else "ok"] += 1
            for i, bound in enumerate(BUCKETS):
                if seconds <= bound:
                    c["buckets"][i] += 1

    def exposition(self) -> str:
        lines = []
        with self.lock:
            for release, c in sorted(self.counts.items()):
                for outcome in ("ok", "error"):
                    lines.append(f'standard_release_requests_total{{release="{release}",outcome="{outcome}"}} {c[outcome]}')
                for bound, n in zip(BUCKETS, c["buckets"]):
                    lines.append(f'standard_release_duration_seconds_bucket{{release="{release}",le="{bound}"}} {n}')
                lines.append(f'standard_release_duration_seconds_bucket{{release="{release}",le="+Inf"}} '
                             f'{c["ok"] + c["error"]}')
        return "\n".join(lines) + "\n"

    def platform_records(self) -> bytes:
        out = []
        for path in self.records:
            try:
                with open(path, "rb") as f:
                    out.append(f.read()[-1_000_000:])
            except OSError:
                pass
        return b"".join(out)

    def handler(self):
        runner = self

        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, headers, data):
                self.send_response(status)
                for k, v in headers:
                    if k.lower() not in HOP:
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _forward(self):
                if self.path == "/__standard/metrics":
                    return self._send(200, [("Content-Type", "text/plain; version=0.0.4")], runner.exposition().encode())
                if self.path == "/__standard/platform":           # D68: what the gate and the egress recorded
                    return self._send(200, [("Content-Type", "application/jsonl")], runner.platform_records())
                with runner.lock:
                    live, canary, weight = runner.live, runner.canary, runner.weight
                target = canary if (canary and self.path != "/metrics" and random.random() * 100 < weight) else live
                if target is None:
                    return self._send(503, [], b"no release serves\n")
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                start = time.perf_counter()
                try:
                    conn = target.connect(30)
                    conn.request(self.command, self.path, body or None,
                                 {k: v for k, v in self.headers.items() if k.lower() not in HOP})
                    r = conn.getresponse()
                    data, status, headers = r.read(), r.status, r.getheaders()
                except OSError:
                    data, status, headers = b"the release did not answer\n", 502, []
                if self.path != "/metrics":
                    runner.record(target.release, status >= 500, time.perf_counter() - start)
                self._send(status, headers, data)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _forward

        return Proxy


def main(argv=None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("registers", help="the deploy directory the guard writes")
    parser.add_argument("port", type=int)
    parser.add_argument("--health", default="/health")
    parser.add_argument("--data")
    parser.add_argument("--repo", required=True, help="the canonical repository, read only")
    parser.add_argument("--releases", default=os.path.expanduser("~/releases"))
    parser.add_argument("--records", action="append", default=[],
                        help="a platform record file (gate, egress) served at /__standard/platform")
    parser.add_argument("--unconfined", action="store_true",
                        help="run releases without the bac: demonstrations only, never inferred")
    a = parser.parse_args(argv)
    bac = None
    if not a.unconfined:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from enclosure.bac import Bac
        bac = Bac()
        if not bac.ready:
            raise SystemExit(f"releases run only in the bac (D68): {bac.why}")
    os.makedirs(a.releases, exist_ok=True)
    root = a.registers if os.path.isdir(a.registers) else os.path.dirname(a.registers)
    runner = Runner(root, a.port, a.health, a.data, a.repo, a.releases, bac=bac, records=a.records)
    threading.Thread(target=runner.follow, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", a.port), runner.handler()).serve_forever()


if __name__ == "__main__":
    main()
