"""The demo product's HTTP API, instrumented the OpenTelemetry way (a request duration histogram per route, method and
status), exposed in Prometheus text format on /metrics. Standard's console reads it; the product needs nothing else.

    python service.py [port]
"""
import json
import random
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
ROUTES = (("GET", re.compile(r"/health"), "/health"),
          ("GET", re.compile(r"/users/[^/]+"), "/users/{id}"),
          ("GET", re.compile(r"/search"), "/search"),
          ("POST", re.compile(r"/orders"), "/orders"),
          ("GET", re.compile(r"/orders/[^/]+"), "/orders/{id}"))


def match(method: str, path: str):
    """The declared route template of a request, or None."""
    path = path.split("?", 1)[0]
    return next((template for m, rx, template in ROUTES if m == method and rx.fullmatch(path)), None)


class Metrics:
    def __init__(self):
        self.lock, self.series = threading.Lock(), {}

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        with self.lock:
            s = self.series.setdefault((method, route, status), {"buckets": [0] * len(BUCKETS), "count": 0, "sum": 0.0})
            s["count"] += 1
            s["sum"] += seconds
            for i, bound in enumerate(BUCKETS):
                if seconds <= bound:
                    s["buckets"][i] += 1

    def render(self) -> str:
        name = "http_server_request_duration_seconds"
        lines = [f"# TYPE {name} histogram"]
        with self.lock:
            for (method, route, status), s in sorted(self.series.items()):
                labels = f'http_request_method="{method}",http_route="{route}",http_response_status_code="{status}"'
                for bound, n in zip(BUCKETS, s["buckets"]):
                    lines.append(f'{name}_bucket{{{labels},le="{bound}"}} {n}')
                lines.append(f'{name}_bucket{{{labels},le="+Inf"}} {s["count"]}')
                lines.append(f"{name}_count{{{labels}}} {s['count']}")
                lines.append(f"{name}_sum{{{labels}}} {s['sum']:.6f}")
        return "\n".join(lines) + "\n"


METRICS = Metrics()


def work(route: str) -> int:
    """Simulated work with realistic latency and a small failure rate."""
    delay = {"/health": (0.001, 0.004), "/users/{id}": (0.008, 0.045), "/search": (0.06, 0.32),
             "/orders": (0.02, 0.09), "/orders/{id}": (0.01, 0.05)}[route]
    time.sleep(random.uniform(*delay) * (6 if random.random() < 0.01 else 1))
    if route == "/orders" and random.random() < 0.02:
        return 500
    return 200


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _serve(self, method: str):
        if self.path == "/metrics":
            body = METRICS.render().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        start, route = time.perf_counter(), match(method, self.path)
        status = work(route) if route else 404
        body = json.dumps({"ok": status == 200}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if route:
            METRICS.observe(method, route, status, time.perf_counter() - start)

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
