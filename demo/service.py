"""The demo product, instrumented the OpenTelemetry way and exposed in Prometheus text format on /metrics.

It has what a real product has, not only an API:
- an HTTP API (http_server_request_duration_seconds per route, method and status);
- a worker that processes the order queue (messaging_process_duration_seconds, messaging_queue_depth);
- a database (db_client_operation_duration_seconds per operation, on SQLite);
- an external payment provider it calls (http_client_request_duration_seconds per server);
- a scheduled job (job_last_success_timestamp_seconds, job_last_duration_seconds, job_period_seconds, job_last_status);
- its own process (process_cpu_seconds_total, process_resident_memory_bytes, process_start_time_seconds).

    python service.py [port]
"""
import json
import queue
import random
import re
import resource
import sqlite3
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
STARTED = time.time()


def match(method: str, path: str):
    """The declared route template of a request, or None."""
    path = path.split("?", 1)[0]
    return next((template for m, rx, template in ROUTES if m == method and rx.fullmatch(path)), None)


class Metrics:
    def __init__(self):
        self.lock, self.hist, self.gauges = threading.Lock(), {}, {}

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        """An HTTP request served (kept as it was: existing callers and tests rely on it)."""
        self.record("http_server_request_duration_seconds", {"http_request_method": method, "http_route": route,
                                                             "http_response_status_code": str(status)}, seconds)

    def record(self, family: str, labels: dict, seconds: float) -> None:
        key = (family, tuple(sorted(labels.items())))
        with self.lock:
            s = self.hist.setdefault(key, {"buckets": [0] * len(BUCKETS), "count": 0, "sum": 0.0})
            s["count"] += 1
            s["sum"] += seconds
            for i, bound in enumerate(BUCKETS):
                if seconds <= bound:
                    s["buckets"][i] += 1

    def set(self, family: str, labels: dict, value: float) -> None:
        with self.lock:
            self.gauges[(family, tuple(sorted(labels.items())))] = value

    def render(self) -> str:
        lines = []
        fmt = lambda pairs, extra="": "{" + ",".join([f'{k}="{v}"' for k, v in pairs] + ([extra] if extra else [])) + "}"
        with self.lock:
            for (family, pairs), s in sorted(self.hist.items()):
                for bound, n in zip(BUCKETS, s["buckets"]):
                    le = 'le="%s"' % bound
                    lines.append(f"{family}_bucket{fmt(pairs, le)} {n}")
                inf = 'le="+Inf"'
                lines.append(f"{family}_bucket{fmt(pairs, inf)} {s['count']}")
                lines.append(f"{family}_count{fmt(pairs)} {s['count']}")
                lines.append(f"{family}_sum{fmt(pairs)} {s['sum']:.6f}")
            for (family, pairs), value in sorted(self.gauges.items()):
                lines.append(f"{family}{fmt(pairs) if pairs else ''} {value}")
        usage = resource.getrusage(resource.RUSAGE_SELF)
        lines += [f"process_cpu_seconds_total {usage.ru_utime + usage.ru_stime:.3f}",
                  f"process_resident_memory_bytes {usage.ru_maxrss * 1024}",
                  f"process_start_time_seconds {STARTED:.0f}"]
        return "\n".join(lines) + "\n"


METRICS = Metrics()
ORDERS: "queue.Queue[int]" = queue.Queue()
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB_LOCK = threading.Lock()
DB.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, amount INTEGER, paid INTEGER)")


def db(operation: str, sql: str, *args):
    start = time.perf_counter()
    with DB_LOCK:
        rows = DB.execute(sql, args).fetchall()
        DB.commit()
    time.sleep(random.uniform(0.001, 0.006) * (8 if random.random() < 0.01 else 1))   # network and disk, simulated
    METRICS.record("db_client_operation_duration_seconds",
                    {"db_system_name": "sqlite", "db_namespace": "shop", "db_operation_name": operation},
                    time.perf_counter() - start)
    return rows


def pay(order: int) -> bool:
    """A call to the external payment provider."""
    start, ok = time.perf_counter(), random.random() > 0.01
    time.sleep(random.uniform(0.05, 0.25))
    labels = {"http_request_method": "POST", "server_address": "api.payments.example",
              "http_response_status_code": "200" if ok else "503"}
    METRICS.record("http_client_request_duration_seconds", labels, time.perf_counter() - start)
    return ok


def worker():
    while True:
        order = ORDERS.get()
        start = time.perf_counter()
        ok = pay(order)
        db("UPDATE", "UPDATE orders SET paid = ? WHERE id = ?", int(ok), order)
        labels = {"messaging_destination_name": "orders", "messaging_operation_name": "process"}
        if not ok:
            labels["error_type"] = "payment_declined"
        METRICS.record("messaging_process_duration_seconds", labels, time.perf_counter() - start)
        METRICS.set("messaging_queue_depth", {"messaging_destination_name": "orders"}, ORDERS.qsize())


def nightly_report(period: float = 60.0):
    """A scheduled job: here every minute, so the demo shows it running."""
    METRICS.set("job_period_seconds", {"job": "daily-report"}, period)
    while True:
        start = time.perf_counter()
        db("SELECT", "SELECT count(*), sum(amount) FROM orders")
        time.sleep(random.uniform(0.2, 0.6))
        ok = random.random() > 0.05
        METRICS.set("job_last_status", {"job": "daily-report"}, 1 if ok else 0)
        METRICS.set("job_last_duration_seconds", {"job": "daily-report"}, round(time.perf_counter() - start, 3))
        if ok:
            METRICS.set("job_last_success_timestamp_seconds", {"job": "daily-report"}, round(time.time()))
        time.sleep(period)


def work(route: str) -> int:
    """Simulated work with realistic latency and a small failure rate."""
    delay = {"/health": (0.001, 0.004), "/users/{id}": (0.008, 0.045), "/search": (0.06, 0.32),
             "/orders": (0.02, 0.09), "/orders/{id}": (0.01, 0.05)}[route]
    if route == "/users/{id}":
        db("SELECT", "SELECT 1")
    if route == "/orders":
        order = db("INSERT", "INSERT INTO orders (amount, paid) VALUES (?, 0) RETURNING id", random.randint(5, 500))[0][0]
        ORDERS.put(order)
        METRICS.set("messaging_queue_depth", {"messaging_destination_name": "orders"}, ORDERS.qsize())
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
    for target in (worker, worker, nightly_report):
        threading.Thread(target=target, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
