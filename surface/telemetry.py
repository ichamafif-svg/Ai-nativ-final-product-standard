"""RUN telemetry for the console: every component of the product and the signals an engineer on call needs.

A product is not only an API. The console recognises, from Prometheus text metrics (exposed directly or through an
OpenTelemetry collector), the components the OpenTelemetry semantic conventions describe, and gives each kind its
golden signals:

| kind       | recognised from                                   | one row per                 | signals                          |
|------------|---------------------------------------------------|-----------------------------|----------------------------------|
| api        | http_server_request_duration_seconds (or the      | method, route               | rate, 5xx, p50/p95/p99,          |
|            | Prometheus client's http_request_duration_seconds) |                             | availability, error budget       |
| worker     | messaging_process_duration_seconds,               | operation, queue            | throughput, failures, latency,   |
|            | messaging_queue_depth (gauge)                     |                             | backlog                          |
| database   | db_client_operation_duration_seconds              | operation, system/namespace | rate, errors, latency            |
| dependency | http_client_request_duration_seconds              | method, server address      | rate, errors, latency            |
| job        | job_last_success_timestamp_seconds, job_period_   | job                         | last success, duration, late or  |
|            | seconds, job_last_duration_seconds, job_last_status|                             | failing                          |
| process    | process_cpu_seconds_total, process_resident_      | process                     | CPU, memory, uptime              |
|            | memory_bytes, process_start_time_seconds          |                             |                                  |

A failure is a 5xx status or an `error_type` label, as the conventions define it. Declared APIs come from the product's
openapi.json; a declared route with no traffic is shown. Latency quantiles are interpolated from the histogram buckets
as Prometheus' histogram_quantile does. Counters are cumulative; one that goes down is a restart and counts from zero.

This is information for people. It opens no right and the kernel never reads it.
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
import threading
import time
import urllib.request
from pathlib import Path

LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([-+0-9.eE]+|NaN|\+Inf|-Inf)(?:\s+-?\d+)?$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def _pick(labels: dict, *keys, default=None):
    return next((labels[k] for k in keys if labels.get(k)), default)


# family -> (kind, function of the labels giving the row's (operation, name), or None to skip)
HISTOGRAMS = {
    "http_server_request_duration_seconds": ("api", lambda l: (_pick(l, "http_request_method", "method", default="GET").upper(),
                                                               _pick(l, "http_route", "route", "handler", "path"))),
    "http_request_duration_seconds": ("api", lambda l: (_pick(l, "method", "http_request_method", default="GET").upper(),
                                                        _pick(l, "route", "handler", "http_route", "path"))),
    "messaging_process_duration_seconds": ("worker", lambda l: (_pick(l, "messaging_operation_name", default="process"),
                                                                _pick(l, "messaging_destination_name", "queue"))),
    "db_client_operation_duration_seconds": ("database", lambda l: (
        _pick(l, "db_operation_name", "db_operation", default="query").upper(),
        "/".join(x for x in (_pick(l, "db_system_name", "db_system"), _pick(l, "db_namespace", "db_collection_name")) if x)
        or None)),
    "http_client_request_duration_seconds": ("dependency", lambda l: (
        _pick(l, "http_request_method", "method", default="GET").upper(), _pick(l, "server_address", "net_peer_name"))),
}
GAUGES = {   # family -> (kind, field, label holding the row's name)
    "messaging_queue_depth": ("worker", "backlog", ("messaging_destination_name", "queue")),
    "job_last_success_timestamp_seconds": ("job", "last_success", ("job", "job_name")),
    "job_last_duration_seconds": ("job", "duration", ("job", "job_name")),
    "job_period_seconds": ("job", "period", ("job", "job_name")),
    "job_last_status": ("job", "ok", ("job", "job_name")),
    "process_cpu_seconds_total": ("process", "cpu_seconds", ("job", "service_name")),
    "process_resident_memory_bytes": ("process", "memory", ("job", "service_name")),
    "process_start_time_seconds": ("process", "started", ("job", "service_name")),
}
KINDS = ("api", "worker", "job", "database", "dependency", "process")


def _failed(labels: dict) -> bool:
    status = _pick(labels, "http_response_status_code", "status", "code", default="")
    return status[:1] == "5" or bool(labels.get("error_type"))


def parse(text: str, process_name: str = "service") -> tuple[dict, dict]:
    """(histograms, gauges) of one scrape: {(kind, operation, name): {"count", "errors", "buckets"}} and
    {(kind, name, field): value}."""
    hist, gauges = {}, {}
    for raw in text.splitlines():
        m = LINE.match(raw.strip())
        if not m or raw.startswith("#"):
            continue
        name, labels, value = m[1], dict(LABEL.findall(m[2] or "")), float(m[3])
        if math.isnan(value):
            continue
        if name in GAUGES:
            kind, field, keys = GAUGES[name]
            row = _pick(labels, *keys, default=process_name if kind == "process" else None)
            if row:
                gauges[(kind, row, field)] = value
            continue
        family = next((f for f in HISTOGRAMS if name in (f + "_bucket", f + "_count")), None)
        if family is None:
            continue
        kind, key = HISTOGRAMS[family]
        operation, row = key(labels)
        if not row:
            continue
        entry = hist.setdefault((kind, operation, row), {"count": 0.0, "errors": 0.0, "buckets": {}})
        if name.endswith("_bucket") and "le" in labels:
            entry["buckets"][labels["le"]] = entry["buckets"].get(labels["le"], 0.0) + value
        elif name.endswith("_count"):
            entry["count"] += value
            if _failed(labels):
                entry["errors"] += value
    return hist, gauges


def quantile(q: float, buckets: dict) -> float | None:
    """histogram_quantile: linear interpolation inside the bucket that holds the q-th observation."""
    bounds = sorted(((math.inf if le == "+Inf" else float(le)), n) for le, n in buckets.items())
    if not bounds or bounds[-1][1] <= 0:
        return None
    rank, prev_bound, prev_count = q * bounds[-1][1], 0.0, 0.0
    for bound, count in bounds:
        if count >= rank:
            if math.isinf(bound):
                return prev_bound
            inside = count - prev_count
            return prev_bound + (bound - prev_bound) * ((rank - prev_count) / inside if inside else 0)
        prev_bound, prev_count = bound, count
    return prev_bound


class Telemetry:
    def __init__(self, store, targets, *, slo: float = 0.999, interval: float = 15.0, fetch=None):
        self.targets, self.slo, self.interval = list(targets), slo, interval
        self.fetch = fetch or (lambda url: urllib.request.urlopen(url, timeout=5).read().decode())
        self.status = {t: {"up": False, "at": None, "error": "not scraped yet"} for t in self.targets}
        Path(store).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(store), check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS hist (at INTEGER, target TEXT, kind TEXT, operation TEXT, "
                            "name TEXT, count REAL, errors REAL, buckets TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS gauge (at INTEGER, target TEXT, kind TEXT, name TEXT, "
                            "field TEXT, value REAL)")
            self.db.execute("CREATE INDEX IF NOT EXISTS hist_at ON hist (at)")
            self.db.execute("CREATE INDEX IF NOT EXISTS gauge_at ON gauge (at)")
            self.db.commit()

    # ---- collecting ------------------------------------------------------------------------------------------
    def scrape(self, now: float | None = None) -> None:
        now = int(now if now is not None else time.time())
        for target in self.targets:
            try:
                name = re.sub(r"^\w+://", "", target).split("/")[0]
                hist, gauges = parse(self.fetch(target), name)
                with self.lock:
                    self.db.executemany("INSERT INTO hist VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [
                        (now, target, kind, op, row, e["count"], e["errors"], json.dumps(e["buckets"]))
                        for (kind, op, row), e in hist.items()])
                    self.db.executemany("INSERT INTO gauge VALUES (?, ?, ?, ?, ?, ?)", [
                        (now, target, kind, row, field, value) for (kind, row, field), value in gauges.items()])
                    for table in ("hist", "gauge"):
                        self.db.execute(f"DELETE FROM {table} WHERE at < ?", (now - 30 * 86400,))
                    self.db.commit()
                self.status[target] = {"up": True, "at": now, "error": None}
            except Exception as exc:                       # a target that does not answer is visible, never zero
                self.status[target] = {"up": False, "at": now, "error": f"{type(exc).__name__}: {exc}"[:200]}

    def start(self) -> None:
        def loop():
            while True:
                self.scrape()
                time.sleep(self.interval)
        threading.Thread(target=loop, daemon=True).start()

    # ---- reading ---------------------------------------------------------------------------------------------
    @staticmethod
    def _deltas(samples: list) -> list:
        """(at, requests, errors, {le: n}) between consecutive scrapes; a lower counter is a restart."""
        out = []
        for (_, c0, e0, b0), (at, c1, e1, b1) in zip(samples, samples[1:]):
            restart = c1 < c0
            out.append((at, c1 if restart else c1 - c0, e1 if restart else e1 - e0,
                        {le: (n if restart else n - b0.get(le, 0.0)) for le, n in b1.items()}))
        return out

    def _stats(self, deltas: list, seconds: float) -> dict:
        requests, errors, buckets = sum(d[1] for d in deltas), sum(d[2] for d in deltas), {}
        for d in deltas:
            for le, n in d[3].items():
                buckets[le] = buckets.get(le, 0.0) + n
        error_rate = errors / requests if requests else None
        ms = lambda q: None if (v := quantile(q, buckets)) is None else round(v * 1000, 1)
        return {"requests": int(requests), "rps": round(requests / seconds, 2) if seconds else 0.0,
                "error_rate": error_rate, "availability": None if error_rate is None else 1 - error_rate,
                "budget": None if error_rate is None else 1 - error_rate / (1 - self.slo),
                "p50": ms(0.5), "p95": ms(0.95), "p99": ms(0.99)}

    def _state(self, s: dict) -> str:
        if s["requests"] == 0:
            return "idle"
        if s["error_rate"] >= 0.05:
            return "failing"
        if s["availability"] < self.slo or (s["p99"] or 0) > 1000:
            return "degraded"
        return "healthy"

    def report(self, declared=(), window: int = 3600, now: float | None = None) -> dict:
        now = int(now if now is not None else time.time())
        since, step = now - window, window / 30
        with self.lock:
            hrows = self.db.execute("SELECT at, target, kind, operation, name, count, errors, buckets FROM hist "
                                    "WHERE at >= ? ORDER BY at", (since,)).fetchall()
            grows = self.db.execute("SELECT at, target, kind, name, field, value FROM gauge WHERE at >= ? ORDER BY at",
                                    (since,)).fetchall()
        series = {}
        for at, target, kind, op, name, count, errors, buckets in hrows:
            series.setdefault((kind, op, name), {}).setdefault(target, []).append((at, count, errors, json.loads(buckets)))
        latest, history = {}, {}
        for at, _, kind, name, field, value in grows:
            latest[(kind, name, field)] = value
            history.setdefault((kind, name, field), []).append((at, value))
        declared = {("api", m, r) for m, r in declared}
        components = {k: [] for k in KINDS}
        fleet, api_fleet = [], []
        for key in sorted(set(series) | declared, key=lambda k: (k[0], k[2], k[1])):
            kind, op, name = key
            by_target = series.get(key, {})
            deltas = [d for samples in by_target.values() for d in self._deltas(samples)]
            times = [s[0] for samples in by_target.values() for s in samples]
            stats = self._stats(deltas, (max(times) - min(times)) if len(times) > 1 else 0)
            spark = [0.0] * 30
            for at, n, _, _ in deltas:
                spark[min(29, max(0, int((at - since) / step)))] += n / step
            row = {"kind": kind, "operation": op, "name": name, "declared": key in declared, "observed": key in series,
                   "state": self._state(stats), "spark": [round(x, 3) for x in spark], **stats}
            if kind == "worker":
                row["backlog"] = latest.get(("worker", name, "backlog"))
            components[kind].append(row)
            fleet += deltas
            if kind == "api":
                api_fleet += deltas
        for (kind, name, field), value in latest.items():          # a queue that only reports its depth
            if kind == "worker" and field == "backlog" and not any(r["name"] == name for r in components["worker"]):
                components["worker"].append({"kind": "worker", "operation": "process", "name": name, "observed": True,
                                             "declared": False, "state": "idle", "spark": [0.0] * 30, "backlog": value,
                                             **self._stats([], 0)})
        for name in sorted({n for (k, n, _) in latest if k == "job"}):
            get = lambda f: latest.get(("job", name, f))
            last, period, ok = get("last_success"), get("period"), get("ok")
            late = bool(last and period and now - last > 2 * period)
            components["job"].append({"kind": "job", "name": name, "last_success": last, "duration": get("duration"),
                                      "period": period, "ok": ok,
                                      "state": "failing" if ok == 0 else "degraded" if late or not last else "healthy"})
        for name in sorted({n for (k, n, _) in latest if k == "process"}):
            cpu = history.get(("process", name, "cpu_seconds"), [])
            usage = None
            if len(cpu) > 1 and cpu[-1][0] > cpu[0][0] and cpu[-1][1] >= cpu[0][1]:
                usage = (cpu[-1][1] - cpu[0][1]) / (cpu[-1][0] - cpu[0][0])
            started = latest.get(("process", name, "started"))
            components["process"].append({"kind": "process", "name": name, "cpu": usage,
                                          "memory": latest.get(("process", name, "memory")),
                                          "uptime": now - started if started else None, "state": "healthy"})
        times = [s[0] for by in series.values() for samples in by.values() for s in samples]
        span = (max(times) - min(times)) if len(times) > 1 else 0
        return {"window": window, "slo": self.slo, "fleet": self._stats(api_fleet or fleet, span),
                "components": components, "routes": components["api"],
                "targets": [{"url": t, **s} for t, s in self.status.items()]}


def declared_routes(openapi_text: str) -> list:
    """(METHOD, path) for every operation of an OpenAPI document (JSON)."""
    try:
        doc = json.loads(openapi_text)
    except ValueError:
        return []
    verbs = {"get", "put", "post", "delete", "patch", "head", "options"}
    return sorted((verb.upper(), path) for path, ops in (doc.get("paths") or {}).items() if isinstance(ops, dict)
                  for verb in ops if verb in verbs)
