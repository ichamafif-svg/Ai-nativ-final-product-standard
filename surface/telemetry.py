"""RUN telemetry for the console: the product's APIs and the metrics an engineer on call needs.

Any product works if it exposes Prometheus text metrics (directly or through an OpenTelemetry collector) with an HTTP
server duration histogram, in the OpenTelemetry convention (`http_server_request_duration_seconds` with `http_route`,
`http_request_method`, `http_response_status_code`) or the Prometheus client's (`http_request_duration_seconds` with
`route`/`handler`, `method`, `status`/`code`). The declared APIs come from the product's own `openapi.json` on main;
the observed ones from the metrics. A declared route with no traffic is shown as such.

Per route, over a window: requests per second, error rate (5xx), latency p50/p95/p99 interpolated from the histogram
buckets as Prometheus' histogram_quantile does, availability, and the remaining error budget against the SLO. Samples
are cumulative counters stored in SQLite; a counter that goes down is a restart and counts from zero.

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

LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([-+0-9.eE]+|NaN|\+Inf|-Inf)(?:\s+\d+)?$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
FAMILIES = ("http_server_request_duration_seconds", "http_request_duration_seconds")
ROUTE, METHOD, STATUS = ("http_route", "route", "handler", "path"), ("http_request_method", "method"), \
    ("http_response_status_code", "status", "code")


def _pick(labels: dict, keys) -> str | None:
    return next((labels[k] for k in keys if k in labels), None)


def parse(text: str) -> dict:
    """{(method, route): {"count": n, "errors": n, "buckets": {le: n}}} from one scrape."""
    out = {}
    for raw in text.splitlines():
        m = LINE.match(raw.strip())
        if not m or raw.startswith("#"):
            continue
        name, labels, value = m[1], dict(LABEL.findall(m[2] or "")), float(m[3])
        family = next((f for f in FAMILIES if name.startswith(f)), None)
        if family is None or math.isnan(value):
            continue
        route, method = _pick(labels, ROUTE), (_pick(labels, METHOD) or "GET").upper()
        if not route:
            continue
        entry = out.setdefault((method, route), {"count": 0.0, "errors": 0.0, "buckets": {}})
        suffix = name[len(family):]
        if suffix == "_bucket" and "le" in labels:
            entry["buckets"][labels["le"]] = entry["buckets"].get(labels["le"], 0.0) + value
        elif suffix == "_count":
            entry["count"] += value
            status = _pick(labels, STATUS) or ""
            if status[:1] == "5":
                entry["errors"] += value
    return out


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
            self.db.execute("CREATE TABLE IF NOT EXISTS samples (at INTEGER, target TEXT, method TEXT, route TEXT, "
                            "count REAL, errors REAL, buckets TEXT)")
            self.db.execute("CREATE INDEX IF NOT EXISTS by_route ON samples (method, route, at)")
            self.db.commit()

    # ---- collecting ------------------------------------------------------------------------------------------
    def scrape(self, now: float | None = None) -> None:
        now = int(now if now is not None else time.time())
        for target in self.targets:
            try:
                rows = parse(self.fetch(target))
                with self.lock:
                    self.db.executemany("INSERT INTO samples VALUES (?, ?, ?, ?, ?, ?, ?)", [
                        (now, target, method, route, e["count"], e["errors"], json.dumps(e["buckets"]))
                        for (method, route), e in rows.items()])
                    self.db.execute("DELETE FROM samples WHERE at < ?", (now - 30 * 86400,))
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
    def _series(self, since: int) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT at, target, method, route, count, errors, buckets FROM samples "
                                   "WHERE at >= ? ORDER BY at", (since,)).fetchall()
        out = {}
        for at, target, method, route, count, errors, buckets in rows:
            out.setdefault((method, route), {}).setdefault(target, []).append((at, count, errors, json.loads(buckets)))
        return out

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
        requests = sum(d[1] for d in deltas)
        errors = sum(d[2] for d in deltas)
        buckets = {}
        for d in deltas:
            for le, n in d[3].items():
                buckets[le] = buckets.get(le, 0.0) + n
        error_rate = errors / requests if requests else None
        budget = None if error_rate is None else 1 - error_rate / (1 - self.slo)
        ms = lambda q: None if (v := quantile(q, buckets)) is None else round(v * 1000, 1)
        return {"requests": int(requests), "rps": round(requests / seconds, 2) if seconds else 0.0,
                "error_rate": error_rate, "availability": None if error_rate is None else 1 - error_rate,
                "budget": budget, "p50": ms(0.5), "p95": ms(0.95), "p99": ms(0.99), "buckets": buckets}

    def report(self, declared=(), window: int = 3600, now: float | None = None) -> dict:
        now = int(now if now is not None else time.time())
        series = self._series(now - window)
        routes, fleet = [], []
        keys = sorted(set(series) | {tuple(k) for k in declared}, key=lambda k: (k[1], k[0]))
        for key in keys:
            deltas = [d for samples in series.get(key, {}).values() for d in self._deltas(samples)]
            times = [s[0] for samples in series.get(key, {}).values() for s in samples]
            stats = self._stats(deltas, (max(times) - min(times)) if len(times) > 1 else 0)
            spark = [0.0] * 30
            step = window / 30
            for at, n, _, _ in deltas:
                i = min(29, max(0, int((at - (now - window)) / step)))
                spark[i] += n / step
            if stats["requests"] == 0:
                state = "idle"
            elif stats["error_rate"] >= 0.05:
                state = "failing"
            elif stats["availability"] < self.slo or (stats["p99"] or 0) > 1000:
                state = "degraded"
            else:
                state = "healthy"
            fleet += deltas
            routes.append({"method": key[0], "route": key[1], "declared": tuple(key) in {tuple(k) for k in declared},
                           "observed": key in series, "state": state, "spark": [round(x, 3) for x in spark],
                           **{k: v for k, v in stats.items() if k != "buckets"}})
        times = [s[0] for by_target in series.values() for samples in by_target.values() for s in samples]
        total = self._stats(fleet, (max(times) - min(times)) if len(times) > 1 else 0)
        total.pop("buckets")
        return {"window": window, "slo": self.slo, "fleet": total, "routes": routes,
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
