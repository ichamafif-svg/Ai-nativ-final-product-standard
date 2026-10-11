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
import re
import sqlite3
import threading
import time
import urllib.request
from pathlib import Path

from trusted.runtime import GAUGES, HISTOGRAMS, KINDS, parse, quantile  # noqa: F401  (one reading, shared with T06)
import trusted.runtime as runtime


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
            self.db.execute("CREATE TABLE IF NOT EXISTS incident (id INTEGER PRIMARY KEY, kind TEXT, operation TEXT, "
                            "name TEXT, opened_at INTEGER, closed_at INTEGER, state TEXT, worst TEXT, why TEXT)")
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

    INCIDENT_WINDOW = 300   # an incident opens or closes on the last five minutes, not on one noisy scrape

    def track(self, now: float | None = None) -> None:
        """Open an incident when a component turns degraded or failing (or its source falls silent), keep it while it
        stays so, close it when it recovers. Incidents are what the console alerts on."""
        now = int(now if now is not None else time.time())
        report = self.report(window=self.INCIDENT_WINDOW, now=now)
        bad = {}
        for kind, rows in report["components"].items():
            for r in rows:
                if r["state"] in ("degraded", "failing"):
                    bad[(kind, r.get("operation") or "", r["name"])] = (r["state"], r.get("why"))
        for target in report["targets"]:
            if not target["up"]:
                bad[("source", "", target["url"])] = ("failing", {"rule": "source_down", "detail": target["error"]})
        if self.extra is not None:                          # D32: the SLOs burning their budget, from the operator
            bad.update(self.extra())
        with self.lock:
            open_ = {(k, o, n): (i, worst) for i, k, o, n, worst in self.db.execute(
                "SELECT id, kind, operation, name, worst FROM incident WHERE closed_at IS NULL")}
            for key, (state, why) in bad.items():
                if key in open_:
                    i, worst = open_[key]
                    self.db.execute("UPDATE incident SET state = ?, why = ?, worst = ? WHERE id = ?",
                                    (state, json.dumps(why), "failing" if "failing" in (state, worst) else state, i))
                else:
                    self.db.execute("INSERT INTO incident (kind, operation, name, opened_at, state, worst, why) "
                                    "VALUES (?, ?, ?, ?, ?, ?, ?)", (*key, now, state, state, json.dumps(why)))
            for key, (i, _) in open_.items():
                if key not in bad:
                    self.db.execute("UPDATE incident SET closed_at = ?, state = 'resolved' WHERE id = ?", (now, i))
            self.db.commit()

    def incidents(self, since: int) -> list:
        with self.lock:
            rows = self.db.execute("SELECT id, kind, operation, name, opened_at, closed_at, state, worst, why FROM incident "
                                   "WHERE closed_at IS NULL OR closed_at >= ? ORDER BY closed_at IS NOT NULL, opened_at DESC",
                                   (since,)).fetchall()
        return [{"id": i, "kind": k, "operation": o, "name": n, "opened_at": a, "closed_at": c, "state": s, "worst": w,
                 "why": json.loads(why) if why else None} for i, k, o, n, a, c, s, w, why in rows]

    def start(self) -> None:
        def loop():
            while True:
                self.scrape()
                try:
                    self.track()
                except Exception:
                    pass                                    # tracking never stops collection
                time.sleep(self.interval)
        threading.Thread(target=loop, daemon=True).start()

    # ---- reading ---------------------------------------------------------------------------------------------
    _deltas = staticmethod(runtime.deltas)
    FAILING, SLOW_P99_MS = runtime.FAILING, runtime.SLOW_P99_MS

    def _stats(self, deltas: list, seconds: float) -> dict:
        return runtime.stats(deltas, seconds, self.slo)

    def rules(self) -> dict:
        """The global rules in force: the engineers' settings when published, else the defaults."""
        g = self._limits("api", "", "")
        return {"slo": g["objective"], "failing_error_rate": g["failing"], "slow_p99_ms": g["p99_ms"],
                "late_periods": self.late_periods}

    extra = None           # more open conditions to track as incidents: {(kind, operation, name): (state, why)}
    limits = None          # the engineers' settings (trusted.policy.Policy.limits), when the operator published them
    late_periods = runtime.LATE_PERIODS

    def _limits(self, kind: str, op: str, name: str) -> dict:
        if self.limits is None:
            return {"objective": self.slo, "p99_ms": self.SLOW_P99_MS, "failing": self.FAILING,
                    "counted": kind != "dependency", "id": None}
        return self.limits(kind, op, name)

    def _state(self, s: dict, kind: str = "api", op: str = "", name: str = "") -> tuple[str, dict | None]:
        return runtime.judge(s, self._limits(kind, op, name))

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
            lim = self._limits(kind, op, name)
            stats = runtime.stats(deltas, (max(times) - min(times)) if len(times) > 1 else 0, lim["objective"])
            spark = [0.0] * 30
            for at, n, _, _ in deltas:
                spark[min(29, max(0, int((at - since) / step)))] += n / step
            state, why = self._state(stats, kind, op, name)
            row = {"kind": kind, "operation": op, "name": name, "declared": key in declared, "observed": key in series,
                   "id": lim["id"], "counted": lim["counted"], "objective": lim["objective"], "p99_limit": lim["p99_ms"],
                   "state": state, "why": why, "spark": [round(x, 3) for x in spark], **stats}
            if kind == "worker":
                row["backlog"] = latest.get(("worker", name, "backlog"))
            components[kind].append(row)
            fleet += deltas
            if kind == "api":
                api_fleet += deltas
        for (kind, name, field), value in latest.items():          # a queue that only reports its depth
            if kind == "worker" and field == "backlog" and not any(r["name"] == name for r in components["worker"]):
                components["worker"].append({"kind": "worker", "operation": "process", "name": name, "observed": True,
                                             "declared": False, "state": "idle", "why": {"rule": "no_traffic"},
                                             "spark": [0.0] * 30, "backlog": value,
                                             **self._stats([], 0)})
        for name in sorted({n for (k, n, _) in latest if k == "job"}):
            get = lambda f: latest.get(("job", name, f))
            last, period, ok = get("last_success"), get("period"), get("ok")
            state, why = runtime.judge_job(last, period, ok, now, self.late_periods)
            lim = self._limits("job", "", name)
            components["job"].append({"kind": "job", "name": name, "last_success": last, "duration": get("duration"),
                                      "period": period, "ok": ok, "why": why, "state": state, "id": lim["id"],
                                      "counted": lim["counted"]})
        for name in sorted({n for (k, n, _) in latest if k == "process"}):
            cpu = history.get(("process", name, "cpu_seconds"), [])
            usage = None
            if len(cpu) > 1 and cpu[-1][0] > cpu[0][0] and cpu[-1][1] >= cpu[0][1]:
                usage = (cpu[-1][1] - cpu[0][1]) / (cpu[-1][0] - cpu[0][0])
            started = latest.get(("process", name, "started"))
            components["process"].append({"kind": "process", "name": name, "cpu": usage,
                                          "memory": latest.get(("process", name, "memory")),
                                          "uptime": now - started if started else None, "state": "healthy",
                                          "why": None})
        times = [s[0] for by in series.values() for samples in by.values() for s in samples]
        span = (max(times) - min(times)) if len(times) > 1 else 0
        return {"window": window, "slo": self.slo, "rules": self.rules(), "fleet": self._stats(api_fleet or fleet, span),
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
