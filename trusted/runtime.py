"""T06 — the production instrument: what the scanner signs about the product in production (D30).

The same reading of metrics the console shows, but on the trusted side, so that it can become a signed fact and open
rights. From Prometheus text metrics in the OpenTelemetry conventions it recognises the product's components (APIs,
workers, databases, external services, scheduled jobs, processes) and judges each over a window with published rules:

    failing    5 % of requests or more fail (a 5xx status or an `error_type` label)
    degraded   availability below the objective, a p99 above one second, or a scheduled job late by two periods
    healthy    otherwise; idle when nothing was requested

It signs two facts: `run:sources:all coverage` (complete only when every declared metrics source answered, every
measure: never "fine" by default) and `run:service:all slo` (`met`, or `breached:N` naming nothing but a count; the
components and their reasons go to the findings; external services are shown but not counted, their failures reach
the objective through the product's own components). An unreachable source makes the service `uncovered`, never `met`.
Counters are cumulative; one that goes down is a restart and counts from zero.
"""
from __future__ import annotations

import json
import math
import re
import subprocess
import time
import urllib.request

LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([-+0-9.eE]+|NaN|\+Inf|-Inf)(?:\s+-?\d+)?$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
FAILING, SLOW_P99_MS, LATE_PERIODS = 0.05, 1000.0, 2


def _pick(labels: dict, *keys, default=None):
    return next((labels[k] for k in keys if labels.get(k)), default)


HISTOGRAMS = {   # family -> (kind, labels -> (operation, name))
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
GAUGES = {       # family -> (kind, field, labels naming the row)
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
OUTSIDE = ("dependency",)   # an external service's own failures are shown, not counted against the product's objective


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


def deltas(samples: list) -> list:
    """(at, requests, errors, {le: n}) between consecutive scrapes; a lower counter is a restart."""
    out = []
    for (_, c0, e0, b0), (at, c1, e1, b1) in zip(samples, samples[1:]):
        restart = c1 < c0
        out.append((at, c1 if restart else c1 - c0, e1 if restart else e1 - e0,
                    {le: (n if restart else n - b0.get(le, 0.0)) for le, n in b1.items()}))
    return out


def stats(ds: list, seconds: float, slo: float) -> dict:
    requests, errors, buckets = sum(d[1] for d in ds), sum(d[2] for d in ds), {}
    for d in ds:
        for le, n in d[3].items():
            buckets[le] = buckets.get(le, 0.0) + n
    error_rate = errors / requests if requests else None
    ms = lambda q: None if (v := quantile(q, buckets)) is None else round(v * 1000, 1)
    return {"requests": int(requests), "rps": round(requests / seconds, 2) if seconds else 0.0,
            "error_rate": error_rate, "availability": None if error_rate is None else 1 - error_rate,
            "budget": None if error_rate is None else 1 - error_rate / (1 - slo),
            "p50": ms(0.5), "p95": ms(0.95), "p99": ms(0.99)}


def judge(s: dict, slo: float) -> tuple[str, dict | None]:
    """(state, why): the rule that decided it, with the measured value and the limit it crossed."""
    if s["requests"] == 0:
        return "idle", {"rule": "no_traffic"}
    if s["error_rate"] >= FAILING:
        return "failing", {"rule": "error_rate", "value": s["error_rate"], "limit": FAILING}
    if s["availability"] < slo:
        return "degraded", {"rule": "availability", "value": s["availability"], "limit": slo}
    if (s["p99"] or 0) > SLOW_P99_MS:
        return "degraded", {"rule": "p99", "value": s["p99"], "limit": SLOW_P99_MS}
    return "healthy", None


def judge_job(last, period, ok, now) -> tuple[str, dict | None]:
    if ok == 0:
        return "failing", {"rule": "job_failed"}
    if not last:
        return "degraded", {"rule": "job_never"}
    if period and now - last > LATE_PERIODS * period:
        return "degraded", {"rule": "job_late", "value": now - last, "limit": LATE_PERIODS * period}
    return "healthy", None


class Production:
    """The operator's reading of production: the last scrapes of every declared source, judged over a window."""

    def __init__(self, sources, *, slo: float = 0.999, window: int = 300, fetch=None):
        self.sources, self.slo, self.window = list(sources), slo, window
        self.fetch = fetch or (lambda url: urllib.request.urlopen(url, timeout=5).read().decode())
        self.samples = {}                                  # source -> [(at, hist, gauges)]
        self.up = {}

    def scrape(self, now: float | None = None) -> None:
        now = int(now if now is not None else time.time())
        for source in self.sources:
            try:
                hist, gauges = parse(self.fetch(source), re.sub(r"^\w+://", "", source).split("/")[0])
                kept = [s for s in self.samples.get(source, []) if s[0] >= now - self.window] + [(now, hist, gauges)]
                self.samples[source], self.up[source] = kept, True
            except Exception:
                self.up[source] = False

    def assess(self, now: float | None = None) -> dict:
        """{"coverage": status, "slo": status, "components": [...]} over the window, from the samples only."""
        now = int(now if now is not None else time.time())
        if not self.sources:
            return {"coverage": "uncovered:empty", "slo": "uncovered:no-source", "components": []}
        silent = [s for s in self.sources if not self.up.get(s) or len(self.samples.get(s, [])) < 2]
        components = []
        for source, samples in self.samples.items():
            series = {}
            for at, hist, _ in samples:
                for key, e in hist.items():
                    series.setdefault(key, []).append((at, e["count"], e["errors"], e["buckets"]))
            span = samples[-1][0] - samples[0][0] if len(samples) > 1 else 0
            for (kind, op, name), rows in series.items():
                state, why = judge(stats(deltas(rows), span, self.slo), self.slo)
                components.append({"kind": kind, "operation": op, "name": name, "state": state, "why": why})
            gauges = samples[-1][2] if samples else {}
            for job in sorted({n for (k, n, _) in gauges if k == "job"}):
                get = lambda f: gauges.get(("job", job, f))
                state, why = judge_job(get("last_success"), get("period"), get("ok"), now)
                components.append({"kind": "job", "operation": "", "name": job, "state": state, "why": why})
        bad = [c for c in components if c["state"] in ("degraded", "failing") and c["kind"] not in OUTSIDE]
        if silent:
            return {"coverage": f"uncovered:{len(silent)}", "slo": f"uncovered:{len(silent)}", "components": components,
                    "silent": silent}
        return {"coverage": "complete", "slo": f"breached:{len(bad)}" if bad else "met", "components": components,
                "silent": []}


ROLLBACK_HORIZON_MS = 30 * 60_000   # a breach this soon after a switch is the new release's; later, it goes to people


def release_facts(slo: str, live: str | None, main: str, history: list, good: set, now_ms: int) -> tuple[list, dict]:
    """The facts that open `deploy` and `rollback`, as (resource, property, status), with their reasons.

    run:release:all lag          none when production runs main's head, else behind (a gap, repaired by deploy)
    run:release:all/{live}/{main} deployable = yes   main moved, and main's head was never rolled back
    run:service:all/{live}/{prev} regressed = yes    the objective is breached within the horizon after `live` went
                                                     live, and `prev`, the release it replaced, met it while live
    A release rolled back is never deployable again: the gap stays open and goes to people at its due time."""
    live_name = live or "none"
    rolled_back = {h["from"] for h in history if h.get("op") == "rollback"}
    facts = [("run:release:all", "lag", "none" if live == main else "behind")]
    why = {"live": live, "main": main, "rolled_back": sorted(rolled_back)}
    if live != main:
        if main in rolled_back:
            why["deploy"] = "main's head was rolled back: a new commit on main is needed"
        else:
            facts.append((f"run:release:all/{live_name}/{main}", "deployable", "yes"))
    switch = next((h for h in reversed(history) if h.get("to") == live), None)
    if live and slo.startswith("breached") and switch:
        prev, age = switch["from"], now_ms - switch["at"]
        if prev == "none" or prev not in good:
            why["rollback"] = "no earlier release is known to have met the objective"
        elif age > ROLLBACK_HORIZON_MS:
            why["rollback"] = f"live for {age // 60_000} min before the breach: not attributable to the switch"
        else:
            facts.append((f"run:service:all/{live}/{prev}", "regressed", "yes"))
    return facts, why


class Pass:
    """The operator's production pass: scrape, judge, sign. Facts under the scanner's capability; reasons to findings."""

    def __init__(self, service, instrument, production: Production, repo, *, releases=None, state=None):
        self.service, self.instrument, self.production, self.repo = service, instrument, production, repo
        self.releases, self.state, self.live, self.offered = releases, state, None, set()
        self.good = set(json.loads(state.read_text())) if state is not None and state.exists() else set()

    def _main(self) -> str:
        return subprocess.run(["git", "-C", str(self.repo), "rev-parse", "refs/heads/main"], capture_output=True,
                              text=True, timeout=60, check=True).stdout.strip()

    def measure(self) -> dict:
        domain = self.service.view()["prefix"]["genesis"]
        live = self.releases.current() if self.releases else None
        if live != self.live:                               # a switch: judge the new release on its own traffic only
            self.production.samples, self.live = {}, live
        self.production.scrape(self.instrument.clock() / 1000)
        a = self.production.assess(self.instrument.clock() / 1000)
        warming = all(self.production.up.get(s) for s in self.production.sources) and a["coverage"] != "complete"
        facts = [] if warming and self.production.sources else [
            ("run:sources:all", "coverage", a["coverage"]), ("run:service:all", "slo", a["slo"])]
        findings = {"run:sources:all|coverage": {"status": a["coverage"], "details": a.get("silent", [])},
                    "run:service:all|slo": {"status": a["slo"], "details": [
                        f"{c['kind']} {c['operation']} {c['name']}: {c['state']} ({json.dumps(c['why'])})".replace("  ", " ")
                        for c in a["components"] if c["state"] in ("degraded", "failing")]}}
        if self.releases is None:
            facts.append(("run:release:all", "lag", "uncovered:not-configured"))
        else:
            if a["slo"] == "met" and live and live not in self.good:
                self.good.add(live)
                if self.state is not None:
                    self.state.write_text(json.dumps(sorted(self.good)))
            released, why = release_facts(a["slo"], live, self._main(), self.releases.history(), self.good,
                                          self.instrument.clock())
            facts += released
            findings["run:release:all|lag"] = {"status": released[0][2], "details": [
                f"{k}: {', '.join(v) if isinstance(v, list) else v}" for k, v in why.items()]}
        offered = {(r, p) for r, p, s in facts if "/" in r and s == "yes"}
        facts += [(r, p, "no") for r, p in self.offered - offered]   # withdrawn: production moved, or recovered
        self.offered = offered
        self.instrument.findings.update(findings)
        for resource, prop, status in facts:
            self.service.admit(self.instrument.observation(domain, resource, prop, status))
        return {"admitted": len(facts), "slo": a["slo"], "live": live}
