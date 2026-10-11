"""T06 — the production instrument: what the scanner signs about the product in production (D30, D31).

The same reading of metrics the console shows, but on the trusted side, so that it can become a signed fact and open
rights. From Prometheus text metrics in the OpenTelemetry conventions it recognises the product's components (APIs,
workers, databases, external services, scheduled jobs, processes), adds the engineers' external probes (requests sent
from outside, so that a product that reports itself healthy while it does not answer is caught), and judges each over
a window with the engineers' settings (trusted/policy.py; defaults below):

    failing    5 % of requests or more fail (a 5xx status, an `error_type` label, or a probe's unexpected answer)
    degraded   availability below the objective, a p99 above its limit, or a scheduled job late by two periods
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
import urllib.error
import urllib.request

from .slo import evaluate

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
    "build_info": ("release", "info", ("version", "service_version")),   # which release answers (D31)
}
KINDS = ("api", "worker", "job", "database", "dependency", "process", "probe")
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


def judge(s: dict, limits) -> tuple[str, dict | None]:
    """(state, why): the rule that decided it, with the measured value and the limit it crossed.
    limits: {"objective", "p99_ms", "failing"}, or an objective alone (the published defaults for the rest)."""
    if not isinstance(limits, dict):
        limits = {"objective": limits, "p99_ms": SLOW_P99_MS, "failing": FAILING}
    if s["requests"] == 0:
        return "idle", {"rule": "no_traffic"}
    if s["error_rate"] >= limits["failing"]:
        return "failing", {"rule": "error_rate", "value": s["error_rate"], "limit": limits["failing"]}
    if s["availability"] < limits["objective"]:
        return "degraded", {"rule": "availability", "value": s["availability"], "limit": limits["objective"]}
    if (s["p99"] or 0) > limits["p99_ms"]:
        return "degraded", {"rule": "p99", "value": s["p99"], "limit": limits["p99_ms"]}
    return "healthy", None


def judge_job(last, period, ok, now, late_periods: int = LATE_PERIODS) -> tuple[str, dict | None]:
    if ok == 0:
        return "failing", {"rule": "job_failed"}
    if not last:
        return "degraded", {"rule": "job_never"}
    if period and now - last > late_periods * period:
        return "degraded", {"rule": "job_late", "value": now - last, "limit": late_periods * period}
    return "healthy", None


RELEASE_LINE = re.compile(r'^standard_release_(requests_total|duration_seconds_bucket)\{(.*)\}\s+([-+0-9.eE]+)$')


def parse_releases(text: str) -> dict:
    """{release: {"count", "errors", "buckets"}} from the runner's own measures (tools/run_release.py): what each
    release answered, seen from in front of it."""
    out = {}
    for raw in text.splitlines():
        m = RELEASE_LINE.match(raw.strip())
        if not m:
            continue
        labels, value = dict(LABEL.findall(m[2])), float(m[3])
        e = out.setdefault(labels.get("release", "?"), {"count": 0.0, "errors": 0.0, "buckets": {}})
        if m[1] == "requests_total":
            e["count"] += value
            e["errors"] += value if labels.get("outcome") == "error" else 0.0
        else:
            e["buckets"][labels["le"]] = e["buckets"].get(labels["le"], 0.0) + value
    return out


BUCKETS = ("0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10", "+Inf")


def _request(method: str, url: str) -> tuple[int, float]:
    start = time.perf_counter()
    try:
        status = urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=10).status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except Exception:
        status = 0                                          # no answer at all
    return status, time.perf_counter() - start


class Production:
    """The operator's reading of production: the last scrapes of every declared source and the probes' answers,
    judged over a window with the engineers' settings."""

    def __init__(self, sources, *, slo: float = 0.999, window: int = 300, fetch=None, policy=None, request=None,
                 store=None, release_source=None):
        self.sources, self.slo, self.window, self.policy = list(sources), slo, window, policy
        self.store, self.release_source, self.last, self.releases = store, release_source, {}, []
        self.fetch = fetch or (lambda url: urllib.request.urlopen(url, timeout=5).read().decode())
        self.request = request or _request
        self.samples = {}                                  # source -> [(at, hist, gauges)]
        self.up, self.probed = {}, {}                      # probe id -> cumulative {"count", "errors", "buckets"}

    def limits(self, kind: str, operation: str, name: str) -> dict:
        if self.policy is None:
            return {"objective": self.slo, "p99_ms": SLOW_P99_MS, "failing": FAILING, "counted": kind != "dependency"}
        return self.policy.limits(kind, operation, name)

    def _probe(self) -> dict:
        """One request per probe, accumulated as a histogram of kind `probe`: the product's answer seen from outside."""
        if self.policy is None or not self.policy.get("base_url"):
            return {}
        out, base = {}, self.policy.get("base_url").rstrip("/")
        for pid, method, path, expected in self.policy.probes():
            status, seconds = self.request(method, base + path)
            e = self.probed.setdefault(pid, {"count": 0.0, "errors": 0.0, "buckets": dict.fromkeys(BUCKETS, 0.0),
                                             "last": None})
            e["count"] += 1
            e["errors"] += status != expected
            e["last"] = status
            for le in BUCKETS:
                if le == "+Inf" or seconds <= float(le):
                    e["buckets"][le] += 1
            out[("probe", method, path)] = e
        return out

    def scrape(self, now: float | None = None) -> None:
        now = int(now if now is not None else time.time())
        if self.policy is not None:
            self.window = int(self.policy.get("window_s"))
        for source in self.sources:
            try:
                hist, gauges = parse(self.fetch(source), re.sub(r"^\w+://", "", source).split("/")[0])
                kept = [s for s in self.samples.get(source, []) if s[0] >= now - self.window] + [(now, hist, gauges)]
                self.samples[source], self.up[source] = kept, True
                self._record(source, now, hist)
            except Exception:
                self.up[source] = False
        probes = self._probe()
        if probes:
            hist = {k: {**v, "buckets": dict(v["buckets"])} for k, v in probes.items()}
            kept = [s for s in self.samples.get("probes", []) if s[0] >= now - self.window]
            self.samples["probes"] = kept + [(now, hist, {})]
            self._record("probes", now, hist)
        if self.release_source:
            try:
                per = parse_releases(self.fetch(self.release_source))
                self.releases = [s for s in self.releases if s[0] >= now - 4 * 3600] + [(now, per)]
            except Exception:
                pass

    def _record(self, source: str, now: int, hist: dict) -> None:
        """Per-minute good and bad events of every component, for the SLOs (trusted/slo.py)."""
        previous, self.last[source] = self.last.get(source), hist
        if self.store is None or previous is None:
            return
        for (kind, op, name), e in hist.items():
            p = previous.get((kind, op, name))
            if p is None:
                continue
            (_, total, bad, buckets), = deltas([(0, p["count"], p["errors"], p["buckets"]),
                                                (now, e["count"], e["errors"], e["buckets"])])
            self.store.add(now // 60, self.limits(kind, op, name).get("id") or f"{kind}|{op}|{name}", kind,
                           total, bad, buckets)

    def release_stats(self, release: str, since: int) -> dict | None:
        """Requests, error rate and p99 the runner saw for one release since a moment (canary analysis)."""
        window = [(at, per.get(release)) for at, per in self.releases if at >= since and per.get(release)]
        if len(window) < 2:
            return None
        (_, a), (_, b) = window[0], window[-1]
        rows = deltas([(0, a["count"], a["errors"], a["buckets"]), (1, b["count"], b["errors"], b["buckets"])])
        s = stats(rows, 1, 0.999)
        return {"requests": s["requests"], "error_rate": s["error_rate"], "p99": s["p99"]}

    def served(self) -> dict:
        """The release that answers (build_info version) and when its process started, from the latest scrape."""
        for source in self.sources:
            if self.up.get(source) and self.samples.get(source):
                gauges = self.samples[source][-1][2]
                version = next((n for (k, n, f) in gauges if k == "release"), None)
                started = next((v for (k, _, f), v in gauges.items() if k == "process" and f == "started"), None)
                return {"version": version, "started": started}
        return {"version": None, "started": None}

    def assess(self, now: float | None = None) -> dict:
        """{"coverage": status, "slo": status, "components": [...]} over the window, from the samples only."""
        now = int(now if now is not None else time.time())
        if not self.sources:
            return {"coverage": "uncovered:empty", "slo": "uncovered:no-source", "components": []}
        silent = [s for s in self.sources if not self.up.get(s) or len(self.samples.get(s, [])) < 2]
        late = int(self.policy.get("late_periods")) if self.policy else LATE_PERIODS
        components = []
        for source, samples in self.samples.items():
            series = {}
            for at, hist, _ in samples:
                for key, e in hist.items():
                    series.setdefault(key, []).append((at, e["count"], e["errors"], e["buckets"]))
            span = samples[-1][0] - samples[0][0] if len(samples) > 1 else 0
            for (kind, op, name), rows in series.items():
                limits = self.limits(kind, op, name)
                s = stats(deltas(rows), span, limits["objective"])
                state, why = judge(s, limits)
                components.append({"kind": kind, "operation": op, "name": name, "state": state, "why": why,
                                   "id": limits.get("id"), "counted": limits["counted"],
                                   "availability": s["availability"], "p99": s["p99"], "requests": s["requests"]})
            gauges = samples[-1][2] if samples else {}
            for job in sorted({n for (k, n, _) in gauges if k == "job"}):
                get = lambda f: gauges.get(("job", job, f))
                state, why = judge_job(get("last_success"), get("period"), get("ok"), now, late)
                limits = self.limits("job", "", job)
                components.append({"kind": "job", "operation": "", "name": job, "state": state, "why": why,
                                   "id": limits.get("id"), "counted": limits["counted"]})
        slos = {}
        if self.store is not None and self.policy is not None:
            counted = lambda cid, kind: (self.policy.get("counted", cid) == "on" if self.policy.get("counted", cid)
                                         else kind != "dependency")
            slos = evaluate(self.store, self.policy.slos(), now // 60, counted=counted,
                            burn_fast=self.policy.get("burn_fast"), burn_slow=self.policy.get("burn_slow"))
        # Broken: a counted component failing outright, or an SLO burning its budget fast. Degraded or a slow burn is
        # an alert for people, not a breach.
        bad = [c for c in components if c["state"] == "failing" and c["counted"]] + [s for s in slos.values() if s["fast"]]
        if silent:
            return {"coverage": f"uncovered:{len(silent)}", "slo": f"uncovered:{len(silent)}", "components": components,
                    "silent": silent, "slos": slos}
        return {"coverage": "complete", "slo": f"breached:{len(bad)}" if bad else "met", "components": components,
                "silent": [], "slos": slos}


MIGRATION = re.compile(r"migrations/(\d+)[^/]*\.sql")


def migrations(repo, commit: str) -> dict:
    """{number: path} of the forward migrations a release carries (migrations/NNNN_name[.compatible].sql)."""
    if commit in (None, "none"):
        return {}
    out = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", commit, "migrations"],
                         capture_output=True, text=True, timeout=60).stdout.split()
    return {int(m[1]): path for path in out if (m := MIGRATION.fullmatch(path)) and not path.endswith(".down.sql")}


def compatible(repo, live: str, prev: str, allow: bool) -> tuple[bool, str | None]:
    """Whether `prev`'s code can run on the schema `live` left: no migration since, or only migrations declared
    backward compatible (`.compatible.sql`, expand-only) when the engineers allow stepping back across them."""
    added = sorted(set(migrations(repo, live).items()) - set(migrations(repo, prev).items()))
    if not added:
        return True, None
    unsafe = [path for _, path in added if not path.endswith(".compatible.sql")]
    if unsafe:
        return False, f"migration not declared compatible: {', '.join(unsafe)}"
    if not allow:
        return False, "stepping back across a compatible migration is turned off"
    return True, None


def _canary(live: str, release: str, history: list, now_ms: int, get, canary_stats) -> tuple[list, str]:
    """Compare the canary with the live release on the same traffic, since it started."""
    started = next((h["at"] for h in reversed(history) if h.get("op") == "canary" and h.get("to") == release), now_ms)
    c, s = canary_stats(release, started // 1000), canary_stats(live, started // 1000)
    baked = (now_ms - started) // 60_000
    need = get("canary_min_requests")
    if c is None or c["requests"] < min(need, 20):
        return [], f"canary on {get('canary_percent')} % of traffic: {0 if c is None else c['requests']} requests so far"
    delta = (c["error_rate"] or 0) - ((s or {}).get("error_rate") or 0)
    if delta * 100 > get("canary_max_error_delta"):
        return [(f"run:canary:abort/{live}/{release}", "canary_bad", "yes")], \
            f"canary fails {delta * 100:.2f} points more than the live release (limit {get('canary_max_error_delta')})"
    limit = max(((s or {}).get("p99") or 0) * 1.5, get("p99_ms"))
    if c["p99"] is not None and c["p99"] > limit:
        return [(f"run:canary:abort/{live}/{release}", "canary_bad", "yes")], \
            f"canary p99 {c['p99']:.0f} ms over {limit:.0f} ms"
    if baked < get("canary_bake_min") or c["requests"] < need:
        return [], f"canary baking: {baked}/{get('canary_bake_min')} min, {c['requests']}/{need} requests, no worse so far"
    return [(f"run:release:all/{live}/{release}", "promotable", "yes")], \
        f"canary held {baked} min on {c['requests']} requests, {delta * 100:+.2f} points of errors: promoted"


START_GRACE_MS = 90_000      # a release that does not answer this long after its switch never started


def release_facts(slo: str, live: str | None, main: str, history: list, good: set, now_ms: int, *,
                  served: str | None = None, policy=None, compat=lambda live, prev: (True, None),
                  canary: str | None = None, canary_stats=lambda release, since: None,
                  budget: float | None = None) -> tuple[list, dict]:
    """The facts that open `deploy`, `rollback` and `restart`, as (resource, property, status), with their reasons.

    run:release:all lag                   none when production serves main's head, else behind (repaired by deploy)
    run:release:all/{live}/{main}         candidate = yes   main moved and its head was never rolled back
                                          deployable = yes  the same, and the engineers let Standard deploy alone
    run:service:all/{live}/{prev}         previous = yes    prev is the release `live` replaced, its code fits the schema
                                          regressed = yes   the same, the objective broke within the horizon after the
                                                            switch and prev met it, or `live` never started; and the
                                                            engineers let Standard step back alone
    run:process:all/{live}/{n}            restartable = yes the objective is broken, not by the switch, and the
                                                            engineers let Standard restart, within the hourly budget
    run:canary:all/{live}/{main}          canary_ready = yes  the release policy is a canary: start it on a share of
                                                              traffic first
    run:release:all/{live}/{canary}       promotable = yes    the canary baked, saw enough requests, and failed no more
                                                              than the live release (error rate, p99)
    run:canary:abort/{live}/{canary}      canary_bad = yes    it failed more, or main moved on: take it out
    Automatic deployment waits for the deployment window, an unfrozen policy and enough error budget left.
    A release rolled back or aborted is never a candidate again: the gap stays open and goes to people at its due time."""
    from .policy import DEFAULTS
    get = (lambda k: policy.get(k)) if policy is not None else DEFAULTS.get
    live_name = live or "none"
    rolled_back = {h["from"] for h in history if h.get("op") == "rollback"} | {
        h["to"] for h in history if h.get("op") == "abort"}
    answering = served or live
    facts = [("run:release:all", "lag", "none" if answering == main and live == main else "behind")]
    why = {"live": live, "served": served, "main": main, "rolled_back": sorted(rolled_back)}
    if live != main:
        if main in rolled_back:
            why["deploy"] = "main's head was rolled back: a new commit on main is needed"
        else:
            facts.append((f"run:release:all/{live_name}/{main}", "candidate", "yes"))
            open_, closed_why = policy.deploy_open(now_ms) if policy is not None else (True, None)
            if get("auto_deploy") != "on":
                why["deploy"] = "automatic deployment is off: an engineer approves"
            elif canary is None and not open_:
                why["deploy"] = closed_why
            elif canary is None and budget is not None and get("freeze_below") > 0 and budget * 100 < get("freeze_below"):
                why["deploy"] = f"error budget left {budget * 100:.1f} % is under {get('freeze_below')} %: frozen"
            elif get("strategy") != "canary" or live is None:  # a first release has nothing to be compared with
                facts.append((f"run:release:all/{live_name}/{main}", "deployable", "yes"))
            elif canary is None:
                facts.append((f"run:canary:all/{live_name}/{main}", "canary_ready", "yes"))
            elif canary == main:
                facts_c, why["canary"] = _canary(live_name, main, history, now_ms, get, canary_stats)
                facts += facts_c
    if canary is not None and canary != main:
        facts.append((f"run:canary:abort/{live_name}/{canary}", "canary_bad", "yes"))
        why["canary"] = "main moved on: the canary is taken out"
    switch = next((h for h in reversed(history) if h.get("to") == live and h.get("op") != "restart"), None)
    prev = switch["from"] if switch else "none"
    if live and prev != "none" and prev not in rolled_back:   # never back to a release that was itself stepped back from
        fits, reason = compat(live, prev)
        if not fits:
            why["rollback"] = reason
        else:
            facts.append((f"run:service:all/{live}/{prev}", "previous", "yes"))
            age = now_ms - switch["at"]
            not_started = served is not None and served != live and age > START_GRACE_MS
            breached = slo.startswith("breached")
            if not (breached or not_started):
                pass
            elif get("auto_rollback") != "on":
                why["rollback"] = "automatic rollback is off: an engineer decides"
            elif not_started:
                facts.append((f"run:service:all/{live}/{prev}", "regressed", "yes"))
                why["rollback"] = f"{live[:7]} never answered: {served[:7]} still serves"
            elif prev not in good:
                why["rollback"] = "no earlier release is known to have met the objective"
            elif age > get("rollback_horizon_min") * 60_000:
                why["rollback"] = f"live for {age // 60_000} min before the breach: not attributable to the switch"
            else:
                facts.append((f"run:service:all/{live}/{prev}", "regressed", "yes"))
    if live and slo.startswith("breached") and not any(p == "regressed" for _, p, _ in facts):
        restarts = [h for h in history if h.get("op") == "restart" and h.get("to") == live]
        recent = [h for h in restarts if now_ms - h["at"] < 3_600_000]
        if switch and now_ms - switch["at"] <= get("rollback_horizon_min") * 60_000:
            why["restart"] = "the breach follows a switch: restarting the same code would not repair it"
        elif get("auto_restart") != "on":
            why["restart"] = "automatic restart is off"
        elif len(recent) >= get("restarts_per_hour"):
            why["restart"] = f"{len(recent)} restarts in the last hour: the budget is spent, people decide"
        else:
            facts.append((f"run:process:all/{live}/{len(restarts) + 1}", "restartable", "yes"))
    return facts, why


class Pass:
    """The operator's production pass: read the settings, scrape, judge, sign. Facts under the scanner's capability;
    reasons, settings and probe answers to the findings."""

    def __init__(self, service, instrument, production: Production, repo, *, releases=None, state=None,
                 policy=None, authors=lambda: set()):
        self.service, self.instrument, self.production, self.repo = service, instrument, production, repo
        self.releases, self.state, self.live, self.offered = releases, state, None, set()
        self.policy, self.authors = policy, authors
        self.good = set(json.loads(state.read_text())) if state is not None and state.exists() else set()

    def _main(self) -> str:
        return subprocess.run(["git", "-C", str(self.repo), "rev-parse", "refs/heads/main"], capture_output=True,
                              text=True, timeout=60, check=True).stdout.strip()

    def measure(self) -> dict:
        now = self.instrument.clock()
        if self.policy is not None:
            self.policy.update(self.service.journal.snapshot()["observations"], self.authors(), now)
        domain = self.service.view()["prefix"]["genesis"]
        link = self.releases.current() if self.releases else None
        served = self.production.served()
        answering = (served["version"] or link, served["started"])
        if answering != self.live:                          # a switch or a restart: judge it on its own traffic only
            self.production.samples, self.live = {}, answering
            self.production.scrape(now / 1000)
            served = self.production.served()
            self.live = (served["version"] or link, served["started"])
        else:
            self.production.scrape(now / 1000)
        a = self.production.assess(now / 1000)
        warming = all(self.production.up.get(s) for s in self.production.sources) and a["coverage"] != "complete"
        facts = [] if warming and self.production.sources else [
            ("run:sources:all", "coverage", a["coverage"]), ("run:service:all", "slo", a["slo"])]
        findings = {"run:sources:all|coverage": {"status": a["coverage"], "details": a.get("silent", [])},
                    "run:service:all|slo": {"status": a["slo"], "details": [
                        f"{c['kind']} {c['operation']} {c['name']}: {c['state']} ({json.dumps(c['why'])})".replace("  ", " ")
                        for c in a["components"] if c["state"] in ("degraded", "failing") and c["counted"]]},
                    "run:components": {"status": a["slo"], "details": a["components"]},
                    "run:probes": {"status": str(len(self.production.probed)), "details": [
                        {"id": pid, "last": e["last"], "count": e["count"], "errors": e["errors"]}
                        for pid, e in self.production.probed.items()]}}
        findings["run:slos"] = {"status": a["slo"], "details": a.get("slos", {})}
        if self.policy is not None:
            findings["run:policy"] = {"status": "published", "details": {
                **self.policy.published(), "silences": self.policy.silences(now)}}
        if self.releases is None:
            facts.append(("run:release:all", "lag", "uncovered:not-configured"))
        else:
            if a["slo"] == "met" and link and link not in self.good and served["version"] in (None, link):
                self.good.add(link)
                if self.state is not None:
                    self.state.write_text(json.dumps(sorted(self.good)))
            allow = self.policy is None or self.policy.get("compatible_migrations") == "on"
            budgets = [s["budget"] for s in a.get("slos", {}).values() if s["budget"] is not None]
            released, why = release_facts(
                a["slo"], link, self._main(), self.releases.history(), self.good, now, served=served["version"],
                policy=self.policy, compat=lambda live, prev: compatible(self.repo, live, prev, allow),
                canary=self.releases.canary(), canary_stats=self.production.release_stats,
                budget=min(budgets) if budgets else None)
            facts += released
            findings["run:release:all|lag"] = {"status": released[0][2], "details": [
                f"{k}: {', '.join(v) if isinstance(v, list) else v}" for k, v in why.items() if v is not None]}
        offered = {(r, p) for r, p, s in facts if "/" in r and s == "yes"}
        facts += [(r, p, "no") for r, p in self.offered - offered]   # withdrawn: production moved, or recovered
        self.offered = offered
        self.instrument.findings.update(findings)
        for resource, prop, status in facts:
            self.service.admit(self.instrument.observation(domain, resource, prop, status))
        return {"admitted": len(facts), "slo": a["slo"], "live": link, "served": served["version"]}
