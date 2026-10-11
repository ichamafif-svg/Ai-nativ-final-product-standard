"""T06 — the production instrument: what the scanner measures and signs about production (D30-D32, D36).

The same reading of metrics the console shows, on the trusted side, so that it can become signed facts. From Prometheus
text metrics in the OpenTelemetry conventions it recognises the product's components (APIs, workers, databases,
external services, scheduled jobs, processes), adds the external probes the engineers declared (a product that says
it is healthy while it does not answer is caught), and keeps per-minute good and bad events for the SLOs (slo.py).

D36: it judges nothing the engineers tune. It signs what is, on exact switches (this release is main's head, that one
was proven good, a canary runs), and numbers (fast burn, failing share, minutes since the switch, canary deltas).
The law compares the numbers with its bounds; the agent compares them with the engineers' settings, inside them.
From standard/rules.json on main it reads only what to measure: probes, SLOs, which components count, the window.

Two summary facts carry the floors' targets: `run:sources:all coverage` (complete only when every declared source
answered: never "fine" by default) and `run:service:all slo` (`met`, or `breached:N`: N counted components failing
5 % of their requests or more, or SLOs burning at 14.4 or more). Counters are cumulative; one that goes down is a
restart and counts from zero.
"""
from __future__ import annotations

import hashlib
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
FAILING, FAST = 0.05, 14.4      # what breaks run:service:all slo (the target; rights are the law's bounds)


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


RULES = "standard/rules.json"      # D35: the engineers' rules, in the product's repository
PROBE = re.compile(r"(GET|HEAD|POST) (/[A-Za-z0-9._~/?=&%-]{0,200}) ([1-5][0-9][0-9])")
SELECTOR = re.compile(r"counted|all|kind:(api|worker|job|database|dependency|probe)|c-[0-9a-f]{12}(,c-[0-9a-f]{12}){0,31}")


def component_id(kind: str, operation: str, name: str) -> str:
    return "c-" + hashlib.sha256(f"{kind}|{operation or ''}|{name}".encode()).hexdigest()[:12]


def _in(value, low, high, default):
    try:
        x = float(value)
    except (TypeError, ValueError):
        return default
    return x if low <= x <= high else default


def measures(doc) -> dict:
    """What to measure, from the rules file: a malformed entry is skipped, never half-read."""
    part = lambda d, k: v if isinstance(v := (d if isinstance(d, dict) else {}).get(k), dict) else {}
    g = part(doc, "global")
    objective, base = _in(g.get("objective"), 50, 99.999, 99.9), str(g.get("base_url", ""))
    slos = {"s-default": {"name": "Disponibilité du service", "sli": "availability", "target": objective,
                          "window_d": 30, "selector": "counted", "threshold_ms": None, "state": "on"}}
    for sid, k in part(doc, "slos").items():
        if re.fullmatch(r"s-[a-z0-9]{1,16}", sid) and isinstance(k, dict):
            b = slos.get(sid, {**slos["s-default"], "name": sid, "threshold_ms": _in(g.get("p99_ms"), 1, 60_000, 1000.0)})
            slos[sid] = {"name": str(k.get("name", b["name"]))[:120],
                         "sli": k["sli"] if k.get("sli") in ("availability", "latency") else b["sli"],
                         "target": _in(k.get("target"), 50, 99.999, b["target"]),
                         "window_d": int(_in(k.get("window_d"), 1, 90, b["window_d"])),
                         "threshold_ms": _in(k.get("threshold_ms"), 1, 60_000, b["threshold_ms"]),
                         "selector": k["selector"] if SELECTOR.fullmatch(str(k.get("selector"))) else b["selector"],
                         "state": "off" if k.get("state") == "off" else "on"}
    return {"objective": objective, "window_s": int(_in(g.get("window_s"), 60, 3600, 300)),
            "canary_percent": int(_in(g.get("canary_percent"), 1, 50, 10)),
            "base_url": base if re.fullmatch(r"https?://[A-Za-z0-9.:-]{1,200}", base) else "",
            "counted": {c: k["counted"] == "on" for c, k in part(doc, "components").items()
                        if re.fullmatch(r"c-[0-9a-f]{12}", c) and isinstance(k, dict) and k.get("counted") in ("on", "off")},
            "probes": [(p, m[1], m[2], int(m[3])) for p, k in sorted(part(doc, "probes").items())
                       if isinstance(k, dict) and (m := PROBE.fullmatch(str(k.get("spec", ""))))],
            "slos": {k: v for k, v in slos.items() if v["state"] == "on" and (v["sli"] != "latency" or v["threshold_ms"])}}


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


def _n(x) -> str:
    """A number the law can compare: a bounded decimal string, never a float."""
    return f"{max(-1e11, min(1e11, x or 0)):.3f}"


class Production:
    """The operator's reading of production: the last scrapes of every declared source and the probes' answers."""

    def __init__(self, sources, *, fetch=None, request=None, store=None, release_source=None):
        self.sources, self.store, self.release_source = list(sources), store, release_source
        self.measures, self.last, self.releases = measures({}), {}, []
        self.fetch = fetch or (lambda url: urllib.request.urlopen(url, timeout=5).read().decode())
        self.request = request or _request
        self.samples = {}                                  # source -> [(at, hist, gauges)]
        self.up, self.probed = {}, {}                      # probe id -> cumulative {"count", "errors", "buckets"}

    def counted(self, cid: str, kind: str) -> bool:
        return self.measures["counted"].get(cid, kind not in OUTSIDE)

    def _probe(self) -> dict:
        """One request per probe, accumulated as a histogram of kind `probe`: the product's answer seen from outside."""
        out, base = {}, self.measures["base_url"].rstrip("/")
        for pid, method, path, expected in self.measures["probes"] if base else []:
            status, seconds = self.request(method, base + path)
            e = self.probed.setdefault(pid, {"count": 0.0, "errors": 0.0, "buckets": dict.fromkeys(BUCKETS, 0.0),
                                             "last": None})
            e["count"], e["errors"], e["last"] = e["count"] + 1, e["errors"] + (status != expected), status
            for le in BUCKETS:
                e["buckets"][le] += le == "+Inf" or seconds <= float(le)
            out[("probe", method, path)] = e
        return out

    def scrape(self, now: float | None = None) -> None:
        now, window = int(now if now is not None else time.time()), self.measures["window_s"]
        for source in self.sources:
            try:
                hist, gauges = parse(self.fetch(source), re.sub(r"^\w+://", "", source).split("/")[0])
                kept = [s for s in self.samples.get(source, []) if s[0] >= now - window] + [(now, hist, gauges)]
                self.samples[source], self.up[source] = kept, True
                self._record(source, now, hist)
            except Exception:
                self.up[source] = False
        probes = self._probe()
        if probes:
            hist = {k: {**v, "buckets": dict(v["buckets"])} for k, v in probes.items()}
            self.samples["probes"] = [s for s in self.samples.get("probes", []) if s[0] >= now - window] + [(now, hist, {})]
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
        for (kind, op, name), e in hist.items() if self.store is not None and previous is not None else ():
            p = previous.get((kind, op, name))
            if p is not None:
                (_, total, bad, buckets), = deltas([(0, p["count"], p["errors"], p["buckets"]),
                                                    (now, e["count"], e["errors"], e["buckets"])])
                self.store.add(now // 60, component_id(kind, op, name), kind, total, bad, buckets)

    def release_stats(self, release: str, since: int) -> dict | None:
        """Requests, error rate and p99 the runner saw for one release since a moment (canary analysis)."""
        window = [(at, per.get(release)) for at, per in self.releases if at >= since and per.get(release)]
        if len(window) < 2:
            return None
        (_, a), (_, b) = window[0], window[-1]
        s = stats(deltas([(0, a["count"], a["errors"], a["buckets"]), (1, b["count"], b["errors"], b["buckets"])]), 1, 0.999)
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
        """Coverage, the slo summary and the numbers, over the window, from the samples only."""
        now = int(now if now is not None else time.time())
        if not self.sources:
            return {"coverage": "uncovered:empty", "slo": "uncovered:no-source", "components": [], "slos": {},
                    "silent": [], "failing_pct": 0, "burn_fast": 0, "budget_pct": None}
        silent = [s for s in self.sources if not self.up.get(s) or len(self.samples.get(s, [])) < 2]
        components = []
        for samples in self.samples.values():
            series = {}
            for at, hist, _ in samples:
                for key, e in hist.items():
                    series.setdefault(key, []).append((at, e["count"], e["errors"], e["buckets"]))
            span = samples[-1][0] - samples[0][0] if len(samples) > 1 else 0
            for (kind, op, name), rows in series.items():
                s, cid = stats(deltas(rows), span, 0.999), component_id(kind, op, name)
                components.append({"id": cid, "kind": kind, "operation": op, "name": name, "requests": s["requests"],
                                   "error_rate": s["error_rate"], "p99": s["p99"], "counted": self.counted(cid, kind)})
            gauges = samples[-1][2] if samples else {}
            for job in sorted({n for (k, n, _) in gauges if k == "job"}):
                cid = component_id("job", "", job)
                components.append({"id": cid, "kind": "job", "operation": "", "name": job, "requests": 1,
                                   "error_rate": 1.0 if gauges.get(("job", job, "ok")) == 0 else 0.0, "p99": None,
                                   "counted": self.counted(cid, "job")})
        slos = evaluate(self.store, self.measures["slos"], now // 60, counted=self.counted) if self.store else {}
        counted = [c["error_rate"] for c in components if c["counted"] and c["error_rate"] is not None]
        bad = sum(r >= FAILING for r in counted) + sum((s["fast_burn"] or 0) >= FAST for s in slos.values())
        budgets = [s["budget"] for s in slos.values() if s["budget"] is not None]
        numbers = {"failing_pct": max(counted, default=0) * 100,
                   "burn_fast": max((s["fast_burn"] or 0 for s in slos.values()), default=0),
                   "budget_pct": min(budgets) * 100 if budgets else None}
        state = f"uncovered:{len(silent)}" if silent else f"breached:{bad}" if bad else "met"
        return {"coverage": f"uncovered:{len(silent)}" if silent else "complete", "slo": state,
                "components": components, "silent": silent, "slos": slos, **numbers}


MIGRATION = re.compile(r"migrations/(\d+)[^/]*\.sql")


def migrations(repo, commit: str) -> dict:
    """{number: path} of the forward migrations a release carries (migrations/NNNN_name[.compatible].sql)."""
    if commit in (None, "none"):
        return {}
    out = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", commit, "migrations"],
                         capture_output=True, text=True, timeout=60).stdout.split()
    return {int(m[1]): path for path in out if (m := MIGRATION.fullmatch(path)) and not path.endswith(".down.sql")}


def crossed(repo, live: str, prev: str) -> int | None:
    """How many migrations stepping back from `live` to `prev` crosses, all declared backward compatible
    (`.compatible.sql`, expand-only); None when one is not: prev's code cannot run on that schema."""
    added = sorted(set(migrations(repo, live).items()) - set(migrations(repo, prev).items()))
    return None if any(not path.endswith(".compatible.sql") for _, path in added) else len(added)


def release_facts(live: str | None, main: str, history: list, good: set, now_ms: int, numbers: dict, *,
                  served: str | None = None, crossed=lambda live, prev: 0, canary: str | None = None,
                  canary_stats=lambda release, since: None) -> list:
    """What is, on each exact switch, as (resource, property, status):

    run:release:all/{live}/{main}     candidate  main moved and its head was never stepped back from; budget_pct; and
                                                 when main runs as the canary, its numbers against the live release
    run:canary:all/{live}/{main}      candidate  the same, beside a live release and no canary yet
    run:canary:abort/{live}/{canary}  running    a canary runs
    run:service:all/{live}/{prev}     previous   prev is what live replaced, never stepped back from, and its code runs
                                                 on live's schema; proven when it met the objective (or still answers);
                                                 switched_min, unanswered_s, migrations_crossed, burn_fast, failing_pct
    run:process:all/{live}/{n}        live       the n-th restart of the live release; restarts_last_hour, the rest"""
    stepped = {h["from"] for h in history if h.get("op") == "rollback"} | {
        h["to"] for h in history if h.get("op") == "abort"}
    live_name, now = live or "none", [(k, _n(numbers.get(k))) for k in ("burn_fast", "failing_pct")]
    facts = [("run:release:all", "lag", "none" if (served or live) == main and live == main else "behind")]
    if live != main and main not in stepped:
        r = f"run:release:all/{live_name}/{main}"
        facts += [(r, "candidate", "yes"), (r, "budget_pct", _n(100 if numbers.get("budget_pct") is None else numbers["budget_pct"]))]
        if live and canary is None:
            facts.append((f"run:canary:all/{live}/{main}", "candidate", "yes"))
        if live and canary == main:
            started = next((h["at"] for h in reversed(history) if h.get("op") == "canary" and h.get("to") == main), now_ms)
            c, s = canary_stats(main, started // 1000) or {}, canary_stats(live, started // 1000) or {}
            facts += [(r, "canary_error_delta", _n(((c.get("error_rate") or 0) - (s.get("error_rate") or 0)) * 100)),
                      (r, "canary_requests", str(int(c.get("requests", 0)))),
                      (r, "canary_baked_min", str((now_ms - started) // 60_000)),
                      (r, "canary_p99_ms", _n(c.get("p99"))), (r, "live_p99_ms", _n(s.get("p99")))]
    if canary is not None:
        facts.append((f"run:canary:abort/{live_name}/{canary}", "running", "yes"))
    switch = next((h for h in reversed(history) if h.get("to") == live and h.get("op") != "restart"), None)
    age = now_ms - switch["at"] if switch else 10 ** 9
    prev = switch["from"] if switch else "none"
    if live and prev != "none" and prev not in stepped and (n := crossed(live, prev)) is not None:
        r = f"run:service:all/{live}/{prev}"
        unanswered = age // 1000 if served is not None and served != live else 0
        facts += [(r, "previous", "yes"), (r, "switched_min", str(age // 60_000)), (r, "unanswered_s", str(unanswered)),
                  (r, "migrations_crossed", str(n)), *((r, k, v) for k, v in now)]
        if prev in good or served == prev:
            facts.append((r, "proven", "yes"))
    if live:
        restarts = [h for h in history if h.get("op") == "restart" and h.get("to") == live]
        r = f"run:process:all/{live}/{len(restarts) + 1}"
        facts += [(r, "live", "yes"), (r, "switched_min", str(age // 60_000)), *((r, k, v) for k, v in now),
                  (r, "restarts_last_hour", str(sum(now_ms - h["at"] < 3_600_000 for h in restarts)))]
    return facts


PREMISES = ("candidate", "previous", "proven", "live", "running")


class Pass:
    """The operator's production pass: read what to measure, scrape, sign. Facts under the scanner's capability;
    components, SLOs and probe answers to the findings."""

    def __init__(self, service, instrument, production: Production, repo, *, releases=None, state=None):
        self.service, self.instrument, self.production, self.repo = service, instrument, production, repo
        self.releases, self.state, self.live, self.offered = releases, state, None, set()
        self.good = set(json.loads(state.read_text())) if state is not None and state.exists() else set()

    def _git(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True, timeout=60)

    def measure(self) -> dict:
        now, main = self.instrument.clock(), self._git("rev-parse", "refs/heads/main").stdout.strip()
        shown = self._git("show", f"{main}:{RULES}")
        try:
            doc = json.loads(shown.stdout) if shown.returncode == 0 else {}
        except ValueError:
            doc = {}
            self.instrument.findings["run:rules"] = {"status": "invalid", "details": [f"{RULES} is not JSON"]}
        self.production.measures = measures(doc)
        link = self.releases.current() if self.releases else None
        before = self.production.served()
        if (before["version"] or link, before["started"]) != self.live:     # a switch or a restart: its own traffic
            self.production.samples = {}
        self.production.scrape(now / 1000)
        served = self.production.served()
        self.live = (served["version"] or link, served["started"])
        a = self.production.assess(now / 1000)
        warming = all(self.production.up.get(s) for s in self.production.sources) and a["coverage"] != "complete"
        facts = [] if warming and self.production.sources else [
            ("run:sources:all", "coverage", a["coverage"]), ("run:service:all", "slo", a["slo"])]
        findings = {"run:sources:all|coverage": {"status": a["coverage"], "details": a["silent"]},
                    "run:service:all|slo": {"status": a["slo"], "details": [
                        f"{c['kind']} {c['operation']} {c['name']}: {c['error_rate'] * 100:.1f} % failed".replace("  ", " ")
                        for c in a["components"] if c["counted"] and (c["error_rate"] or 0) >= FAILING]},
                    "run:components": {"status": a["slo"], "details": a["components"]},
                    "run:slos": {"status": a["slo"], "details": a["slos"]},
                    "run:probes": {"status": str(len(self.production.probed)), "details": [
                        {"id": pid, "last": e["last"], "count": e["count"], "errors": e["errors"]}
                        for pid, e in self.production.probed.items()]}}
        if self.releases is None:
            facts.append(("run:release:all", "lag", "uncovered:not-configured"))
        else:
            if a["slo"] == "met" and link and link not in self.good and served["version"] in (None, link):
                self.good.add(link)
                if self.state is not None:
                    self.state.write_text(json.dumps(sorted(self.good)))
            history = self.releases.history()
            released = release_facts(link, main, history, self.good, now, a, served=served["version"],
                                     crossed=lambda live, prev: crossed(self.repo, live, prev),
                                     canary=self.releases.canary(), canary_stats=self.production.release_stats)
            facts += released
            findings["run:release:all|lag"] = {"status": released[0][2], "details": [
                f"live: {link}", f"served: {served['version']}", f"main: {main}"]}
        offered = {(r, p) for r, p, s in facts if p in PREMISES}
        facts += [(r, p, "no") for r, p in self.offered - offered]   # withdrawn: production moved
        self.offered = offered
        self.instrument.findings.update(findings)
        domain = self.service.view()["prefix"]["genesis"]
        for resource, prop, status in facts:
            self.service.admit(self.instrument.observation(domain, resource, prop, status))
        return {"admitted": len(facts), "slo": a["slo"], "live": link, "served": served["version"]}
