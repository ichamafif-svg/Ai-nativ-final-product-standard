"""Production measures (D30-D32, D36): metrics, probes and the release registers -> numbers and what is.

Inputs, all recorded by the host: the scrapes of every declared source (Prometheus text, OpenTelemetry conventions)
at decreasing resolution (every scrape for minutes, one a minute for hours, one an hour for months), the answers of
the probes, the release registers and their history, the rules file on main, and the scanner's own earlier facts on
run:*. From them, the same reading the console shows: components (APIs, workers, databases, external services,
scheduled jobs, processes, probes), SLOs with error budgets and burn rates (Google SRE workbook), the served version.

It signs `run:sources:all coverage` (complete only when every source answered: never "fine" by default),
`run:service:all slo` (`met`, or `breached:N`: counted components failing 5 % or more, SLOs burning at 14.4 or more),
`run:release:all lag`, and on exact switches what is (`candidate`, `previous`, `proven`, `live`, `running`, `good`)
with numbers the law compares (D36). It asks the host to send the declared probes on the next pass (`fetch`).
A counter that goes down is a restart and counts from zero; between two sparse points a restart loses the requests
it hides (declared limit of the budget over long windows).
"""
from __future__ import annotations

import hashlib
import math
import re

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


def _n(x) -> str:
    """A number the law can compare: a bounded decimal string, never a float."""
    return f"{max(-1e11, min(1e11, x or 0)):.3f}"




SPANS = {"5m": 5, "30m": 30, "1h": 60, "6h": 360}
MIN_EVENTS = 20


def matches(selector: str, cid: str, kind: str, counted) -> bool:
    if selector == "all":
        return True
    if selector == "counted":
        return counted(cid, kind)
    if selector.startswith("kind:"):
        return kind == selector[5:]
    return cid in selector.split(",")


def good_under(buckets: dict, threshold_ms: float) -> float:
    """Requests answered under the threshold: the largest bucket bound not above it (never rounded up)."""
    bounds = sorted((float(le), n) for le, n in buckets.items() if le != "+Inf")
    return max((n for bound, n in bounds if bound * 1000 <= threshold_ms), default=0.0)


def evaluate(rows: list, slos: dict, now_minute: int, *, counted) -> dict:
    """{slo id: {"name", "sli", "target", "window_d", "compliance", "budget", "events", "burn": {span: rate},
    "fast_burn", "slow_burn"}} at this minute."""
    out = {}
    for sid, s in slos.items():
        allowed = 1 - s["target"] / 100
        picked = [r for r in rows if matches(s["selector"], r[1], r[2], counted)]

        def share(minutes: int) -> tuple[float, float]:
            total = bad = 0.0
            for minute, _, _, t, b, buckets in picked:
                if minute > now_minute - minutes:
                    total += t
                    bad += b if s["sli"] == "availability" else t - good_under(buckets, s["threshold_ms"])
            return total, bad

        total, bad = share(s["window_d"] * 1440)
        burn = {}
        for span, minutes in SPANS.items():
            t, b = share(minutes)
            burn[span] = None if t < MIN_EVENTS else round((b / t) / allowed, 2)
        both = lambda a, b: None if burn[a] is None or burn[b] is None else min(burn[a], burn[b])
        out[sid] = {**{k: s.get(k) for k in ("name", "sli", "target", "window_d", "selector", "threshold_ms")},
                    "events": int(total), "compliance": None if not total else 1 - bad / total,
                    "budget": None if not total else 1 - (bad / total) / allowed, "burn": burn,
                    "fast_burn": both("1h", "5m"), "slow_burn": both("6h", "30m")}
    return out


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
                      (r, "canary_p99_ms", _n(c.get("p99"))), (r, "live_p99_ms", _n(s.get("p99"))),
                      (r, "canary_error_pct", _n((c.get("error_rate") or 0) * 100)),
                      (r, "live_error_pct", _n((s.get("error_rate") or 0) * 100)),
                      (r, "live_requests", str(int(s.get("requests", 0))))]
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




PREMISES = ("candidate", "previous", "proven", "live", "running", "good")
START_GRACE_S = 90


def _rows(points: list) -> list:
    """Per-minute (minute, cid, kind, total, bad, buckets) from consecutive scrapes of one source."""
    out = []
    for (_, h0), (at, h1) in zip(points, points[1:]):
        for (kind, op, name), e in h1.items():
            p = h0.get((kind, op, name))
            if p is not None:
                (_, total, bad, buckets), = deltas([(0, p["count"], p["errors"], p["buckets"]),
                                                    (at, e["count"], e["errors"], e["buckets"])])
                if total > 0:
                    out.append((at // 60, component_id(kind, op, name), kind, total, bad, buckets))
    return out


def _probe_hist(answers: list) -> dict:
    """Cumulative histograms of kind `probe` from the probes' answers [(at, [[id, method, path, expected, status,
    seconds]])], one point per pass."""
    acc, points = {}, []
    for at, results in answers:
        for pid, method, path, expected, status, seconds in results:
            e = acc.setdefault(("probe", method, path), {"count": 0.0, "errors": 0.0,
                                                         "buckets": dict.fromkeys(BUCKETS, 0.0), "last": None, "id": pid})
            e["count"], e["errors"], e["last"] = e["count"] + 1, e["errors"] + (status != expected), status
            for le in BUCKETS:
                e["buckets"][le] += le == "+Inf" or seconds <= float(le)
        points.append((at, {k: {**v, "buckets": dict(v["buckets"])} for k, v in acc.items()}))
    return points


def assess(sources: dict, answers: list, m: dict, now: int, since: int) -> dict:
    """Coverage, the slo summary and the numbers. sources: {name: [(at, text or None)]}; `since` is the last switch
    or restart: the window judges the live process on its own traffic."""
    counted = lambda cid, kind: m["counted"].get(cid, kind not in OUTSIDE)
    parsed, silent, components, rows = {}, [], [], []
    for name, points in sources.items():
        good = [(at, parse(text, re.sub(r"^\w+://", "", name).split("/")[0])) for at, text in points if text is not None]
        parsed[name] = good
        recent = [p for p in good if p[0] >= max(now - m["window_s"], since)]
        if not points or points[-1][1] is None or len(recent) < 2:
            silent.append(name)
        rows += _rows([(at, h) for at, (h, _) in good])
    probes = _probe_hist(answers)
    rows += _rows(probes)
    windows = [[(at, h) for at, (h, _) in good if at >= max(now - m["window_s"], since)] for good in parsed.values()]
    windows.append([p for p in probes if p[0] >= max(now - m["window_s"], since)])
    for points in windows:
        series = {}
        for at, hist in points:
            for key, e in hist.items():
                series.setdefault(key, []).append((at, e["count"], e["errors"], e["buckets"]))
        for (kind, op, name), pts in series.items():
            s, cid = stats(deltas(pts), 1, 0.999), component_id(kind, op, name)
            components.append({"id": cid, "kind": kind, "operation": op, "name": name, "requests": s["requests"],
                               "error_rate": s["error_rate"], "p99": s["p99"], "counted": counted(cid, kind)})
    for good in parsed.values():
        gauges = good[-1][1][1] if good else {}
        for job in sorted({n for (k, n, _) in gauges if k == "job"}):
            cid = component_id("job", "", job)
            components.append({"id": cid, "kind": "job", "operation": "", "name": job, "requests": 1,
                               "error_rate": 1.0 if gauges.get(("job", job, "ok")) == 0 else 0.0, "p99": None,
                               "counted": counted(cid, "job")})
    slos = evaluate(rows, m["slos"], now // 60, counted=counted)
    rates = [c["error_rate"] for c in components if c["counted"] and c["error_rate"] is not None]
    bad = sum(r >= FAILING for r in rates) + sum((s["fast_burn"] or 0) >= FAST for s in slos.values())
    budgets = [s["budget"] for s in slos.values() if s["budget"] is not None]
    served = next(({"version": next((n for (k, n, f) in g[-1][1][1] if k == "release"), None),
                    "started": next((v for (k, _, f), v in g[-1][1][1].items() if k == "process" and f == "started"),
                                    None)} for g in parsed.values() if g), {"version": None, "started": None})
    if not sources:                                     # nothing declared is never "fine"
        silent = ["no-source"]
    return {"coverage": f"uncovered:{len(silent)}" if silent else "complete",
            "slo": f"uncovered:{len(silent)}" if silent else f"breached:{bad}" if bad else "met",
            "components": components, "silent": silent, "slos": slos, "served": served,
            "failing_pct": max(rates, default=0) * 100,
            "burn_fast": max((s["fast_burn"] or 0 for s in slos.values()), default=0),
            "budget_pct": min(budgets) * 100 if budgets else None}


def release_stats(points: list, release: str, since: int) -> dict | None:
    """Requests, error rate and p99 the runner saw for one release since a moment (canary analysis)."""
    window = [(at, per.get(release)) for at, per in points if at >= since and per.get(release)]
    if len(window) < 2:
        return None
    (_, a), (_, b) = window[0], window[-1]
    s = stats(deltas([(0, a["count"], a["errors"], a["buckets"]), (1, b["count"], b["errors"], b["buckets"])]), 1, 0.999)
    return {"requests": s["requests"], "error_rate": s["error_rate"], "p99": s["p99"]}


def crossed(live: dict | None, prev: dict | None) -> int | None:
    """How many migrations stepping back from `live` to `prev` crosses, all declared backward compatible
    (`.compatible.sql`, expand-only); None when one is not. live, prev: {path: entry} manifests."""
    found = lambda e: {int(x[1]): p for p in (e or {}) if (x := MIGRATION.fullmatch(p)) and not p.endswith(".down.sql")}
    added = sorted(set(found(live).items()) - set(found(prev).items()))
    return None if any(not path.endswith(".compatible.sql") for _, path in added) else len(added)


MIGRATION = re.compile(r"migrations/(\d+)[^/]*\.sql")


def measure(inp: dict) -> dict:
    """The production job: inputs as the host materialised them; facts and what the console shows."""
    m, now_ms, regs = measures(inp.get("rules") or {}), inp["now"], inp["registers"]
    now, history, live, canary = now_ms // 1000, regs["history"], regs.get("current"), regs.get("canary")
    since = max([h["at"] // 1000 for h in history if h.get("to") == live] or [0])
    sources = {n: s["points"] for n, s in inp["series"].items() if s["role"] == "metrics"}
    runner = [(at, parse_releases(text)) for n, s in inp["series"].items() if s["role"] == "runner"
              for at, text in s["points"] if text is not None]
    answers = [(at, results) for n, s in inp["series"].items() if s["role"] == "probes"
               for at, results in s["points"] if results is not None]
    a = assess(sources, answers, m, now, since)
    warming = sources and a["coverage"] != "complete" and all(p and p[-1][1] is not None for p in sources.values())
    facts = [] if warming else [("run:sources:all", "coverage", a["coverage"]), ("run:service:all", "slo", a["slo"])]
    earlier = {(f["resource"], f["property"]): f["status"] for f in inp["facts"]}
    good = {r.split("/")[1] for (r, p), s in earlier.items() if p == "good" and s == "yes"}
    if not inp.get("deploy"):
        facts.append(("run:release:all", "lag", "uncovered:not-configured"))
    else:
        if a["slo"] == "met" and live and a["served"]["version"] in (None, live):
            facts.append((f"run:release:all/{live}", "good", "yes"))
            good.add(live)
        facts += release_facts(live, inp["main"], history, good, now_ms, a, served=a["served"]["version"],
                               crossed=lambda l, p: crossed(inp["manifests"].get(l), inp["manifests"].get(p)),
                               canary=canary, canary_stats=lambda rel, since: release_stats(runner, rel, since))
    offered = {(r, p) for r, p, s in facts if p in PREMISES}
    facts += [(r, p, "no") for (r, p), s in sorted(earlier.items()) if p in PREMISES and s == "yes"
              and (r, p) not in offered and p != "good"]
    base = m["base_url"].rstrip("/")
    return {"facts": [[r, p, s, []] for r, p, s in facts],
            "extra": {"served": a["served"], "canary_percent": m["canary_percent"], "components": a["components"], "slos": a["slos"], "silent": a["silent"],
                      "fetch": [[pid, method, base + path, expected, path] for pid, method, path, expected in m["probes"]]
                      if base else [], "probes": answers[-1][1] if answers else []}}
