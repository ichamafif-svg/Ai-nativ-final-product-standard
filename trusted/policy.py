"""T06 — the engineers' settings for production (D31, D32): objectives, SLOs, alerting, release policy, probes.

A setting is a statement an engineer signs in the browser and the kernel admits: an observation on
`run:policy/<scope>/<key>` whose status is the value. The journal keeps who set what and when. Only the holders of the
`engineer` grant are read; anything else on these resources is ignored.

A setting that makes Standard stricter (a higher objective, a lower latency limit, less autonomy, a smaller canary, one
more probe or SLO) applies at once. A setting that loosens it applies only after the law's witnessed delay, like any
widening, and is shown as pending until then: one tired engineer cannot silently lower the bar. Some settings hold
nothing to a bar (a name, a silence) and apply at once.

    global   health rules       objective (%), failing (%), p99_ms, window_s, late_periods
             alerting           burn_fast, burn_slow (multiples of the budget rate; the classic 14.4 and 6)
             release policy     auto_deploy, auto_rollback, rollback_horizon_min, auto_restart, restarts_per_hour,
                                compatible_migrations, freeze, freeze_below (% of error budget left), deploy_days,
                                deploy_hours, deploy_tz, strategy (direct, canary), canary_percent, canary_bake_min,
                                canary_max_error_delta (points of %), canary_min_requests
             probes             base_url
    c-<12 hex>   one component (sha256 of "kind|operation|name"): objective, p99_ms, counted
    s-<id>       one SLO: name, sli (availability, latency), threshold_ms, target, window_d, selector, state
    p-<id>       one probe: spec ("GET /health 200" or "off")
    m-<id>       one silence: target (a component, an SLO or "all"), until (epoch ms), reason
"""
from __future__ import annotations

import hashlib
import json
import re
from zoneinfo import ZoneInfo

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DEFAULTS = {"objective": 99.9, "failing": 5.0, "p99_ms": 1000.0, "window_s": 300, "late_periods": 2,
            "burn_fast": 14.4, "burn_slow": 6.0,
            "auto_deploy": "on", "auto_rollback": "on", "rollback_horizon_min": 30, "auto_restart": "off",
            "restarts_per_hour": 2, "compatible_migrations": "on", "freeze": "off", "freeze_below": 0.0,
            "deploy_days": ",".join(DAYS), "deploy_hours": "00-24", "deploy_tz": "UTC",
            "strategy": "direct", "canary_percent": 10, "canary_bake_min": 10, "canary_max_error_delta": 0.5,
            "canary_min_requests": 100, "base_url": ""}
# key -> (type, bounds or choices, stricter way). Way: +1 higher is stricter, -1 lower is, a value names the stricter
# choice, "subset" fewer is stricter, "within" a narrower interval is, 0 any change waits, None any change applies.
SCHEMA = {
    "objective": ("num", (50.0, 99.999), 1), "failing": ("num", (0.1, 50.0), -1), "p99_ms": ("num", (1.0, 60_000.0), -1),
    "window_s": ("int", (60, 3600), 0), "late_periods": ("int", (1, 10), -1),
    "burn_fast": ("num", (1.0, 100.0), -1), "burn_slow": ("num", (1.0, 100.0), -1),
    "auto_deploy": ("toggle", None, "off"), "auto_rollback": ("toggle", None, "off"),
    "rollback_horizon_min": ("int", (1, 240), -1), "auto_restart": ("toggle", None, "off"),
    "restarts_per_hour": ("int", (0, 12), -1), "compatible_migrations": ("toggle", None, "off"),
    "freeze": ("toggle", None, "on"), "freeze_below": ("num", (0.0, 100.0), 1),
    "deploy_days": ("days", None, "subset"), "deploy_hours": ("hours", None, "within"), "deploy_tz": ("tz", None, 0),
    "strategy": ("choice", ("direct", "canary"), "canary"), "canary_percent": ("int", (1, 50), -1),
    "canary_bake_min": ("int", (1, 240), 1), "canary_max_error_delta": ("num", (0.0, 10.0), -1),
    "canary_min_requests": ("int", (10, 100_000), 1), "base_url": ("url", None, 0),
    "counted": ("toggle", None, "on"),
    "name": ("text", None, None), "sli": ("choice", ("availability", "latency"), 0),
    "threshold_ms": ("num", (1.0, 60_000.0), -1), "target": ("num", (50.0, 99.999), 1),
    "window_d": ("int", (1, 90), 0), "selector": ("selector", None, 0), "state": ("toggle", None, "on"),
    "spec": ("spec", None, None), "target_of": ("text", None, None), "until": ("int", (0, 10 ** 14), None),
    "reason": ("text", None, None),
}
SCOPES = {"global": set(DEFAULTS), "c": {"objective", "p99_ms", "counted"}, "p": {"spec"},
          "s": {"name", "sli", "threshold_ms", "target", "window_d", "selector", "state"},
          "m": {"target_of", "until", "reason"}}
PROBE = re.compile(r"(GET|HEAD|POST) (/[A-Za-z0-9._~/?=&%-]{0,200}) ([1-5][0-9][0-9])")
SELECTOR = re.compile(r"counted|all|kind:(api|worker|job|database|dependency|probe)|c-[0-9a-f]{12}(,c-[0-9a-f]{12}){0,31}")
RESOURCE = re.compile(r"run:policy/(global|[cpsm]-[a-z0-9]{1,16})/([a-z_0-9]{1,32})")


def component_id(kind: str, operation: str, name: str) -> str:
    return "c-" + hashlib.sha256(f"{kind}|{operation or ''}|{name}".encode()).hexdigest()[:12]


def _hours(value: str) -> tuple[int, int]:
    m = re.fullmatch(r"([01]?[0-9]|2[0-3])-([01]?[0-9]|2[0-4])", value)
    if not m or int(m[1]) >= int(m[2]):
        raise ValueError("hours are HH-HH, start before end")
    return int(m[1]), int(m[2])


def parse(key: str, value: str):
    """The typed value of a setting, or ValueError: a malformed setting is ignored, never half-applied."""
    kind, spec, _ = SCHEMA.get(key, (None, None, None))
    if kind is None:
        raise ValueError(f"unknown setting {key}")
    if kind == "spec":
        if value != "off" and not PROBE.fullmatch(value):
            raise ValueError("a probe is METHOD /path STATUS")
        return value
    if kind == "url":
        if value and not re.fullmatch(r"https?://[A-Za-z0-9.:-]{1,200}", value):
            raise ValueError("a base URL is scheme://host[:port]")
        return value
    if kind == "toggle":
        if value not in ("on", "off"):
            raise ValueError("a toggle is on or off")
        return value
    if kind == "choice":
        if value not in spec:
            raise ValueError(f"{key} is one of {', '.join(spec)}")
        return value
    if kind == "text":
        if not re.fullmatch(r"[\w .,:'()%/-]{0,120}", value):
            raise ValueError("a short text")
        return value
    if kind == "selector":
        if not SELECTOR.fullmatch(value):
            raise ValueError("a selector is counted, all, kind:<kind> or component ids")
        return value
    if kind == "days":
        days = value.split(",")
        if not days or any(d not in DAYS for d in days) or len(set(days)) != len(days):
            raise ValueError("days are mon,tue,…")
        return ",".join(d for d in DAYS if d in days)
    if kind == "hours":
        _hours(value)
        return value
    if kind == "tz":
        ZoneInfo(value)                                   # raises on an unknown zone
        return value
    low, high = spec
    number = float(value)
    if not low <= number <= high:
        raise ValueError(f"{key} is between {low} and {high}")
    return int(number) if kind == "int" else number


def stricter(key: str, old, new) -> bool | None:
    """True when moving from old to new tightens (or keeps) what Standard holds the product to, False when it loosens,
    None when the setting holds nothing to a bar (applies at once)."""
    way = SCHEMA[key][2]
    if way is None:
        return None
    if old is None:                                       # a new override, probe or SLO adds a check
        return key not in ("counted", "state") or new == "on"
    if way == "subset":
        return set(new.split(",")) <= set(old.split(","))
    if way == "within":
        (a, b), (c, d) = _hours(old), _hours(new)
        return a <= c and d <= b
    if isinstance(way, str):
        return new == old or new == way
    if way == 0:
        return new == old
    return (new - old) * way >= 0


class Policy:
    """The effective settings, from the journal's signed statements, with the pending loosenings and the history."""

    def __init__(self, delay_ms: int, state_path=None, defaults=None):
        self.delay_ms, self.path = delay_ms, state_path
        self.defaults = {**DEFAULTS, **(defaults or {})}  # the installation's own starting values (standard.toml)
        saved = json.loads(state_path.read_text()) if state_path is not None and state_path.exists() else {}
        self.effective = saved.get("effective", {})       # "scope/key" -> value
        self.pending = saved.get("pending", {})           # "scope/key" -> {"value", "at", "author", "applies_at"}
        self.seen = saved.get("seen", {})                 # "scope/key" -> id of the last statement read
        self.history = saved.get("history", [])

    def update(self, observations: dict, authors: set, now_ms: int) -> None:
        for o in sorted(observations.values(), key=lambda o: o["at"]):
            m = RESOURCE.fullmatch(o["resource"])
            if not m or o["property"] != "value" or o["author"] not in authors:
                continue
            scope, key = m[1], m[2]
            name = f"{scope}/{key}"
            if self.seen.get(name) == o["id"] or key not in SCOPES[scope if scope == "global" else scope[0]]:
                continue
            self.seen[name] = o["id"]
            try:
                value = parse(key, o["status"])
            except (ValueError, KeyError) as exc:
                self.history.append({"at": o["at"], "author": o["author"], "setting": name, "value": o["status"],
                                     "outcome": f"ignored: {exc}"})
                continue
            old = self.effective.get(name)
            if old is None and key in ("objective", "p99_ms"):  # an override is compared with what it overrides
                old = self.get(key)
            elif old is None and scope == "global":
                old = self.defaults[key]
            tighter = stricter(key, old, value)
            if tighter is not False:
                self.effective[name] = value
                self.pending.pop(name, None)
                outcome = "applied"
            else:
                self.pending[name] = {"value": value, "at": o["at"], "author": o["author"],
                                      "applies_at": o["at"] + self.delay_ms}
                outcome = "pending"
            self.history.append({"at": o["at"], "author": o["author"], "setting": name, "value": value,
                                 "outcome": outcome})
        for name, p in list(self.pending.items()):
            if now_ms >= p["applies_at"]:
                self.effective[name] = p["value"]
                del self.pending[name]
        self.history = self.history[-200:]
        if self.path is not None:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"effective": self.effective, "pending": self.pending, "seen": self.seen,
                                       "history": self.history}))
            tmp.replace(self.path)

    def get(self, key: str, scope: str = "global"):
        name = f"{scope}/{key}"
        if name in self.effective:
            return self.effective[name]
        return self.defaults.get(key) if scope == "global" else None

    def limits(self, kind: str, operation: str, name: str) -> dict:
        """The objective, latency limit and counting of one component: its own override, else the global value."""
        cid = component_id(kind, operation, name)
        counted = self.get("counted", cid)
        return {"id": cid, "objective": (self.get("objective", cid) or self.get("objective")) / 100,
                "p99_ms": self.get("p99_ms", cid) or self.get("p99_ms"), "failing": self.get("failing") / 100,
                "counted": counted == "on" if counted else kind != "dependency"}

    def _scoped(self, prefix: str) -> dict:
        out = {}
        for name, value in self.effective.items():
            scope, key = name.split("/", 1)
            if scope.startswith(prefix):
                out.setdefault(scope, {})[key] = value
        return out

    def probes(self) -> list:
        """(id, method, path, status) of every active probe."""
        out = []
        for pid, keys in sorted(self._scoped("p-").items()):
            if keys.get("spec", "off") != "off":
                method, path, status = keys["spec"].split(" ")
                out.append((pid, method, path, int(status)))
        return out

    def slos(self) -> dict:
        """Every SLO in force: the default one (availability of every counted component, over 30 days, at the global
        objective) unless turned off, and those the engineers declared."""
        out = {"s-default": {"name": "Disponibilité du service", "sli": "availability", "target": self.get("objective"),
                             "window_d": 30, "selector": "counted", "threshold_ms": None, "state": "on"}}
        for sid, keys in self._scoped("s-").items():
            base = out.get(sid, {"name": sid, "sli": "availability", "target": self.get("objective"), "window_d": 30,
                                 "selector": "counted", "threshold_ms": self.get("p99_ms"), "state": "on"})
            out[sid] = {**base, **keys}
        return {k: v for k, v in out.items() if v.get("state") != "off"}

    def silences(self, now_ms: int) -> dict:
        """Active silences: id -> {"target_of", "until", "reason"}. They mute the interface, never a signed fact."""
        return {mid: keys for mid, keys in self._scoped("m-").items() if keys.get("until", 0) > now_ms}

    def deploy_open(self, now_ms: int) -> tuple[bool, str | None]:
        """Whether an automatic deployment may start now: not frozen, inside the declared days and hours."""
        from datetime import datetime, timezone
        if self.get("freeze") == "on":
            return False, "deployments are frozen"
        local = datetime.fromtimestamp(now_ms / 1000, timezone.utc).astimezone(ZoneInfo(self.get("deploy_tz")))
        start, end = _hours(self.get("deploy_hours"))
        if DAYS[local.weekday()] not in self.get("deploy_days").split(",") or not start <= local.hour < end:
            return False, f"outside the deployment window ({self.get('deploy_days')} {self.get('deploy_hours')} " \
                          f"{self.get('deploy_tz')})"
        return True, None

    def document(self) -> dict:
        """The effective settings as one document, for the rules-as-code view: global, components, SLOs, probes,
        silences."""
        doc = {"global": {k: self.get(k) for k in DEFAULTS}}
        for prefix, label in (("c-", "components"), ("s-", "slos"), ("p-", "probes"), ("m-", "silences")):
            doc[label] = self._scoped(prefix)
        return doc

    def published(self) -> dict:
        """What the interface shows: every effective value, the pending loosenings, the latest changes."""
        return {"defaults": self.defaults, "bounds": {k: v[1] for k, v in SCHEMA.items() if v[1] is not None},
                "ways": {k: v[2] for k, v in SCHEMA.items()}, "effective": self.effective, "pending": self.pending,
                "history": self.history[-50:][::-1], "delay_ms": self.delay_ms, "document": self.document(),
                "slos": self.slos()}
