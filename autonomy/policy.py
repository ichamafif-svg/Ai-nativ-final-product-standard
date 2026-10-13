"""U — the engineers' settings for production (D31, D32, D35, D36): objectives, SLOs, alerting, release policy, probes.

The settings live in the product's repository, in standard/rules.json on main (D35): they change like code, by a
reviewed contribution, or from the interface with one signature (an engineer signs the new file's digest, the agent
commits exactly that file, the law lands it). Git keeps the history, the journal the proof. Silences alone are
statements an engineer signs in the browser (`run:policy/m-<id>/<key>`): a maintenance cannot wait for a review.

D36: these settings are the agent's own restraint and the interface's alerting, not a trusted judgment. The kernel
holds the floors' bounds (the least evidence on which the agent may act alone in production; tightening the law, a
revocation or a freeze apply at once, widening waits for the witnessed delay); inside them, a setting applies as soon
as main carries it. A setting that asks for less than the law (a lower burn threshold, a longer horizon) changes
nothing the agent may do: the kernel refuses, and the interface says so. The scanner reads from the same file only
what to measure (instruments/production.py `measures`).

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

import re
from zoneinfo import ZoneInfo

from instruments.production import PROBE, SELECTOR, component_id, measures

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
RESOURCE = re.compile(r"run:policy/(global|[cpsm]-[a-z0-9]{1,16})/([a-z_0-9]{1,32})")


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


# setting -> (law property, comparison): the floors' bound a setting may only ask more than (D36)
LAW = {"burn_fast": ("burn_fast", "ge"), "failing": ("failing_pct", "ge"), "rollback_horizon_min": ("switched_min", "le"),
       "restarts_per_hour": ("restarts_last_hour", "le"), "canary_max_error_delta": ("canary_error_delta", "le"),
       "canary_min_requests": ("canary_requests", "ge"), "canary_bake_min": ("canary_baked_min", "ge")}


def law_bounds(conditions: dict) -> dict:
    """{setting: (way, bound)} from the effective law's conditions: the loosest bound any condition declares."""
    out = {}
    for setting, (prop, way) in LAW.items():
        bounds = [float(a["compare"][2]) for c in conditions.values() for a in c.get("all", [])
                  if "compare" in a and a["compare"][0] == prop and a["compare"][1] == way]
        if bounds:
            bound = min(bounds) if way == "ge" else max(bounds)
            out[setting] = (way, bound + 1 if setting == "restarts_per_hour" else bound)
    return out


def flatten(doc) -> dict:
    """"scope/key" -> value of a rules document (global, components, SLOs, probes), unknown keys left out."""
    doc, flat = doc if isinstance(doc, dict) else {}, {}
    for k, v in (doc.get("global") if isinstance(doc.get("global"), dict) else {}).items():
        if k in SCOPES["global"]:
            flat[f"global/{k}"] = v
    for part, prefix in (("components", "c"), ("slos", "s"), ("probes", "p")):
        section = doc.get(part) if isinstance(doc.get(part), dict) else {}
        for scope, keys in section.items():
            if RESOURCE.fullmatch(f"run:policy/{scope}/x") and scope.startswith(prefix + "-") and isinstance(keys, dict):
                flat.update({f"{scope}/{k}": v for k, v in keys.items() if k in SCOPES[prefix]})
    return flat


def history(versions: list) -> list:
    """What changed, newest first, from the rules file's versions on main [(at, author, doc)], oldest first."""
    out, before = [], {}
    for at, author, doc in versions:
        after = flatten(doc)
        for name in sorted(set(before) | set(after)):
            if str(before.get(name)) != str(after.get(name)):
                out.append({"at": at, "author": author, "setting": name,
                            "value": "(retiré)" if name not in after else after[name], "outcome": "applied"})
        before = after
    return out[::-1][:200]


class Policy:
    """The effective settings: the rules file as main has it, and the signed silences."""

    def __init__(self, doc=None, defaults=None, transitions=None):
        self.doc, self.defaults = doc if isinstance(doc, dict) else {}, {**DEFAULTS, **(defaults or {})}
        self.effective, self.ignored = {}, []
        for name, raw in flatten(self.doc).items():
            try:
                self.effective[name] = parse(name.split("/", 1)[1], str(raw))
            except (ValueError, KeyError) as exc:
                self.ignored.append({"setting": name, "value": raw, "outcome": f"ignored: {exc}"})
        for resource, facts in (transitions or {}).items():   # silences: signed statements, applied at once
            m = RESOURCE.fullmatch(resource)                  # (only an engineer's grant reaches run:policy/*)
            if m and m[1].startswith("m-") and m[2] in SCOPES["m"] and "value" in facts:
                try:
                    self.effective[f"{m[1]}/{m[2]}"] = parse(m[2], str(facts["value"]))
                except ValueError:
                    pass

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

    def slos(self) -> dict:
        """Every SLO in force, exactly as the scanner measures them."""
        return measures(self.doc)["slos"]

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
        """The effective settings as one document, for the rules-as-code view."""
        doc = {"global": {k: self.get(k) for k in DEFAULTS}}
        for prefix, label in (("c-", "components"), ("s-", "slos"), ("p-", "probes"), ("m-", "silences")):
            doc[label] = self._scoped(prefix)
        return doc

    def published(self, now_ms: int = 0, law: dict | None = None, changes: list | None = None) -> dict:
        """What the interface shows: every effective value, its bounds, the law's bounds, the latest changes."""
        return {"defaults": self.defaults, "bounds": {k: v[1] for k, v in SCHEMA.items() if v[1] is not None},
                "law": law or {}, "effective": self.effective, "pending": {}, "ignored": self.ignored,
                "history": (changes or [])[:50], "document": self.document(), "slos": self.slos(),
                "silences": self.silences(now_ms)}
