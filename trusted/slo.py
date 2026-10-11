"""T06 — service level objectives with error budgets and multi-window burn-rate alerts (D32).

The operator keeps, per minute and per component, how many requests it saw, how many failed and their latency
buckets (slo.db, 90 days). An SLO selects components (`counted`, `all`, `kind:api`, or component ids) and an SLI:

    availability   a good event is a request that did not fail
    latency        a good event is a request answered under threshold_ms (by histogram bucket, never rounded up)

over a rolling window of days, against a target. Its error budget is the share of bad events the target allows;
`budget` is what is left of it over the window. The burn rate over a span is the bad share divided by the allowed
share: 1 spends the budget exactly over the window. Multi-window rule (Google SRE workbook), as numbers:

    fast_burn   the lower of the burns over 1 h and over 5 min (both must be high: significant, and still going on)
    slow_burn   the lower of the burns over 6 h and over 30 min

D36: the scanner signs the fast burn as a number; the law compares it (14.4: 2 % of a 30-day budget in one hour), the
engineers' alert thresholds are read by the interface and the agent. A span with fewer than `MIN_EVENTS` requests
has no burn: no alert on noise.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

SPANS = {"5m": 5, "30m": 30, "1h": 60, "6h": 360}
MIN_EVENTS = 20


class Store:
    def __init__(self, path=":memory:", readonly: bool = False):
        if readonly:                                        # the interface reads what the operator wrote, nothing more
            self.db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
            self.lock = threading.Lock()
            return
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db, self.lock = sqlite3.connect(str(path), check_same_thread=False), threading.Lock()
        with self.lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS m (minute INTEGER, cid TEXT, kind TEXT, total REAL, bad REAL, "
                            "buckets TEXT, PRIMARY KEY (minute, cid))")
            self.db.commit()

    def add(self, minute: int, cid: str, kind: str, total: float, bad: float, buckets: dict) -> None:
        if total <= 0:
            return
        with self.lock:
            row = self.db.execute("SELECT total, bad, buckets FROM m WHERE minute = ? AND cid = ?", (minute, cid)).fetchone()
            if row:
                merged = json.loads(row[2])
                for le, n in buckets.items():
                    merged[le] = merged.get(le, 0.0) + n
                self.db.execute("UPDATE m SET total = ?, bad = ?, buckets = ? WHERE minute = ? AND cid = ?",
                                (row[0] + total, row[1] + bad, json.dumps(merged), minute, cid))
            else:
                self.db.execute("INSERT INTO m VALUES (?, ?, ?, ?, ?, ?)", (minute, cid, kind, total, bad,
                                                                           json.dumps(buckets)))
            self.db.execute("DELETE FROM m WHERE minute < ?", (minute - 90 * 1440,))
            self.db.commit()

    def rows(self, since_minute: int) -> list:
        with self.lock:
            return self.db.execute("SELECT minute, cid, kind, total, bad, buckets FROM m WHERE minute >= ?",
                                   (since_minute,)).fetchall()


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


def evaluate(store: Store, slos: dict, now_minute: int, *, counted) -> dict:
    """{slo id: {"name", "sli", "target", "window_d", "compliance", "budget", "events", "burn": {span: rate},
    "fast_burn", "slow_burn"}} at this minute."""
    longest = max([s["window_d"] for s in slos.values()] or [1]) * 1440
    rows = store.rows(now_minute - longest)
    out = {}
    for sid, s in slos.items():
        allowed = 1 - s["target"] / 100
        picked = [r for r in rows if matches(s["selector"], r[1], r[2], counted)]

        def share(minutes: int) -> tuple[float, float]:
            total = bad = 0.0
            for minute, _, _, t, b, buckets in picked:
                if minute > now_minute - minutes:
                    total += t
                    bad += b if s["sli"] == "availability" else t - good_under(json.loads(buckets), s["threshold_ms"])
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
