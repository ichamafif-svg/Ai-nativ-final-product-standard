"""Trusted data: third-party security data as snapshots pinned by digest (D17, §15.4).

An instrument and an agent that compute from the same snapshot compute the same thing; a snapshot is refreshed only
by the operator (tools/refresh_data.py) and loaded only if its bytes match the pinned digest. A vulnerability
published after the snapshot does not exist for Standard until the next refresh: that is a declared limit, bounded by
the snapshot's age, which is itself checked against the freshness the floors require.

    {"format": "standard-data/1", "taken_at": ms,
     "advisories": {"name==version": [{"id": str, "fix_versions": [str]}]},   # every audited pin, even with no advisory
     "packages":   {"name": {"latest": str, "license": str, "classifiers": [str]}},
     "actions":    {"owner/repo@ref": "<40-hex sha>"}}
"""
from __future__ import annotations

from pathlib import Path

from kernel.canon import digest, parse

FORMAT = "standard-data/1"


class DataError(ValueError):
    pass


class TrustedData:
    def __init__(self, value: dict):
        if not isinstance(value, dict) or value.get("format") != FORMAT or type(value.get("taken_at")) is not int:
            raise DataError("DATA.FORMAT")
        self.value, self.digest = value, digest(value)
        self.taken_at = value["taken_at"]
        self.advisories = value.get("advisories", {})
        self.packages = value.get("packages", {})
        self.actions = value.get("actions", {})

    @classmethod
    def load(cls, path, pinned: str) -> "TrustedData":
        data = cls(parse(Path(path).read_bytes(), max_bytes=64 << 20))
        if data.digest != pinned:
            raise DataError("DATA.PIN: the snapshot is not the pinned one")
        return data

    def fresh(self, now: int, max_age_ms: int) -> bool:
        return self.taken_at <= now <= self.taken_at + max_age_ms


EMPTY = TrustedData({"format": FORMAT, "taken_at": 0})
