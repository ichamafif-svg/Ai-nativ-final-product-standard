"""Structured, redacted logs (LOG-METADATA, LOG-NO-SECRETS, LOG-INJECTION, LOG-SECURITY-EVENTS)."""
from __future__ import annotations

import json
import logging
import re
import sys
import time

from . import Values

SECRET = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session)")
VALUE_SECRET = re.compile(r"(eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}|AKIA[0-9A-Z]{16}|sk_(live|test)_\w{8,}|"
                          r"-----BEGIN [A-Z ]*PRIVATE KEY-----)")
_logger = logging.getLogger("standard")
if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False

_values = Values.from_env()


def configure(values: Values) -> None:
    global _values
    _values = values


def _clean(name: str, value):
    sensitive = _values.get("sensitive", ["*"])
    if SECRET.search(name) or "*" in sensitive and name not in ("event", "at", "who", "outcome", "route", "status",
                                                                  "ref", "id") and not name.endswith("_id") \
            or name in sensitive:
        return "[redacted]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = str(value)
    if VALUE_SECRET.search(text):
        return "[redacted]"
    return text.replace("\r", "\\r").replace("\n", "\\n")[:2000]


def event(name: str, *, level: int = logging.INFO, who: str | None = None, **fields) -> dict:
    """Log one event as one JSON line: UTC time, name, who, then fields. With @sensitive at its default ('*'), only
    ids and outcome-like fields are kept: log ids, not values."""
    record = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": name.replace("\n", " ")[:200]}
    if who is not None:
        record["who"] = _clean("who", who)
    record.update({k: _clean(k, v) for k, v in sorted(fields.items())})
    _logger.log(level, json.dumps(record, ensure_ascii=False, sort_keys=False))
    return record


def security(name: str, **fields) -> dict:
    """A security event (sign-in, refusal, bypass attempt): logged at WARNING."""
    return event(f"security.{name}", level=logging.WARNING, **fields)
