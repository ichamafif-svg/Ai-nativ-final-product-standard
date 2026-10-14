"""Structured, redacted logs (LOG-METADATA, LOG-NO-SECRETS, LOG-INJECTION, LOG-SECURITY-EVENTS, LOG-INTEGRITY).

Beyond the checklists: a Secret is redacted by type, and values that look like credentials (JWTs, cloud, GitHub,
Slack, Stripe, Google keys, private keys, bearer headers) by shape; control characters, ANSI escapes and
bidirectional overrides are neutralised (no forged lines, no terminal tricks, no reordered text); a record stays
under MAX_RECORD; each record carries `seq` and `chain`, the SHA-256 of the previous chain and this record, so a
deleted, reordered or edited line breaks the chain from there on (`verify_chain`).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
import threading
import time

from . import Values
from .types import Secret

SECRET = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session)")
VALUE_SECRET = re.compile(r"(eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}|(AKIA|ASIA)[0-9A-Z]{16}|[sr]k_(live|test)_\w{8,}|"
                          r"-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{30,}|"
                          r"xox[abposr]-[\w-]{10,}|AIza[\w-]{35}|(?i:bearer\s+[\w.~+/-]{16,}=*)|"
                          r"sk-(ant-|proj-)?[\w-]{20,}|glpat-[\w-]{20})")
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
MAX_RECORD = 8192
_logger = logging.getLogger("standard")
if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
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
    if isinstance(value, Secret):
        return "[redacted]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = str(value)
    if VALUE_SECRET.search(text):
        return "[redacted]"
    return CONTROL.sub(lambda m: f"\\u{ord(m.group()):04x}", text)[:2000]


_chain = {"seq": 0, "last": "0" * 64}
_chain_lock = threading.Lock()


def verify_chain(lines) -> int:
    """How many records, from the first line (the anchor), keep an unbroken chain; it stops at the first record
    that was edited, removed or moved."""
    last, n = None, 0
    for line in lines:
        record = json.loads(line)
        chain = record.pop("chain", "")
        body = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if last is not None and hashlib.sha256((last + body).encode()).hexdigest() != chain:
            break
        last, n = chain, n + 1
    return n


def event(name: str, *, level: int = logging.INFO, who: str | None = None, **fields) -> dict:
    """Log one event as one JSON line: UTC time, name, who, then fields. With @sensitive at its default ('*'), only
    ids and outcome-like fields are kept: log ids, not values."""
    record = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": name.replace("\n", " ")[:200]}
    if who is not None:
        record["who"] = _clean("who", who)
    record.update({k: _clean(k, v) for k, v in sorted(fields.items()) if k not in ("seq", "chain")})
    text = json.dumps(record, ensure_ascii=False)
    if len(text) > MAX_RECORD:
        record = {k: (v[:200] if isinstance(v, str) else v) for k, v in record.items()}
        record["truncated"] = True
    with _chain_lock:
        _chain["seq"] += 1
        record["seq"] = _chain["seq"]
        body = json.dumps(record, ensure_ascii=False, sort_keys=True)
        _chain["last"] = hashlib.sha256((_chain["last"] + body).encode()).hexdigest()
        record["chain"] = _chain["last"]
        _logger.log(level, json.dumps(record, ensure_ascii=False))
    return record


def security(name: str, **fields) -> dict:
    """A security event (sign-in, refusal, bypass attempt): logged at WARNING."""
    return event(f"security.{name}", level=logging.WARNING, **fields)
