"""Canonical JSON: one value, one byte string (K01).

Floats, NaN, -0, non-string keys, duplicate keys, invalid Unicode and integers beyond 2**53 do not exist here.
Every failure is a CanonError; nothing else escapes.
"""
from __future__ import annotations

import hashlib
import json

MAX_DEPTH = 32
MAX_INT = 2 ** 53
MAX_BYTES = 1 << 20


class CanonError(ValueError):
    pass


def _check(value, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonError("nested too deep")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise CanonError("strings are valid Unicode") from None
        return
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise CanonError("integer out of range")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonError("object keys are strings")
            _check(key, depth + 1)
            _check(item, depth + 1)
        return
    raise CanonError(f"{type(value).__name__} is not canonical JSON")


def canon(value) -> bytes:
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canon(value)).hexdigest()


def _refuse(token):
    raise CanonError(f"{token} is not canonical JSON")


def parse(raw: bytes, *, max_bytes: int = MAX_BYTES):
    """Bytes to value, only if the bytes are exactly the canonical encoding of that value."""
    def pairs(items):
        out = {}
        for key, item in items:
            if key in out:
                raise CanonError(f"duplicate key {key!r}")
            out[key] = item
        return out
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > max_bytes:
        raise CanonError(f"at most {max_bytes} bytes")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=_refuse, parse_constant=_refuse)
    except CanonError:
        raise
    except (ValueError, RecursionError) as exc:
        raise CanonError(str(exc)[:200]) from None
    if canon(value) != raw:
        raise CanonError("bytes are not the canonical encoding")
    return value


def detach(value):
    """A deep, independent copy made only of dicts, lists and scalars (tuples become lists)."""
    if isinstance(value, dict):
        return {k: detach(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [detach(v) for v in value]
    return value
