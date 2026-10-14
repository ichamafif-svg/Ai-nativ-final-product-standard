"""Standard's Python primitives and FastAPI integrations: one module per concern. Install `standard-blocks[web]`
for web, sessions, access and file integrations. Generic modules can be imported without FastAPI; `Pages.render`
and `runtime.install` are optional Starlette/FastAPI helpers. Product code may not call what a block covers (the ban list in
catalog/blocks.toml, checked by Standard's scanner on every change).

    web       security headers, cookies, CORS, CSRF, methods, errors, proxies, redirects, rate limits
    session   OpenID Connect sign-in, server-side sessions, re-authentication, token verification
    access    route ids, the access matrix, owner filters
    crypto    hashing, MACs, AEAD, tokens, constant-time compare, key derivation
    files     uploads, archives, storage by id, downloads
    parse     XML, YAML, CSV, bounded regex, LDAP escaping
    process   processes without a shell
    outbound  the one HTTP client to other services
    input     request models
    render    templates, HTML sanitising, URL building
    log       structured, redacted logs
    runtime   settings, secrets, health, shutdown, bounded queues, last-resort errors
    data      owner and tenant filters, applied to every ORM statement of a user's session
    types     Secret, SafeHtml, TrustedUrl: values whose misuse is a type error, not a review comment
    store     where sessions and rate limits live: in memory for one process, Redis for several

Every block fails closed: a missing or malformed value, an unknown case, a dependency that cannot answer, all refuse.
Products extend a block only through hooks that can refuse more, never accept more; loosening is a signed value.

Values (`@origins`, `@upload_max_bytes`…) come from the rules of the game the human signed, handed to the product as
JSON in STANDARD_VALUES (or a file named by STANDARD_VALUES_FILE); a value absent takes its strict default.
"""
from __future__ import annotations

import json
import os
import threading

from ._defaults import DEFAULTS, TYPES

__version__ = "0.3.0"
_KIND = {"list": list, "map": dict, "int": int, "text": str}


class ValuesError(RuntimeError):
    """The values handed to the product cannot be read: the product refuses to run on a guess."""


def _checked(chosen) -> dict:
    """Keep only well-typed values; a value of the wrong type keeps its strict default (and says so)."""
    if not isinstance(chosen, dict):
        raise ValuesError("the values in force are a JSON object")
    out = {}
    for name, value in chosen.items():
        kind = _KIND.get(TYPES.get(name, ""))
        ok = kind is not None and isinstance(value, kind) and not (kind is int and isinstance(value, bool))
        if ok and kind is int and value < 0:
            ok = False
        if ok and kind is list and not all(isinstance(v, (str, int)) for v in value):
            ok = False
        if ok:
            out[name] = value
        elif name not in _REPORTED:
            _REPORTED.add(name)
            import sys
            print(f'{{"event": "security.values.refused", "name": {json.dumps(str(name)[:80])}}}', file=sys.stderr)
    return out


_REPORTED: set = set()


class Values:
    """The named values in force. Read again on every access when `reload` is set, so a signed change of the rules
    applies at once (AUTHZ-IMMEDIATE)."""

    def __init__(self, chosen: dict | None = None, *, source=None):
        self._chosen, self._source, self._lock = dict(chosen or {}), source, threading.Lock()

    @classmethod
    def from_env(cls) -> "Values":
        path = os.environ.get("STANDARD_VALUES_FILE")
        if path:
            def read():
                try:
                    with open(path, encoding="utf-8") as f:
                        return json.load(f)
                except (OSError, ValueError) as exc:
                    raise ValuesError(f"STANDARD_VALUES_FILE cannot be read: {type(exc).__name__}") from None
            read()                                          # at start: a broken file stops the product now
            return cls(source=read)
        try:
            return cls(json.loads(os.environ.get("STANDARD_VALUES", "{}") or "{}"))
        except ValueError:
            raise ValuesError("STANDARD_VALUES is not JSON") from None

    def _all(self) -> dict:
        chosen = self._source() if self._source else self._chosen
        return {**DEFAULTS, **_checked(chosen)}

    def __getitem__(self, name: str):
        values = self._all()
        if name not in values:
            raise KeyError(f"@{name} is not set and has no default: the rule that reads it stays uncovered")
        return values[name]

    def get(self, name: str, default=None):
        return self._all().get(name, default)

    def set(self, name: str, value) -> None:
        """For tests and local runs; in production the values come from the signed rules."""
        with self._lock:
            self._chosen[name] = value
