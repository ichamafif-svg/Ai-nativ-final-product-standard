"""Standard's building blocks for Python products (FastAPI first): one module per concern, so a rule holds by using
the block rather than by remembering the rule. Product code may not call what a block covers (the ban list in
standard/catalog/blocks.toml, checked by Standard's scanner on every change).

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

Values (`@origins`, `@upload_max_bytes`…) come from the rules of the game the human signed, handed to the product as
JSON in STANDARD_VALUES (or a file named by STANDARD_VALUES_FILE); a value absent takes its strict default.
"""
from __future__ import annotations

import json
import os
import threading

from ._defaults import DEFAULTS

__version__ = "0.1.0"


class Values:
    """The named values in force. Read again on every access when `reload` is set, so a signed change of the rules
    applies at once (AUTHZ-IMMEDIATE)."""

    def __init__(self, chosen: dict | None = None, *, source=None):
        self._chosen, self._source, self._lock = dict(chosen or {}), source, threading.Lock()

    @classmethod
    def from_env(cls) -> "Values":
        path = os.environ.get("STANDARD_VALUES_FILE")
        if path:
            return cls(source=lambda: json.loads(open(path, encoding="utf-8").read()))
        return cls(json.loads(os.environ.get("STANDARD_VALUES", "{}") or "{}"))

    def _all(self) -> dict:
        chosen = self._source() if self._source else self._chosen
        return {**DEFAULTS, **(chosen if isinstance(chosen, dict) else {})}

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
