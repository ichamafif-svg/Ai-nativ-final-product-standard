"""Values whose misuse is a type error (beyond review): a secret that never prints, HTML that is safe by
construction, a URL that was built or checked. Blocks return them and accept them; product code cannot forge the
safe ones by accident because only the blocks construct them.

    key = secret("billing-key")      # Secret: str(key), repr(key), f"{key}" and the log all show [redacted]
    key.reveal()                     # the value, where it is really needed (an explicit, greppable act)
    body = clean_html(text)          # SafeHtml: a Jinja template prints it as is, any other str is escaped
    link = url("https://shop.example", "orders", oid)   # TrustedUrl
"""
from __future__ import annotations

from markupsafe import Markup

REDACTED = "[redacted]"


class Secret(str):
    """A str that hides itself: printing, formatting, repr, logging and pickling show [redacted]. The value is still
    usable as bytes by libraries that take str (str.encode works); building text from it needs .reveal()."""

    __slots__ = ()

    def reveal(self) -> str:
        return str.__str__(self)

    def __str__(self) -> str:
        return REDACTED

    def __repr__(self) -> str:
        return "Secret([redacted])"

    def __format__(self, spec) -> str:
        return REDACTED

    def __reduce__(self):
        raise TypeError("a Secret is not pickled")

    def __add__(self, other):
        raise TypeError("a Secret is not concatenated: use .reveal() where the value is really needed")

    __radd__ = __add__
    __mod__ = __add__


class SafeHtml(Markup):
    """HTML that a block produced (escaped or sanitised). Templates print it as is; nothing else is trusted."""

    __slots__ = ()


class TrustedUrl(str):
    """A URL built part by part by render.url, or checked against an allow-list by TrustedUrl.check."""

    __slots__ = ()

    @classmethod
    def check(cls, value: str, hosts) -> "TrustedUrl":
        from urllib.parse import urlsplit
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password \
                or parts.hostname not in set(hosts) or any(c in value for c in "\\\r\n\t\x00"):
            raise ValueError("not a trusted URL")
        return cls(value)
