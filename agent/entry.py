"""U — the candidate's product behind the real entry path, in the precheck (D68 step 2, D69).

When the rules of the game say how the product starts (`@start`), the precheck runs base and candidate behind the
same gateway as production (Envoy, the gate, the bac) and calls the routes it can name without guessing: `/` and
the GET routes of `@public`. What the gate had to correct or refuse on the candidate's responses, and not on
base's, is the candidate's lesson. Without `@start`, Envoy or the bac, nothing runs and the reason is said.
"""
from __future__ import annotations

import re
import socket
import tempfile
import urllib.error
import urllib.request

from enclosure.refusals import from_platform

GET_ROUTE = re.compile(r"GET (/[A-Za-z0-9._~/-]*)")


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _paths(values: dict) -> list:
    return sorted({"/", *(m.group(1) for m in map(GET_ROUTE.fullmatch, values.get("public", [])) if m)})


def lessons(tree, values: dict, *, env=None, readable=(), during: str) -> tuple[list, str | None]:
    """(lessons, why_not): the gate's corrections and refusals on this tree's product, or why it did not run."""
    from enclosure.bac import Bac
    from enclosure.components import where
    from enclosure.stack import Stack
    if not values.get("start"):
        return [], "@start is not set: the product was not run behind the gateway"
    if not where("envoy") or not Bac().ready:
        return [], "the gateway is not available here (Envoy or the bac): the product was not run behind it"
    port = _port()
    try:
        with Stack(tempfile.mkdtemp(prefix="entry-"), values, ["/bin/sh", "-c", values["start"]], cwd=tree,
                   port=port, env=env, readable=readable) as stack:
            for path in _paths(values):
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=values["request_timeout_s"] + 2)
                except (urllib.error.URLError, OSError):
                    pass                                    # an error answer is still traffic the gate saw
            return from_platform(stack.read_records(), during=during), None
    except RuntimeError as exc:
        return [], f"the product did not start behind the gateway: {str(exc)[:300]}"
