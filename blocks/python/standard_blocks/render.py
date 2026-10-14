"""Output for browsers (OUT-ENCODE, INJ-TEMPLATE, SANITIZE-RICH, URL-BUILD, INJ-OTHER).

    pages = Pages("templates");  return pages.render("order.html", order=order)
    safe = clean_html(user_text)
    link = url("https://shop.example", "orders", oid, q=term)

Templates come from files and escape every value; HTML from users keeps only an allow-list of tags and attributes;
URLs are built part by part, encoded, http(s) only.

Beyond the checklists: what the block made is typed (SafeHtml, TrustedUrl), so a template prints a cleaned body as is
and escapes everything else, including a str that merely looks safe; data for scripts goes through json_for_script
(no `</script>`, no U+2028); templates run in a sandbox (no attribute walk to Python internals) and fail on a
missing variable instead of printing nothing.
"""
from __future__ import annotations

import html
import json
from html.parser import HTMLParser
from urllib.parse import quote, urlencode, urlsplit

from .types import SafeHtml, TrustedUrl

TAGS = {"p", "br", "b", "strong", "i", "em", "u", "ul", "ol", "li", "a", "code", "pre", "blockquote", "h2", "h3",
        "h4"}
DROP_CONTENT = {"script", "style", "iframe", "object", "embed", "svg", "math", "template", "noscript"}
ATTRS = {"a": {"href", "title"}}
SCHEMES = ("http", "https", "mailto")


class Pages:
    def __init__(self, folder):
        from jinja2 import FileSystemLoader, StrictUndefined, select_autoescape
        from jinja2.sandbox import ImmutableSandboxedEnvironment
        self.env = ImmutableSandboxedEnvironment(loader=FileSystemLoader(str(folder)), undefined=StrictUndefined,
                                                 autoescape=select_autoescape(default=True, default_for_string=True))
        self.env.filters["script_json"] = json_for_script

    def render(self, name: str, status: int = 200, **context):
        from starlette.responses import HTMLResponse as _Html
        return _Html(self.env.get_template(name).render(**context), status_code=status)


class _Clean(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.skip, self.open = [], 0, []

    def handle_starttag(self, tag, attrs):
        if tag in DROP_CONTENT:
            self.skip += 1
            return
        if self.skip or tag not in TAGS:
            return
        kept = []
        for name, value in attrs:
            if name in ATTRS.get(tag, set()) and value is not None:
                if name == "href" and urlsplit(value.strip()).scheme not in SCHEMES:
                    continue
                kept.append(f' {name}="{html.escape(value, quote=True)}"')
        if tag == "a":
            kept.append(' rel="noopener noreferrer nofollow"')
        self.out.append(f"<{tag}{''.join(kept)}>")
        if tag != "br":
            self.open.append(tag)

    def handle_endtag(self, tag):
        if tag in DROP_CONTENT:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or tag not in TAGS or tag not in self.open:
            return
        while self.open:
            last = self.open.pop()
            self.out.append(f"</{last}>")
            if last == tag:
                break

    def handle_data(self, data):
        if not self.skip:
            self.out.append(html.escape(data, quote=False))


def clean_html(text: str) -> SafeHtml:
    """User HTML reduced to an allow-list: text, a few formatting tags, links with http(s)/mailto only."""
    p = _Clean()
    p.feed(text or "")
    p.close()
    return SafeHtml("".join(p.out) + "".join(f"</{t}>" for t in reversed(p.open)))


def escape(text) -> SafeHtml:
    """Any value as HTML text."""
    return SafeHtml(html.escape(str(text), quote=True))


def json_for_script(value) -> SafeHtml:
    """Data embedded in a <script type="application/json"> or an attribute: no tag, no line separator can end it."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for raw, safe in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("'", "\\u0027"),
                      ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        text = text.replace(raw, safe)
    return SafeHtml(text)


def url(base: str, *parts, **query) -> TrustedUrl:
    """A URL from a fixed base, path parts each encoded, a query encoded. The base is http(s) and has no query."""
    b = urlsplit(base)
    if b.scheme not in ("http", "https") or not b.netloc or b.query or b.fragment or b.username or b.password \
            or any(c in base for c in "\\\r\n\t\x00 "):
        raise ValueError("the base is http(s)://host[/path] without query")
    if any(str(p) in (".", "..") for p in parts):
        raise ValueError("a path part is not . or ..")
    path = "/".join(quote(str(p), safe="") for p in parts)
    out = base.rstrip("/") + ("/" + path if path else "")
    return TrustedUrl(out + ("?" + urlencode({k: str(v) for k, v in query.items()}) if query else ""))


def one_line(value: str, limit: int = 200) -> str:
    """A value safe for a mail header or a one-line context: no CR, LF, NUL or other line or control separator."""
    text = "".join(" " if (ord(c) < 32 or 0x7f <= ord(c) < 0xa0 or c in "\u2028\u2029\u0085") else c for c in str(value))
    return " ".join(text.split())[:limit]
