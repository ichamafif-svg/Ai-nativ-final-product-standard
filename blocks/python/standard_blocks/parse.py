"""Safe parsers (XXE, DESER, PARSER-CONSIST, REDOS, REGEX-ESCAPE, CSV-INJ, INJ-LDAP, INJ-XPATH): one parser per
format, configured once.

Beyond the checklists: every parser has a size bound; JSON is read the one way every parser agrees on
(strict_json); YAML refuses anchors and aliases (the "billion laughs" of YAML) and every tag; XML refuses DTDs;
patterns with nested or overlapping repetition are refused, and with the `regex` package installed every match has
a time limit; CSV cells are neutralised even behind leading spaces or full-width signs.
"""
from __future__ import annotations

import csv
import io
import json
import re

import defusedxml.ElementTree as _xml

MAX_REGEX_INPUT = 10_000
NESTED = re.compile(r"\((?:[^()\\]|\\.)*[+*}]\)[+*{]")          # (a+)+, (a*)*, (a{2,}){3,}
OVERLAP = re.compile(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)[+*{]")    # (a|aa)+, (\w|\d)*
REGEX_TIMEOUT_S = 0.1


class ParseError(ValueError):
    pass


MAX_DOCUMENT = 1_000_000


def json_depth(text: str) -> int:
    """The deepest nesting of a JSON text, read without parsing it (strings skipped)."""
    depth = deepest = 0
    in_string = escaped = False
    for c in text:
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif c in "]}":
            depth -= 1
    return deepest


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ParseError("a key appears twice")          # two parsers would read two different documents
        out[k] = v
    return out


def _refuse_constant(name):
    raise ParseError(f"{name} is not JSON")


def _encodable(value):
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            try:
                v.encode("utf-8")
            except UnicodeEncodeError:
                raise ParseError("a lone surrogate") from None
        elif isinstance(v, dict):
            stack += list(v.keys()) + list(v.values())
        elif isinstance(v, list):
            stack += v


def strict_json(data, *, max_depth: int = 32, max_bytes: int = MAX_DOCUMENT):
    """JSON as every parser reads it the same way: UTF-8 only, no byte-order mark, no duplicate key, no NaN or
    Infinity, no lone surrogate, nesting at most `max_depth`, at most `max_bytes`."""
    if isinstance(data, (bytes, bytearray)):
        if len(data) > max_bytes:
            raise ParseError("document too large")
        if data[:3] == b"\xef\xbb\xbf":
            raise ParseError("a byte-order mark")
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            raise ParseError("not UTF-8") from None
    else:
        text = str(data)
        if len(text.encode("utf-8", "surrogatepass")) > max_bytes:
            raise ParseError("document too large")
    if json_depth(text) > max_depth:
        raise ParseError("nested too deep")
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_refuse_constant)
    except ParseError:
        raise
    except (ValueError, RecursionError):
        raise ParseError("not JSON") from None
    _encodable(value)
    return value


def xml(text):
    """Parse XML with external entities, DTD retrieval and entity expansion refused."""
    if len(text) > MAX_DOCUMENT:
        raise ParseError("document too large")
    try:
        return _xml.fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except Exception as exc:
        raise ParseError(f"refused XML: {type(exc).__name__}") from None


def yaml(text):
    """YAML into plain data only: no object construction, no tags, no anchors or aliases, bounded size."""
    import yaml as _yaml
    if len(text) > MAX_DOCUMENT:
        raise ParseError("document too large")

    class _Loader(_yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(_yaml.AliasEvent):
                raise ParseError("YAML aliases are refused")
            event = self.peek_event()
            if getattr(event, "anchor", None):
                raise ParseError("YAML anchors are refused")
            return super().compose_node(parent, index)
    try:
        return _yaml.load(text, Loader=_Loader)                  # noqa: S506 (a SafeLoader, narrowed further)
    except _yaml.YAMLError:
        raise ParseError("refused YAML") from None


def pattern(source: str) -> re.Pattern:
    """Compile a pattern written in code; one with nested or overlapping repetition is refused (catastrophic
    backtracking), as are backreferences (no linear-time guarantee at all)."""
    if len(source) > 1000:
        raise ParseError("pattern too long")
    if NESTED.search(source) or OVERLAP.search(source):
        raise ParseError("nested or overlapping repetition backtracks catastrophically")
    if re.search(r"\\[1-9]|\(\?P=", source):
        raise ParseError("backreferences are refused")
    return re.compile(source)


def search(source: str, text: str, *, literal: bool = False):
    """Search `text` (bounded to MAX_REGEX_INPUT) for a pattern; `literal=True` escapes input used as a pattern.
    With the `regex` package installed the search also stops after REGEX_TIMEOUT_S."""
    text = text[:MAX_REGEX_INPUT]
    compiled = re.escape(source) if literal else pattern(source).pattern
    try:
        import regex as _regex
    except ImportError:
        return re.compile(compiled).search(text)
    try:
        return _regex.compile(compiled).search(text, timeout=REGEX_TIMEOUT_S)
    except TimeoutError:
        raise ParseError("pattern took too long") from None


FORMULA = ("=", "+", "-", "@", "\t", "\r", "\n", "\uff1d", "\uff0b", "\uff0d", "\uff20")


def csv_cell(value) -> str:
    """A cell a spreadsheet will not run: a formula sign, even after spaces or in its full-width form, is
    neutralised with a leading quote; numbers stay numbers."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    text = "" if value is None else str(value).replace("\x00", "")
    return "'" + text if text.lstrip(" \u3000").startswith(FORMULA) else text


def csv_row(cells) -> str:
    """One CSV line (RFC 4180 quoting) with every cell escaped against formula injection."""
    out = io.StringIO()
    csv.writer(out, lineterminator="\r\n").writerow([csv_cell(c) for c in cells])
    return out.getvalue()


def ldap_escape(value: str) -> str:
    """Escape a value for an LDAP filter (RFC 4515)."""
    return "".join({"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00"}.get(c, c) for c in value)


def ldap_dn_escape(value: str) -> str:
    """Escape a value for an attribute of a distinguished name (RFC 4514)."""
    out = "".join("\\" + c if c in ',+"\\<>;=' else "\\00" if c == "\0" else c for c in value)
    if out[:1] in (" ", "#"):
        out = "\\" + out
    if out.endswith(" ") and not out.endswith("\\ "):
        out = out[:-1] + "\\ "
    return out
