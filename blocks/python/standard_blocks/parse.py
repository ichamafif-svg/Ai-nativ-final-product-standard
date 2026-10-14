"""Safe parsers (XXE, DESER, PARSER-CONSIST, REDOS, REGEX-ESCAPE, CSV-INJ, INJ-LDAP, INJ-XPATH): one parser per
format, configured once."""
from __future__ import annotations

import csv
import io
import re

import defusedxml.ElementTree as _xml

MAX_REGEX_INPUT = 10_000
NESTED = re.compile(r"\((?:[^()\\]|\\.)*[+*}]\)[+*{]")          # (a+)+, (a*)*, (a{2,}){3,}


class ParseError(ValueError):
    pass


def xml(text):
    """Parse XML with external entities, DTD retrieval and entity expansion refused."""
    try:
        return _xml.fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except Exception as exc:
        raise ParseError(f"refused XML: {type(exc).__name__}") from None


def yaml(text):
    """YAML into plain data only (no object construction)."""
    import yaml as _yaml
    try:
        return _yaml.safe_load(text)
    except _yaml.YAMLError:
        raise ParseError("refused YAML") from None


def pattern(source: str) -> re.Pattern:
    """Compile a pattern written in code; one with nested quantifiers is refused (catastrophic backtracking)."""
    if NESTED.search(source):
        raise ParseError("nested quantifiers backtrack catastrophically")
    return re.compile(source)


def search(source: str, text: str, *, literal: bool = False):
    """Search `text` (bounded to MAX_REGEX_INPUT) for a pattern; `literal=True` escapes input used as a pattern."""
    rx = re.compile(re.escape(source)) if literal else pattern(source)
    return rx.search(text[:MAX_REGEX_INPUT])


FORMULA = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA) else text


def csv_row(cells) -> str:
    """One CSV line (RFC 4180 quoting) with every cell escaped against formula injection."""
    out = io.StringIO()
    csv.writer(out, lineterminator="\r\n").writerow([csv_cell(c) for c in cells])
    return out.getvalue()


def ldap_escape(value: str) -> str:
    """Escape a value for an LDAP filter (RFC 4515)."""
    return "".join({"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00"}.get(c, c) for c in value)
