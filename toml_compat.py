"""Small TOML compatibility shim.

Use the stdlib parser when available. The fallback is deliberately tiny: it covers
the configuration files this repository writes in tests and demos, not TOML in
general.
"""
from __future__ import annotations

import ast
import re

_tomllib = None


def loads(text: str) -> dict:
    if _tomllib is not None:
        return _tomllib.loads(text)
    out: dict = {}
    current = out
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = out
            for part in line[1:-1].split("."):
                current = current.setdefault(part, {})
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError(f"unsupported TOML line: {raw!r}")
        current[key.strip()] = _value(value.strip())
    return out


def _value(text: str):
    if text in ("true", "false"):
        return text == "true"
    if re.fullmatch(r"-?[0-9]+", text):
        return int(text)
    if re.fullmatch(r"-?[0-9]+\.[0-9]+", text):
        return float(text)
    if text.startswith("{") and text.endswith("}"):
        body = text[1:-1].strip()
        item = {}
        if body:
            for part in body.split(","):
                key, sep, value = part.partition("=")
                if not sep:
                    raise ValueError(f"unsupported inline table item: {part!r}")
                item[key.strip()] = _value(value.strip())
        return item
    if text.startswith("[") and text.endswith("]"):
        return ast.literal_eval(text)
    if text.startswith('"') and text.endswith('"'):
        return ast.literal_eval(text)
    raise ValueError(f"unsupported TOML value: {text!r}")
