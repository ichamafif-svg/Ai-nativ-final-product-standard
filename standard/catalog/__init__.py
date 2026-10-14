"""The rule catalog: the rules the agent codes to and Standard measures (standard/catalog/README.md).

Data only, read from the TOML files beside this module, validated against itself and against the OWASP ASVS 5.0 index
(every requirement carried by a rule or set aside with its reason). Pure functions on it:

    load()                          the validated catalog (cached), with its digest
    applicable(cat, features)       rules that apply to a product with these features
    select(cat, features, touched, pass_)   rules a funnel pass shows, for what a change touches
    effective(cat, chosen)          named values: the human's choices over the strict defaults
    render(rule, values)            the AI-native block of one rule, @values resolved: the same text before coding
                                    and in a refusal

Nothing here is a permission or a fact: the scanner measures, the kernel judges.
"""
from __future__ import annotations

import copy
import functools
import re
import tomllib
from pathlib import Path

from kernel.canon import digest as _digest

HERE = Path(__file__).resolve().parent
WHO = ("det", "ai", "human")
ABSORB = ("full", "partial", "none")
PASSES = ("wide", "medium", "fine")
PHASES = ("build", "run")
VALUE_TYPES = ("list", "map", "int", "text")
EXAMPLES = ("py_ok", "py_no", "js_ok", "js_no")
REQUIRED = {"id": str, "do": str, "applies": list, "when": list, "who": list, "block": str, "absorb": str,
            "pass": str, "phase": str, "check": list, "asvs": list, "cwe": list}
OPTIONAL = {"never": str, "values": list, "wire": list, "team_only": bool, **{k: str for k in EXAMPLES}}
CHECK = re.compile(r"blocks|patrol|human|mypy|fact:[a-z_]+|probe:[a-z0-9-]+|test:[a-z0-9-]+|bandit:B\d{3}"
                   r"|semgrep:standard\.[a-z0-9-]+")
BAN = re.compile(r"(import|call|builtin|attr-set|js-call|js-import):[\w.*]+(:[\w.]+)?"
                 r"|call-kw:[\w.*]+:\w+=\w+|call-dyn:[\w.]+:\d")
VALUE_REF = re.compile(r"@([a-z_]+)")


class CatalogError(ValueError):
    pass


def _read(name: str) -> dict:
    with open(HERE / name, "rb") as f:
        return tomllib.load(f)


def _rules() -> list:
    out = []
    for path in sorted((HERE / "rules").glob("*.toml")):
        with open(path, "rb") as f:
            doc = tomllib.load(f)
        for rule in doc.get("rule", []):
            out.append({**rule, "category": doc["category"], "file": path.name})
    return out


def validate(cat: dict) -> None:
    """Every field typed, every name defined, every ASVS requirement accounted for exactly once."""
    vocab, values, blocks, asvs = cat["vocabulary"], cat["values"], cat["blocks"], cat["asvs"]
    terms = {f"{kind[:-1]}:{t}" for kind in ("surfaces", "constructs") for t in vocab[kind]}
    probes = {p for b in blocks.values() for p in b["probes"]}
    for name, spec in values.items():
        if spec.get("type") not in VALUE_TYPES or not spec.get("doc") or spec.get("way") not in ("less", "more"):
            raise CatalogError(f"value {name}: type, doc and way")
    for name, b in blocks.items():
        if not all(isinstance(b.get(k), str) for k in ("module", "does", "use")):
            raise CatalogError(f"block {name}: module, does, use")
        for ban in b["bans"]:
            if not BAN.fullmatch(ban):
                raise CatalogError(f"block {name}: ban {ban}")
    seen, carried = set(), {}
    for r in cat["rules"]:
        rid = r.get("id", "?")
        for key, kind in REQUIRED.items():
            if not isinstance(r.get(key), kind):
                raise CatalogError(f"{rid}: {key} is required ({kind.__name__})")
        for key in set(r) - set(REQUIRED) - set(OPTIONAL) - {"category", "file"}:
            raise CatalogError(f"{rid}: unknown field {key}")
        for key, kind in OPTIONAL.items():
            if key in r and not isinstance(r[key], kind):
                raise CatalogError(f"{rid}: {key} is {kind.__name__}")
        if not re.fullmatch(r"[A-Z][A-Z0-9-]{1,30}", rid) or rid in seen:
            raise CatalogError(f"{rid}: id is upper-case, unique")
        seen.add(rid)
        if any(f not in vocab["features"] for f in r["applies"]):
            raise CatalogError(f"{rid}: applies names an unknown feature")
        if any(t not in terms for t in r["when"]):
            raise CatalogError(f"{rid}: when names an unknown surface or construct")
        if not r["who"] or any(w not in WHO for w in r["who"]) or len(set(r["who"])) != len(r["who"]):
            raise CatalogError(f"{rid}: who is det, ai and/or human")
        if r["absorb"] not in ABSORB or (r["absorb"] == "none") != (r["block"] == "") or \
                (r["block"] and r["block"] not in blocks):
            raise CatalogError(f"{rid}: a block absorbs it fully or partly, or no block and absorb none")
        if r["pass"] not in PASSES or r["phase"] not in PHASES:
            raise CatalogError(f"{rid}: pass and phase")
        named = set(r.get("values", []))
        if any(v not in values for v in named):
            raise CatalogError(f"{rid}: values names an unknown value")
        used = set(VALUE_REF.findall(r["do"] + " " + r.get("never", "")))
        if used - named:
            raise CatalogError(f"{rid}: @{sorted(used - named)[0]} is used but not listed in values")
        if not r["check"]:
            raise CatalogError(f"{rid}: at least one check")
        for c in r["check"]:
            if not CHECK.fullmatch(c):
                raise CatalogError(f"{rid}: check {c}")
            if c == "blocks" and not r["block"]:
                raise CatalogError(f"{rid}: check blocks needs a block")
            if c.startswith("probe:") and c[6:] not in probes:
                raise CatalogError(f"{rid}: no block declares probe {c[6:]}")
            if c == "patrol" and "ai" not in r["who"] or c == "human" and "human" not in r["who"]:
                raise CatalogError(f"{rid}: check {c} without {c == 'patrol' and 'ai' or 'human'} in who")
        if r.get("team_only") and r["who"] != ["human"]:
            raise CatalogError(f"{rid}: a team-only rule is the humans' to check")
        for a in r["asvs"]:
            if a not in asvs["levels"] or a in carried:
                raise CatalogError(f"{rid}: ASVS {a} unknown or carried twice ({carried.get(a)})")
            carried[a] = rid
        if not all(re.fullmatch(r"\d{1,4}", c) for c in r["cwe"]):
            raise CatalogError(f"{rid}: cwe ids are numbers")
    aside = asvs["set_aside"]
    if set(aside) & set(carried) or set(aside.values()) - {"doc", "infra", "socle"}:
        raise CatalogError("ASVS: a requirement set aside is also carried, or an unknown reason")
    missing = set(asvs["levels"]) - set(carried) - set(aside)
    if missing:
        raise CatalogError(f"ASVS: not accounted for: {sorted(missing)[:5]}")


@functools.lru_cache(maxsize=1)
def load() -> dict:
    blocks = _read("blocks.toml")["block"]
    cat = {"vocabulary": _read("vocabulary.toml"), "values": _read("values.toml"), "blocks": blocks,
           "asvs": _read("asvs.toml"), "rules": _rules()}
    validate(cat)
    cat["digest"] = _digest({k: v for k, v in cat.items() if k != "digest"})
    return cat


def applicable(cat: dict, features) -> list:
    """Rules that apply to a product with these features ([] applies = every product); team-only rules apply only
    when the root has more than one human (`team`)."""
    features = set(features)
    team = "team" in features
    return [r for r in cat["rules"] if set(r["applies"]) <= features and (team or not r.get("team_only"))]


def select(cat: dict, features, touched, pass_: str) -> list:
    """The rules one funnel pass shows for a change touching these surfaces and constructs (`surface:x`,
    `construct:y`). Coding passes show build rules, and run rules only when they ask the code to bring something
    (`wire`): the others are checked on the running product, the agent does nothing for them while coding. Wide: the
    applicable wide rules the change triggers, and those with no trigger. Medium and fine: the rules of that pass the
    change triggers. Deterministic: sorted by id."""
    if pass_ not in PASSES:
        raise CatalogError(f"pass is one of {PASSES}")
    touched = set(touched)
    out = []
    for r in applicable(cat, features):
        if r["pass"] != pass_ or r["phase"] == "run" and not r.get("wire"):
            continue
        if r["when"] and not touched & set(r["when"]) or not r["when"] and pass_ != "wide":
            continue
        out.append(r)
    return sorted(out, key=lambda r: r["id"])


def effective(cat: dict, chosen: dict | None) -> dict:
    """Named values in force: the human's choices over the defaults. A value without a default and not chosen is
    absent: rules reading it stay uncovered."""
    out = {}
    for name, spec in cat["values"].items():
        if name in (chosen or {}):
            out[name] = copy.deepcopy(chosen[name])
        elif "default" in spec:
            out[name] = copy.deepcopy(spec["default"])
    return out


def check_value(cat: dict, name: str, value):
    """A value the human may sign, or CatalogError. Loosening is allowed: only the human signs rules."""
    spec = cat["values"].get(name)
    if spec is None:
        raise CatalogError(f"unknown value {name}")
    kind = spec["type"]
    ok = {"list": lambda v: isinstance(v, list) and all(isinstance(x, str) and 0 < len(x) <= 200 for x in v)
                  and len(v) <= 500,
          "map": lambda v: isinstance(v, dict) and len(v) <= 2000 and all(
              isinstance(k, str) and 0 < len(k) <= 200 and (isinstance(x, (int, str)) or isinstance(x, list)
                                                            and all(isinstance(y, str) for y in x))
              for k, x in v.items()),
          "int": lambda v: type(v) is int and 0 <= v <= 10 ** 12,
          "text": lambda v: isinstance(v, str) and len(v) <= 200}[kind]
    if not ok(value):
        raise CatalogError(f"{name} is a {kind}")
    if name == "mfa" and value not in ("all", "admins"):
        raise CatalogError("mfa is all or admins")
    return copy.deepcopy(value)


def _show(value) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(value) + "]" if value else "[] (none)"
    if isinstance(value, dict):
        return f"{len(value)} entries" if value else "{} (none)"
    return str(value)


def render(rule: dict, values: dict, *, full: bool = True) -> str:
    """The AI-native block of a rule. `full=False`: one line, for rules a block absorbs fully."""
    def resolve(text):
        return VALUE_REF.sub(lambda m: f"@{m[1]}={_show(values[m[1]])}" if m[1] in values else
                             f"@{m[1]}=(not set: uncovered)", text)
    head = f"{rule['id']}  [{rule['pass']} · verify {'+'.join(rule['who'])}" + \
           (f" · block {rule['block']}" if rule["block"] else "") + "]"
    if not full:
        return f"{head}  {resolve(rule['do'])}"
    lines = [head, f"do     {resolve(rule['do'])}"]
    if rule.get("never"):
        lines.append(f"never  {resolve(rule['never'])}")
    for key in EXAMPLES:
        if key in rule:
            lang, verdict = key.split("_")
            body = rule[key].replace("\n", "\n" + " " * 7)
            lines.append(f"{lang} {verdict:<3}{body}")
    if rule.get("wire"):
        lines.append(f"wire   {', '.join(rule['wire'])}")
    lines.append(f"check  {', '.join(rule['check'])}")
    src = [f"ASVS {', '.join(rule['asvs'])}"] if rule["asvs"] else []
    src += [f"CWE-{', '.join(rule['cwe'])}"] if rule["cwe"] else []
    if src:
        lines.append(f"src    {' · '.join(src)}")
    return "\n".join(lines)
