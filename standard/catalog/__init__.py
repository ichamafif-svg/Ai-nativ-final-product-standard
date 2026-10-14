"""The rule catalog: the rules the agent codes to and Standard measures (standard/catalog/README.md).

Data only, read from the TOML files beside this module, validated against itself and against the OWASP ASVS 5.0 index
(every requirement carried by a rule or set aside with its reason). Pure functions on it:

    load()                          the validated catalog (cached), with its digest
    applicable(cat, features)       rules that apply to a product with these features
    select(cat, features, touched)   technical requirements triggered by a change
    effective(cat, chosen)          named values: the human's choices over the strict defaults
    render(rule, values)            the AI-native block of one rule, @values resolved: the same text before coding
                                    and in a refusal

Nothing here is a permission or a fact: the scanner measures, the kernel judges.
"""
from __future__ import annotations

import copy
import functools
import json
import re
import tomllib
from decimal import Decimal
from pathlib import Path

from kernel.canon import digest as _digest

HERE = Path(__file__).resolve().parent
WHO = ("det", "ai", "human")
ABSORB = ("full", "partial", "none")
PHASES = ("build", "run")
VALUE_TYPES = ("list", "map", "int", "text")
EXAMPLES = ("py_ok", "py_no", "js_ok", "js_no")
REQUIRED = {"id": str, "do": str, "applies": list, "when": list, "who": list, "block": str, "absorb": str,
            "phase": str, "check": list, "asvs": list, "cwe": list}
OPTIONAL = {"never": str, "values": list, "wire": list, "team_only": bool, **{k: str for k in EXAMPLES}}
CHECK = re.compile(r"blocks|patrol|human|mypy|fact:[a-z_]+|probe:[a-z0-9-]+|test:[a-z0-9-]+|bandit:B\d{3}"
                   r"|semgrep:standard\.[a-z0-9-]+")
BAN = re.compile(r"(import|call|builtin|attr-set|js-word):[\w.*$]+(:[\w.]+)?"
                 r"|js-call:[\w.*$()]+(:[\w.-]+)?|js-import:[\w@/.:-]+"
                 r"|call-kw:[\w.*]+:\w+=\w+|call-dyn:[\w.]+:\d")
STACKS = ("fastapi", "nextjs", "js", "any")       # js: bans for any JavaScript; any: no code, a configuration
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
        if set(VALUE_REF.findall(spec["doc"])) - values.keys():
            raise CatalogError(f"value {name}: unknown parameter dependency")
    for name, b in blocks.items():
        if not isinstance(b.get("does"), str) or not isinstance(b.get("probes"), list) or not b["stacks"]:
            raise CatalogError(f"block {name}: does, probes and at least one stack")
        if set(VALUE_REF.findall(b["does"])) - values.keys():
            raise CatalogError(f"block {name}: unknown named guarantee parameter")
        for stack, impl in b["stacks"].items():
            if stack not in STACKS or not all(isinstance(impl.get(k), str) for k in ("module", "use")) \
                    or not isinstance(impl.get("bans"), list):
                raise CatalogError(f"block {name}.{stack}: module, use, bans")
            for ban in impl["bans"]:
                if not BAN.fullmatch(ban):
                    raise CatalogError(f"block {name}.{stack}: ban {ban}")
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
        if r["phase"] not in PHASES:
            raise CatalogError(f"{rid}: phase")
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
    seen = set()
    for target in cat["targets"]:
        required = {"id", "kind", "resource", "property", "expect", "min_level", "fresh_ms", "due_ms", "owner", "sources"}
        if (not required <= target.keys() or set(target) - TARGET_FIELDS - {"instruction"}
                or target["id"] in seen or target["kind"] not in ("property", "coverage")
                or any(not isinstance(target[k], str) or not target[k] for k in required - {"sources", "fresh_ms", "due_ms"})
                or any(type(target[k]) is not int or target[k] <= 0 for k in ("fresh_ms", "due_ms"))
                or not isinstance(target["sources"], list) or not target["sources"]
                or any(not isinstance(s, str) for s in target["sources"])
                or "instruction" in target and not isinstance(target["instruction"], str)):
            raise CatalogError(f"invalid maintenance target {target.get('id')}")
        seen.add(target["id"])
    for group in ("parameter", "field"):
        for name, spec in cat["policy"][group].items():
            if spec.get("type") not in ("num", "int", "days", "hours", "tz", "url", "toggle", "spec", "text", "choice", "selector"):
                raise CatalogError(f"invalid policy type {name}")
            if spec["type"] in ("num", "int") and (not isinstance(spec.get("bounds"), list)
                    or len(spec["bounds"]) != 2 or Decimal(str(spec["bounds"][0])) > Decimal(str(spec["bounds"][1]))):
                raise CatalogError(f"invalid policy bounds {name}")
    for name, spec in cat["policy"]["section"].items():
        if not spec.get("id") or not set(spec.get("fields", [])) <= cat["policy"]["field"].keys():
            raise CatalogError(f"invalid policy section {name}")


def categories(cat=None) -> list:
    """Category slugs of the catalog, in a fixed order: one socle target each (rules-<slug>)."""
    return sorted({slug(r["category"]) for r in (cat or load())["rules"]})


def slug(category: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", category.lower()).strip("-")


TARGET_FIELDS = {"id", "kind", "coverage", "resource", "property", "expect", "min_level", "fresh_ms", "due_ms",
                 "owner", "sources", "repair", "human"}


def targets(cat=None) -> list:
    """Release requirements compiled into the existing law language, without U's work instructions."""
    return [{k: copy.deepcopy(v) for k, v in t.items() if k in TARGET_FIELDS} for t in (cat or load())["targets"]]


def policy_values(kind: str, cat=None) -> dict:
    """Floor and recommended values from one declaration. They are enforced by the two judges."""
    return {name: copy.deepcopy(spec[kind]) for name, spec in (cat or load())["policy"]["parameter"].items()
            if kind in spec}


def instruction(ident: str, cat=None) -> str | None:
    return next((t.get("instruction") for t in (cat or load())["targets"] if t["id"] == ident), None)


def definition(target: dict, cat=None) -> dict:
    """Explicit link from an effective-law target to its release requirements. Unknown client targets stay visible."""
    cat = cat or load()
    declared = next((t for t in cat["targets"] if t["id"] == target["id"]), None)
    category = target["id"][6:] if target["id"].startswith("rules-") else None
    return {"target": target["id"], "catalog": cat["digest"],
            "origin": "release" if declared else "client law; no catalog mapping",
            "instruction": declared and declared.get("instruction"),
            "rules": [r["id"] for r in cat["rules"] if slug(r["category"]) == category],
            "measurement": "declared requirements only; instrument registration and results are separate"}


def compact(cat: dict) -> dict:
    """What the scanner's programs need of the catalog (rules and blocks), as plain data for their inputs."""
    return {"rules": cat["rules"], "blocks": cat["blocks"]}


def _blocks(raw: dict) -> dict:
    """Each block's contract with its stacks; `module`, `use` and `bans` summarise them (the FastAPI module and use
    when it exists; the bans of every stack, each checked on its own language)."""
    out = {}
    for name, b in raw.items():
        stacks = {k: v for k, v in b.items() if isinstance(v, dict)}
        main = stacks.get("fastapi") or stacks.get("nextjs") or next(iter(stacks.values()), {})
        out[name] = {**{k: v for k, v in b.items() if not isinstance(v, dict)}, "stacks": stacks,
                     "module": main.get("module", ""), "use": main.get("use", ""),
                     "bans": sorted({p for impl in stacks.values() for p in impl.get("bans", [])})}
    return out


def implementation(cat: dict, block: str, stack: str) -> dict | None:
    """The block's implementation on a stack (fastapi, nextjs), or None when that stack has no such block yet."""
    return cat["blocks"][block]["stacks"].get(stack)


@functools.lru_cache(maxsize=1)
def load() -> dict:
    blocks = _blocks(_read("blocks.toml")["block"])
    cat = {"vocabulary": _read("vocabulary.toml"), "values": _read("values.toml"), "blocks": blocks,
           "asvs": _read("asvs.toml"), "rules": _rules(), "policy": _read("policy.toml")}
    cat["targets"] = []
    for entry in _read("maintenance.toml")["target"]:
        if entry["id"] == "rules-{category}":
            cat["targets"].extend({**entry, "id": f"rules-{c}", "resource": f"repo:rules:{c}"}
                                  for c in categories(cat))
        else:
            cat["targets"].append(entry)
    validate(cat)
    cat["digest"] = _digest({k: v for k, v in cat.items() if k != "digest"})
    return cat


def applicable(cat: dict, features) -> list:
    """Rules that apply to a product with these features ([] applies = every product); team-only rules apply only
    when the root has more than one human (`team`)."""
    features = set(features)
    team = "team" in features
    return [r for r in cat["rules"] if set(r["applies"]) <= features and (team or not r.get("team_only"))]


def select(cat: dict, features, touched) -> list:
    """Triggered build requirements and RUN requirements requiring code wiring. No generation-pass hierarchy."""
    touched = set(touched)
    out = []
    for r in applicable(cat, features):
        if r["phase"] == "run" and not r.get("wire"):
            continue
        if r["when"] and not touched & set(r["when"]):
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
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def render(rule: dict, values: dict, *, full: bool = True) -> str:
    """The AI-native block of a rule. `full=False`: one line, for rules a block absorbs fully."""
    def resolve(text):
        return VALUE_REF.sub(lambda m: f"@{m[1]}={_show(values[m[1]])}" if m[1] in values else
                             f"@{m[1]}=(not set: uncovered)", text)
    head = f"{rule['id']}  [verify {'+'.join(rule['who'])}" + \
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


def contracts(cat: dict, features, values: dict, *, touched=None, category=None, ids=None, stacks=()) -> dict:
    """The single technical reading used by constructors, reviewers, patrol and the interface.

    Applicability describes requirements, not proof. `absorb` states the intended division of responsibility;
    static adoption, a runtime probe and coverage of every execution path remain different claims.
    """
    chosen = applicable(cat, features) if touched is None or ids is not None else select(cat, features, touched)
    if category is not None:
        chosen = [r for r in chosen if slug(r["category"]) == category]
    if ids is not None:
        chosen = [r for r in chosen if r["id"] in ids]
    chosen = sorted(chosen, key=lambda r: r["id"])
    block_names = sorted({r["block"] for r in chosen if r["block"]})
    named = {n for r in chosen for n in r.get("values", [])} | \
            {n for name in block_names for n in VALUE_REF.findall(cat["blocks"][name]["does"])}
    while (dependencies := {dep for n in named for dep in VALUE_REF.findall(cat["values"][n]["doc"])} - named):
        named |= dependencies
    named = sorted(named)
    return {"catalog": cat["digest"],
            "rules": [{"id": r["id"], "text": render(r, values, full=r["absorb"] != "full"),
                       "block": r["block"], "absorption": r["absorb"], "checks": r["check"],
                       "wire": r.get("wire", []), "verifiers": r["who"]} for r in chosen],
            "blocks": {name: {"guarantees": cat["blocks"][name]["does"],
                              "probes": cat["blocks"][name]["probes"],
                              "bans": cat["blocks"][name]["bans"],
                              "implementations": {stack: cat["blocks"][name]["stacks"].get(stack)
                                                  or cat["blocks"][name]["stacks"].get("any")
                                                  or (cat["blocks"][name]["stacks"].get("js") if stack == "nextjs" else None)
                                                  for stack in stacks or cat["blocks"][name]["stacks"]}}
                       for name in block_names},
            "parameters": {n: {"definition": cat["values"][n], "value": values.get(n), "set": n in values}
                           for n in named},
            "limits": "Selected requirements only; omission never exempts code. Block absorption is a design "
                      "contract, not evidence of correct adoption or universal traversal. Checks marked ai/human "
                      "are opinions, never independent measurements. Check names declare intended verification; "
                      "missing tools and uncovered results remain unknown. Preserve block guarantees when simplifying."}


def render_contracts(packet: dict) -> str:
    """Same text for human and model; a bounded consumer can defer entire entries without rewriting them."""
    lines = [r["text"] + f"\nabsorb {r['absorption']}; wire {', '.join(r['wire']) or '(none)'}; "
             f"check {', '.join(r['checks'])}" for r in packet["rules"]]
    for name, block in packet["blocks"].items():
        lines.append(f"block {name}: {block['guarantees']}\nprobes {', '.join(block['probes']) or '(none)'}\n"
                     f"bans {', '.join(block['bans']) or '(none)'}")
        for stack, impl in block["implementations"].items():
            lines.append(f"  {stack}: {impl['module']}\nuse {impl['use']}"
                         if impl else f"  {stack}: missing implementation; bans still apply; request a human decision")
    for name, param in packet["parameters"].items():
        lines.append(f"@{name}: {json.dumps(param, ensure_ascii=False, sort_keys=True)}")
    return "\n\n".join([*lines, packet["limits"]])
