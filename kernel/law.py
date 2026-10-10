"""The law the kernel executes (§4): the release floors composed with the client law in force.

The floors come with the release and never change from a journal. The client law lives in the journal: it binds the
floor roles to its identities, adds its own declarations and may only tighten what the floors declare. `compose`
enforces that, plus the autonomy floor (every target has a repair route the law can execute, or is declared human).
`Law` then validates the effective result. A law carries declarations and conditions, never authority: authority
lives in the ledger.
"""
from __future__ import annotations

import copy
import re

from . import obligations as obl
from .canon import CanonError, digest
from .floor0 import MIN_DELAY_MS, MIN_WITNESSES, POLARITY, floor0_digest
from .language import LanguageError, compile_program
from .types import ID, RESOURCE, SCALARS, SEGMENT, ShapeError, check_spec

FORMAT = "standard-law/1"
CLIENT_FORMAT = "standard-client/1"
TTL = ("pending", "unredeemed", "reconcile", "proof", "observation")
DELAYS = ("rotate", "grant", "unfreeze", "law")
TRUSTED = tuple(f"T{i:02}" for i in range(1, 10))
EFFECT_MINIMUM = ("T07", "T08")
SLOT = re.compile(r"\{([A-Za-z][A-Za-z0-9_]{0,63})\}")
TOP = ("format", "floor0", "levels", "ops", "evidence", "discharges", "conditions", "ttl", "delays", "witnesses",
       "controls", "targets", "obligations", "resources", "instruments")
CLIENT_TOP = ("format", "floors", "bindings", "ops", "evidence", "discharges", "conditions", "targets", "obligations",
              "tighten", "ttl", "delays", "witnesses", "controls", "resources", "instruments")
OBLIGATION_RANK = {"measure": 0, "escalate": 1, "refuse": 2}
YEAR_MS = 365 * 86_400_000
MAX_ENTITIES = 4096


class LawError(ValueError):
    pass


class Release:
    """The floors shipped with a release, and the floor roles every client binds. Data only."""

    def __init__(self, floors: dict, roles):
        self.floors, self.roles = copy.deepcopy(floors), tuple(roles)
        self.digest = digest({"format": FORMAT, "floors": self.floors, "roles": list(self.roles)})


def _condition(raw):
    try:
        return compile_program(raw)
    except LanguageError as exc:
        raise LawError(f"condition: {exc}") from None


# ---- composition ----------------------------------------------------------------------------------------------------
def _tighter(section: str, base, value) -> bool:
    if type(value) is not int:
        return False
    if section == "ttl":
        return 0 < value <= base                      # sooner expiry, sooner deadlines
    if section == "controls":
        return value == base == 0 or (value > 0 and (base == 0 or value <= base))
    return value >= base                              # longer delays, larger witness quorum


def _reaches(op: dict, resource: str) -> bool:
    """Whether an op's resource template can denote this resource (bounded inversion, no regex search).
    An op on a typed child (repo:x:y/base/head) repairs its parent (repo:x:y)."""
    parts, values = re.split(r"([:/])", op["resource"]), re.split(r"([:/])", resource)
    if len(parts) > len(values) and parts[len(values)] == "/" and any(SLOT.search(p) for p in parts[len(values):]):
        parts = parts[:len(values)]
    if len(parts) != len(values):
        return False
    bound = {}
    for part, value in zip(parts, values):
        slot = SLOT.search(part)
        if slot is None:
            if part != value:
                return False
            continue
        name, left, right = slot[1], part[:slot.start()], part[slot.end():]
        if not value.startswith(left) or not value.endswith(right) or len(value) < len(left) + len(right):
            return False
        value = value[len(left):len(value) - len(right)]
        ok = (SEGMENT.fullmatch(value) is not None if op["args"][name] == "segment"
              else re.fullmatch(r"-?[0-9]{1,16}", value) is not None and str(int(value)) == value)
        if not ok or bound.get(name, value) != value:
            return False
        bound[name] = value
    return True


def compose(release: Release, client) -> dict:
    """The effective law: the floors bound to the client's identities plus the client's own declarations.
    A client never redefines, removes or weakens a floor."""
    if not isinstance(client, dict) or set(client) - set(CLIENT_TOP):
        raise LawError(f"a client law declares only {list(CLIENT_TOP)}")
    if client.get("format") != CLIENT_FORMAT or client.get("floors") != release.digest:
        raise LawError("the client law is not written for the floors of this release")
    for section in ("ops", "evidence", "discharges", "conditions", "ttl", "delays", "witnesses", "controls", "tighten",
                    "resources", "instruments"):
        if not isinstance(client.get(section, {}), dict):
            raise LawError(f"{section} is a map")
    for section in ("targets", "obligations"):
        if not isinstance(client.get(section, []), list):
            raise LawError(f"{section} is a list")
    law = copy.deepcopy(release.floors)
    bindings = client.get("bindings")
    if (not isinstance(bindings, dict) or set(bindings) != set(release.roles)
            or not all(isinstance(v, str) and ID.fullmatch(v) for v in bindings.values())):
        raise LawError(f"bindings name one identity for each floor role {list(release.roles)}")
    bind = lambda v: bindings[v[1:]] if isinstance(v, str) and v.startswith("@") else v
    for t in law["targets"]:
        t["owner"], t["sources"] = bind(t["owner"]), [bind(x) for x in t["sources"]]
    for spec in law.get("instruments", {}).values():
        spec["sources"] = [bind(x) for x in spec["sources"]]
    for section in ("ops", "evidence", "discharges", "conditions", "resources", "instruments"):
        extra = client.get(section, {})
        if set(extra) & set(law.get(section, {})):
            raise LawError(f"{section}: a client adds names, it never redefines a floor")
        law[section] = {**law.get(section, {}), **copy.deepcopy(extra)}
    for section in ("targets", "obligations"):
        extra, floor_ids = client.get(section, []), {item["id"] for item in law[section]}
        if any(not isinstance(i, dict) or i.get("id") in floor_ids for i in extra):
            raise LawError(f"{section}: a client adds entries, it never redefines a floor")
        law[section] = law[section] + copy.deepcopy(extra)
    for section in ("ttl", "delays", "witnesses", "controls"):
        for field, value in client.get(section, {}).items():
            if field not in law[section] or not _tighter(section, law[section][field], value):
                raise LawError(f"{section}.{field}: a client may only tighten the floors")
            law[section][field] = value
    rank = {name: i for i, name in enumerate(law["levels"])}
    floor_proof = max((rank[d["min_level"]] for rules in release.floors.get("discharges", {}).values() for d in rules),
                      default=0)
    for rules in client.get("discharges", {}).values():
        if not isinstance(rules, list) or any(not isinstance(d, dict) or rank.get(d.get("min_level"), -1) < floor_proof
                                              for d in rules):
            raise LawError("discharges: a client adds ways to prove, never below the floors' level")
    _tighten(release, law, client.get("tighten", {}), rank)
    ops = check_ops(law["ops"])
    for t in law["targets"]:                          # the autonomy floor
        if not isinstance(t, dict):
            raise LawError("a target is a map")
        human, repair = t.get("human"), t.get("repair")
        if human is True and repair is None:
            continue
        op = ops.get(repair) if isinstance(repair, str) else None
        if human is not None or op is None or not isinstance(t.get("resource"), str) or not _reaches(op, t["resource"]):
            raise LawError(f"target {t.get('id')}: name an op of this law that repairs its resource, or declare it human")
    return law


def _tighten(release: Release, law: dict, tighten, rank) -> None:
    if not isinstance(tighten, dict) or set(tighten) - {"targets", "obligations", "ops"}:
        raise LawError("tighten names floor targets, obligations and ops")
    if any(not isinstance(v, dict) for v in tighten.values()):
        raise LawError("tighten sections are maps")
    floors = release.floors
    for op, change in tighten.get("ops", {}).items():
        if (op not in floors["ops"] or not isinstance(change, dict) or not change or set(change) - {"profile", "trusted"}
                or change.get("profile", "human_quorum") != "human_quorum"
                or not isinstance(change.get("trusted", []), list)):
            raise LawError("tighten.ops only raises a profile to human_quorum or adds trusted contracts")
        if "profile" in change:
            law["ops"][op]["profile"] = "human_quorum"
        if "trusted" in change:
            law["ops"][op]["trusted"] = sorted(set(law["ops"][op].get("trusted", [])) | set(change["trusted"]))
    floor_targets = {t["id"]: t for t in law["targets"][:len(floors["targets"])]}
    for tid, change in tighten.get("targets", {}).items():
        t = floor_targets.get(tid)
        if t is None or not isinstance(change, dict) or set(change) - {"min_level", "fresh_ms", "due_ms"}:
            raise LawError(f"tighten: {tid} is not a floor target or the change is unknown")
        if "min_level" in change and rank.get(change["min_level"], -1) < rank[t["min_level"]]:
            raise LawError(f"tighten: {tid}.min_level may only rise")
        for k in ("fresh_ms", "due_ms"):
            if k in change and not (type(change[k]) is int and 0 < change[k] <= t[k]):
                raise LawError(f"tighten: {tid}.{k} may only shorten")
        t.update(change)
    floor_obl = {o["id"]: o for o in law["obligations"][:len(floors["obligations"])]}
    for oid, change in tighten.get("obligations", {}).items():
        o = floor_obl.get(oid)
        if o is None or not isinstance(change, dict) or set(change) - {"level", "due_ms"}:
            raise LawError(f"tighten: {oid} is not a floor obligation or the change is unknown")
        if "level" in change and OBLIGATION_RANK.get(change["level"], -1) < OBLIGATION_RANK[o["level"]]:
            raise LawError(f"tighten: {oid}.level may only rise")
        if "due_ms" in change and not (type(change["due_ms"]) is int and 0 < change["due_ms"] <= o["due_ms"]):
            raise LawError(f"tighten: {oid}.due_ms may only shorten")
        o.update(change)


# ---- validated sections ---------------------------------------------------------------------------------------------
def check_ops(raw) -> dict:
    """An op: a closed scalar argument shape, a resource template filled from separator-free arguments, a profile,
    and the trusted contracts its effect needs (T07 and T08 always)."""
    if not isinstance(raw, dict) or not raw:
        raise LawError("the law declares at least one op")
    ops = {}
    for name, decl in raw.items():
        if (not isinstance(name, str) or not ID.fullmatch(name) or not isinstance(decl, dict)
                or not {"args", "resource", "profile"} <= set(decl) or set(decl) - {"args", "resource", "profile", "trusted"}
                or decl["profile"] not in ("capability", "human_quorum")):
            raise LawError(f"op {name}: args, resource, profile, optional trusted")
        trusted = decl.get("trusted", [])
        if not isinstance(trusted, list) or len(set(trusted)) != len(trusted) or any(t not in TRUSTED for t in trusted):
            raise LawError(f"op {name}: unknown or repeated trusted contract")
        try:
            args = check_spec(decl["args"], SCALARS)
        except ShapeError as exc:
            raise LawError(f"op {name}: {exc}") from None
        template = decl["resource"]
        if not isinstance(template, str) or any(len(SLOT.findall(p)) > 1 for p in re.split(r"[:/]", template)):
            raise LawError(f"op {name}: a template with at most one slot per segment")
        if any(args.get(slot) not in ("segment", "int") for slot in SLOT.findall(template)):
            raise LawError(f"op {name}: a slot fills from a required segment or int argument")
        if not RESOURCE.fullmatch(SLOT.sub("x", template)):
            raise LawError(f"op {name}: the template yields an exact resource")
        ops[name] = {"args": args, "resource": template, "profile": decl["profile"],
                     "trusted": sorted(set(trusted) | set(EFFECT_MINIMUM))}
    return ops


def check_targets(raw, rank) -> tuple[dict, dict]:
    if not isinstance(raw, list) or not 2 <= len(raw) <= 128:
        raise LawError("declare at least one coverage and one property target (at most 128)")
    required = {"id", "kind", "resource", "property", "expect", "min_level", "fresh_ms", "due_ms", "owner", "sources"}
    targets, by_key = {}, {}
    for t in raw:
        if not isinstance(t, dict) or not required <= set(t) or set(t) - required - {"coverage", "repair", "human"}:
            raise LawError("a target has only its declared fields")
        ident = t["id"]
        if not isinstance(ident, str) or not ID.fullmatch(ident) or ident in targets:
            raise LawError("target ids are unique identifiers")
        if t["kind"] not in ("coverage", "property"):
            raise LawError(f"{ident}: kind is coverage or property")
        if any(not isinstance(t[f], str) or not ID.fullmatch(t[f]) for f in ("property", "owner")):
            raise LawError(f"{ident}: property and owner are identifiers")
        if not isinstance(t["resource"], str) or not RESOURCE.fullmatch(t["resource"]):
            raise LawError(f"{ident}: a target resource is exact")
        if not isinstance(t["expect"], str) or not 0 < len(t["expect"]) <= 256:
            raise LawError(f"{ident}: expect is a short non-empty string")
        if rank.get(t["min_level"], 0) == 0:
            raise LawError(f"{ident}: a known positive proof level")
        if any(type(t[k]) is not int or not 0 < t[k] <= YEAR_MS for k in ("fresh_ms", "due_ms")):
            raise LawError(f"{ident}: freshness and due time are positive bounded milliseconds")
        sources = t["sources"]
        if (not isinstance(sources, list) or not 0 < len(sources) <= 16 or len(set(sources)) != len(sources)
                or any(not isinstance(x, str) or not ID.fullmatch(x) for x in sources) or t["owner"] in sources):
            raise LawError(f"{ident}: named sources, distinct from the owner")
        key = (t["resource"], t["property"])
        if key in by_key:
            raise LawError(f"{ident}: {key} is already declared by {by_key[key]}")
        targets[ident], by_key[key] = dict(t), ident
    if {t["kind"] for t in targets.values()} != {"coverage", "property"}:
        raise LawError("coverage and property targets are both required")
    for t in targets.values():
        if t["kind"] == "property" and targets.get(t.get("coverage"), {}).get("kind") != "coverage":
            raise LawError(f"{t['id']}: a property target names its coverage target")
        if t["kind"] == "coverage" and "coverage" in t:
            raise LawError(f"{t['id']}: a coverage target has no parent")
    order = sorted(targets, key=lambda i: (targets[i]["kind"] != "coverage", i))
    return {i: targets[i] for i in order}, by_key


def check_resources(raw) -> dict:
    """Versioned resource types with finite transitions; writes touch declared scalar fields only."""
    if not isinstance(raw, dict) or len(raw) > 64:
        raise LawError("resources is a map of at most 64 types")
    out = {}
    for name, spec in raw.items():
        if (not isinstance(name, str) or not ID.fullmatch(name) or not isinstance(spec, dict)
                or set(spec) != {"fields", "states", "initial", "transitions"}):
            raise LawError(f"resource {name}: fields, states, initial, transitions")
        try:
            fields = check_spec(spec["fields"], SCALARS)
        except ShapeError as exc:
            raise LawError(f"resource {name}: {exc}") from None
        states, transitions = spec["states"], spec["transitions"]
        if (not isinstance(states, list) or not 0 < len(states) <= 32 or len(set(states)) != len(states)
                or not all(isinstance(s, str) and ID.fullmatch(s) for s in states) or spec["initial"] not in states):
            raise LawError(f"resource {name}: distinct states including the initial one")
        if not isinstance(transitions, dict) or len(transitions) > 64:
            raise LawError(f"resource {name}: at most 64 transitions")
        compiled = {}
        for operation, rule in transitions.items():
            if (not isinstance(operation, str) or not ID.fullmatch(operation) or not isinstance(rule, dict)
                    or set(rule) != {"from", "to", "requires", "writes"}):
                raise LawError(f"resource {name}.{operation}: from, to, requires, writes")
            if (not isinstance(rule["from"], list) or not rule["from"] or len(set(rule["from"])) != len(rule["from"])
                    or any(s not in states for s in rule["from"]) or rule["to"] not in states):
                raise LawError(f"resource {name}.{operation}: endpoints are states of the type")
            writes = rule["writes"]
            if not isinstance(writes, list) or len(set(writes)) != len(writes) or any(f not in fields for f in writes):
                raise LawError(f"resource {name}.{operation}: writes names distinct declared fields")
            compiled[operation] = {"from": list(rule["from"]), "to": rule["to"], "writes": list(writes),
                                   "requires": _condition(rule["requires"])}
        out[name] = {"fields": fields, "states": list(states), "initial": spec["initial"],
                     "transitions": compiled, "contract": digest(spec)}
    return out


def check_instruments(raw, rank) -> dict:
    """A property measured by a pinned instrument: method, exact coverage, sources, minimum level, freshness."""
    if not isinstance(raw, dict) or len(raw) > 128:
        raise LawError("instruments is a bounded map")
    out = {}
    for prop, spec in raw.items():
        if (not isinstance(prop, str) or not ID.fullmatch(prop) or not isinstance(spec, dict)
                or set(spec) != {"method", "coverage", "sources", "min_level", "fresh_ms"}):
            raise LawError(f"instrument {prop}: method, coverage, sources, min_level, fresh_ms")
        sources = spec["sources"]
        if (not isinstance(spec["method"], str) or not ID.fullmatch(spec["method"])
                or not isinstance(spec["coverage"], str) or not RESOURCE.fullmatch(spec["coverage"])
                or not isinstance(sources, list) or not 0 < len(sources) <= 32 or len(set(sources)) != len(sources)
                or not all(isinstance(s, str) and ID.fullmatch(s) for s in sources)
                or spec["min_level"] not in rank or type(spec["fresh_ms"]) is not int
                or not 0 < spec["fresh_ms"] <= YEAR_MS):
            raise LawError(f"instrument {prop}: invalid contract")
        out[prop] = {**copy.deepcopy(spec), "contract": digest(spec)}
    return out


class Law:
    """A validated effective law, pinned by digest. Immutable by convention: nothing writes to it after __init__."""

    def __init__(self, effective: dict):
        effective = copy.deepcopy(effective)
        try:
            self.digest = digest(effective)
        except CanonError as exc:
            raise LawError(f"the law is not canonical: {exc}") from None
        if not isinstance(effective, dict) or set(effective) - set(TOP):
            raise LawError(f"a law declares only {list(TOP)}")
        if effective.get("format") != FORMAT or effective.get("floor0") != floor0_digest():
            raise LawError("the law does not declare this FLOOR-0")
        self.raw = effective
        levels = effective.get("levels")
        if (not isinstance(levels, list) or not levels or levels[0] != "unknown" or len(set(levels)) != len(levels)
                or not all(isinstance(x, str) and ID.fullmatch(x) for x in levels)):
            raise LawError("levels are an ordered list of names starting at unknown")
        self.levels, self.rank = list(levels), {name: i for i, name in enumerate(levels)}
        self.ops = check_ops(effective.get("ops"))
        self.targets, self.by_key = check_targets(effective.get("targets"), self.rank)
        self.resources = check_resources(effective.get("resources", {}))
        self.instruments = check_instruments(effective.get("instruments", {}), self.rank)
        self.evidence = {}
        for name, decl in (effective.get("evidence") or {}).items():
            if name in POLARITY or not isinstance(name, str) or not ID.fullmatch(name) or not isinstance(decl, dict) or set(decl) != {"fields"}:
                raise LawError(f"evidence {name}: a new kind with {{fields}}")
            try:
                fields = check_spec(decl["fields"])
            except ShapeError as exc:
                raise LawError(f"evidence {name}: {exc}") from None
            if fields.get("under") != "id" or fields.get("resource") != "resource" or fields.get("level", "str") != "str":
                raise LawError(f"evidence {name}: names its capability (under), its exact resource, a str level")
            self.evidence[name] = fields
        self.discharges = {}
        for kind, rules in (effective.get("discharges") or {}).items():
            if kind not in self.evidence or "level" not in self.evidence[kind] or not isinstance(rules, list):
                raise LawError(f"discharges: {kind} is not an evidence kind with a level")
            for d in rules:
                if (not isinstance(d, dict) or set(d) != {"obligation", "key", "min_level"} or d["obligation"] != "proof"
                        or d["min_level"] not in self.rank or self.evidence[kind].get(d["key"]) != "id"):
                    raise LawError(f"discharges of {kind}: {d}")
            self.discharges[kind] = list(rules)
        self.conditions = {}
        for name, program in (effective.get("conditions") or {}).items():
            if not isinstance(name, str) or not ID.fullmatch(name):
                raise LawError(f"condition name {name}")
            self.conditions[name] = _condition(program)
        self.ttl = effective.get("ttl")
        if (not isinstance(self.ttl, dict) or set(self.ttl) != set(TTL)
                or not all(type(v) is int and v > 0 for v in self.ttl.values())):
            raise LawError(f"ttl declares exactly {list(TTL)}")
        self.delay = effective.get("delays")
        if (not isinstance(self.delay, dict) or set(self.delay) != set(DELAYS)
                or any(type(v) is not int or v < MIN_DELAY_MS for v in self.delay.values())):
            raise LawError(f"delays declares exactly {list(DELAYS)}, each at least FLOOR-0's minimum")
        witnesses = effective.get("witnesses")
        if (not isinstance(witnesses, dict) or set(witnesses) != {"quorum"} or type(witnesses["quorum"]) is not int
                or witnesses["quorum"] < MIN_WITNESSES):
            raise LawError(f"witnesses declares a quorum of at least {MIN_WITNESSES}")
        self.witness_quorum = witnesses["quorum"]
        controls = effective.get("controls")
        if (not isinstance(controls, dict) or set(controls) != {"heartbeat_ms"}
                or type(controls["heartbeat_ms"]) is not int or controls["heartbeat_ms"] < 0):
            raise LawError("controls declares heartbeat_ms (0: no silent-control rule)")
        self.heartbeat_ms = controls["heartbeat_ms"]
        kinds = {**POLARITY, **dict.fromkeys(self.evidence, "attest")}
        try:
            self.obligations = obl.validate(effective.get("obligations"), kinds, _condition)
        except obl.DeclarationError as exc:
            raise LawError(f"obligations: {exc}") from None

    def resource_of(self, op: str, args: dict) -> str:
        """The resource an effect touches derives from its arguments, never declared beside them (F0-9)."""
        return SLOT.sub(lambda m: str(args[m.group(1)]), self.ops[op]["resource"])

    def condition_digest(self, name: str) -> str:
        return digest({"name": name, "policy": self.raw.get("conditions", {}).get(name)})

    def obligation_contract(self, stage: str):
        return self.obligations.get(stage, {}).get("contract")
