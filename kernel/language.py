"""The law's language (§4.4): finite, bounded, positive conjunctions.

    {"all": [atom, ...]}           1..16 atoms, every one must hold
    eq              [path, scalar]           a request field equals a string or integer
    prefix          [path, text]             a request field starts with text
    observed        [property, status, level]  an eligible, independent observation of the request's resource
    closed_at_least [obligation, count]      at least count distinct keys closed, fresh, independent
    open            [obligation, path]       an independent, live instance keyed by a request field is open
    related         [relation, left, right]  a closed constitutional relation; $author, $resource, $under bind

No negation, no recursion, no code: the absence of a fact never permits. Admission supplies only facts already
checked for freshness and independence (F0-8); this module never looks for facts itself.
"""
from __future__ import annotations

import re

from .types import PATH, get_path

ATOMS = ("eq", "prefix", "observed", "closed_at_least", "open", "related")
RELATIONS = ("role", "holds", "parent", "owns", "type", "state")
BINDINGS = ("$author", "$resource", "$under")
NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}")
MAX_ATOMS = 16
MAX_FACTS = 20_000


class LanguageError(ValueError):
    pass


def compile_program(program) -> tuple:
    """Immutable atoms after exact-shape checking."""
    if not isinstance(program, dict) or set(program) != {"all"} or not isinstance(program["all"], list):
        raise LanguageError("a condition is {all: [atoms]}")
    if not 0 < len(program["all"]) <= MAX_ATOMS:
        raise LanguageError(f"a condition has 1..{MAX_ATOMS} atoms")
    out = []
    for atom in program["all"]:
        if not isinstance(atom, dict) or len(atom) != 1:
            raise LanguageError("an atom has exactly one operator")
        op, args = next(iter(atom.items()))
        arity = 3 if op in ("observed", "related") else 2
        if op not in ATOMS or not isinstance(args, list) or len(args) != arity:
            raise LanguageError(f"unknown atom or arity: {op}")
        if not all(type(a) is int or (isinstance(a, str) and 0 < len(a) <= 128) for a in args):
            raise LanguageError("arguments are bounded strings or integers")
        if op in ("eq", "prefix") and (not isinstance(args[0], str) or not PATH.fullmatch(args[0])):
            raise LanguageError("eq and prefix read a request field path")
        if op == "prefix" and not isinstance(args[1], str):
            raise LanguageError("prefix compares with text")
        if op in ("observed", "closed_at_least", "open") and (not isinstance(args[0], str) or not NAME.fullmatch(args[0])):
            raise LanguageError(f"{op} names a pinned fact kind")
        if op == "observed" and not all(isinstance(a, str) for a in args):
            raise LanguageError("observed names property, status and level")
        if op == "closed_at_least" and not (type(args[1]) is int and 1 <= args[1] <= MAX_FACTS):
            raise LanguageError("closed_at_least counts a positive bounded number")
        if op == "open" and (not isinstance(args[1], str) or not PATH.fullmatch(args[1])):
            raise LanguageError("open keys on a request field path")
        if op == "related":
            if args[0] not in RELATIONS or not all(isinstance(a, str) for a in args):
                raise LanguageError("related uses a closed constitutional relation")
            if any(a.startswith("$") and a not in BINDINGS for a in args[1:]):
                raise LanguageError(f"relation bindings are {BINDINGS}")
        out.append((op, tuple(args)))
    return tuple(out)


def named(atoms, op: str) -> set:
    """The fact kinds an atom set names for one operator: a condition only ever sees those."""
    return {args[0] for o, args in atoms if o == op}


def evaluate(atoms, *, request: dict, observations=frozenset(), closed=frozenset(), opened=frozenset(),
             relations=frozenset()) -> bool:
    """observations: {(resource, property, status, level)}; closed / opened: {(type, key)};
    relations: {(name, left, right)}. Malformed facts or a fact set over its bound raise LanguageError."""
    if any(len(rows) > MAX_FACTS for rows in (observations, closed, opened, relations)):
        raise LanguageError("fact set exceeds its bound")
    for op, args in atoms:
        if op == "eq":
            value = get_path(request, args[0])
            ok = value is not None and type(value) is type(args[1]) and value == args[1]
        elif op == "prefix":
            value = get_path(request, args[0])
            ok = isinstance(value, str) and value.startswith(args[1])
        elif op == "observed":
            ok = (request.get("resource"), *args) in observations
        elif op == "closed_at_least":
            ok = len({key for kind, key in closed if kind == args[0]}) >= args[1]
        elif op == "open":
            value = get_path(request, args[1])
            ok = value is not None and (args[0], value) in opened
        elif op == "related":
            bind = lambda x: request.get(x[1:]) if x.startswith("$") else x
            ok = (args[0], bind(args[1]), bind(args[2])) in relations
        else:
            raise LanguageError(f"unknown atom {op}")
        if not ok:
            return False
    return True
