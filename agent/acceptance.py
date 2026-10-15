"""U — acceptance tests drafted by a separate agent, for the human to sign (D70, quality).

The tests a request is judged by are its contract (D34). A different agent from the one that will build drafts them,
from the specification alone, before any implementation exists, with read-only access to the repository: it cannot
shape the tests to a candidate it never saw. The draft is a proposal. The human reads it, may change it, and signs it
as the contract exactly as before; nothing here signs, stores or admits anything.
"""
from __future__ import annotations

import ast

HEADER = ("# DRAFT acceptance tests, written by Standard's acceptance agent from the specification alone.\n"
          "# Read and correct them before signing: once signed, they are the request's contract.\n")
LIMIT = 200_000


class DraftError(ValueError):
    pass


def prompt(spec: str) -> str:
    return ("ROLE acceptance: write the acceptance tests of a feature request, from its specification only. You will "
            "never see the implementation, and another agent will build it against your tests. Test observable "
            "behaviour through the public interface the specification names, one test per stated requirement, plus "
            "the refusals it states. No network, no sleeps, no reliance on private names. Return JSON "
            '{"tests": "<one complete pytest file>", "uncovered": ["requirement you could not test, and why"]}.\n'
            f"Specification:\n{spec[:20_000]}")


def validate(reply: dict) -> tuple[str, list]:
    """A draft is one parseable pytest module with at least one test; what it could not cover is said."""
    tests = reply.get("tests") if isinstance(reply, dict) else None
    if not isinstance(tests, str) or not tests.strip() or len(tests) > LIMIT:
        raise DraftError("the acceptance agent returned no test file")
    try:
        module = ast.parse(tests)
    except SyntaxError as exc:
        raise DraftError(f"the draft is not valid Python: {exc}") from exc
    names = [n.name for n in ast.walk(module) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not any(name.startswith("test_") for name in names):
        raise DraftError("the draft contains no test")
    uncovered = [str(u)[:300] for u in reply.get("uncovered", []) if isinstance(u, str)][:20]
    return HEADER + tests if not tests.startswith(HEADER) else tests, uncovered


def draft(research, spec: str, tree, *, key: str = "acceptance") -> dict:
    """Ask the acceptance agent (read-only, its own dialogue) and return the draft for the human."""
    reply = research.worker(prompt(spec), "acceptance", tree=tree, read_only=True, key=key)
    tests, uncovered = validate(reply)
    return {"tests": tests, "uncovered": uncovered,
            "authority": "draft only: the human signs the contract; the building agent never wrote it"}
