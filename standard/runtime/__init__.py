"""Privileged Standard assembly. Its location does not remove it from the installation's trust base."""
from pathlib import Path

from bt.release import code_digest as source_digest

# The dependency closure is part of the release: cryptography verifies every signature K and T admit (T01, D49).
# The rule catalog is too: the scanner measures the product against it, so changing a rule changes the release; and so
# are the building blocks products install: a block is pinned with the rules it holds.
SOURCES = ("kernel", "bt", "standard/__init__.py", "standard/floors.py", "standard/runtime", "requirements.hashes",
           "standard/catalog", "blocks/python/standard_blocks", "blocks/js/front.mjs")
CATALOG_DATA = ("asvs.toml", "blocks.toml", "maintenance.toml", "policy.toml", "values.toml", "vocabulary.toml", "LICENSE.md")


def code_digest(root=None) -> str:
    """Bind all privileged assembly code, the reusable core and the rule catalog's data to the installation's genesis
    (directories contribute their Python files; the catalog's data files and the JS blocks are named one by one)."""
    base = Path(root) if root else Path(__file__).resolve().parents[2]
    data = [f"standard/catalog/{name}" for name in CATALOG_DATA]
    data += sorted(str(p.relative_to(base)) for p in (base / "standard" / "catalog" / "rules").glob("*.toml"))
    data += sorted(str(p.relative_to(base)) for p in (base / "blocks" / "js" / "nextjs").glob("*")
                   if p.suffix in (".js", ".json"))                           # the Next.js blocks, pinned the same way
    return source_digest(root, sources=SOURCES + tuple(data))
