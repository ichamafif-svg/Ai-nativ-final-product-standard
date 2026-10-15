"""Privileged Standard assembly. Its location does not remove it from the installation's trust base."""
from pathlib import Path

from fabric.control.bt.release import CORE, code_digest as source_digest

# The dependency closure is part of the release: cryptography verifies every signature K and T admit (T01, D49).
# The rule catalog is too: the scanner measures the product against it, so changing a rule changes the release; and so
# are the building blocks products install: a block is pinned with the rules it holds.
SOURCES = (*CORE, "tools/cgroup_setup.sh", "tools/install_server.sh", "engine/__init__.py", "engine/agents/enclosed.py", "engine/catalog/floors.py", "fabric/control/runtime", "requirements.hashes",
           "engine/catalog", "blocks/python/standard_blocks", "blocks/js/front.mjs", "fabric")
CATALOG_DATA = ("asvs.toml", "blocks.toml", "maintenance.toml", "policy.toml", "values.toml", "vocabulary.toml", "LICENSE.md")


def code_digest(root=None) -> str:
    """Bind all privileged assembly code, the reusable core and the rule catalog's data to the installation's genesis
    (directories contribute their Python files; the catalog's data files and the JS blocks are named one by one)."""
    base = Path(root) if root else Path(__file__).resolve().parents[3]
    data = [f"engine/catalog/{name}" for name in CATALOG_DATA]
    data += sorted(str(p.relative_to(base)) for p in (base / 'engine/catalog' / "rules").glob("*.toml"))
    data += sorted(str(p.relative_to(base)) for p in (base / "blocks" / "js" / "nextjs").glob("*")
                   if p.suffix in (".js", ".json"))                           # the Next.js blocks, pinned the same way
    data += sorted(str(p.relative_to(base)) for p in (base / "fabric").rglob("*")
                   if p.is_file() and p.suffix in (".toml", ".json", ".txt", ".sql", ".hcl"))
    return source_digest(root, sources=SOURCES + tuple(data))
