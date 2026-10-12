"""Privileged product assembly. Its location does not remove it from the installation's trust base."""
from bt.release import code_digest as source_digest

SOURCES = ("kernel", "bt", "product/__init__.py", "product/floors.py", "product/runtime")


def code_digest(root=None) -> str:
    """Bind all privileged assembly code as well as the reusable core to the installation's genesis."""
    return source_digest(root, sources=SOURCES)
