"""Privileged Standard assembly. Its location does not remove it from the installation's trust base."""
from bt.release import code_digest as source_digest

# The dependency closure is part of the release: cryptography verifies every signature K and T admit (T01, D49).
SOURCES = ("kernel", "bt", "standard/__init__.py", "standard/floors.py", "standard/runtime", "requirements.hashes")


def code_digest(root=None) -> str:
    """Bind all privileged assembly code as well as the reusable core to the installation's genesis."""
    return source_digest(root, sources=SOURCES)
