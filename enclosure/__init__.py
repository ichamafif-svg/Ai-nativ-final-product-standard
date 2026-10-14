"""The bac (D68, ARCHITECTURE.md §4.10): the one enclosure product code and candidate code run in.

The walls are data. Linux enforces them: no network namespace route out, a read-only filesystem except the declared
places, an empty environment, no capabilities, its own process tree, and resource limits. Nothing here trusts the
code it runs, and nothing here decides anything: it builds the enclosure and reports whether it could.
"""
from enclosure.bac import Bac, Ran, Walls

__all__ = ["Bac", "Ran", "Walls"]
