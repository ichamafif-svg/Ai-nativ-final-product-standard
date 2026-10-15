"""K — the constitutional kernel (ARCHITECTURE.md §6).

One deterministic judgment over a signed, anchored prefix. No clock, no network, no provider, no secret, no AI.
This package imports nothing else from Standard.
"""
from .accountability import Accountability
from .canon import CanonError, canon, digest, parse
from .floor0 import FLOOR0, floor0_digest
from .judge import MECHANISMS, SHAPES, Decision, Kernel, Refused, apply, empty
from .law import CLIENT_FORMAT, FORMAT, Law, LawError, Release, compose

__all__ = ["Accountability", "CanonError", "canon", "digest", "parse", "FLOOR0", "floor0_digest", "MECHANISMS",
           "SHAPES", "Decision", "Kernel", "Refused", "apply", "empty", "CLIENT_FORMAT", "FORMAT", "Law", "LawError",
           "Release", "compose"]
