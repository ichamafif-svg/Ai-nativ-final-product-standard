"""Shared vocabulary for U: advisory work, never authority.

This module is intentionally small. It gives names to the recurring concepts in autonomy and surface code so that
different views do not invent their own words for the same thing.
"""
from __future__ import annotations

AUTHORITY = {
    "context": "Information only. Submit signed statements; the kernel decides. Agent work cannot certify a fact.",
    "dossier": "Dossier only. It cannot certify, close or authorize; the kernel decides.",
    "patrol": "Exploratory patrol only. It produces suspicions, never facts, authorization or closure.",
    "surface": "Information only. The interface and agent do not decide; the kernel admits or refuses signed statements.",
}

CONTEXT_KINDS = ("target", "request", "patrol", "surface")
ADVISORY_OUTPUTS = ("dossier", "proposal", "suspicion", "note")
