"""LLM advisory passes for drift and law patrol.

These helpers filter model replies down to proposal-only shapes. They never return facts or authority.
"""
from __future__ import annotations

import json

from .patrol import SUSPICION_KEYS

def propose_reading(dossier: dict, tree, research, *, key=None) -> dict:
    """Ask a read-only research loop for an explanatory proposal, never for a fact or authority."""
    prompt = ("Read this drift dossier and propose an explanation for a human operator. You may inspect/search the "
              "snapshot and propose files or a fix, but you cannot certify evidence, close the gap, change law or "
              "claim authority. Return JSON with only these keys: hypothesis, suggested_files, suggested_fix, "
              "confidence, requires_human.\n\nDossier:\n" + json.dumps(dossier, sort_keys=True))
    reply = research.dialogue(prompt, tree, key=key or f"drift:{dossier.get('id')}")
    if not isinstance(reply, dict):
        return {}
    out = {k: reply[k][:2000] for k in ("hypothesis", "suggested_fix", "confidence")
           if isinstance(reply.get(k), str)}
    if isinstance(reply.get("suggested_files"), list):
        out["suggested_files"] = [v[:500] for v in reply["suggested_files"][:20] if isinstance(v, str)]
    if isinstance(reply.get("requires_human"), bool):
        out["requires_human"] = reply["requires_human"]
    return out


def propose_patrol(context: dict, tree, research, *, key=None) -> dict:
    """Ask a read-only research loop to patrol for possible law violations not yet deterministically born."""
    prompt = ("Patrol this repository snapshot for possible violations of Standard law that deterministic instruments "
              "may miss. You receive the complete rules in force, known findings and weak spots. "
              "You may read/search the snapshot and propose suspicions only. Do not claim facts, close gaps, authorize "
              "work, change law, or treat your output as evidence. Return JSON {\"suspicions\": [objects with only "
              f"these keys: {', '.join(SUSPICION_KEYS)}]}}.\n\n"
              + ("This round reads the repository for these rules only (law_ref = the rule id). A deterministic "
                 "check already covers part of some of them: look for what it cannot see.\n\n"
                 + "\n\n".join(context["rules"]) + "\n\n" if context.get("rules") else "")
              + "Patrol context:\n" + json.dumps({k: v for k, v in context.items() if k != "rules"}, sort_keys=True))
    reply = research.dialogue(prompt, tree, key=key or f"patrol:{context.get('focus') or 'wide'}")
    suspicions = reply.get("suspicions", []) if isinstance(reply, dict) else []
    out = []
    for item in (suspicions[:50] if isinstance(suspicions, list) else []):
        if not isinstance(item, dict) or not isinstance(item.get("law_ref"), str) or not item["law_ref"]:
            continue
        filtered = {k: item[k][:2000] for k in ("law_ref", "surface", "why", "determinism_gap",
                                                  "suggested_action", "confidence")
                    if isinstance(item.get(k), str)}
        for k in ("evidence_seen", "needs"):
            if isinstance(item.get(k), list):
                filtered[k] = [v[:500] for v in item[k][:20] if isinstance(v, str)]
        filtered["authority"] = "proposal_only"
        out.append(filtered)
    return {"suspicions": out, "authority": context["authority"]}
