"""Human-facing projection of the common read model, never a code binding or certification."""
from __future__ import annotations

from .concepts import AUTHORITY
from .drift_map import gap_dossiers
from .read_model import ReadModel, projection_labels


def law_surface_map(view: dict, findings=None, routes=(), qualify=None, *, settings=None, focus=None,
                    mode: str = "RUN", inputs=None, model: ReadModel | None = None) -> dict:
    model = model or ReadModel(view, findings, routes, qualify, settings=settings, inputs=inputs)
    dossiers = {d["id"]: d for d in gap_dossiers(view, model=model, mode=mode)}
    entries = []
    for row in model.targets():
        target = row["target"]
        if focus and str(focus) not in (target["id"], target["resource"]) and str(focus) not in str(target):
            continue
        dossier = dossiers[target["id"]]
        resource = target["resource"]
        parts = resource.split(":", 2)
        measure = row["measurement"]
        unknowns = []
        if not row["finding"]:
            unknowns.append("no diagnostic finding supplied; findings are not tied to the law prefix")
        elif row["diagnostic_alignment"] == "stale":
            unknowns.append("diagnostic finding names another main commit or law digest; it cannot describe this basis")
        elif row["diagnostic_alignment"] in ("unverified", "recorded_unbound"):
            unknowns.append("diagnostic finding is not verified against this law prefix and main commit")
        elif row["diagnostic_conflict"]:
            unknowns.append("diagnostic finding disagrees with constitutional proof/debt; check its freshness")
        if measure["kind"] == "unmapped":
            unknowns.append("no registered measurement mapped to this target")
        if row["proof"] and not row["facts"]:
            unknowns.append("proof is in constitutional health but its observation is outside the bounded public fact view")
        if row["state"] != "held" and dossier["route"]["state"] in ("NO_ROUTE", "TRUST_BLOCKED"):
            unknowns.append("no available route can currently turn the obligation into admitted work")
        if target.get("human") or resource.startswith("org:"):
            unknowns.append("requires human attestation; repository inspection cannot certify it")
        entries.append({
            "id": target["id"],
            "law": {k: target.get(k) for k in ("id", "resource", "property", "expect", "min_level", "fresh_ms",
                                               "sources", "repair", "human", "due_ms")},
            "surface": {"kind": parts[0], "domain": parts[1] if len(parts) > 1 else "",
                        "item": parts[2] if len(parts) > 2 else ""},
            "code": {"locations": row["locations"], "from": "diagnostic_findings" if row["finding"] else "unknown",
                     "binding": "candidate_locations_only"},
            "instrumentation": {"sources": target.get("sources", []),
                                "instruments": ([{"id": target["property"], **measure["declared"]}]
                                                if measure["declared"] else []),
                                "measurement": {k: measure[k] for k in ("method", "kind")},
                                "alignment": row["diagnostic_alignment"],
                                "finding": {k: row["finding"].get(k) for k in ("status", "summary")
                                            if k in row["finding"]}},
            "evidence": {"proven": row["proof"], "facts": row["facts"],
                         "proof_to_close": dossier["proof_to_close"]},
            "route": dossier["route"], "autonomy": dossier["autonomy"], "state": row["state"],
            "unknowns": unknowns,
            "compliance_projection": [{"framework": name, "authority": "projection_only", "certifies": False}
                                      for name in row["projections"]],
            "human_validation": {"status": "not_recorded", "recording_available": False,
                                 "effect": "review is not persisted; the kernel still decides from signed facts"},
        })
    return {"kind": "law-surface-map", "basis": view["prefix"], "law_digest": view["law"]["digest"],
            "system_settings": model.settings,
            "inputs": model.basis["inputs"] or {"findings": "unversioned diagnostic file",
                                                   "settings": "unversioned main document"},
            "scope": {"mapped": ["targets"], "unmapped": ["FLOOR-0", "operations", "conditions", "obligations",
                                                      "capabilities", "restrictions"]},
            "entries": entries,
            "summary": {"targets": len(entries), "unknowns": sum(bool(e["unknowns"]) for e in entries),
                        "with_code_locations": sum(any("path" in loc for loc in e["code"]["locations"])
                                                   for e in entries)},
            "authority": AUTHORITY["surface"],
            "certification": {"certifies": False,
                              "why": "framework labels are projections of Standard targets, not legal certification"}}
