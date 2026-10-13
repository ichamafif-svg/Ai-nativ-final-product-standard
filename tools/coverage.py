"""Inspect Standard's declared targets against registered measures and repair routes.

This source inventory does not execute probes, qualify an installation, sign a fact or authorize an effect.
REGISTERED means the implementation is wired into the jobs registry, not that its coverage is sufficient.
Missing chains remain visible; adding a floor never silently creates an instrument.

    python -m tools.coverage [--json]
"""
from __future__ import annotations

import argparse
import json

from instruments.data import EMPTY
from instruments.jobs import JOBS
from instruments.recipes import recipes_for
from standard.autonomy.agent import TASKS, WRITE_SCOPE
from standard.autonomy.read_model import measurement_for
from standard.floors import CONTRACTS, FLOORS


def inventory(targets=None) -> list[dict]:
    """One row per release target, derived from the actual registries; unknown targets stay MISSING."""
    recipes = recipes_for(EMPTY)
    floors_job = "floors" in JOBS and "floors" in CONTRACTS["observe"]["floors"]["jobs"]
    suite_job = "remediation" in JOBS and "remediation" in CONTRACTS["observe"]["suite"]["jobs"]
    production_job = "production" in CONTRACTS["observe"]["production"]["jobs"]
    rows = []
    for target in FLOORS["targets"] if targets is None else targets:
        tid, resource = target["id"], target["resource"]
        registered = measurement_for(target, FLOORS)
        kind, method, condition = registered["kind"], registered["method"], ""
        measure = ("REGISTERED" if kind == "registered_probe" and floors_job else
                   "CONDITIONAL" if kind == "conditional_program" and production_job else
                   "MANUAL" if kind == "manual" else "MISSING")
        if measure == "MISSING":
            method = None
        elif tid == "inventory":
            condition = "Readable tracked entries; not semantic, language or submodule coverage."
        elif measure == "CONDITIONAL":
            condition = "Requires configured sources or deployment; sources are attested inputs."
        elif measure == "MANUAL":
            condition = "No automated assessment of the asserted organisational control."
        repair = target.get("repair")
        if repair == "remediate":
            route = "recipe + review fallback" if tid in recipes else "model + human review"
            if tid not in TASKS and tid not in recipes or tid not in WRITE_SCOPE:
                route = "MISSING"
            verification = "tests + recipe reproduction or signed review" if suite_job else "MISSING"
        elif repair in ("deploy", "rollback"):
            route, verification = "release agent + guarded register", "switch measures + effect readback"
        elif repair == "inventory-refresh":
            route, verification = "declared capability; inventory measured by scanner", "readable tracked entries"
        elif target.get("human"):
            route, verification = "human", "remeasure" if measure != "MANUAL" else "fresh signed attestation"
        else:
            route, verification = "MISSING", "MISSING"
        rows.append({"target": tid, "resource": resource, "property": target["property"],
                     "measurement": measure, "method": method, "repair": route,
                     "verification": verification, "condition": condition})
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    rows = inventory()
    if args.json:
        print(json.dumps({"scope": "source inventory, not installation qualification", "targets": rows}, indent=2))
    else:
        print("Source inventory only: REGISTERED is not a proof of sufficient coverage or installation qualification.")
        print("| Target | Measurement | Repair | Verification |")
        print("|---|---|---|---|")
        for row in rows:
            print(f"| {row['target']} | {row['measurement']} | {row['repair']} | {row['verification']} |")
        print("\nScope and unimplemented capabilities: ARCHITECTURE.md §20.2–§20.4.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
