"""Inventory guarantees or measure the local fabric fixtures. Never qualify a production deployment.

    python -m tools.fabric inventory
    python -m tools.fabric measure --strict
"""
import argparse
import json
import time

from engine.catalog import effective, load
from engine.verification import platform_walls, walls
from fabric.control.runtime import code_digest
from fabric.evidence.guarantees import inventory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "measure"))
    parser.add_argument("--strict", action="store_true", help="nonzero if any local wall is not measured held")
    args = parser.parse_args(argv)
    if args.command == "inventory":
        print(json.dumps({"scope": "engineering inventory; no deployment qualification", "guarantees": inventory()},
                         indent=2))
        return 0
    started = time.time()
    results = {"runtime": walls.measure(), "platform": platform_walls.measure(effective(load(), {}))}
    incomplete = [f"{group}/{name}" for group, entries in results.items()
                  for name, status in entries.items() if status != "held"]
    print(json.dumps({"schema": "standard-fabric-measurement/1", "scope": "local fixtures only",
                      "installation": code_digest(), "started_at": started, "finished_at": time.time(),
                      "results": results, "not_held": incomplete, "production_qualified": False}, indent=2))
    return int(any(status == "broken" for entries in results.values() for status in entries.values())
               or (args.strict and bool(incomplete)))


if __name__ == "__main__":
    raise SystemExit(main())
