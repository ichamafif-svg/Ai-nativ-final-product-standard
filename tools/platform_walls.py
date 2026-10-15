"""Measure the platform's walls (D68): `python -m tools.platform_walls` prints {wall: held|broken|unmeasured}."""
import json
import sys

from engine.catalog import effective, load
from engine.verification.platform_walls import measure

if __name__ == "__main__":
    walls = measure(effective(load(), {}))
    print(json.dumps(walls, indent=2))
    sys.exit(1 if "broken" in walls.values() else 0)
