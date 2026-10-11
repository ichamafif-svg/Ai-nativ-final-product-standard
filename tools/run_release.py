"""Run the live release of a product and follow its switches (D30), without any privilege over the guard.

    python tools/run_release.py /srv/standard/run/current 9000

Starts `<current>/service.py PORT` and checks the link every second: when the guard switches it (deploy or rollback),
the old process is stopped and the new release started. The product's own process, not a trusted component.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time


def live(link: str) -> str | None:
    try:
        return os.readlink(link)
    except OSError:
        return None


def main(link: str, port: str) -> None:
    running, child = None, None
    while True:
        target = live(link)
        if target != running or (child is not None and child.poll() is not None):
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
            running = target
            child = None
            if target is not None:
                release = os.path.join(os.path.dirname(link), target)
                child = subprocess.Popen([sys.executable, os.path.join(release, "service.py"), port], cwd=release)
                print(f"live: {target}", flush=True)
        time.sleep(1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
