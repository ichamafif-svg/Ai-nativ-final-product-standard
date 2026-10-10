"""Take a trusted data snapshot (D17) for the pins of one requirements file:

    python tools/refresh_data.py requirements.txt [--actions owner/repo@ref ...] > data.json

Advisories come from the OSV API, package metadata from PyPI's JSON API, action refs from GitHub's API. Every fixed
version proposed by an advisory is audited too, so that the next main can be measured from the same snapshot. The
operator reviews the snapshot, then pins its digest in standard.toml ([data] digest); instruments and agents refuse
any other bytes.
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kernel import canon, digest  # noqa: E402

PIN = re.compile(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)")


def get(url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json", "User-Agent": "standard-refresh"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def advisories(name, version) -> list:
    reply = get("https://api.osv.dev/v1/query", {"package": {"name": name, "ecosystem": "PyPI"}, "version": version})
    out = []
    for vuln in reply.get("vulns", []):
        fixes = sorted({e["fixed"] for a in vuln.get("affected", []) for r in a.get("ranges", [])
                        for e in r.get("events", []) if "fixed" in e})
        out.append({"id": vuln["id"], "fix_versions": fixes})
    return out


def package(name) -> dict:
    info = get(f"https://pypi.org/pypi/{name}/json")["info"]
    return {"latest": info["version"], "license": info.get("license_expression") or info.get("license") or "",
            "classifiers": [c for c in info.get("classifiers", []) if c.startswith("License ::")]}


def snapshot(requirements: Path, actions=()) -> dict:
    pins = [m.groups() for line in requirements.read_text().splitlines() if (m := PIN.fullmatch(line.split("#")[0].strip()))]
    adv, todo = {}, [(n.lower(), v) for n, v in pins]
    while todo:
        name, version = todo.pop()
        if f"{name}=={version}" in adv:
            continue
        adv[f"{name}=={version}"] = found = advisories(name, version)
        todo += [(name, v) for a in found for v in a["fix_versions"]]
    resolved = {}
    for ref in actions:
        repo, tag = ref.split("@", 1)
        resolved[ref] = get(f"https://api.github.com/repos/{repo}/commits/{tag}")["sha"]
    return {"format": "standard-data/1", "taken_at": int(time.time() * 1000), "advisories": adv,
            "packages": {n.lower(): package(n) for n, _ in pins}, "actions": resolved}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    actions = sys.argv[sys.argv.index("--actions") + 1:] if "--actions" in sys.argv else []
    value = snapshot(Path(sys.argv[1]), actions)
    sys.stdout.buffer.write(canon(value))
    print(f"\n# digest {digest(value)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
