"""Fetch and verify the platform's pinned components (D68): `enclosure/components.toml`.

    python -m tools.components fetch [DIR]     download, check both digests, install into DIR/bin
    python -m tools.components where NAME      the installed path of one component, or nothing

DIR defaults to $STANDARD_COMPONENTS or ~/.standard/components. Nothing is installed whose archive or binary does
not match its pinned digest; an archive is only unpacked once its digest matched.
"""
from __future__ import annotations

import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from enclosure.components import digest, home, pins, where


def fetch(name: str, spec: dict, root: Path) -> Path:
    (root / "bin").mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp, "archive")
        with urllib.request.urlopen(spec["url"], timeout=300) as response, open(archive, "wb") as f:
            shutil.copyfileobj(response, f)
        if digest(archive) != spec["archive_sha256"]:
            raise RuntimeError(f"{name}: archive digest differs from the pin; nothing installed")
        if spec["url"].endswith(".tar.gz"):
            with tarfile.open(archive) as t:
                t.extractall(tmp, filter="data")
            binary = Path(tmp, spec["binary"])
        else:
            binary = archive
        if digest(binary) != spec["binary_sha256"]:
            raise RuntimeError(f"{name}: binary digest differs from the pin; nothing installed")
        target = root / "bin" / name
        shutil.copyfile(binary, target)
        target.chmod(0o755)
        return target


def main(argv) -> int:
    if not argv or argv[0] not in ("fetch", "where"):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[0] == "where":
        found = where(argv[1])
        if found:
            print(found)
        return 0 if found else 1
    root = Path(argv[1]) if len(argv) > 1 else home()
    for name, spec in pins().items():
        if where(name, root):
            print(f"{name} {spec['version']}: already installed")
            continue
        print(f"{name} {spec['version']}: {fetch(name, spec, root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
