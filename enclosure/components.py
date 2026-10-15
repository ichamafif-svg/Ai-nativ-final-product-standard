"""Where the platform's pinned components are (D68, `components.toml`): a binary is found only if its digest is
the pinned one. Fetching them is `python -m tools.components fetch`."""
from __future__ import annotations

import hashlib
import os
import tomllib
from pathlib import Path

PINS = Path(__file__).with_name("components.toml")


def home() -> Path:
    return Path(os.environ.get("STANDARD_COMPONENTS") or Path.home() / ".standard" / "components")


def pins() -> dict:
    return tomllib.loads(PINS.read_text())


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def where(name: str, root: Path | None = None) -> str | None:
    """The installed binary of a component, only if its digest is the pinned one."""
    spec = pins().get(name)
    path = (root or home()) / "bin" / name
    if spec and path.is_file() and digest(path) == spec["binary_sha256"]:
        return str(path)
    return None
