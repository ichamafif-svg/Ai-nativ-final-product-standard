"""Read the engineering guarantee inventory; never infer deployment qualification."""
from pathlib import Path
import tomllib


def inventory() -> list[dict]:
    path = Path(__file__).resolve().parents[1] / "guarantees.toml"
    return tomllib.loads(path.read_text())["guarantee"]
