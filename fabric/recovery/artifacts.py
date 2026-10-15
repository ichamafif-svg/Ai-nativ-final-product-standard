"""Reconstruct an artifact in a new directory using Python's native safe tar extraction.

The digest must come from an independently trusted release record (for example a TUF
target verified by tools.distribute). This function checks bytes, not provenance or
rollback freshness. It neither restores keys nor changes deployment registers.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


def prepare(archive, expected_digest: str, destination, *, max_bytes: int = 1 << 30) -> Path:
    """Fail without publishing on corruption, unsafe entries, overflow or an existing destination.

    The parent directory and archive are controlled by the recovery operator. The open
    archive descriptor is hashed and extracted without reopening its pathname.
    """
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
        raise ValueError("an exact trusted SHA-256 digest is required")
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("a positive extraction budget is required")
    target = Path(destination).absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target.parent / (target.name + ".restore.lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.exists() or target.is_symlink():
            raise FileExistsError(target)
        with open(archive, "rb") as raw, tempfile.TemporaryDirectory(dir=target.parent, prefix=".restore-") as work:
            digest = "sha256:" + hashlib.file_digest(raw, "sha256").hexdigest()
            if digest != expected_digest:
                raise ValueError("recovery artifact digest mismatch")
            raw.seek(0)
            with tarfile.open(fileobj=raw, mode="r:*") as source:
                names, total, members = set(), 0, []
                for member in source:
                    path = PurePosixPath(member.name)
                    if (path.is_absolute() or ".." in path.parts or not path.parts
                            or not (member.isfile() or member.isdir()) or str(path) in names):
                        raise ValueError("unsafe or duplicate recovery entry")
                    names.add(str(path))
                    total += member.size
                    if total > max_bytes or len(names) > 100_000:
                        raise ValueError("recovery extraction budget exceeded")
                    members.append(member)
                source.extractall(work, members=members, filter="data")
            os.rename(work, target)
    return target
