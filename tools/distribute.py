"""Distribute releases through The Update Framework (TUF): an installation fetches only what the release roles signed.

A release archive and its provenance (`tools/provenance.py`) are TUF targets. Four roles, each its own Ed25519 key:
root (offline; it names the others), targets (what a release is), snapshot and timestamp (freshness, against
rollback and freeze). A client holding the root it trusts fetches through `python-tuf`'s reference client, which
refuses an unsigned, expired, rolled-back or altered file. The repository is static files: any web server serves it.

    python -m tools.distribute init REPO KEYS              -> REPO/metadata (1.root.json ...), KEYS/<role>.pem
    python -m tools.distribute add REPO KEYS FILE...       -> the files become signed targets (new versions)
    python -m tools.distribute fetch URL ROOT NAME OUT     -> OUT/NAME, verified, or an error and nothing

Keys here are files for the prototype; `KEYS` for root belongs offline, and targets can be signed through the key
service as Standard's other roles are. Expiry: root one year, targets three months, snapshot one week, timestamp one day.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata, MetaFile, Root, Snapshot, TargetFile, Targets, Timestamp
from tuf.api.serialization.json import JSONSerializer

ROLES = {"root": 365, "targets": 90, "snapshot": 7, "timestamp": 1}


def _expiry(role: str) -> datetime:
    return (datetime.now(timezone.utc) + timedelta(days=ROLES[role])).replace(microsecond=0)


def _signer(keys: Path, role: str) -> CryptoSigner:
    pem = (keys / f"{role}.pem").read_bytes()
    private = serialization.load_pem_private_key(pem, password=None)
    return CryptoSigner(private)


def _write(repo: Path, md: Metadata, name: str) -> None:
    folder = repo / "metadata"
    folder.mkdir(parents=True, exist_ok=True)
    md.to_file(str(folder / name), JSONSerializer(compact=False))


def _sign(md: Metadata, signer: CryptoSigner) -> Metadata:
    md.signatures.clear()
    md.sign(signer)
    return md


def init(repo: Path, keys: Path) -> None:
    keys.mkdir(parents=True, exist_ok=True)
    root = Root(expires=_expiry("root"), consistent_snapshot=False)
    signers = {}
    for role in ROLES:
        signer = CryptoSigner.generate_ed25519()
        path = keys / f"{role}.pem"
        path.write_bytes(signer.private_bytes)
        path.chmod(0o600)
        root.add_key(signer.public_key, role)
        signers[role] = signer
    targets = Metadata(Targets(expires=_expiry("targets")))
    snapshot = Metadata(Snapshot(expires=_expiry("snapshot")))
    timestamp = Metadata(Timestamp(expires=_expiry("timestamp")))
    _write(repo, _sign(Metadata(root), signers["root"]), "1.root.json")
    shutil.copy(repo / "metadata" / "1.root.json", repo / "metadata" / "root.json")
    _publish(repo, targets, snapshot, timestamp, signers)


def _publish(repo, targets, snapshot, timestamp, signers) -> None:
    _write(repo, _sign(targets, signers["targets"]), "targets.json")
    snapshot.signed.meta["targets.json"] = MetaFile(version=targets.signed.version)
    _write(repo, _sign(snapshot, signers["snapshot"]), "snapshot.json")
    timestamp.signed.snapshot_meta = MetaFile(version=snapshot.signed.version)
    _write(repo, _sign(timestamp, signers["timestamp"]), "timestamp.json")


def add(repo: Path, keys: Path, files) -> None:
    folder = repo / "metadata"
    targets = Metadata[Targets].from_file(str(folder / "targets.json"))
    snapshot = Metadata[Snapshot].from_file(str(folder / "snapshot.json"))
    timestamp = Metadata[Timestamp].from_file(str(folder / "timestamp.json"))
    (repo / "targets").mkdir(exist_ok=True)
    for f in files:
        f = Path(f)
        shutil.copy(f, repo / "targets" / f.name)
        targets.signed.targets[f.name] = TargetFile.from_file(f.name, str(f))
    for md, role in ((targets, "targets"), (snapshot, "snapshot"), (timestamp, "timestamp")):
        md.signed.version += 1
        md.signed.expires = _expiry(role)
    _publish(repo, targets, snapshot, timestamp, {r: _signer(keys, r) for r in ("targets", "snapshot", "timestamp")})


def fetch(url: str, trusted_root: Path, name: str, out: Path) -> Path:
    from tuf.ngclient import Updater
    cache = out / ".tuf"
    cache.mkdir(parents=True, exist_ok=True)
    updater = Updater(metadata_dir=str(cache), metadata_base_url=f"{url.rstrip('/')}/metadata/",
                      target_base_url=f"{url.rstrip('/')}/targets/", target_dir=str(out),
                      bootstrap=trusted_root.read_bytes())          # the root this installation trusts, never a download
    updater.refresh()
    info = updater.get_targetinfo(name)
    if info is None:
        raise LookupError(f"{name} is not a signed target")
    return Path(updater.download_target(info, str(out / name)))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.distribute")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init")
    p.add_argument("repo", type=Path)
    p.add_argument("keys", type=Path)
    p = sub.add_parser("add")
    p.add_argument("repo", type=Path)
    p.add_argument("keys", type=Path)
    p.add_argument("files", nargs="+")
    p = sub.add_parser("fetch")
    p.add_argument("url")
    p.add_argument("root", type=Path)
    p.add_argument("name")
    p.add_argument("out", type=Path)
    a = parser.parse_args(argv)
    if a.command == "init":
        init(a.repo, a.keys)
    elif a.command == "add":
        add(a.repo, a.keys, a.files)
    else:
        print(fetch(a.url, a.root, a.name, a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
