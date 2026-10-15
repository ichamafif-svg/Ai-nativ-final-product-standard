"""SLSA provenance for what Standard produces: each instrument run and each release (in-toto Statement v1, DSSE).

The ledger already holds the scanner's signed facts and names the run record each one came from (D37, D38). This
tool restates a run record in the format supply-chain verifiers read (SLSA Provenance v1): the record is the subject,
the pinned programs are the builder, the inputs by digest are the resolved dependencies. A release gets the same:
the source tree's archive is the subject, the commit and the trust core's digest are its parameters.

    python -m tools.provenance run standard.toml RECORD     -> DSSE envelope, signed by the scanner, kept in evidence
    python -m tools.provenance release DIR [--key KEY]      -> DIR/standard-<commit>.tar.gz and its provenance

These statements add no authority: the kernel never reads them, and `tools/replay.py` remains the way to check that
a record computes again. They let someone outside, with standard tools (slsa-verifier, in-toto, cosign verify-blob
--bundle aside), see who claims to have produced which bytes from which inputs.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import tomllib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fabric.control.bt.signing import Signer
from fabric.control.kernel import canon
from fabric.control.kernel.identity import PAYLOAD_TYPE, STATEMENT_TYPE, pae

ROOT = Path(__file__).resolve().parents[1]
SLSA = "https://slsa.dev/provenance/v1"
RUN_TYPE = "https://standard.invalid/instrument-run/v1"
RELEASE_TYPE = "https://standard.invalid/release/v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dependencies(inputs: dict) -> list:
    """Every input the run read, by the digest the record names (evidence) or by commit."""
    out = []
    for name, resolved in sorted(inputs.items()):
        if not isinstance(resolved, dict):
            continue
        if resolved.get("evidence"):
            out.append({"name": name, "digest": {"sha256": resolved["evidence"].split(":", 1)[1]}})
        for kind in ("commit", "manifest"):
            if resolved.get(kind):
                out.append({"name": name, "digest": {"gitCommit": resolved[kind]}})
        if "value" in resolved or "series" in resolved:
            out.append({"name": name, "digest": {"sha256": _sha(json.dumps(resolved, sort_keys=True).encode())}})
    return out


def run_statement(raw: bytes) -> dict:
    """The provenance of one run record (its exact bytes, as kept in evidence)."""
    record = json.loads(raw)
    return {"_type": STATEMENT_TYPE, "predicateType": SLSA,
            "subject": [{"name": f"evidence/{_sha(raw)}", "digest": {"sha256": _sha(raw)}}],
            "predicate": {
                "buildDefinition": {"buildType": RUN_TYPE,
                                    "externalParameters": {"job": record["job"],
                                                           "network": bool(record.get("network"))},
                                    "resolvedDependencies": _dependencies(record.get("inputs", {}))},
                "runDetails": {"builder": {"id": f"https://standard.invalid/{record['method']}"}}}}


def release_statement(archive: bytes, name: str, commit: str, core: str, locks: dict) -> dict:
    return {"_type": STATEMENT_TYPE, "predicateType": SLSA,
            "subject": [{"name": name, "digest": {"sha256": _sha(archive)}}],
            "predicate": {
                "buildDefinition": {"buildType": RELEASE_TYPE,
                                    "externalParameters": {"commit": commit},
                                    "internalParameters": {"core": core},
                                    "resolvedDependencies": [{"name": n, "digest": {"sha256": d}}
                                                             for n, d in sorted(locks.items())]},
                "runDetails": {"builder": {"id": "https://standard.invalid/tools/provenance"}}}}


def envelope(statement: dict, signer) -> dict:
    """DSSE over the canonical statement (RFC 8785 bytes), as the ledger's own envelopes are."""
    payload = canon(statement)
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
            "signatures": [signer.sign(pae(payload))]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.provenance")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("config", type=Path)
    run.add_argument("record")
    rel = sub.add_parser("release")
    rel.add_argument("out", type=Path)
    rel.add_argument("--key", type=Path, help="raw Ed25519 private key, base64 (default: an unsigned statement)")
    a = parser.parse_args(argv)

    if a.command == "run":
        from fabric.control.bt.host import Evidence
        from fabric.control.runtime.operator import key
        c = tomllib.loads(a.config.read_text())
        evidence = Evidence(a.config.parent / "evidence")
        statement = run_statement(evidence.get(a.record))
        signed = envelope(statement, key((a.config.parent / c["keys"]["dir"]).resolve(), "scanner"))
        digest = evidence.put(json.dumps(signed, sort_keys=True).encode())
        print(json.dumps({"record": a.record, "provenance": digest}))
        return 0

    from fabric.control.bt.release import code_digest
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                            check=True).stdout.strip()
    name = f"standard-{commit[:12]}.tar.gz"
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar.gz", "--prefix=standard/", commit],
                             capture_output=True, check=True).stdout
    locks = {p: _sha((ROOT / p).read_bytes()) for p in ("requirements.hashes", "fabric/supply_chain/components.toml",
                                                        "fabric/supply_chain/egress-requirements.txt") if (ROOT / p).exists()}
    with tempfile.TemporaryDirectory() as tree:                 # the core digest of the archived bytes, not this tree
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(tree, filter="data")
        core = code_digest(Path(tree) / "standard")
    statement = release_statement(archive, name, commit, core, locks)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / name).write_bytes(archive)
    if a.key:
        signer = Signer("release", Ed25519PrivateKey.from_private_bytes(base64.b64decode(a.key.read_text().strip())))
        (a.out / f"{name}.intoto.jsonl").write_text(json.dumps(envelope(statement, signer)) + "\n")
    else:
        (a.out / f"{name}.statement.json").write_text(json.dumps(statement, indent=1) + "\n")
    print(json.dumps({"archive": name, "sha256": statement["subject"][0]["digest"]["sha256"], "signed": bool(a.key)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
