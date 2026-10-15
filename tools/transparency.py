"""Publish the journal's head to transparency witnesses (L-04, `fabric/control/bt/transparency.py`).

    python -m tools.transparency checkpoint standard.toml          -> the signed note (C2SP tlog-checkpoint)
    python -m tools.transparency prove standard.toml OLD_SIZE      -> the consistency proof from OLD_SIZE (JSON)
    python -m tools.transparency verify NOTE ORIGIN VKEY [VKEY...]  -> size and root if every key signed it
    python -m tools.transparency vkey standard.toml                -> the verifier key to give witnesses

The note is signed by the `clock` role (the role that already witnesses the head), with its own key or through the
key service. `[transparency] origin` names the log (default: `standard/<genesis digest>`). Each checkpoint is also
kept as `checkpoints/<size>.note` beside the configuration, so a witness or monitor can be served the latest one and
the proof from what it saw. Submitting to a witness is the witness protocol's job (C2SP tlog-witness), not this tool's.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import tomllib

from fabric.control.bt import transparency
from fabric.control.bt.journal import Journal, PinStore
from engine.catalog.floors import RELEASE
from fabric.control.kernel import Kernel, canon
from fabric.control.runtime import code_digest
from fabric.control.runtime.operator import key

NAME = "standard-clock"


def _open(config: Path):
    c, base = tomllib.loads(config.read_text()), config.parent
    resolve = lambda p: (base / p).resolve()
    journal = Journal(resolve(c["ledger"]["journal"]), Kernel(RELEASE, code_digest()),
                      PinStore(resolve(c["ledger"]["pins"])), c["ledger"]["genesis"])
    origin = c.get("transparency", {}).get("origin") or f"standard/{c['ledger']['genesis']}"
    return c, base, resolve, journal, origin


def leaves(journal) -> list:
    return [canon(e) for e in journal.entries()]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.transparency")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("checkpoint", "vkey"):
        sub.add_parser(name).add_argument("config", type=Path)
    prove = sub.add_parser("prove")
    prove.add_argument("config", type=Path)
    prove.add_argument("old", type=int)
    verify = sub.add_parser("verify")
    verify.add_argument("note", type=Path)
    verify.add_argument("origin")
    verify.add_argument("vkeys", nargs="+")
    a = parser.parse_args(argv)

    if a.command == "verify":
        keys = {}
        for vkey in a.vkeys:
            name, _, raw = vkey.split("+")
            keys[name] = base64.b64decode(raw)[1:]
        try:
            size, root = transparency.verify(a.note.read_text(), a.origin, keys)
        except transparency.TransparencyError as exc:
            print(json.dumps({"verified": False, "why": str(exc)}))
            return 1
        print(json.dumps({"verified": True, "size": size, "root": base64.b64encode(root).decode()}))
        return 0

    c, base, resolve, journal, origin = _open(a.config)
    if a.command == "vkey":
        signer = key(resolve(c["keys"]["dir"]), "clock")
        print(transparency.verifier_key(NAME, base64.b64decode(signer.root_key()["public"])))
    elif a.command == "checkpoint":
        signer = key(resolve(c["keys"]["dir"]), "clock")
        items = leaves(journal)
        note = transparency.checkpoint(origin, items, signer, NAME)
        folder = base / "checkpoints"
        folder.mkdir(exist_ok=True)
        (folder / f"{len(items)}.note").write_text(note)
        sys.stdout.write(note)
    else:
        items = leaves(journal)
        proof = transparency.consistency(items, a.old)
        print(json.dumps({"old": a.old, "new": len(items),
                          "proof": [base64.b64encode(p).decode() for p in proof]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
