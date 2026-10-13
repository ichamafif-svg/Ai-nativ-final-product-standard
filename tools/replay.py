"""Replay the measures of an installation (D37): every fact the scanner signed is a pure function of a run record.

    python tools/replay.py standard.toml [--limit N] [RECORD ...]

A measurement in the ledger names its method (`programs@<digest>/<contract>`: the pinned programs, instruments/) and
its artifact (the OBSERVE boundary transaction, D38, which names the run record: job, inputs by digest, answer). This tool opens the ledger read-only, takes the records the
latest measurements name (or the ones given), runs each job again with the same programs on the same recorded inputs,
in its own isolated runner, and compares the facts. It holds no key and signs nothing: anyone with a copy of the
ledger, the evidence store and the repository can run it, on another machine, under another administrator.

Each record ends in one of:
    agrees       the ledger's signed facts are in the record, and the programs compute the record again
    disagrees    the scanner signed a status its record does not hold, or the programs compute other facts
    programs     the record was made by other programs than these: replay with that release
    unreadable   the record or one of its inputs is missing or corrupt
Exit code 1 when any record disagrees or is unreadable.
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from standard.floors import RELEASE  # noqa: E402
from kernel import Kernel  # noqa: E402
from bt.host import Evidence, Host  # noqa: E402
from bt.journal import Journal, PinStore  # noqa: E402
from standard.runtime import code_digest  # noqa: E402
from standard.runtime.daemon import isolation  # noqa: E402


def facts(output: dict) -> set:
    return {tuple(f[:3]) for f in output.get("facts", [])}


def replay(host: Host, record: str, signed=frozenset()) -> dict:
    """signed: the (resource, property, status) the ledger admitted with this record as artifact."""
    try:
        rec = json.loads(host.evidence.get(record))
        if rec.get("bt") == "observe":                      # D38: a boundary transaction names its run record
            rec = json.loads(host.evidence.get(rec["material"]["run"]))
    except (OSError, LookupError, ValueError, KeyError) as exc:
        return {"record": record, "result": "unreadable", "why": f"{type(exc).__name__}: {exc}"}
    if rec.get("method") != host.method:
        return {"record": record, "result": "programs", "why": f"made by {rec.get('method')}, these are {host.method}"}
    try:
        again = host.run(rec["job"], rec["inputs"], network=rec.get("network", False))
    except (OSError, LookupError, ValueError) as exc:
        return {"record": record, "job": rec["job"], "result": "unreadable", "why": f"{type(exc).__name__}: {exc}"}
    if "error" in again:
        return {"record": record, "job": rec["job"], "result": "unreadable", "why": again["error"][:300]}
    before, after = facts(rec["output"]), facts(again)
    unrecorded = set(signed) - before
    if before == after and not unrecorded:
        return {"record": record, "job": rec["job"], "result": "agrees", "facts": len(before),
                "ledger": len(set(signed))}
    return {"record": record, "job": rec["job"], "result": "disagrees", "ledger_not_in_record": sorted(unrecorded),
            "recorded": sorted(before - after), "computed": sorted(after - before)}


def ledger(config: Path, limit: int) -> dict:
    """{artifact: {(resource, property, status)}}: what the latest measurements in the ledger signed, newest first."""
    c, base = tomllib.loads(config.read_text()), config.parent
    resolve = lambda p: (base / p).resolve()
    journal = Journal(resolve(c["ledger"]["journal"]), Kernel(RELEASE, code_digest()),
                      PinStore(resolve(c["ledger"]["pins"])), c["ledger"]["genesis"])
    out = {}
    for o in sorted(journal.snapshot()["observations"].values(), key=lambda o: -o["at"]):
        artifact = o.get("artifact")
        if artifact and not artifact.endswith("0" * 64) and (artifact in out or len(out) < limit):
            out.setdefault(artifact, set()).add((o["resource"], o["property"], o["status"]))
    return out


def records(config: Path, limit: int) -> list:
    """The run records the latest measurements in the ledger name, newest first."""
    return list(ledger(config, limit))


def host_for(config: Path) -> Host:
    c, base = tomllib.loads(config.read_text()), config.parent
    resolve = lambda p: (base / p).resolve()
    repo = c["repository"]
    data = c.get("data")
    return Host(ROOT, Evidence(base / "evidence"), resolve(repo.get("path") or repo["mirror"]),
                isolation=isolation(c, c.get("demo") is True),
                stores={"requests": resolve(c.get("build", {}).get("store", "requests"))},
                data=(resolve(data["path"]), data["digest"]) if data else None)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config")
    parser.add_argument("records", nargs="*")
    parser.add_argument("--limit", type=int, default=20)
    a = parser.parse_args(argv)
    config = Path(a.config).resolve()
    host = host_for(config)
    signed = ledger(config, a.limit if not a.records else 10 ** 6)
    out = [replay(host, r, signed.get(r, frozenset())) for r in (a.records or list(signed)[:a.limit])]
    print(json.dumps(out, indent=2))
    return 1 if any(r["result"] in ("disagrees", "unreadable") for r in out) else 0


if __name__ == "__main__":
    sys.exit(main())
