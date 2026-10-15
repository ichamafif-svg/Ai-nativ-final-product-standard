"""Qualification probes for one installation (ARCHITECTURE.md §15.2).

    python tools/qualify.py standard.toml

Each probe checks what can be checked from this host and states what it does not prove. A PASS here is evidence for
an independent assessor, not a qualification; a FAIL names the physical premise that does not hold. Exit code 1 when
any probe fails.
"""
from __future__ import annotations

import json
import base64
import os
import sqlite3
import subprocess
import time
import sys
import tomllib
from pathlib import Path
from contextlib import closing

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fabric.control.runtime import code_digest  # noqa: E402
from engine.catalog.floors import RELEASE  # noqa: E402
from fabric.control.kernel import Kernel, empty  # noqa: E402
from fabric.control.kernel.canon import parse  # noqa: E402
from fabric.control.bt.assessment import SignedAssessment  # noqa: E402
from fabric.control.bt.signing import Signer  # noqa: E402
from fabric.control.bt.isolation import Isolation  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

def probe(name, ok, observed, proves, does_not_prove):
    return {"probe": name, "result": "PASS" if ok else "FAIL", "observed": observed, "proves": proves,
            "does_not_prove": does_not_prove}


def release_basis(journal, genesis, actual):
    """Read-only: validate the signed genesis with K and compare it to the configured external pin."""
    with closing(sqlite3.connect(Path(journal).resolve().as_uri() + "?mode=ro", uri=True)) as db:
        row = db.execute("SELECT raw FROM entries WHERE seq=0").fetchone()
    if row is None:
        raise ValueError("no genesis entry")
    record, delta = Kernel(RELEASE, actual).decide(empty(), parse(bytes(row[0])))
    if record["kind"] != "genesis":
        raise ValueError("first entry is not genesis")
    domain = next(op[2] for op in delta if op[:2] == ("set", "domain"))
    if domain != genesis or record["body"]["code"] != actual:
        raise ValueError("genesis pin or source fingerprint mismatch")
    return record["body"]["root"]["identities"]


def qualify(config_path) -> list:
    path = Path(config_path).resolve()
    c, base = tomllib.loads(path.read_text()), path.parent
    resolve = lambda p: (base / p).resolve()
    journal, pins = resolve(c["ledger"]["journal"]), resolve(c["ledger"]["pins"])
    keys = resolve(c["keys"]["dir"])
    out = []
    actual = code_digest()
    try:
        identities = release_basis(journal, c["ledger"]["genesis"], actual)
        release_ok, release_observed = True, {"code": actual, "genesis": c["ledger"]["genesis"]}
    except Exception as exc:
        identities, release_ok = {}, False
        release_observed = f"{type(exc).__name__}: {exc}"
    same = os.stat(journal.parent).st_dev == os.stat(pins.parent).st_dev
    out.append(probe("T04 pins apart from the journal", not same,
                     f"journal device {os.stat(journal.parent).st_dev}, pins device {os.stat(pins.parent).st_dev}",
                     "the pins are not on the journal's filesystem",
                     "that the two volumes are not restored together from one backup (L-04)"))
    sep = c.get("separation")
    owner = __import__("pwd").getpwnam(sep["guard_user"]).pw_uid if sep else os.getuid()
    files = list(keys.glob("*.key"))
    loose = [p.name for p in files if p.is_symlink() or not p.is_file() or p.stat().st_mode & 0o077
             or p.stat().st_uid != owner]
    local_public = set()
    for file in files:
        if file.name in loose:
            continue
        try:
            private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(file.read_text().strip(), validate=True))
            local_public.add(Signer("diagnostic", private).public)
        except (OSError, ValueError):
            loose.append(file.name)
    out.append(probe("key files owner-only", bool(files) and not loose, loose or f"{len(files)} owner-only files",
                     "no other local user can read a key file", "who else holds a copy (custody, L-03)"))
    humans = [h for h, spec in identities.items() if spec["kind"] == "human"
              and any(key["public"] in local_public for key in spec["keys"])]
    out.append(probe("T02 the human holds their own key", release_ok and not humans, humans or "no human key here",
                     "no human key on the operator's host: the human signs from their own device",
                     "that the device is the human's alone (G01)"))
    witnesses = [w for w, spec in identities.items() if spec["kind"] == "witness"
                 and any(key["public"] in local_public for key in spec["keys"])]
    out.append(probe("T03 time", release_ok and bool(witnesses), {"witness_keys_here": witnesses},
                     "one human, one agent: the operator's clock states time (F0-1)",
                     "that the operator's clock is right; the operator can advance time alone"))
    try:
        bundle = json.loads(resolve(c["assessment"]["path"]).read_text())
        assessment = SignedAssessment(bundle, {n: base64.b64decode(k, validate=True)
                                              for n, k in c["assessment"]["assessors"].items()})
        assessment.check([], release=actual, genesis=c["ledger"]["genesis"], ledger=str(journal),
                         now=int(time.time() * 1000))
        independent, observed = release_ok and assessment.independent, "authenticated, bound and in date at the host's wall time"
    except Exception as exc:
        independent, observed = False, f"{type(exc).__name__}: {exc}"
    out.append(probe("independent assessment", independent, observed,
                     "a pinned assessor signed a bound assessment that declares independence",
                     "that independence is physical, the assessor's claims are true, or this host's clock is trusted"))
    runner = c.get("tests", {}).get("runner_user")
    try:
        import pwd
        entry = pwd.getpwnam(runner) if runner else None
        guard = sep["guard_user"] if sep else None
        groups = os.getgrouplist(runner, entry.pw_gid) if entry else []
        guard_entry = pwd.getpwnam(guard) if guard else None
        clean = (entry is not None and guard_entry is not None and entry.pw_uid not in (0, guard_entry.pw_uid)
                 and guard_entry.pw_gid not in groups)
        if clean:
            run = subprocess.run(["sudo", "-n", "-u", runner, "--", "/usr/bin/env", "-i",
                                  "PATH=/usr/bin:/bin", "unshare", "-rn", "true"],
                                 capture_output=True, timeout=10)
            clean = run.returncode == 0
    except (KeyError, OSError, subprocess.SubprocessError):
        entry, clean, groups = None, False, []
    unconfined = c.get("tests", {}).get("unconfined") is True
    out.append(probe("T06 contributors' code runs isolated",
                     bool(clean and not unconfined and Isolation(runner).candidate_fs_confined),
                     {"runner": runner, "groups": groups, "identity_and_network": bool(clean),
                      "unconfined_demo_executor": unconfined,
                      "filesystem": "the bac under the runner account (D68)" if runner and
                      Isolation(runner).candidate_fs_confined else "the bac does not run under the runner here"},
                     "the code a contribution brings runs without keys, network or access to unrelated files",
                     "that the kernel's namespaces and sudo are themselves sound"))
    try:                                                    # D37: the signed measures replay from their records
        from tools import replay
        signed = replay.ledger(path, 5)
        results = [replay.replay(replay.host_for(path), r, facts) for r, facts in signed.items()]
        bad = [r for r in results if r["result"] != "agrees"]
        observed = bad or f"{len(results)} latest records agree" if results else "no measurement recorded yet"
    except Exception as exc:
        results, bad, observed = [], [exc], f"{type(exc).__name__}: {exc}"
    out.append(probe("T06 measures replay from their records", bool(results) and not bad, observed,
                     "the latest signed measures are what the pinned programs compute from what was recorded",
                     "that the recorded inputs are what the world was (a source's word, the host's fetch)"))
    if sep:                                                 # D38 (E): count privileges, not only lines
        import grp
        guard = sep["guard_user"]
        members = sorted(grp.getgrnam(guard).gr_mem)
        expected = {sep.get("agent_user", "standard-agent"), "standard-web", "standard-gate"}
        sudo = []
        for f in [Path("/etc/sudoers"), *sorted(Path("/etc/sudoers.d").glob("*"))]:
            try:
                sudo += [f"{f.name}: {line.strip()}" for line in f.read_text().splitlines()
                         if "standard" in line and not line.lstrip().startswith("#")]
            except OSError:
                pass
        extra = [m for m in members if m not in expected]
        out.append(probe("privileges around the guard", not extra,
                         {"group " + guard: members, "beyond agent, web, gate": extra, "sudo": sudo},
                         "who can read the guard's files and join its socket, and every sudo rule naming Standard",
                         "privileges granted outside this host's groups and sudoers (cloud IAM, CI secrets)"))
    out.append(probe("T01 code release", release_ok, release_observed,
                     "the source files match the signed genesis and configured genesis pin",
                     "that the configured pin has independent custody or the process loaded these files (verify before import)"))
    repo = c["repository"]
    if repo["kind"] == "github":
        from fabric.control.bt.adapters import GitHub
        gh = GitHub(repo["name"], resolve(repo["token_file"]).read_text().strip())
        try:
            rules = gh.protections()
            need = {"update", "deletion", "non_fast_forward"}
            out.append(probe("T07 only the guard moves main", need <= rules, sorted(rules),
                             "main is protected against direct update, deletion and force push",
                             "who holds bypass rights; list the ruleset's bypass actors and every token with write"))
        except Exception as exc:
            out.append(probe("T07 only the guard moves main", False, f"{type(exc).__name__}: {exc}",
                             "nothing", "the protection of main could not be read"))
    elif not sep:
        out.append(probe("T07 only the guard moves main", False, "local git repository, one Unix user",
                         "nothing", "without `ceremony.py separate`, the agent's user can write the repository"))
    else:
        import pwd
        guard, agent = pwd.getpwnam(sep["guard_user"]), pwd.getpwnam(sep["agent_user"])
        tree = Path(repo["path"])
        writable = [str(q) for q in [tree, *tree.rglob("*")] if not q.is_symlink()
                    and (q.stat().st_uid != guard.pw_uid or q.stat().st_mode & 0o022)]
        ok = not writable and guard.pw_uid != agent.pw_uid and 0 not in (guard.pw_uid, agent.pw_uid)
        out.append(probe("T07 only the guard moves main", ok,
                         writable[:5] or f"{tree} owned by {guard.pw_name}, no group or other write; "
                                         f"the agent runs as {agent.pw_name}",
                         "the host's kernel refuses any write to the repository by the agent's user",
                         "root, sudo rules that let someone become the guard, and the guard process itself"))
    if "hosting" in c:                                     # D23: clients reach repositories only through the gate
        import pwd
        import tomllib as toml
        gate, guard = pwd.getpwnam(c["hosting"]["gate_user"]), pwd.getpwnam(sep["guard_user"]) if sep else None
        hosted = toml.loads(Path(c["hosting"]["config"]).read_text())["repositories"]
        bad = [n for n, r in hosted.items() if guard is None or Path(r["inbox"]).stat().st_uid == guard.pw_uid
               or any(q.stat().st_uid != guard.pw_uid or q.stat().st_mode & 0o022
                      for q in [Path(r["canonical"]), *Path(r["canonical"]).rglob("*")] if not q.is_symlink())]
        ok = not bad and guard is not None and gate.pw_uid not in (0, guard.pw_uid)
        out.append(probe("T07 hosted repositories behind the gate", ok, bad or f"{len(hosted)} repositories; "
                         f"canonical owned by {guard.pw_name}, inboxes by {gate.pw_name}",
                         "a client's push, run as the gate user, cannot write a canonical repository",
                         "sshd's configuration, other accounts on the host, and keys authorized outside tools/hosting.py"))
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    report = qualify(sys.argv[1])
    print(json.dumps(report, indent=2))
    return 1 if any(p["result"] == "FAIL" for p in report) else 0


if __name__ == "__main__":
    sys.exit(main())
