"""Qualification probes for one installation (ARCHITECTURE.md §15.2).

    python tools/qualify.py standard.toml

Each probe checks what can be checked from this host and states what it does not prove. A PASS here is evidence for
an independent assessor, not a qualification; a FAIL names the physical premise that does not hold. Exit code 1 when
any probe fails.
"""
from __future__ import annotations

import json
import os
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trusted.release import code_digest  # noqa: E402

HUMANS = ("h1", "h2", "h3", "h4")
WITNESSES = ("w1", "w2")


def probe(name, ok, observed, proves, does_not_prove):
    return {"probe": name, "result": "PASS" if ok else "FAIL", "observed": observed, "proves": proves,
            "does_not_prove": does_not_prove}


def qualify(config_path) -> list:
    path = Path(config_path).resolve()
    c, base = tomllib.loads(path.read_text()), path.parent
    resolve = lambda p: (base / p).resolve()
    journal, pins = resolve(c["ledger"]["journal"]), resolve(c["ledger"]["pins"])
    keys = resolve(c["keys"]["dir"])
    out = []
    same = os.stat(journal.parent).st_dev == os.stat(pins.parent).st_dev
    out.append(probe("T04 pins apart from the journal", not same,
                     f"journal device {os.stat(journal.parent).st_dev}, pins device {os.stat(pins.parent).st_dev}",
                     "the pins are not on the journal's filesystem",
                     "that the two volumes are not restored together from one backup (L-04)"))
    sep = c.get("separation")
    owner = __import__("pwd").getpwnam(sep["guard_user"]).pw_uid if sep else os.getuid()
    loose = [p.name for p in keys.glob("*.key") if p.stat().st_mode & 0o077 or p.stat().st_uid != owner]
    out.append(probe("key files owner-only", not loose, loose or "all 0600, owned by this user",
                     "no other local user can read a key file", "who else holds a copy (custody, L-03)"))
    humans = [h for h in HUMANS if (keys / f"{h}.key").exists()]
    out.append(probe("T02 humans hold their own keys", len(humans) <= 1, humans or "no human key on this host",
                     "at most one human key on the operator's host",
                     "that the enrolled humans are distinct persons (G01)"))
    witnesses = [w for w in WITNESSES if (keys / f"{w}.key").exists()]
    out.append(probe("T03 witnesses apart from the operator", not witnesses, witnesses or "no witness key here",
                     "the operator cannot advance witnessed time alone", "that the witnesses' clocks are independent"))
    assessment = json.loads(resolve(c["assessment"]["path"]).read_text())["payload"]
    out.append(probe("independent assessment", assessment.get("independent") is True,
                     f"assessor {assessment.get('assessor')}, independent={assessment.get('independent')}",
                     "the installation was assessed by an assessor other than the operator (D19)",
                     "that the assessor's statements are true"))
    out.append(probe("T01 code release", c.get("demo") is not True,
                     f"running code {code_digest()}",
                     "the source files on disk hash to this release",
                     "that the running process loaded exactly these files (verify before import)"))
    repo = c["repository"]
    if repo["kind"] == "github":
        from trusted.github import GitHub
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
                         "sshd's configuration, other accounts on the host, and keys authorized outside tools/host.py"))
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
