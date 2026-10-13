"""Constitute an installation (§13.2 step 1, D18), in two phases separated by FLOOR-0's witnessed delay:

    python tools/ceremony.py init DIR --repo PATH [--pins PATH]                 a local git repository
    python tools/ceremony.py init DIR --github OWNER/NAME --token-file F [--pins PATH]
    ... at least one hour later ...
    python tools/ceremony.py activate DIR
    python tools/ceremony.py separate DIR --guard-user U --agent-user V      (as root, before serving)

`init` writes keys, the client law, the genesis, the witnesses' first checkpoint, the grant proposals, a
self-assessment and DIR/standard.toml. `activate` anchors time again and activates the grants. The genesis grants
nothing: capabilities are widenings, so they wait for the delay like any other.

DEMO: one operator generates every key on one host, including the four humans and the two witnesses. The quorum,
the witnesses and the assessment are therefore not physical (G01, G06, D19). Use this for a demonstration, never as
a qualified installation.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat  # noqa: E402

from standard.floors import RELEASE  # noqa: E402
from kernel import Kernel, canon, digest, empty  # noqa: E402
from bt.assessment import CONTRACTS, PREFIX, SignedAssessment  # noqa: E402
from standard.runtime.daemon import key  # noqa: E402
from bt.journal import Journal, PinStore  # noqa: E402
from standard.runtime import code_digest  # noqa: E402
from bt.signing import Signer, entry  # noqa: E402

IDENTITIES = {"h1": "human", "h2": "human", "h3": "human", "h4": "human", "w1": "witness", "w2": "witness",
              "guard": "guard", "agent": "agent", "scanner": "service", "oracle": "oracle", "sentinel": "sentinel"}
YEAR = 365 * 86_400_000
GRANTS = {
    "scanner": ("scanner", ["observe", "certify:real"], ["repo:*", "run:*", "build:*"], []),
    "oracle": ("oracle", ["reconcile", "evidence", "certify:real"], ["repo:*", "run:*"], []),
    "agent_deploy": ("agent", ["effect:deploy"], ["run:release:*"], ["deploy-autonomous"]),
    "agent_rollback": ("agent", ["effect:rollback"], ["run:service:*"], ["rollback-autonomous"]),
    "agent_rollback_failing": ("agent", ["effect:rollback"], ["run:service:*"], ["rollback-failing"]),
    "agent_rollback_unanswered": ("agent", ["effect:rollback"], ["run:service:*"], ["rollback-unanswered"]),
    "agent_deploy_reviewed": ("agent", ["effect:deploy"], ["run:release:*"], ["deploy-reviewed"]),
    "agent_rollback_reviewed": ("agent", ["effect:rollback"], ["run:service:*"], ["rollback-reviewed"]),
    "agent_restart": ("agent", ["effect:restart"], ["run:process:*"], ["restart-autonomous"]),
    "agent_restart_burn": ("agent", ["effect:restart"], ["run:process:*"], ["restart-burn"]),
    "agent_restart_reviewed": ("agent", ["effect:restart"], ["run:process:*"], ["restart-reviewed"]),
    "agent_canary": ("agent", ["effect:canary"], ["run:canary:*"], ["canary-autonomous"]),
    # D34: the agent implements contracted requests (always reviewed) and records their delivery.
    "agent_implement": ("agent", ["effect:implement"], ["repo:feature:*"], ["implement-reviewed"]),
    "agent_configure": ("agent", ["effect:configure"], ["repo:config:*"], ["configure-signed"]),
    "agent_deliver": ("agent", ["transition:request:deliver"], ["build:request/*"], []),
    # The product owner writes requests and signs their contracts; the reviewer (h3) reviews the code.
    "product": ("h1", ["register:request", "transition:request:contract", "transition:request:withdraw"],
                ["build:request/*"], []),
    "agent_promote": ("agent", ["effect:deploy"], ["run:release:*"], ["deploy-canary"]),
    "agent_abort": ("agent", ["effect:abort"], ["run:canary:*"], ["abort-autonomous"]),
    "agent_abort_reviewed": ("agent", ["effect:abort"], ["run:canary:*"], ["abort-reviewed"]),
    # D31: the engineer sets production's objectives and limits, and decides switches Standard does not take alone.
    "engineer": ("h1", ["observe", "certify:real"], ["run:policy/*", "run:release:*", "run:service:*", "run:process:*",
                                                   "run:canary:*", "repo:config:*"], []),
    "agent_recipe": ("agent", ["effect:remediate"], ["repo:*"], ["remediate-autonomous"]),
    "agent_review": ("agent", ["effect:remediate"], ["repo:*"], ["remediate-reviewed"]),
    "agent_integrate": ("agent", ["effect:integrate"], ["repo:contrib:*"], ["integrate-reviewed"]),
    "reviewer": ("h3", ["observe", "certify:real"], ["repo:*"], []),
    "officer": ("h2", ["observe", "certify:real"], ["org:*"], []),
}


def now() -> int:
    return int(time.time() * 1000)


def new_key(path: Path) -> Signer:
    sk = Ed25519PrivateKey.generate()
    raw = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(raw).decode())
    return Signer(path.stem, sk)


def git(*args) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True, timeout=600).stdout.strip()


def init(args) -> None:
    d = Path(args.dir).resolve()
    (d / "keys").mkdir(parents=True)
    os.chmod(d / "keys", 0o700)
    (d / "agent").mkdir()                                  # U's own directory: its key, its store, its notes
    signers = {i: new_key(d / ("agent" if i == "agent" else "keys") / f"{i}.key") for i in IDENTITIES}
    assessor = new_key(d / "keys" / "assessor.key")
    root = {"threshold": 2, "identities": {i: {"kind": k, "keys": [signers[i].root_key()]} for i, k in IDENTITIES.items()}}
    law = {"format": "standard-client/1", "floors": RELEASE.digest,
           "bindings": {"owner": "h1", "inventory_source": "scanner", "scanner": "scanner", "compliance_officer": "h2"}}
    code = code_digest()
    kernel = Kernel(RELEASE, code)
    t = now()
    genesis = entry(empty(), "genesis", {"id": "genesis", "at": t, "author": "h1", "root": root, "law": law,
                                         "code": code}, [signers["h1"], signers["h2"]])
    domain = next(op[2] for op in kernel.decide(empty(), genesis)[1] if op[:2] == ("set", "domain"))
    pins_path = Path(args.pins).resolve() if args.pins else d / "pins" / "pins.db"
    if pins_path.parent == d / "pins":
        print("WARNING: the pins live on the journal's volume: anti-rollback is not independent (L-04).")
    journal_path = d / "journal.db"
    journal = Journal(journal_path, kernel, PinStore(pins_path, create=True), domain, create=True)
    journal.append(genesis)
    s = journal.snapshot()
    journal.append(entry(s, "checkpoint", {"id": "checkpoint-0", "at": t + 1, "author": "w1", "size": s["size"],
                                           "head": s["head"]}, [signers["w1"], signers["w2"]]))
    grants = {}
    for name, (holder, actions, resources, conditions) in GRANTS.items():
        s = journal.snapshot()
        body = {"id": f"grant-{name}", "at": s["last_at"] + 1, "author": "h1", "holder": holder, "actions": actions,
                "resources": resources, "conditions": conditions, "not_after": t + YEAR}
        journal.append(entry(s, "grant", body, [signers["h1"], signers["h2"]]))
        grants[name] = body["id"]
    payload = {"schema": SignedAssessment.SCHEMA, "assessor": "operator", "independent": False, "release": code,
               "genesis": domain, "ledger": digest(str(journal_path)), "issued_at": t, "expires_at": t + 30 * 86_400_000,
               "contracts": dict.fromkeys(CONTRACTS, "VERIFIED")}
    signature = assessor.sign(PREFIX + canon(payload))["sig"]
    (d / "assessment.json").write_text(json.dumps({"payload": payload, "signature": signature}, indent=2))
    if args.github:
        mirror = d / "mirror"
        git("clone", "-q", "--mirror", f"https://github.com/{args.github}.git", str(mirror))
        anchor = git("-C", str(mirror), "rev-parse", "refs/heads/main")
        git("clone", "-q", "--bare", f"https://github.com/{args.github}.git", str(d / "agent" / "store"))
        repository = (f'kind = "github"\nname = "{args.github}"\ntoken_file = "{Path(args.token_file).resolve()}"\n'
                      f'mirror = "mirror"\nanchor = "{anchor}"')
    else:
        source = Path(args.repo).resolve()
        anchor = git("-C", str(source), "rev-parse", "refs/heads/main")
        git("clone", "-q", "--bare", "--no-hardlinks", str(source), str(d / "agent" / "store"))  # U owns no inode of the repository
        repository = f'kind = "git"\npath = "{source}"\nproposals = "agent/store"\nanchor = "{anchor}"'
        if getattr(args, "inbox", None):                    # D23: clients' contributions, from the hosting gate
            repository += f'\ninbox = "{Path(args.inbox).resolve()}"'
    assessor_public = assessor.public
    data_section = ""
    if getattr(args, "data", None):
        from kernel import parse
        snapshot = Path(args.data).resolve()
        data_section = f'\n[data]\npath = "{snapshot}"\ndigest = "{digest(parse(snapshot.read_bytes(), max_bytes=64 << 20))}"\n'
    if getattr(args, "unconfined_tests", False):             # functional tests only: candidate code runs as the operator
        data_section += "\n[tests]\nunconfined = true\n"
    (d / "standard.toml").write_text(f'''# DEMO installation: every key on one host, self-assessed (ARCHITECTURE.md §15.4, D18, D19).
demo = true

[ledger]
journal = "journal.db"
pins = "{pins_path}"
genesis = "{domain}"

[keys]
dir = "keys"

[grants]
{chr(10).join(f'{n} = "{g}"' for n, g in grants.items())}

[repository]
{repository}

[assessment]
path = "assessment.json"
assessors = {{ operator = "{assessor_public}" }}

[socket]
path = "admission.sock"

[agent]
key = "agent/agent.key"
store = "agent/store"
{data_section}''')
    activate_after = time.ctime((journal.snapshot()["last_at"] + 3_600_000) / 1000)
    print(f"constituted {d}: genesis {domain}. Activate the grants after {activate_after}:")
    print(f"    python tools/ceremony.py activate {d}")


def activate(args) -> None:
    d = Path(args.dir).resolve()
    import tomllib
    c = tomllib.loads((d / "standard.toml").read_text())
    kernel = Kernel(RELEASE, code_digest())
    journal = Journal(d / c["ledger"]["journal"], kernel, PinStore(Path(c["ledger"]["pins"])), c["ledger"]["genesis"])
    keys = d / c["keys"]["dir"]
    h1, h2 = key(keys, "h1"), key(keys, "h2")
    s = journal.snapshot()
    journal.append(entry(s, "checkpoint", {"id": f"checkpoint-{now()}", "at": max(now(), s["last_at"] + 1),
                                           "author": "w1", "size": s["size"], "head": s["head"]},
                         [key(keys, "w1"), key(keys, "w2")]))
    for name, grant in c["grants"].items():
        s = journal.snapshot()
        if grant in s["grants"]:
            continue
        journal.append(entry(s, "activate", {"id": f"activate-{name}", "at": s["last_at"] + 1, "author": "h1",
                                             "proposal": grant}, [h1, h2]))
    print("grants active:", ", ".join(c["grants"]))


def separate(args) -> None:
    """Give K/T and U distinct Unix users (run as root). The guard owns the installation, the maintained repository and
    every key but the agent's; the agent owns only DIR/agent and reads the rest. The kernel of the host enforces it."""
    import grp
    import pwd
    import tomllib
    d = Path(args.dir).resolve()
    c = tomllib.loads((d / "standard.toml").read_text())
    guard, agent = pwd.getpwnam(args.guard_user), pwd.getpwnam(args.agent_user)
    if guard.pw_uid == agent.pw_uid or 0 in (guard.pw_uid, agent.pw_uid):
        raise SystemExit("two distinct, unprivileged users")
    if guard.pw_name not in grp.getgrgid(agent.pw_gid).gr_mem and agent.pw_name not in grp.getgrgid(guard.pw_gid).gr_mem:
        print(f"note: add {agent.pw_name} to group {grp.getgrgid(guard.pw_gid).gr_name} so it can reach the socket")
    trees = [d, Path(c["ledger"]["pins"]).parent]
    if c["repository"]["kind"] == "git":
        trees.append(Path(c["repository"]["path"]))
    for tree in trees:
        for p in [tree, *tree.rglob("*")]:
            os.chown(p, guard.pw_uid, guard.pw_gid, follow_symlinks=False)
            if not p.is_symlink():
                os.chmod(p, p.stat().st_mode & ~0o022)       # nobody but the guard writes
    for p in [d / "agent", *(d / "agent").rglob("*")]:
        os.chown(p, agent.pw_uid, guard.pw_gid, follow_symlinks=False)
        if p.is_dir():
            os.chmod(p, 0o2750)                              # the guard reads proposals, never writes them
    os.chmod(d / "agent" / "agent.key", 0o600)
    # Each side reads the other's repository from outside only (fetch, ls-remote): git must be told to accept the owner.
    # The guard never runs git inside U's store, so U's repository configuration never executes as the guard.
    reads = {guard: [d / "agent" / "store"], agent: []}
    if c["repository"]["kind"] == "git":                     # upload-pack checks the .git of a non-bare repository
        reads[agent] = [Path(c["repository"]["path"]), Path(c["repository"]["path"]) / ".git",
                        *([Path(c["repository"]["inbox"])] if "inbox" in c["repository"] else [])]
    for user, paths in reads.items():
        for path in paths:
            subprocess.run(["runuser", "-u", user.pw_name, "--", "git", "config", "--global", "--add", "safe.directory",
                            str(path)], check=True)
    if "separation" not in c:
        with open(d / "standard.toml", "a") as f:
            f.write(f'\n[separation]\nguard_user = "{guard.pw_name}"\nagent_user = "{agent.pw_name}"\n')
    print(f"separated: {guard.pw_name} runs `python -m standard.runtime serve`, {agent.pw_name} runs `python -m standard.autonomy run`")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    i = sub.add_parser("init")
    i.add_argument("dir")
    i.add_argument("--repo")
    i.add_argument("--github")
    i.add_argument("--token-file")
    i.add_argument("--pins")
    i.add_argument("--inbox", help="the hosting inbox of this repository (tools/host.py)")
    i.add_argument("--data", help="a reviewed snapshot from tools/refresh_data.py, pinned by its digest")
    i.add_argument("--unconfined-tests", action="store_true",
                   help="DEMO ONLY: run candidate tests as the operator, with its keys (no jail)")
    a = sub.add_parser("activate")
    a.add_argument("dir")
    s = sub.add_parser("separate")
    s.add_argument("dir")
    s.add_argument("--guard-user", required=True)
    s.add_argument("--agent-user", required=True)
    args = parser.parse_args()
    if args.command == "init":
        if bool(args.repo) == bool(args.github) or (args.github and not args.token_file):
            parser.error("give --repo, or --github with --token-file")
        init(args)
    elif args.command == "activate":
        activate(args)
    else:
        separate(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
