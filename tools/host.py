"""Host repositories behind the SSH gate (D23, bt/hosting.py). Run as root.

    python tools/host.py create HOSTING.toml NAME --from PATH --guard-user G --gate-user U
    python tools/host.py authorize HOSTING.toml NAME IDENTITY --key id_ed25519.pub [--write] --gate-user U

`create` makes two bare repositories: the canonical one (owned by the guard, no group or other write; the guard's
compare-and-swap is the only way main moves) and the inbox (owned by the gate user, with the update hook that keeps
each client under refs/heads/<identity>/*). `authorize` lets one client key fetch, and with --write push to the inbox.
Point the installation at the canonical repository: `ceremony.py init DIR --repo <canonical>`. What clients push to
the inbox does not reach main yet: admitting client work needs its own operation in the law (next step of D23).
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bt.hosting import HOOK, IDENTITY  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def git(*args, user=None) -> str:
    cmd = ["git", *args] if user is None else ["runuser", "-u", user, "--", "env", f"HOME={pwd.getpwnam(user).pw_dir}",
                                               "git", *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600).stdout.strip()


def load(path: Path) -> dict:
    import tomllib
    return tomllib.loads(path.read_text()) if path.exists() else {"repositories": {}}


def save(path: Path, config: dict) -> None:
    lines = ["# Repositories served by the SSH gate (bt/hosting.py). Written by tools/host.py."]
    for name, repo in sorted(config["repositories"].items()):
        lines.append(f"\n[repositories.{name}]")
        for key in ("canonical", "inbox", "readers", "writers"):
            lines.append(f"{key} = {json.dumps(repo.get(key, []))}")
    path.write_text("\n".join(lines) + "\n")
    os.chmod(path, 0o644)


def own(tree: Path, user, mode_mask: int = 0o022) -> None:
    for p in [tree, *tree.rglob("*")]:
        os.chown(p, user.pw_uid, user.pw_gid, follow_symlinks=False)
        if not p.is_symlink():
            os.chmod(p, p.stat().st_mode & ~mode_mask)


def create(args) -> None:
    if not IDENTITY.fullmatch(args.name):
        raise SystemExit("a repository name is lowercase letters, digits, - and _")
    guard, gate = pwd.getpwnam(args.guard_user), pwd.getpwnam(args.gate_user)
    if guard.pw_uid == gate.pw_uid or 0 in (guard.pw_uid, gate.pw_uid):
        raise SystemExit("the guard and the gate are two distinct, unprivileged users")
    path = Path(args.config).resolve()
    config = load(path)
    base = path.parent
    canonical, inbox = base / "repos" / f"{args.name}.git", base / "inbox" / f"{args.name}.git"
    for d in (canonical.parent, inbox.parent):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)
    git("clone", "-q", "--bare", "--no-hardlinks", str(Path(args.source).resolve()), str(canonical))
    git("init", "-q", "--bare", "--shared=0640", str(inbox))  # the guard's group reads pushes, never writes them
    hook = inbox / "hooks" / "update"
    hook.write_text(HOOK)
    os.chmod(hook, 0o755)
    own(canonical, guard)                                     # T07: only the guard writes the canonical repository
    own(inbox, gate, 0o027)                                   # the inbox is the gate's; the guard's group reads it
    os.chown(inbox, gate.pw_uid, guard.pw_gid)
    for p in inbox.rglob("*"):
        os.chown(p, gate.pw_uid, guard.pw_gid, follow_symlinks=False)
    git("config", "--global", "--add", "safe.directory", str(canonical), user=gate.pw_name)   # gate reads it
    git("config", "--global", "--add", "safe.directory", str(inbox), user=guard.pw_name)      # guard reads, outside
    config["repositories"][args.name] = {"canonical": str(canonical), "inbox": str(inbox), "readers": [], "writers": []}
    save(path, config)
    print(f"hosted {args.name}: canonical {canonical} (guard), inbox {inbox} (gate)")


def authorize(args) -> None:
    if not IDENTITY.fullmatch(args.identity):
        raise SystemExit("an identity is lowercase letters, digits, - and _")
    path = Path(args.config).resolve()
    config = load(path)
    repo = config["repositories"][args.name]
    for role in ("readers",) + (("writers",) if args.write else ()):
        if args.identity not in repo[role]:
            repo[role].append(args.identity)
    save(path, config)
    key = Path(args.key).read_text().strip()
    if "\n" in key or not key.startswith(("ssh-ed25519 ", "sk-ssh-ed25519@openssh.com ", "ecdsa-sha2-")):
        raise SystemExit("one public key, ed25519 or ecdsa")
    gate = pwd.getpwnam(args.gate_user)
    ssh = Path(gate.pw_dir) / ".ssh"
    ssh.mkdir(mode=0o700, exist_ok=True)
    keys = ssh / "authorized_keys"
    line = f'command="cd {ROOT} && exec {sys.executable} -m bt.hosting {path} {args.identity}",restrict {key}'
    existing = keys.read_text().splitlines() if keys.exists() else []
    if line not in existing:
        keys.write_text("\n".join(existing + [line]) + "\n")
    for p in (ssh, keys):
        os.chown(p, gate.pw_uid, gate.pw_gid)
    os.chmod(keys, 0o600)
    print(f"{args.identity} may fetch {args.name}" + (" and push to its inbox" if args.write else ""))


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create")
    c.add_argument("config")
    c.add_argument("name")
    c.add_argument("--from", dest="source", required=True)
    c.add_argument("--guard-user", required=True)
    c.add_argument("--gate-user", required=True)
    a = sub.add_parser("authorize")
    a.add_argument("config")
    a.add_argument("name")
    a.add_argument("identity")
    a.add_argument("--key", required=True)
    a.add_argument("--write", action="store_true")
    a.add_argument("--gate-user", required=True)
    args = parser.parse_args()
    (create if args.command == "create" else authorize)(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
