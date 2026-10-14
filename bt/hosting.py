"""T07 at the hosting boundary (D23): clients reach the repositories we host only through this gate, over SSH.

The gate user's authorized_keys gives every client key a forced command:

    command="python3 -m bt.hosting /srv/standard/hosting.toml alice",restrict ssh-ed25519 AAAA...

- fetch (git-upload-pack 'NAME'): the canonical repository, which the gate user can read but not write.
- push (git-receive-pack 'NAME'): the repository's inbox only, and there only refs/heads/<identity>/* (the inbox's
  update hook, installed by tools/hosting.py). A client never writes the canonical repository.

`main` of a canonical repository moves only by the guard's compare-and-swap. The gate runs as its own Unix user, owns
the inboxes and nothing the guard owns; the guard reads an inbox from outside only (ls-remote, fetch), so a client's
bytes never run as the guard. Nothing a client sends reaches a shell: the command is matched whole, the repository is
looked up by name, and git is executed directly with a clean environment.
"""
from __future__ import annotations

import os
import re
import sys
import tomllib
from pathlib import Path

COMMAND = re.compile(r"(git-upload-pack|git-receive-pack) '/?([a-z0-9][a-z0-9._-]{0,63}?)(?:\.git)?/?'")
IDENTITY = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
HOOK = """#!/bin/sh
# Inbox update hook (bt.hosting): a client writes only under its own name.
case "$1" in
  refs/heads/"$STANDARD_IDENTITY"/*) exit 0 ;;
esac
echo "standard: you may push only refs/heads/$STANDARD_IDENTITY/*" >&2
exit 1
"""
DENIED = "no such repository, or not permitted"            # one answer: a refusal never says which


def route(config: dict, identity: str, original: str) -> tuple[str, str, dict]:
    """(program, repository path, extra environment) for one SSH command; PermissionError otherwise."""
    if not IDENTITY.fullmatch(identity or ""):
        raise PermissionError(DENIED)
    m = COMMAND.fullmatch(original or "")
    if not m:
        raise PermissionError("only git fetch and git push are served")
    program, name = m[1], m[2]
    repo = config.get("repositories", {}).get(name)
    if repo is None or identity not in set(repo.get("readers", [])) | set(repo.get("writers", [])):
        raise PermissionError(DENIED)
    if program == "git-upload-pack":
        return program, repo["canonical"], {}
    if identity not in repo.get("writers", []):
        raise PermissionError(DENIED)
    return program, repo["inbox"], {"STANDARD_IDENTITY": identity}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: python -m bt.hosting hosting.toml IDENTITY  (as an SSH forced command)", file=sys.stderr)
        return 2
    try:
        config = tomllib.loads(Path(argv[0]).read_text())
        program, path, extra = route(config, argv[1], os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    except PermissionError as exc:
        print(f"standard: {exc}", file=sys.stderr)
        return 1
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/"), **extra}
    os.execvpe(program, [program, path], env)


if __name__ == "__main__":
    sys.exit(main())
