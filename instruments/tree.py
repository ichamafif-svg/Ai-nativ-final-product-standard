"""Trees and the one rule that turns a measure into a status (§7.3).

- a pass is a proof of coverage: a status equals the expected one only when the whole non-empty universe was covered
  without finding; an exception, a skipped element or an empty universe is `uncovered` (M2-r1: never "OK by default");
- one immutable snapshot per measurement (R07): a tree is one exact commit, with every entry's mode and kind.

`GitTree` reads a commit from a repository (the agent's own store); `DirTree` reads the copy the trusted host
exported for a program (files, plus the manifest of every entry: mode, kind, object id).
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Measure:
    universe: frozenset
    covered: frozenset
    findings: tuple = ()
    details: tuple = ()                                    # what helps a repair: locations, traces; never a verdict


def verdict(expect: str, measure) -> str:
    """The only place a status is decided."""
    if isinstance(measure, BaseException):
        return f"uncovered:{type(measure).__name__}"
    if not measure.universe:
        return "uncovered:empty"
    missing = measure.universe - measure.covered
    if missing:
        return f"uncovered:{len(missing)}"
    return f"found:{len(measure.findings)}" if measure.findings else expect


def git(repo, *args, check=True, input=None) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, input=input, timeout=300)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {args[0]}: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout.decode(errors="replace")


class Tree:
    entries: dict                                          # path -> (mode, kind, object id)
    commit: str

    def paths(self) -> set:
        return {p for p, (_, kind, _) in self.entries.items() if kind == "blob"}


class GitTree(Tree):
    """The tracked tree of one exact commit, read from the object store: no working tree to tamper with."""

    def __init__(self, repo, commit: str):
        self.repo, self.commit = Path(repo), git(repo, "rev-parse", "--verify", commit + "^{commit}").strip()
        self.entries = {}
        for line in git(repo, "ls-tree", "-r", "-z", "--full-tree", self.commit).split("\0"):
            if line:
                meta, path = line.split("\t", 1)
                mode, kind, sha = meta.split()
                self.entries[path] = (mode, kind, sha)

    def read(self, path: str) -> bytes:
        mode, kind, sha = self.entries[path]
        if kind != "blob" or mode == "120000":
            raise FileNotFoundError(path)                  # symlinks and gitlinks are never followed
        return subprocess.run(["git", "-C", str(self.repo), "cat-file", "blob", sha], capture_output=True,
                              check=True, timeout=60).stdout


Snapshot = GitTree


class DirTree(Tree):
    """A commit the host exported: `<dir>/files/...` and `<dir>/commit.json` {sha, parents, message, entries}."""

    def __init__(self, path):
        self.path = Path(path)
        meta = json.loads((self.path / "commit.json").read_text())
        self.commit, self.parents, self.message = meta["sha"], meta["parents"], meta["message"]
        self.entries = {p: tuple(e) for p, e in meta["entries"].items()}

    @property
    def files(self) -> Path:
        return self.path / "files"

    def read(self, path: str) -> bytes:
        mode, kind, _ = self.entries[path]
        if kind != "blob" or mode == "120000":
            raise FileNotFoundError(path)
        return (self.files / path).read_bytes()


def write_blobs(repo, entries: dict, files: Path) -> None:
    """Every regular blob of a tree, byte for byte from the object store. `git archive` would apply the measured
    tree's own .gitattributes (export-ignore, export-subst): the subject would decide what its instrument sees."""
    wanted = [(p, sha, mode) for p, (mode, kind, sha) in sorted(entries.items()) if kind == "blob" and mode != "120000"]
    if not wanted:
        return
    out = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch"], input="".join(f"{sha}\n" for _, sha, _ in wanted).encode(),
                         capture_output=True, check=True, timeout=600).stdout
    at = 0
    for path, sha, mode in wanted:
        header_end = out.index(b"\n", at)
        got, kind, size = out[at:header_end].decode().split()
        if got != sha or kind != "blob":
            raise RuntimeError(f"object store answered {got} {kind} for {path}")
        start = header_end + 1
        data = out[start:start + int(size)]
        at = start + int(size) + 1
        dest = files / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        if mode == "100755":
            dest.chmod(0o755)


def export(repo, commit: str, target) -> DirTree:
    """A commit of a repository as the host exports it for a program (U and tests use the same shape)."""
    target = Path(target)
    (target / "files").mkdir(parents=True)
    tree = GitTree(repo, commit)
    meta = {"sha": tree.commit, "parents": git(repo, "rev-list", "--parents", "-n", "1", tree.commit).split()[1:],
            "message": git(repo, "log", "-1", "--format=%B", tree.commit),
            "entries": {p: list(e) for p, e in tree.entries.items()}}
    (target / "commit.json").write_text(json.dumps(meta))
    write_blobs(repo, tree.entries, target / "files")
    return DirTree(target)
