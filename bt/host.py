"""T06 — the instrument host (D37): run a pinned program on recorded inputs, keep the record, sign nothing itself.

Trusted code that does not grow with what Standard measures. It knows how to materialise inputs (an exact commit of
its own repository, a commit's manifest, a file at a commit, a blob of a store checked against its digest, the pinned
data, a recorded series of scrapes, a value), how to run the programs package (instruments/) as the isolated runner,
and how to keep, content-addressed, everything a run read and returned. It refuses to run a package whose digest is
not the one the floors pin. What a fact means is the program's; that it was computed from these exact inputs by that
exact code is the host's, and anyone can check it by running the record again (product/tools/replay.py).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from kernel.canon import digest as canon_digest, parse as canon_parse

from .isolation import Isolation

KEEP = ((900, 0), (6 * 3600, 60), (32 * 86400, 3600))      # age below -> keep one point per period (0: every one)


def programs_digest(root) -> str:
    h = hashlib.sha256()
    for path in sorted((Path(root) / "instruments").glob("*.py")):
        h.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return "sha256:" + h.hexdigest()


def _git(repo, *args, data: bool = False):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=300)
    if r.returncode != 0:
        raise LookupError(f"git {args[0]}: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout if data else r.stdout.decode()


def _request(method: str, url: str) -> tuple[int, float]:
    start = time.perf_counter()
    try:
        status = urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=10).status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except Exception:
        status = 0                                          # no answer at all
    return status, time.perf_counter() - start


class Evidence:
    """Content-addressed, append-only: a digest names its bytes forever. Inputs and answers of measures only, never
    a key; a run gets copies of what it reads."""

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o755)

    def path(self, digest: str) -> Path:
        return self.root / digest.split(":", 1)[1]

    def put(self, data: bytes) -> str:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        path = self.path(digest)
        if not path.exists():
            tmp = path.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_bytes(data)
            tmp.chmod(0o644)
            tmp.replace(path)
        return digest

    def get(self, digest: str) -> bytes:
        data = self.path(digest).read_bytes()
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            raise LookupError(f"evidence {digest} is corrupt")
        return data


class Series:
    """Scrapes of declared sources, kept at decreasing resolution and published as immutable chunks: an hour chunk
    for the last day, a day chunk before. A run names chunks, never thousands of scrapes."""

    def __init__(self, evidence: Evidence, state):
        self.evidence, self.state = evidence, Path(state)
        self.index = json.loads(self.state.read_text()) if self.state.exists() else {}

    def add(self, name: str, role: str, at: int, data: bytes | None) -> str | None:
        s = self.index.setdefault(name, {"role": role, "points": []})
        ref = None if data is None else self.evidence.put(data)
        s["points"].append([at, ref])
        kept, last = [], {}
        for point in s["points"]:
            age = at - point[0]
            rule = next((period for limit, period in KEEP if age < limit), None)
            if rule is None:
                continue
            slot = (rule, point[0] // rule) if rule else None
            if slot is None or slot not in last:
                kept.append(point)
                if slot is not None:
                    last[slot] = True
        s["points"] = kept
        tmp = self.state.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.index))
        tmp.replace(self.state)
        return ref

    def chunks(self, now: int) -> dict:
        out = {}
        for name, s in self.index.items():
            groups = {}
            for at, d in s["points"]:
                key = at // 3600 if now - at < 86400 else -(at // 86400)
                groups.setdefault(key, []).append([at, d])
            out[name] = {"role": s["role"], "chunks": [self.evidence.put(json.dumps(g).encode())
                                                       for _, g in sorted(groups.items(), key=lambda kv: kv[1][0][0])]}
        return out


class Host:
    def __init__(self, code_root, evidence: Evidence, repo, *, isolation: Isolation | None = None, stores=None,
                 data=None, world=None, series: Series | None = None, pinned: str | None = None, clock=None):
        self.root, self.evidence, self.repo = Path(code_root), evidence, Path(repo)
        self.isolation, self.stores = isolation or Isolation(), {k: Path(v) for k, v in (stores or {}).items()}
        self.data, self.world, self.series = data, world, series  # data: (path, digest)
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.digest = programs_digest(self.root)
        if pinned is not None and pinned != f"programs@{self.digest}":
            raise ValueError("the programs on disk are not the ones the floors pin")
        self.method, self.cache_dir = f"programs@{self.digest}", evidence.root / "cache"
        self.fetch = lambda url: urllib.request.urlopen(url, timeout=5).read()
        self.request = _request
        self.cache_dir.mkdir(exist_ok=True)

    # ---- inputs: identity first (cheap), materialisation only on a cache miss ----------------------------------------
    def resolve(self, spec: dict):
        kind = "store" if "store" in spec else next(iter(spec))     # a program's answer arrives with sorted keys
        arg = spec[kind]
        if kind in ("commit", "manifest"):
            return {kind: _git(self.repo, "rev-parse", "--verify", f"{arg}^{{commit}}").strip()}
        if kind == "file":
            r = subprocess.run(["git", "-C", str(self.repo), "cat-file", "blob", f"{arg[0]}:{arg[1]}"],
                               capture_output=True, timeout=60)
            return {"evidence": self.evidence.put(r.stdout) if r.returncode == 0 else None}
        if kind == "store":
            path = self.stores[arg] / spec.get("digest", ":").split(":", 1)[1]
            data = path.read_bytes() if path.is_file() else None
            ok = data is not None and "sha256:" + hashlib.sha256(data).hexdigest() == spec["digest"]
            return {"evidence": self.evidence.put(data) if ok else None}
        if kind == "data":
            if self.data is None:
                return {"evidence": None}
            raw = Path(self.data[0]).read_bytes()
            if canon_digest(canon_parse(raw, max_bytes=64 << 20)) != self.data[1]:
                raise ValueError("DATA.PIN: the snapshot is not the pinned one")
            return {"evidence": self.evidence.put(raw)}
        if kind == "world":
            try:
                return {"value": sorted(self.world.protections())}
            except Exception:
                return {"value": None}
        if kind == "log":
            return {"value": _git(self.repo, "rev-list", "--first-parent", f"{arg[0]}..{arg[1]}").split()}
        if kind == "series":
            return {"series": self.series.chunks(self.clock() // 1000) if self.series else {}}
        if kind == "value":
            return {"value": arg}
        raise ValueError(f"unknown input {kind}")

    def materialise(self, resolved, work: Path, name: str):
        kind, arg = next(iter(resolved.items()))
        if kind in ("commit", "manifest"):
            target = work / name
            (target / "files").mkdir(parents=True)
            entries = {}
            for line in _git(self.repo, "ls-tree", "-r", "-z", "--full-tree", arg).split("\0"):
                if line:
                    meta, path = line.split("\t", 1)
                    entries[path] = meta.split()
            parents = _git(self.repo, "rev-list", "--parents", "-n", "1", arg).split()[1:]
            message = _git(self.repo, "log", "-1", "--format=%B", arg)
            (target / "commit.json").write_text(json.dumps({"sha": arg, "parents": parents, "message": message,
                                                            "entries": entries}))
            if kind == "manifest":
                return {"manifest": str(target / "commit.json")}
            subprocess.run(["tar", "-x", "-C", str(target / "files")], input=_git(
                self.repo, "archive", "--format=tar", arg, data=True), check=True, capture_output=True, timeout=300)
            return {"tree": str(target)}
        if kind == "evidence":
            return None if arg is None else {"bytes": self._copy(arg, work)}
        if kind == "series":
            out = {}
            for source, s in arg.items():
                points = [p for c in s["chunks"] for p in json.loads(self.evidence.get(c))]
                out[source] = {"role": s["role"], "points": [[at, None if d is None else self._copy(d, work)]
                                                             for at, d in points]}
            return out
        return arg

    def _copy(self, digest: str, work: Path) -> str:
        target = work / "evidence" / digest.split(":", 1)[1]
        if not target.exists():
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(self.evidence.get(digest))
        return str(target)

    # ---- running ---------------------------------------------------------------------------------------------------
    def call(self, job: str, inputs: dict, *, network: bool = False, cache: bool = True) -> tuple[dict, str]:
        """(answer, digest of the run record). A cached answer is the recorded one, never recomputed silently."""
        resolved = {name: self.resolve(spec) for name, spec in inputs.items()}
        key = "sha256:" + hashlib.sha256(json.dumps([self.method, job, resolved], sort_keys=True).encode()).hexdigest()
        cached = self.cache_dir / key.split(":", 1)[1]
        if cache and cached.exists():
            record = cached.read_text().strip()
            return json.loads(self.evidence.get(record))["output"], record
        output = self.run(job, resolved, network=network)
        record = self.evidence.put(json.dumps({"method": self.method, "job": job, "inputs": resolved,
                                               "network": network, "output": output}, sort_keys=True).encode())
        if cache and "error" not in output:
            cached.write_text(record + "\n")
        return output, record

    def run(self, job: str, resolved: dict, *, network: bool = False) -> dict:
        work = Path(tempfile.mkdtemp(prefix="standard-run-"))
        try:
            inputs = {name: self.materialise(r, work, name) for name, r in resolved.items()}
            scratch = self.isolation.writable(work / "scratch")
            self.isolation.open_to_runner(work)
            work.chmod(0o755)
            env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "TMPDIR": str(scratch), "PYTHONDONTWRITEBYTECODE": "1",
                   **({k: v for k, v in os.environ.items() if k.endswith(("_PROXY", "_proxy", "CA_BUNDLE", "CERT_FILE"))}
                      if network else {})}
            boot = f"import sys; sys.path.insert(0, {str(self.root)!r}); from instruments.jobs import main; main()"
            r = subprocess.run(self.isolation.command([sys.executable, "-I", "-c", boot], env, network=network),
                               input=json.dumps({"job": job, "inputs": inputs}).encode(), capture_output=True,
                               timeout=3600, cwd=work)
            try:
                return json.loads(r.stdout.decode().strip().splitlines()[-1])
            except (ValueError, IndexError):
                return {"error": f"no answer: {r.stderr.decode(errors='replace')[-500:]}"}
        finally:
            if self.isolation.isolated:                     # what the runner wrote, it removes
                subprocess.run(self.isolation.command(["rm", "-rf", str(work / "scratch")], {"PATH": "/usr/bin:/bin"}),
                               capture_output=True, timeout=300)
            shutil.rmtree(work, ignore_errors=True)

    # ---- the live world: scrapes and probes, recorded before any program reads them -------------------------------
    def observe(self, sources: dict, fetch: list) -> list:
        """sources: {name: (role, url)}; fetch: the probes the production program asked for on its last pass.
        -> [(source, url, at, digest or None)]: the material of a capture transaction (D38)."""
        if self.series is None:
            return []
        now, get, points = self.clock() // 1000, self.fetch, []
        for name, (role, url) in sources.items():
            try:
                data = get(url)
                data = data.encode() if isinstance(data, str) else data
            except Exception:
                data = None
            points.append((name, url, now, self.series.add(name, role, now, data)))
        if fetch:
            answers = []
            for pid, method, url, expected, path in fetch:
                if method not in ("GET", "HEAD", "POST") or not str(url).startswith(("http://", "https://")):
                    continue
                status, seconds = self.request(method, url)
                answers.append([pid, method, path, expected, status, seconds])
            points.append(("probes", "", now, self.series.add("probes", "probes", now, json.dumps(answers).encode())))
        return points
