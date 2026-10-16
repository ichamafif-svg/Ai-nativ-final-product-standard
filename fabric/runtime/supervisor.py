"""External candidate executor. No keys, admission, network grant or arbitrary host mount API.

The installed lab uses the agent UID on both sides for scratch ownership. Its
namespace boundary, protected launch and absent cgroup mount are essential;
this is not an independent identity or a micro-VM boundary. A candidate never
receives the supervisor socket. Each execution uses the existing OCI bac.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
import stat
import struct
import tempfile
import time
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from pathlib import Path

from fabric.runtime.bac import BASE_ENV, Bac, Ran, Walls, REFUSED

MAX_MESSAGE = 1 << 20
STAGE_BYTES = 1 << 30
STAGE_ENTRIES = 50_000
STAGE_SECONDS = 120
SOCKET_ENV = "STANDARD_CANDIDATE_SOCKET"


class Refused(ValueError):
    pass


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def pin(root: Path, value: str, stack: ExitStack, *, allow_root=False) -> int:
    """Open a scratch/cache inode without following any component.

    Only a trusted copy process receives this descriptor. OCI containers receive
    paths into a private snapshot, never descriptors pointing outside their root.
    """
    if not isinstance(value, str):
        raise Refused("CANDIDATE.PATH")
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise Refused("CANDIDATE.PATH")
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        raise Refused("CANDIDATE.SCRATCH_ONLY") from None
    if not parts and not allow_root:
        raise Refused("CANDIDATE.SCRATCH_ROOT")
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    stack.callback(os.close, fd)
    for index, part in enumerate(parts):
        flags = os.O_PATH | os.O_NOFOLLOW
        if index < len(parts) - 1:
            flags |= os.O_DIRECTORY
        fd = os.open(part, flags, dir_fd=fd)
        stack.callback(os.close, fd)
    mode = os.fstat(fd).st_mode
    if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
        raise Refused("CANDIDATE.FILE_TYPE")
    return fd


class StageBudget:
    def __init__(self, seconds=STAGE_SECONDS, bytes_limit=STAGE_BYTES, entries=STAGE_ENTRIES):
        self.deadline = time.monotonic() + seconds
        self.bytes_left, self.entries_left = bytes_limit, entries

    def charge(self, size=0, entries=0):
        self.bytes_left -= size
        self.entries_left -= entries
        if time.monotonic() > self.deadline or self.bytes_left < 0 or self.entries_left < 0:
            raise Refused("CANDIDATE.STAGING_LIMIT")


@contextmanager
def _opened(path, flags, *, dir_fd=None):
    fd = os.open(path, flags, dir_fd=dir_fd)
    try:
        yield fd
    finally:
        os.close(fd)


def _copy_file(source_fd, target_fd, budget):
    while True:
        budget.charge()
        chunk = os.read(source_fd, min(1 << 20, budget.bytes_left + 1))
        if not chunk:
            break
        budget.charge(size=len(chunk))
        view = memoryview(chunk)
        while view:
            budget.charge()
            view = view[os.write(target_fd, view):]


def _copy_entry(source_fd, target_dir_fd, name, budget, depth=0):
    budget.charge(entries=1)
    if depth > 64:
        raise Refused("CANDIDATE.STAGING_LIMIT")
    mode = os.stat(name, dir_fd=source_fd, follow_symlinks=False).st_mode
    if stat.S_ISLNK(mode):
        link = os.readlink(name, dir_fd=source_fd)
        budget.charge(size=len(os.fsencode(link)))
        os.symlink(link, name, dir_fd=target_dir_fd)
    elif stat.S_ISREG(mode):
        with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                               dir_fd=source_fd), "rb") as data, \
                os.fdopen(os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600,
                                  dir_fd=target_dir_fd), "wb") as output:
            if not stat.S_ISREG(os.fstat(data.fileno()).st_mode):
                raise Refused("CANDIDATE.FILE_TYPE")
            _copy_file(data.fileno(), output.fileno(), budget)
        os.chmod(name, stat.S_IMODE(mode) & ~0o6000, dir_fd=target_dir_fd, follow_symlinks=False)
    elif stat.S_ISDIR(mode):
        os.mkdir(name, 0o700, dir_fd=target_dir_fd)
        with _opened(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd) as child, \
                _opened(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=target_dir_fd) as dest:
            _copy_directory(child, dest, budget, depth + 1)
        os.chmod(name, stat.S_IMODE(mode) & ~0o6000, dir_fd=target_dir_fd, follow_symlinks=False)
    else:
        raise Refused("CANDIDATE.FILE_TYPE")


def _copy_directory(source_fd, target_fd, budget, depth=0):
    with os.scandir(source_fd) as entries:
        for entry in entries:
            _copy_entry(source_fd, target_fd, entry.name, budget, depth)


def _clear_directory(fd, budget, depth=0):
    with os.scandir(fd) as entries:
        for entry in entries:
            budget.charge(entries=1)
            if depth > 64:
                raise Refused("CANDIDATE.STAGING_LIMIT")
            if entry.is_dir(follow_symlinks=False):
                with _opened(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd) as child:
                    _clear_directory(child, budget, depth + 1)
                os.rmdir(entry.name, dir_fd=fd)
            else:
                os.unlink(entry.name, dir_fd=fd)


def _count_entries(fd, budget, depth=0):
    count = 0
    with os.scandir(fd) as entries:
        for entry in entries:
            budget.charge(entries=1)
            count += 1
            if depth > 64:
                raise Refused("CANDIDATE.STAGING_LIMIT")
            if entry.is_dir(follow_symlinks=False):
                with _opened(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd) as child:
                    count += _count_entries(child, budget, depth + 1)
    return count


def copy_in(fd: int, target: Path, budget=None):
    """Bounded snapshot of a pinned inode, without following nested symlinks."""
    budget = budget or StageBudget()
    mode = os.fstat(fd).st_mode
    if stat.S_ISREG(mode):
        if os.fstat(fd).st_size > budget.bytes_left:
            raise Refused("CANDIDATE.STAGING_LIMIT")
        with os.fdopen(os.open(f"/proc/self/fd/{fd}", os.O_RDONLY)) as data, target.open("xb") as output:
            _copy_file(data.fileno(), output.fileno(), budget)
        target.chmod(stat.S_IMODE(mode) & ~0o6000)
    else:
        target.mkdir(mode=0o700)
        with _opened(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_DIRECTORY) as source, \
                _opened(target, os.O_RDONLY | os.O_DIRECTORY) as destination:
            _copy_directory(source, destination, budget)


def copy_out(source: Path, fd: int, budget=None):
    """Reconcile a writable snapshot with its pinned original, including deletions."""
    budget = budget or StageBudget()
    if stat.S_ISREG(os.fstat(fd).st_mode):
        with source.open("rb") as data, os.fdopen(os.open(f"/proc/self/fd/{fd}", os.O_WRONLY), "wb") as output:
            if data.seek(0, os.SEEK_END) > budget.bytes_left:
                raise Refused("CANDIDATE.STAGING_LIMIT")
            data.seek(0)
            budget.charge()
            output.truncate(0)
            _copy_file(data.fileno(), output.fileno(), budget)
    else:
        # Prepare a complete bounded copy before deleting anything in the original.
        with tempfile.TemporaryDirectory(prefix="standard-candidate-output-") as temporary:
            prepared = Path(temporary, "output")
            before_bytes, before_entries = budget.bytes_left, budget.entries_left
            with _opened(source, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW) as source_fd:
                copy_in(source_fd, prepared, budget)
            bytes_to_commit = before_bytes - budget.bytes_left
            entries_to_commit = before_entries - budget.entries_left
            with _opened(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_DIRECTORY) as destination, \
                    _opened(prepared, os.O_RDONLY | os.O_DIRECTORY) as staged:
                old_entries = _count_entries(destination, budget)
                # Reserve the entire commit before the first deletion. The private
                # prepared tree is immutable to candidate code after execution.
                budget.charge(size=bytes_to_commit, entries=old_entries + entries_to_commit)
                commit_budget = StageBudget(seconds=max(0, budget.deadline - time.monotonic()),
                                            bytes_limit=bytes_to_commit, entries=old_entries + entries_to_commit)
                _clear_directory(destination, commit_budget)
                _copy_directory(staged, destination, commit_budget)


class Executor:
    def __init__(self, scratch, *, cache=None, ceiling=Walls(), bac_factory=Bac):
        self.scratch = Path(scratch).resolve(strict=True)
        self.cache = Path(cache).resolve(strict=True) if cache else None
        self.ceiling, self.bac_factory = ceiling, bac_factory
        self.probe = bac_factory(ceiling)

    def execute(self, request):
        if request == {"action": "status"}:
            return {"ready": self.probe.ready, "why": self.probe.why,
                    "ceiling": asdict(self.ceiling), "scratch": str(self.scratch)}
        fields = {"action", "args", "cwd", "env", "readable", "writable", "walls"}
        if not isinstance(request, dict) or set(request) != fields or request["action"] != "run":
            raise Refused("CANDIDATE.REQUEST")
        args, env = request["args"], request["env"]
        if not isinstance(args, list) or not 0 < len(args) <= 256 or \
                any(not isinstance(v, str) or "\x00" in v for v in args):
            raise Refused("CANDIDATE.ARGS")
        if not isinstance(env, dict) or set(env) - {"PYTHONPATH"} or \
                any(not isinstance(v, str) or "\x00" in v for v in env.values()):
            raise Refused("CANDIDATE.ENV")
        walls = Walls(**request["walls"])
        if any(getattr(walls, k) > v for k, v in asdict(self.ceiling).items()):
            raise Refused("CANDIDATE.LIMIT: request exceeds allocated ceiling")
        for kind in ("readable", "writable"):
            if not isinstance(request[kind], list) or len(request[kind]) > 32:
                raise Refused("CANDIDATE.MOUNTS")
        if not self.probe.ready:
            raise Refused("CANDIDATE.RUNTIME_UNAVAILABLE")
        with ExitStack() as stack, tempfile.TemporaryDirectory(prefix="standard-candidate-stage-") as staging:
            budget = StageBudget()
            descriptors, sources = {}, {}
            for p in (request["cwd"], *request["readable"], *request["writable"]):
                if p in sources:
                    continue
                root = self.cache if self.cache and isinstance(p, str) and Path(p).is_relative_to(self.cache) else self.scratch
                fd = pin(root, p, stack, allow_root=root == self.cache)
                source = Path(staging, f"mount-{len(sources)}")
                copy_in(fd, source, budget)
                descriptors[p], sources[p] = fd, str(source)
            bac = self.bac_factory(walls)
            if not bac.ready:
                raise Refused("CANDIDATE.RUNTIME_UNAVAILABLE")
            remaining_stage_s = budget.deadline - time.monotonic()
            result = bac._execute(args, request["cwd"], {**BASE_ENV, **env}, request["readable"], request["writable"],
                                  walls.timeout_s, mount_sources=sources)
            budget.deadline = time.monotonic() + remaining_stage_s
            for p in request["writable"]:
                copy_out(Path(sources[p]), descriptors[p], budget)
            return asdict(result)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            pid, uid, _ = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != self.server.agent_uid:
                raise Refused("CANDIDATE.IDENTITY")
            if self.server.agent_cgroup is not None:
                groups = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
                if f"0::{self.server.agent_cgroup}" not in groups:
                    raise Refused("CANDIDATE.IDENTITY")
            raw = self.rfile.readline(MAX_MESSAGE + 1)
            if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
                raise Refused("CANDIDATE.SIZE")
            result = self.server.executor.execute(json.loads(raw))
            response = {"ok": True, "result": result}
        except Exception as exc:
            response = {"ok": False, "error": str(exc)[:160] if isinstance(exc, Refused) else "CANDIDATE.REFUSED"}
        try:
            self.wfile.write(encode(response))
        except OSError:
            pass  # disconnected callers do not interrupt bac cleanup


class Supervisor(socketserver.UnixStreamServer):
    """Serial admission bounds concurrent executions to one; kernel limits bound each run.

    The socket parent belongs to root. Its client cannot replace or unlink it.
    Other requests queue; this is deliberately not an unbounded thread factory.
    """
    def __init__(self, path, executor, *, agent_uid, agent_cgroup=None):
        self.path, self.executor, self.agent_uid, self.agent_cgroup = Path(path), executor, agent_uid, agent_cgroup
        super().__init__(str(path), Handler)
        os.chmod(path, 0o600)

    def server_close(self):
        super().server_close()
        self.path.unlink(missing_ok=True)


class RemoteBac:
    """Agent-side view. A lost supervisor is a refusal, never local execution."""
    groups = True

    def __init__(self, path, walls):
        self.path, self.walls = str(path), walls
        try:
            state = self.call({"action": "status"})
            self.ready, self.why = state["ready"], state["why"]
        except (OSError, ValueError, KeyError):
            self.ready, self.why = False, "external candidate supervisor unavailable"

    @property
    def isolation(self):
        return "external OCI candidate bac" if self.ready else f"UNAVAILABLE: {self.why}"

    def call(self, request):
        raw = encode(request)
        if len(raw) > MAX_MESSAGE:
            raise Refused("CANDIDATE.SIZE")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.walls.timeout_s + STAGE_SECONDS + 60)
            connection.connect(self.path)
            connection.sendall(raw)
            with connection.makefile("rb") as stream:
                raw = stream.readline(MAX_MESSAGE + 1)
        if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
            raise Refused("CANDIDATE.RESPONSE")
        response = json.loads(raw)
        if response.get("ok") is not True:
            raise Refused(response.get("error", "CANDIDATE.REFUSED"))
        return response["result"]

    def run(self, args, cwd, *, env=None, readable=(), writable=()):
        try:
            response = self.call({"action": "run", "args": list(map(str, args)), "cwd": str(cwd),
                                  "env": env or {}, "readable": list(map(str, readable)),
                                  "writable": list(map(str, writable)), "walls": asdict(self.walls)})
            return Ran(response["code"], response["out"],
                       tuple(response["limited"]) if response["limited"] is not None else None, response["err"])
        except (OSError, ValueError, KeyError) as exc:
            return Ran(REFUSED, f"candidate execution refused: {exc}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket")
    parser.add_argument("scratch")
    parser.add_argument("--cache")
    parser.add_argument("--agent-uid", required=True, type=int)
    args = parser.parse_args()
    if os.getuid() == 0:
        parser.error("supervisor must run under an unprivileged account")
    executor = Executor(args.scratch, cache=args.cache)
    if not executor.probe.ready:
        parser.error(executor.probe.why)
    path = Path(args.socket)
    if path.exists() and stat.S_ISSOCK(path.lstat().st_mode) and path.stat().st_uid == os.getuid():
        path.unlink()  # stale socket; root-controlled service ordering permits one instance
    with Supervisor(path, executor, agent_uid=args.agent_uid,
                    agent_cgroup=f"/standard-bac/{args.agent_uid}/enclosure") as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
