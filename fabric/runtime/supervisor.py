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
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path

from fabric.runtime.bac import BASE_ENV, Bac, Ran, Walls, REFUSED

MAX_MESSAGE = 1 << 20
SOCKET_ENV = "STANDARD_CANDIDATE_SOCKET"


class Refused(ValueError):
    pass


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def pin(root: Path, value: str, stack: ExitStack, *, allow_root=False) -> tuple[str, str]:
    """Open every component without following links; retain the inode through OCI mount.

    /proc/PID/fd is interpreted by the external runtime, never exposed in the bac.
    Replacing a scratch entry after validation cannot substitute a host path.
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
    return value, f"/proc/{os.readlink('/proc/self')}/fd/{fd}"


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
        with ExitStack() as stack:
            sources = {}
            for p in (request["cwd"], *request["readable"], *request["writable"]):
                root = self.cache if self.cache and isinstance(p, str) and Path(p).is_relative_to(self.cache) else self.scratch
                destination, source = pin(root, p, stack, allow_root=root == self.cache)
                sources[destination] = source
            bac = self.bac_factory(walls)
            if not bac.ready:
                raise Refused("CANDIDATE.RUNTIME_UNAVAILABLE")
            result = bac._execute(args, request["cwd"], {**BASE_ENV, **env}, request["readable"], request["writable"],
                                  walls.timeout_s, mount_sources=sources)
            return asdict(result)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            _, uid, _ = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != self.server.agent_uid:
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
    def __init__(self, path, executor, *, agent_uid):
        self.path, self.executor, self.agent_uid = Path(path), executor, agent_uid
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
            connection.settimeout(self.walls.timeout_s + 120)
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
    with Supervisor(path, executor, agent_uid=args.agent_uid) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
