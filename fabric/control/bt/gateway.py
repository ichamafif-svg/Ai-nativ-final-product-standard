"""The narrow admission gateway between U and K/T (ARCHITECTURE.md §11.6).

A Unix socket, one JSON line per request, one JSON line per answer. It exposes `view`, `status`, `qualify` and
`admit`; never the guard, a key or a provider port. Every request gets an answer: an internal failure, including a
result that cannot be serialized, is a typed refusal, never a dropped connection or internal detail (HK-1).
Filesystem permissions and distinct OS accounts on the host are physical prerequisites, not properties of this code.
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import stat
from pathlib import Path

MAX_MESSAGE = 1 << 20
ACTIONS = {"view": {"action"}, "status": {"action"}, "qualify": {"action", "required"}, "admit": {"action", "envelope"}}


class GatewayError(ValueError):
    pass


def _encode(response: dict) -> bytes:
    return json.dumps(response, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode() + b"\n"


def answer(service, raw: bytes) -> bytes:
    """Pure request -> answer. Never raises; the answer is always one bounded JSON line."""
    try:
        if not raw or len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
            raise GatewayError("REQUEST.SIZE")
        request = json.loads(raw)
        if not isinstance(request, dict) or ACTIONS.get(request.get("action")) != set(request):
            raise GatewayError("REQUEST.SHAPE")
        action = request["action"]
        if action == "view":
            result = service.view()
        elif action == "status":
            result = service.status()
        elif action == "qualify":
            service.qualify(request["required"])
            result = {"qualified": True}
        else:
            result = service.admit(request["envelope"])
        encoded = _encode({"ok": True, "result": result})
        if len(encoded) > MAX_MESSAGE:
            raise GatewayError("RESPONSE.SIZE")
        return encoded
    except Exception as exc:
        code = getattr(exc, "code", None) or (exc.args[0] if isinstance(exc, GatewayError) else type(exc).__name__)
        return _encode({"ok": False, "error": str(code)[:128]})


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            raw = self.rfile.readline(MAX_MESSAGE + 1)
        except OSError:
            return
        self.wfile.write(answer(self.server.service, raw))


class AdmissionGateway(socketserver.UnixStreamServer):
    def __init__(self, path, service, *, mode: int = 0o600):
        if mode not in (0o600, 0o660):
            raise GatewayError("SOCKET.MODE")
        if any(not callable(getattr(service, name, None)) for name in ("view", "status", "qualify", "admit")):
            raise GatewayError("SERVICE.REQUIRED")
        target = Path(path)
        if target.exists() or target.is_symlink():
            raise GatewayError("SOCKET.EXISTS")
        if stat.S_IMODE(target.parent.stat().st_mode) & 0o002:
            raise GatewayError("SOCKET.UNSAFE_DIRECTORY")
        self.service, self._path = service, target
        super().__init__(str(target), _Handler)
        try:
            os.chmod(target, mode)
        except BaseException:
            self.server_close()
            raise

    def server_close(self):
        super().server_close()
        self._path.unlink(missing_ok=True)


class GatewayClient:
    """The unprivileged U side. A refusal is an exception carrying the refusal code."""

    def __init__(self, path, *, timeout: float = 15):
        self.path, self.timeout = str(path), timeout

    def _call(self, request: dict):
        data = _encode(request)
        if len(data) > MAX_MESSAGE:
            raise GatewayError("REQUEST.SIZE")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.path)
                s.sendall(data)
                with s.makefile("rb") as stream:
                    raw = stream.readline(MAX_MESSAGE + 1)
            response = json.loads(raw)
        except (OSError, ValueError) as exc:
            raise GatewayError("GATEWAY.UNAVAILABLE") from exc
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise GatewayError(response.get("error", "GATEWAY.REFUSED") if isinstance(response, dict) else "GATEWAY.REFUSED")
        return response["result"]

    def view(self):
        return self._call({"action": "view"})

    def status(self):
        return self._call({"action": "status"})

    def qualify(self, required):
        return self._call({"action": "qualify", "required": sorted(required)})

    def admit(self, envelope):
        return self._call({"action": "admit", "envelope": envelope})
