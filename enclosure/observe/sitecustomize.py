"""Observer loaded into the candidate's Python runs in the precheck (D69): it makes swallowed network refusals
visible with the stack of the code that tried, so a caught error still becomes a lesson.

It only reports and re-raises: it changes no behaviour and holds no wall. The candidate may defeat it; it then only
loses its own lesson, and the bac still refuses. The candidate cannot ship its own sitecustomize (reserved path).
"""
import socket
import sys
import traceback

_connect, _resolve = socket.socket.connect, socket.getaddrinfo


def _report(exc):
    frames = traceback.format_stack()[:-2]
    sys.stderr.write("standard-bac: refused\n" + "".join(frames[-6:]) + f"standard-bac: {exc!r} {exc}\n")


def connect(self, address):
    try:
        return _connect(self, address)
    except OSError as exc:
        if getattr(self, "family", None) != socket.AF_UNIX and not str(address).startswith(("('127.", "('::1")):
            _report(exc)
        raise


def getaddrinfo(host, *args, **kwargs):
    try:
        return _resolve(host, *args, **kwargs)
    except OSError as exc:
        if host not in ("localhost", "127.0.0.1", "::1"):
            _report(exc)
        raise


socket.socket.connect = connect
socket.getaddrinfo = getaddrinfo
