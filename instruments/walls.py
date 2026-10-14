"""Measure the bac's walls from inside (D68, ARCHITECTURE.md §4.10).

A wall is measured by trying what it must refuse: reaching the network or the host's loopback, resolving a name,
seeing a host file, writing where nothing was declared writable, inheriting the caller's environment, holding a
capability, seeing host processes, making a system call the filter refuses, exceeding memory, file size, process
count or wall time. `cgroups` holds only when the kernel itself reports having enforced the run's process limit.
Each wall is `held`, `broken`, `absent` (the host lacks the mechanism) or `unmeasured` (the bac could not run).
Nothing here is `held` by declaration: only a refused attempt counts.
"""
from __future__ import annotations

import json
import socket
import sys
import tempfile
from pathlib import Path

from enclosure.bac import BASE_ENV, TIMED_OUT, Bac, Walls

WALLS = ("network", "host_loopback", "dns", "host_files", "read_only", "environment", "capabilities",
         "processes", "syscalls", "memory", "file_size", "process_count", "time", "cgroups")

INSIDE = r"""
import errno, json, os, socket, sys, time
port, hidden, memory, file_bytes, processes, allowed = sys.argv[1:7]
r = {}
def refused(attempt):
    try:
        attempt()
    except Exception:
        return "held"
    return "broken"
r["network"] = refused(lambda: socket.create_connection(("1.1.1.1", 443), timeout=2).close())
r["host_loopback"] = refused(lambda: socket.create_connection(("127.0.0.1", int(port)), timeout=2).close())
r["dns"] = refused(lambda: socket.getaddrinfo("example.com", 443))
r["host_files"] = "broken" if os.path.exists(hidden) else "held"
r["read_only"] = refused(lambda: open(".bac-probe", "w").close())
r["environment"] = "held" if set(os.environ) <= set(allowed.split(",")) else "broken"
status = dict(line.split(":\t", 1) for line in open("/proc/self/status").read().splitlines() if ":\t" in line)
r["capabilities"] = "held" if int(status["CapEff"], 16) == 0 and int(status["CapPrm"], 16) == 0 else "broken"
r["processes"] = "held" if len([p for p in os.listdir("/proc") if p.isdigit()]) < 16 else "broken"
r["syscalls"] = "held" if status.get("Seccomp", "").strip() == "2" and \
    refused(lambda: os.unshare(os.CLONE_NEWUSER)) == "held" else "broken"
r["memory"] = refused(lambda: bytearray(int(memory)))
def big():
    with open("/tmp/bac-probe", "wb") as f:
        f.write(b"\0" * (int(file_bytes) + 1))
r["file_size"] = refused(big)
children, started = [], 0
try:
    for _ in range(int(processes) + 8):
        pid = os.fork()
        if pid == 0:
            time.sleep(5)
            os._exit(0)
        children.append(pid)
except OSError:
    pass
for pid in children:
    os.kill(pid, 9)
    os.waitpid(pid, 0)
r["process_count"] = "held" if len(children) <= int(processes) else "broken"
print(json.dumps(r))
"""


def measure(walls: Walls = Walls(), *, python: str = sys.executable, kind: type[Bac] = Bac) -> dict[str, str]:
    """One run inside the bac with these walls, and one deliberately overlong run for the time wall."""
    bac = kind(walls, python=python)
    result = {wall: "unmeasured" for wall in WALLS}
    if not bac.ready:
        return result
    allowed = ",".join(sorted({*BASE_ENV, "PWD"}))           # bwrap sets PWD from --chdir
    with socket.socket() as listener, tempfile.TemporaryDirectory(prefix="bac-hidden-") as hidden, \
            tempfile.TemporaryDirectory(prefix="bac-cwd-") as cwd:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        secret = Path(hidden, "secret")
        secret.write_text("host")
        ran = bac.run([python, "-I", "-c", INSIDE, str(listener.getsockname()[1]), str(secret),
                       str(walls.memory_mb << 20), str(walls.file_bytes), str(walls.processes), allowed], cwd)
        try:
            inside = json.loads(ran.out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            inside = {}
        result.update({wall: inside[wall] for wall in inside if wall in result and inside[wall] in ("held", "broken")})
        result["cgroups"] = ("held" if "processes" in ran.limited else "broken") if bac.hierarchy else "absent"
        short = kind(Walls(timeout_s=1, memory_mb=walls.memory_mb, processes=walls.processes,
                          file_bytes=walls.file_bytes), python=python)
        result["time"] = "held" if short.run(["/usr/bin/sleep", "5"], cwd).code == TIMED_OUT else "broken"
    return result


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
