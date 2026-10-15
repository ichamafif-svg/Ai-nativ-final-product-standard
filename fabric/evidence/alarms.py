"""Alarms (D69): the outer wall is silent toward the code, and loud toward the platform.

The bac's system-call filter carries SECCOMP_FILTER_FLAG_LOG: the kernel logs every call it refused (audit record
type 1326, with the process and the call). The watcher, a platform process, reads the kernel log as it is written,
keeps the refusals no ordinary code makes (mounting, changing namespaces, tracing another process, loading kernel
code, keyrings, BPF, perf...) and attributes each to the bac run whose control group held the process. It writes
them where the hidden control and the human read them, never to the agent: an alarm is not a lesson.

    python -m fabric.evidence.alarms ALARMS.jsonl        (needs the right to read the kernel log)

Ordinary refusals that libraries trigger on their own (a C library trying clone3 before clone) are not alarms.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import re
import sys
import threading
import time

ALARMING = frozenset({
    "mount", "umount2", "pivot_root", "chroot", "unshare", "setns", "move_mount", "open_tree", "fsopen", "fsmount",
    "fsconfig", "fspick", "mount_setattr", "ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
    "init_module", "finit_module", "delete_module", "kexec_load", "kexec_file_load", "bpf", "perf_event_open",
    "keyctl", "add_key", "request_key", "open_by_handle_at", "name_to_handle_at", "userfaultfd", "iopl", "ioperm",
    "swapon", "swapoff", "reboot", "acct", "quotactl", "settimeofday", "clock_settime", "adjtimex",
})
AUDIT = re.compile(r"type=1326 .*?\bpid=(?P<pid>\d+) .*?comm=\"(?P<comm>[^\"]*)\".*?\barch=(?P<arch>[0-9a-f]+) "
                   r"syscall=(?P<syscall>\d+)")
BAC = re.compile(r"standard-bac/(?:[0-9]+/)?([0-9a-f]{32})")
ARCH = {"c000003e": 0xC000003E, "c00000b7": 0xC00000B7}       # x86_64, aarch64 (AUDIT_ARCH_*)


def _resolver():
    name = ctypes.util.find_library("seccomp")
    if not name:
        return lambda arch, number: str(number)
    lib = ctypes.CDLL(name)
    lib.seccomp_syscall_resolve_num_arch.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_num_arch.argtypes = [ctypes.c_uint32, ctypes.c_int]
    libc = ctypes.CDLL(None)

    def resolve(arch: str, number: int) -> str:
        pointer = lib.seccomp_syscall_resolve_num_arch(ARCH.get(arch, 0), number)
        if not pointer:
            return str(number)
        text = ctypes.cast(pointer, ctypes.c_char_p).value.decode()
        libc.free(ctypes.c_void_p(pointer))
        return text
    return resolve


def run_of(pid: int) -> str | None:
    """The bac run a process belongs to, read from its control group while it still exists."""
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            found = BAC.search(f.read())
    except OSError:
        return None
    return found.group(1) if found else None


class Watcher:
    def __init__(self, path, *, source: str = "/dev/kmsg"):
        self.path, self.source, self.stopped = path, source, threading.Event()
        self.resolve = _resolver()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "Watcher":
        self.fd = os.open(self.source, os.O_RDONLY | os.O_NONBLOCK)
        os.lseek(self.fd, 0, os.SEEK_END)                    # only what happens from now on
        self.thread.start()
        return self

    def read(self, line: str) -> dict | None:
        found = AUDIT.search(line)
        if not found:
            return None
        call = self.resolve(found["arch"], int(found["syscall"]))
        if call not in ALARMING:
            return None
        return {"kind": "alarm", "capability": "syscalls", "held_by": "platform:resources",
                "run": run_of(int(found["pid"])), "attempt": f"{found['comm']} called {call}", "at": int(time.time())}

    def _run(self):
        while not self.stopped.is_set():
            try:
                raw = os.read(self.fd, 8192)
            except BlockingIOError:
                time.sleep(0.05)
                continue
            except OSError:
                time.sleep(0.05)                             # an overrun of the kernel's buffer: keep reading
                continue
            alarm = self.read(raw.decode("utf-8", "replace"))
            if alarm:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(alarm, sort_keys=True) + "\n")

    def stop(self):
        self.stopped.set()
        self.thread.join(timeout=2)
        os.close(self.fd)


if __name__ == "__main__":
    Watcher(sys.argv[1]).start().thread.join()
