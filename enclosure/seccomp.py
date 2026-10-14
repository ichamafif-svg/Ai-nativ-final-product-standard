"""The bac's system-call filter (D68), compiled with the system's libseccomp and handed to Bubblewrap.

A deny list for now, the same family of calls Flatpak refuses: anything that changes mounts or namespaces, loads
kernel code, traces or reads another process, reaches kernel keyrings, BPF or perf, or injects terminal input.
`clone3` answers ENOSYS so the C library falls back to `clone`, whose namespace flags can then be checked. An
allow list is stronger and comes later; until then this wall is `held` only for the calls it names.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os

ALLOW = 0x7FFF0000
MASKED_EQ = 7
CLONE_NEWUSER = 0x10000000
TIOCSTI, TIOCLINUX = 0x5412, 0x541C

DENIED = (
    "mount", "umount2", "pivot_root", "chroot", "unshare", "setns", "move_mount", "open_tree", "fsopen", "fsmount",
    "fsconfig", "fspick", "mount_setattr", "kexec_load", "kexec_file_load", "init_module", "finit_module",
    "delete_module", "ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "add_key", "request_key", "keyctl",
    "bpf", "perf_event_open", "userfaultfd", "open_by_handle_at", "name_to_handle_at", "swapon", "swapoff",
    "reboot", "syslog", "acct", "quotactl", "iopl", "ioperm", "lookup_dcookie", "uselib", "vm86", "vm86old",
    "settimeofday", "clock_settime", "clock_adjtime", "adjtimex", "nfsservctl",
)


class _Arg(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int), ("datum_a", ctypes.c_uint64),
                ("datum_b", ctypes.c_uint64)]


def _errno(code: int) -> int:
    return 0x00050000 | (code & 0xFFFF)


def _library():
    name = ctypes.util.find_library("seccomp")
    if not name:
        return None
    lib = ctypes.CDLL(name, use_errno=True)
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
                                           ctypes.POINTER(_Arg)]
    lib.seccomp_export_bpf.restype = ctypes.c_int
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    return lib


def program() -> bytes | None:
    """The compiled BPF filter for this machine's architecture, or None when libseccomp is missing."""
    lib = _library()
    if lib is None:
        return None
    ctx = lib.seccomp_init(ALLOW)
    if not ctx:
        return None
    fd = os.memfd_create("bac-seccomp")
    try:
        def rule(name: str, action: int, *args: tuple[int, int, int]) -> None:
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number < 0:                                   # not a call on this architecture
                return
            array = (_Arg * max(1, len(args)))(*[_Arg(i, MASKED_EQ, mask, value) for i, mask, value in args])
            if lib.seccomp_rule_add_array(ctx, action, number, len(args), array) < 0:
                raise OSError(f"seccomp rule for {name} refused")

        for name in DENIED:
            rule(name, _errno(errno.EPERM))
        rule("clone3", _errno(errno.ENOSYS))
        rule("clone", _errno(errno.EPERM), (0, CLONE_NEWUSER, CLONE_NEWUSER))
        rule("ioctl", _errno(errno.EPERM), (1, 0xFFFFFFFF, TIOCSTI))
        rule("ioctl", _errno(errno.EPERM), (1, 0xFFFFFFFF, TIOCLINUX))
        if lib.seccomp_export_bpf(ctx, fd) < 0:
            return None
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)
        lib.seccomp_release(ctx)
