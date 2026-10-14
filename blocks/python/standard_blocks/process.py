"""Processes without a shell (INJ-CMD, INJ-LATEX, CWE-88 argument injection).

    out = run(["/usr/bin/convert", arg(user_name), "out.png"])

Beyond the checklists:
    - the program is named by absolute path or found on a fixed PATH, never on the product's;
    - the child gets a clean environment (PATH, LANG, nothing inherited: no secrets, no LD_PRELOAD), its own process
      group (a timeout kills grandchildren too), and resource limits: CPU time, memory, file size, open files;
    - its output is bounded (MAX_OUTPUT), read as it comes;
    - a value from a user goes through `arg()`, which refuses what a program would read as an option ("-o…").
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading

LATEX = {"pdflatex", "xelatex", "lualatex", "latex"}
PATH = "/usr/local/bin:/usr/bin:/bin"
MAX_OUTPUT = 16 * 1024 * 1024
LIMITS = {"cpu_s": 60, "memory_bytes": 2 * 1024 ** 3, "file_bytes": 512 * 1024 ** 2, "open_files": 256}


class ProcessError(ValueError):
    pass


def arg(value: str) -> str:
    """A user-supplied argument: refused when it would be read as an option, a NUL or a line break."""
    value = str(value)
    if value.startswith("-") or any(c in value for c in "\x00\r\n"):
        raise ProcessError("an argument from a user cannot start with '-' or hold control characters")
    return value


def _limits(cpu_s: int):
    def apply():
        import resource
        for name, value in (("RLIMIT_CPU", cpu_s), ("RLIMIT_AS", LIMITS["memory_bytes"]),
                            ("RLIMIT_FSIZE", LIMITS["file_bytes"]), ("RLIMIT_NOFILE", LIMITS["open_files"]),
                            ("RLIMIT_CORE", 0)):
            if hasattr(resource, name):
                try:
                    resource.setrlimit(getattr(resource, name), (value, value))
                except (ValueError, OSError):
                    pass
    return apply


def run(argv, *, timeout: float = 30, cwd=None, input: bytes | None = None, env: dict | None = None,
        max_output: int = MAX_OUTPUT) -> subprocess.CompletedProcess:
    """Run argv[0] with arguments argv[1:]: a list of strings, never a shell, always a timeout. LaTeX runs with shell
    escape disabled."""
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
        raise ProcessError("argv is a list of strings")
    if any("\x00" in a for a in argv):
        raise ProcessError("no NUL in arguments")
    argv = list(argv)
    program = argv[0]
    if "/" in program and not os.path.isabs(program):
        raise ProcessError("a program is named by absolute path or by name")
    found = program if os.path.isabs(program) else shutil.which(program, path=PATH)
    if not found:
        raise ProcessError(f"{program} is not installed")
    argv[0] = found
    if os.path.basename(found) in LATEX:
        argv = [a for a in argv if not a.lstrip("-").startswith(("shell-escape", "enable-write18", "shell-restricted"))]
        argv.insert(1, "-no-shell-escape")
    clean = {"PATH": PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": cwd or "/nonexistent"}
    for k, v in (env or {}).items():
        if k.upper().startswith(("LD_", "DYLD_", "PYTHON", "NODE_OPTIONS", "PERL5", "RUBYOPT")) or k == "PATH":
            raise ProcessError(f"{k} is not passed to a child process")
        clean[k] = str(v)
    proc = subprocess.Popen(argv, shell=False, cwd=cwd, env=clean, stdin=subprocess.PIPE if input is not None
                            else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True, preexec_fn=_limits(int(timeout) + 1), close_fds=True)
    out, err, over = bytearray(), bytearray(), {"hit": False}

    def drain(stream, buf):
        while chunk := stream.read(65_536):
            if len(buf) + len(chunk) > max_output:
                over["hit"] = True
                buf += chunk[: max_output - len(buf)]
                _kill(proc)
                break
            buf += chunk
        stream.close()
    readers = [threading.Thread(target=drain, args=(proc.stdout, out), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, err), daemon=True)]
    for r in readers:
        r.start()
    if input is not None:
        try:
            proc.stdin.write(input)
        except BrokenPipeError:
            pass
        finally:
            proc.stdin.close()
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(proc)
        proc.wait()
        raise
    finally:
        for r in readers:
            r.join(timeout=5)
    if over["hit"]:
        raise ProcessError(f"the process wrote more than {max_output} bytes")
    return subprocess.CompletedProcess(argv, code, bytes(out), bytes(err))


def _kill(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)                  # the whole group: grandchildren too
    except (ProcessLookupError, PermissionError):
        pass
