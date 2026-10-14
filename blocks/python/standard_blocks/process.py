"""Processes without a shell (INJ-CMD, INJ-LATEX)."""
from __future__ import annotations

import subprocess

LATEX = {"pdflatex", "xelatex", "lualatex", "latex"}


class ProcessError(ValueError):
    pass


def run(argv, *, timeout: float = 30, cwd=None, input: bytes | None = None) -> subprocess.CompletedProcess:
    """Run argv[0] with arguments argv[1:]: a list of strings, never a shell, always a timeout. LaTeX runs with shell
    escape disabled."""
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
        raise ProcessError("argv is a list of strings")
    if any("\x00" in a for a in argv):
        raise ProcessError("no NUL in arguments")
    argv = list(argv)
    if argv[0].rsplit("/", 1)[-1] in LATEX:
        argv = [a for a in argv if not a.startswith(("--shell-escape", "-shell-escape", "--enable-write18"))]
        argv.insert(1, "-no-shell-escape")
    return subprocess.run(argv, shell=False, capture_output=True, timeout=timeout, cwd=cwd, input=input, check=False)
