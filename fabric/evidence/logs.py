"""The product's logs (D68): captured by the platform, structured, bounded and redacted, never writable by the bac.

Whatever the product writes on stdout or stderr reaches the platform through a pipe; the platform writes one JSON
line per line read (time, release, stream line cut at LINE_MAX) into a file the bac cannot see. Every value the
platform knows to be secret (the broker's secrets, the identity tokens it signs) is replaced by `[secret]` before
anything is written: a secret the product never had cannot leak through its logs, and one it received by mistake
does not reach the log store either. An OpenTelemetry Collector can read this file (`telemetry.collector_config`).
"""
from __future__ import annotations

import json
import os
import threading
import time

LINE_MAX = 4096


class Capture:
    def __init__(self, path, *, release: str, secrets=()):
        self.path, self.release = path, release
        self.secrets = sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True)
        self.read_end, self.write_end = os.pipe()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def redact(self, line: str) -> str:
        for value in self.secrets:
            line = line.replace(value, "[secret]")
        return line

    def _run(self):
        with os.fdopen(self.read_end, "rb") as source, open(self.path, "a", encoding="utf-8") as sink:
            discarding = False
            while raw := source.readline(LINE_MAX + 1):
                if discarding:
                    discarding = not raw.endswith(b"\n")
                    continue
                if len(raw) > LINE_MAX and not raw.endswith(b"\n"):
                    # Never publish a prefix whose suffix might complete a secret on the next read.
                    line, discarding = "[oversized line omitted]", True
                else:
                    line = self.redact(raw.decode("utf-8", "replace").rstrip("\n"))[:LINE_MAX]
                sink.write(json.dumps({"at": round(time.time(), 3), "release": self.release, "line": line}) + "\n")
                sink.flush()

    def fileno(self) -> int:
        return self.write_end

    def close(self):
        """After the product stopped: the pipe drains, the file is complete."""
        try:
            os.close(self.write_end)
        except OSError:
            pass
        self.thread.join(timeout=10)
