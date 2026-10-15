"""Reading the bac's refusals (D69, ARCHITECTURE.md §4.11): one wall, a lesson for each honest collision.

A run that touched a wall is read against the capability map. Each refusal becomes a record: what the code tried
(its own output line), which capability the map says is absent, which part of the platform holds it, what to do
instead and how to ask for more. A record never says more than the map: no mechanism, rule number or threshold
that the map does not already state.

Two sources, of unequal trust. The kernel's counters (`Ran.limited`) and the runtime's own outcome (a deadline)
are facts. The program's output is the candidate's own text: it can only teach the candidate about itself, never
clear or accuse anything else, so a forged or hidden line costs the candidate alone and the wall still holds.
Escape attempts are therefore not read here: an alarm needs the platform's own observation (the kernel's log of
refused system calls), never the candidate's output. An error this reader does not recognise stays raw.
"""
from __future__ import annotations

import re
from pathlib import Path

from enclosure.bac import TIMED_OUT, Ran

# capability in the map -> (part of the platform that holds it, signatures in the program's output, what to do)
WALLS = {
    "network.outbound": ("platform:egress", re.compile(
        r"Network is unreachable|\[Errno 101\]|ENETUNREACH|Temporary failure in name resolution|"
        r"Name or service not known|\[Errno -[23]\]|EAI_AGAIN|ENOTFOUND|getaddrinfo"),
        "do not reach the network from tests or checks: fake the remote side; a host the product needs in "
        "production is a value to draft for @hosts"),
    "filesystem": ("platform:files", re.compile(r"Read-only file system|\[Errno 30\]|EROFS"),
        "write under /tmp or a declared writable directory, never into the checkout or the system"),
    "limits.file_bytes": ("platform:resources", re.compile(r"File too large|\[Errno 27\]|EFBIG"),
        "stream or split the output, or draft a higher limit with its reason"),
    "limits.memory_mb": ("platform:resources", re.compile(
        r"\bMemoryError\b|Cannot allocate memory|ENOMEM|heap out of memory"),
        "bound what is held in memory (stream, page, cap the input), or draft a higher limit with its reason"),
    "limits.processes": ("platform:resources", re.compile(
        r"can't start new thread|fork: Resource temporarily unavailable|EAGAIN.*(fork|spawn|thread)"),
        "bound the workers and threads you start, or draft a higher limit with its reason"),
    "limits.time_s": ("platform:resources", None,
        "make the slow step bounded or faster; a run is stopped at the time limit"),
}
FROM_KERNEL = {"memory": "limits.memory_mb", "processes": "limits.processes"}
# Python tracebacks, pytest's short frames and Node's stack lines: where in the candidate's own code a call started.
FRAMES = (re.compile(r'File "(?P<path>[^"]+)", line (?P<line>\d+)'),
          re.compile(r"^(?P<path>[\w./-]+\.py):(?P<line>\d+): in "),
          re.compile(r"\((?P<path>/[^():]+\.[cm]?[jt]sx?):(?P<line>\d+):\d+\)"))


def _available(capability: str, capabilities: dict):
    section, _, key = capability.partition(".")
    value = capabilities.get(section)
    return value.get(key) if key and isinstance(value, dict) else value


def _own(path: str, root: Path | None) -> str | None:
    """A frame in the candidate's own checkout, relative to it; None for libraries and the interpreter."""
    if root is None:
        return None
    p = Path(path)
    if not p.is_absolute():
        return None if "site-packages" in path or path.startswith("<") else path
    try:
        rel = p.relative_to(root)
    except ValueError:
        return None
    return None if "site-packages" in rel.parts or "node_modules" in rel.parts else str(rel)


def read(ran: Ran, capabilities: dict, *, during: str, root=None) -> list[dict]:
    """The lessons of one run, at most one per capability, in a stable order.

    With `root` (the checkout the run used), each lesson read from the output also carries `stack`: the frames of
    the candidate's own code that led to it, innermost last, as `path:line` relative to the checkout."""
    root = Path(root).resolve() if root is not None else None
    found: dict[str, str] = {}
    stacks: dict[str, list] = {}
    frames: list = []
    for kernel_limit in ran.limited or ():
        if kernel_limit in FROM_KERNEL:
            found.setdefault(FROM_KERNEL[kernel_limit], "the kernel enforced this limit on the run")
    if ran.code == TIMED_OUT:
        found.setdefault("limits.time_s", "the run reached the time limit and was stopped")
    for line in ran.out.splitlines():
        for frame in FRAMES:
            m = frame.search(line)
            if m:
                own = _own(m.group("path"), root)
                if own:
                    frames.append(f"{own}:{m.group('line')}")
                break
        if not line.strip() or line.startswith(("Traceback", "____", "====")):
            frames = [] if line.startswith(("____", "====")) else frames
        for capability, (_, pattern, _) in WALLS.items():
            if pattern is not None and pattern.search(line) and (
                    capability not in found or (not stacks.get(capability) and frames)):
                found[capability] = line.strip()[:240]      # a line with its stack beats one without
                stacks[capability] = frames[-3:]
    return [{"kind": "lesson", "during": during, "capability": capability, "held_by": WALLS[capability][0],
             "attempt": found[capability], "stack": stacks.get(capability, []),
             "available": _available(capability, capabilities),
             "instead": WALLS[capability][2], "ask": capabilities.get("ask")}
            for capability in WALLS if capability in found]


# What the platform corrected or refused on the product's own traffic (D68 steps 2-4), read as lessons for its code.
PLATFORM = {
    "ingress.headers": "the product sent a banner or a security header weaker than the rules: send nothing (the "
                       "gateway imposes the rules' value) or a stricter one",
    "ingress.cookies": "set Secure, HttpOnly, SameSite and Path on every cookie the product sets",
    "ingress.json": "accept only JSON every parser reads the same way: no duplicate key, no two keys equal once "
                    "Unicode-normalised, bounded depth",
    "ingress.isolation": "a cross-site request must come from an origin in @origins; draft it if it is legitimate",
    "ingress.time": "answer within @request_timeout_s: make the slow step bounded or asynchronous",
    "ingress.size": "keep request bodies under @body_max_bytes, or draft a higher limit with its reason",
    "egress.destination": "call only hosts in @destinations; a host the product needs is a value to draft for it",
    "egress.private": "never call private addresses: the services the product may use are in the capability map",
    "egress.secret": "use `secret:NAME` only in a header, toward a host the rules allow for that secret",
    "egress.keys": "use the key service with the product's own keys (product-*) and its five operations",
    "egress.files": "store files of a type in @upload_types, within @upload_max_bytes and @user_quota_bytes",
}


def from_platform(records: list, *, during: str) -> list[dict]:
    """Lessons from the platform's records (gate, egress): corrections of the code and refusals. What the platform
    merely imposed (a header the product did not send) is its job, not a defect, and teaches nothing; an alarm goes
    to the hidden control, never to the agent."""
    out, seen = [], set()
    for r in records:
        if r.get("kind") not in ("correction", "refusal") or r.get("capability") not in PLATFORM:
            continue
        key = (r["capability"], r["route"], r["attempt"])
        if key in seen:
            continue
        seen.add(key)
        out.append({"kind": "lesson", "during": during, "capability": r["capability"], "held_by": r["held_by"],
                    "attempt": f"{r['route']}: {r['attempt']}", "stack": [], "available": None,
                    "instead": PLATFORM[r["capability"]], "ask": None, "route": r["route"]})
    return out
