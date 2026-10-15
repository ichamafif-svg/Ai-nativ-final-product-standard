"""The capability map (D69, ARCHITECTURE.md §4.11): what code can use in the bac, read from the bac itself.

The map is a projection of the very OCI configuration the runtime executes, never a text written beside it: if a
wall changes, the map changes with it. It says what is available and how to ask for more. It never names the
mechanism, rule or threshold behind a refusal, and it promises nothing the bac does not provide yet.
"""
from __future__ import annotations

ASK = ("A limit that blocks a real need is a value for the human: draft it (for example a host for @hosts) and "
       "explain why; the human signs it in the rules of the game. Never work around a limit.")
NOT_YET = ["outbound network through the egress proxy (D68 step 3)", "secrets by reference (D68 step 3)",
           "key service: encrypt, sign, HMAC by key reference (D68 step 4)", "database through the proxy (D68 step 4)"]


def describe(config: dict, *, timeout_s: int, writable_roles: dict | None = None) -> dict:
    """The map of one bac configuration. `writable_roles` names declared writable paths by their purpose."""
    linux, process = config["linux"], config["process"]
    namespaces = {n["type"] for n in linux["namespaces"]}
    rlimits = {r["type"]: r["hard"] for r in process["rlimits"]}
    resources = linux.get("resources", {})
    binds = [m for m in config["mounts"] if m["type"] == "bind"]
    writable = sorted(m["destination"] for m in binds if "rw" in m["options"])
    roles = writable_roles or {}
    memory = resources.get("memory", {}).get("limit", rlimits.get("RLIMIT_AS"))
    return {
        "where": "every process of your candidate's tests and checks runs in this bac",
        "network": ({"outbound": "none: no host is reachable", "inbound": "none"} if "network" in namespaces
                    else {"outbound": "unrestricted", "inbound": "unrestricted"}),
        "filesystem": {
            "working_tree": "your checkout, read-only (the current directory)",
            "temporary": "/tmp, writable, private to the run, emptied after it",
            "system": "read-only",
            "writable": [{"path": path, "purpose": roles.get(path, "declared for this run")} for path in writable],
            "elsewhere": "nothing else is visible",
        },
        "environment": sorted(entry.split("=", 1)[0] for entry in process["env"]),
        "privileges": "none: no administrative operation, no other process, no new privileges",
        "limits": {
            "time_s": timeout_s,
            "memory_mb": memory >> 20 if memory else None,
            "processes": resources.get("pids", {}).get("limit", rlimits.get("RLIMIT_NPROC")),
            "file_bytes": rlimits.get("RLIMIT_FSIZE"),
            "cpu_percent": (resources["cpu"]["quota"] * 100 // resources["cpu"]["period"]
                            if resources.get("cpu") else None),
        },
        "services": [],
        "secrets": [],
        "not_available_yet": NOT_YET,
        "production": "the product's own runtime is not yet in a bac (D68 step 2)",
        "ask": ASK,
    }
