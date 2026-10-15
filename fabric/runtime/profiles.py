"""Runtime requirements, not an assertion of administrative independence.

Every profile requires cgroup limits. A stronger profile restricts the runtimes;
missing runtime support refuses execution rather than silently changing the threat model.
Independent evidence and recovery authorities still require deployment qualification.
"""

PROFILES = {
    "base": ("runsc", "runc", "crun"),
    "reinforced": ("runsc",),
    "critical": ("runsc",),
}


def runtime_names(profile: str) -> tuple[str, ...]:
    try:
        return PROFILES[profile]
    except (KeyError, TypeError):
        raise ValueError("profile must be base, reinforced or critical") from None
