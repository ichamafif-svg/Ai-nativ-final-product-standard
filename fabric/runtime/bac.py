"""One bac definition for the agent's precheck, the tests and production (D68).

`Bac.run` writes the OCI configuration of the walls (`fabric/runtime/oci.py`) into a fresh bundle and executes it with an
OCI runtime: gVisor's runsc first when it is installed and runs this definition (a user-space kernel between the
product and Linux, the OCI seccomp profile still applied inside), then runc (it keeps a finished container until its
counters are read), then crun: every namespace unshared, an empty network, no capability, Docker's allow-list seccomp profile, a read-only
system with only the declared paths mounted, rlimits per process and one control group per run bounding processes,
memory and CPU for the run as a whole. The host bounds wall time and removes the container afterwards, whatever
it left behind. The environment is exactly what the caller passes on top of a fixed base, never the caller's own.

With `as_user`, the runtime itself runs under another account (`sudo -n -u USER -- /usr/bin/env -i`), with that
account's ids mapped to root inside: the trust side's candidate runner (T06) is a bac inside a separate account.

Fail closed: nothing runs unless this very definition runs `true`. A host without working control groups refuses execution: per-process limits do not
replace group budgets. Reinforced and critical runtime profiles require runsc without fallback.
"""
from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from fabric.runtime import capabilities, oci

BASE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8"}
REFUSED, TIMED_OUT = 126, 124
OUTPUT_TAIL = 20_000
GROUP = "standard-bac"
CGROUP_ROOT = Path("/sys/fs/cgroup")
RUNNER_LAUNCHER = "/usr/local/libexec/standard-cgroup-run"


@dataclass(frozen=True)
class Walls:
    """Limits derived from the effective law or the operator's configuration, never chosen by the code inside."""
    timeout_s: int = 600
    memory_mb: int = 2048
    processes: int = 64
    file_bytes: int = 10_485_760
    cpu_percent: int = 100

    def __post_init__(self):
        for name, value in vars(self).items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class Ran:
    code: int
    out: str
    limited: tuple[str, ...] | None = ()      # limits the kernel enforced on the run's group; None: not readable
    err: str = ""                             # standard error, when asked apart (`split=True`)

    @property
    def ok(self) -> bool:
        return self.code == 0


def _limited(name: str, *, uid: int | None = None) -> tuple[str, ...] | None:
    """The kernel's own counters for this run's group (cgroup v2, or the v1 pids and memory hierarchies)."""
    found, readable = set(), set()
    subtree = Path(GROUP, str(os.getuid() if uid is None else uid), name)
    places = [CGROUP_ROOT / subtree, CGROUP_ROOT / "pids" / subtree, CGROUP_ROOT / "memory" / subtree]
    for place in places:
        for file, wall in (("pids.events", "processes"), ("memory.events", "memory")):
            try:
                counts = dict(line.split() for line in (place / file).read_text().splitlines() if line.strip())
            except OSError:
                continue
            if "max" not in counts:
                continue
            maximum, killed = int(counts["max"]), int(counts.get("oom_kill", 0))
            readable.add(wall)
            if maximum or killed:
                found.add(wall)
        try:
            count = int((place / "memory.failcnt").read_text())
            readable.add("memory")
            if count:
                found.add("memory")
        except (OSError, ValueError):
            pass
    return tuple(sorted(found)) if readable == {"memory", "processes"} else None


class Bac:
    def __init__(self, walls: Walls = Walls(), *, python: str = sys.executable, as_user: str | None = None, profile: str = "base"):
        from fabric.runtime.profiles import runtime_names
        self.runtime_names = runtime_names(profile)
        self.profile = profile
        self.walls, self.python, self.as_user = walls, python, as_user
        self.ids = None
        if as_user:
            entry = pwd.getpwnam(as_user)
            self.ids = (entry.pw_uid, entry.pw_gid)
        self.runtime: str | None = None
        self.groups = True
        self.why = self._unavailable()
        self.ready = self.why is None

    @property
    def isolation(self) -> str:
        return "network and filesystem jail" if self.ready else f"UNAVAILABLE: {self.why}"

    def config(self, args, cwd, *, env=None, readable=(), writable=(), name: str = "run") -> dict:
        """The OCI configuration of one run. Pure: it builds, it does not check that the runtime exists."""
        return oci.config(self.walls, args, cwd, env={**BASE_ENV, **(env or {})}, readable=readable,
                          writable=writable, cgroup=f"/{GROUP}/{self.ids[0] if self.ids else os.getuid()}/{name}" if self.groups else None, ids=self.ids)

    def _unavailable(self) -> str | None:
        """Why no runtime can run this very definition, filter and groups included; None once one does."""
        try:
            oci.seccomp()
        except (OSError, ValueError, KeyError, StopIteration) as exc:
            return f"system-call filter unavailable: {exc}"
        found = [path for path in map(shutil.which, self.runtime_names) if path]
        if not found:
            return f"OCI runtime unavailable ({', '.join(self.runtime_names)})"
        refusals = []
        with tempfile.TemporaryDirectory(prefix="bac-check-") as cwd:
            os.chmod(cwd, 0o755)                            # a runner account must be able to enter it
            for runtime in found:
                if Path(runtime).name == "runsc" and (os.getuid() != 0 or self.as_user):
                    # runsc's rootless mode ignores cgroup configuration errors.
                    # Successful execution cannot establish our fail-closed group budget.
                    refusals.append("runsc: rootless mode cannot guarantee cgroup configuration")
                    continue
                for groups in (True,):
                    self.runtime, self.groups = runtime, groups
                    ran = self._execute(["/usr/bin/true"], cwd, None, (), (), 30)
                    if ran.code == 0:
                        return None
                    refusals.append(f"{Path(runtime).name}: {ran.out.strip()[-200:]}")
        self.runtime = None
        return "OCI runtime refused the bac: " + "; ".join(refusals)

    def _base(self) -> list:
        if self.as_user:
            # The runtime runs as the runner; it creates its own state directory, which this account cannot touch.
            state = Path(tempfile.gettempdir(), f"bac-state-{self.as_user}")
            prefix = ["sudo", "-n", "--", RUNNER_LAUNCHER, self.as_user]
        else:
            state = Path(tempfile.gettempdir(), f"bac-state-{os.getuid()}")
            state.mkdir(mode=0o700, exist_ok=True)
            prefix = []
        base = [*prefix, str(self.runtime), "--root", str(state)]
        if Path(str(self.runtime)).name == "crun":
            base.append(f"--cgroup-manager={'cgroupfs' if self.groups else 'disabled'}")
        if Path(str(self.runtime)).name == "runsc":
            # The same walls under gVisor: its own empty network, the OCI seccomp profile applied too (not ignored).
            base += ["--network=none", "--oci-seccomp"]
            if not self.groups:
                base.append("--ignore-cgroups")
        return base

    def _bundle(self, bundle, args, cwd, env, readable, writable, name, mount_sources=None) -> None:
        rootfs = Path(bundle, "rootfs")
        rootfs.mkdir()
        for path in oci.SYSTEM:
            if Path(path).is_symlink():
                Path(rootfs, path.lstrip("/")).symlink_to(Path(path).readlink())
        config = self.config(args, cwd, env=env, readable=readable, writable=writable, name=name)
        if mount_sources is not None:
            # The supervisor pins each requested inode before invoking the runtime.
            # Never resolve an agent-controlled pathname again at mount time.
            expected = {str(Path(p)) for p in (cwd, *readable, *writable)}
            actual = {m["destination"] for m in config["mounts"] if m["destination"] in expected}
            if actual != expected:
                raise ValueError("candidate mount changed during configuration")
            for mount in config["mounts"]:
                if mount["destination"] in expected:
                    mount["source"] = mount_sources[mount["destination"]]
            config["process"]["cwd"] = str(cwd)
        Path(bundle, "config.json").write_text(json.dumps(config))
        if self.as_user:                    # the runner reads its bundle; its empty root is its own (mount points)
            Path(bundle).chmod(0o755)
            Path(bundle, "config.json").chmod(0o644)
            for path in (rootfs, *rootfs.iterdir()):
                os.lchown(path, *self.ids)

    def _execute(self, args, cwd, env, readable, writable, timeout, stdin: bytes | None = None,
                 split: bool = False, mount_sources=None) -> Ran:
        name = uuid.uuid4().hex
        base = self._base()
        with tempfile.TemporaryDirectory(prefix="bac-bundle-") as bundle, tempfile.TemporaryFile() as output, \
                tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as input_file:
            self._bundle(bundle, args, cwd, env, readable, writable, name, mount_sources)
            process = None
            try:
                try:
                    keep = ["--keep"] if Path(str(self.runtime)).name == "runc" else []
                    observed = None
                    deadline = time.monotonic() + timeout
                    if stdin is not None:
                        input_file.write(stdin)
                        input_file.seek(0)
                    process = subprocess.Popen([*base, "run", *keep, "--bundle", bundle, name],
                                               stdin=input_file if stdin is not None else subprocess.DEVNULL,
                                               stdout=output, stderr=errors if split else subprocess.STDOUT)
                    # Sample while the group exists: runsc removes it before returning.
                    while True:
                        sample = _limited(name, uid=self.ids[0] if self.ids else os.getuid()) if self.groups else ()
                        if sample is not None:
                            observed = tuple(sorted(set(observed or ()) | set(sample)))
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(process.args, timeout)
                        try:
                            process.wait(timeout=min(0.01, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            pass
                    code, out = process.returncode, None
                except subprocess.TimeoutExpired:
                    try:
                        subprocess.run([*base, "kill", name, "KILL"], capture_output=True, timeout=30)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=30)
                    code, out = TIMED_OUT, f"timeout after {timeout}s"
                sample = _limited(name, uid=self.ids[0] if self.ids else os.getuid()) if self.groups else ()
                limited = tuple(sorted(set(observed or ()) | set(sample or ()))) if observed is not None or sample is not None else None
            except OSError as exc:
                return Ran(REFUSED, f"execution refused: {exc}")
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=30)
                subprocess.run([*base, "delete", "--force", name], capture_output=True, timeout=30)
            if out is None:
                output.seek(0, 2)
                output.seek(max(0, output.tell() - OUTPUT_TAIL))
                out = output.read().decode(errors="replace")
            errors.seek(0, 2)
            errors.seek(max(0, errors.tell() - OUTPUT_TAIL))
            return Ran(code, out, limited, errors.read().decode(errors="replace"))

    def run(self, args, cwd, *, env=None, readable=(), writable=(), stdin: bytes | None = None,
            split: bool = False) -> Ran:
        if not self.ready:
            return Ran(REFUSED, f"execution refused: {self.why}")
        return self._execute(args, cwd, {**BASE_ENV, **(env or {})}, readable, writable, self.walls.timeout_s, stdin,
                             split)


class Service:
    """A long-running process in the bac (the product in production): same walls, no time limit, stopped by the
    platform. The runtime removes the container, and every process it left, when it stops."""

    def __init__(self, bac: "Bac", args, cwd, *, env=None, readable=(), writable=(), log=None):
        if not bac.ready:
            raise RuntimeError(f"execution refused: {bac.why}")
        self.name, self.base = uuid.uuid4().hex, bac._base()
        self._bundle = tempfile.mkdtemp(prefix="bac-service-")
        bac._bundle(self._bundle, args, cwd, {**BASE_ENV, **(env or {})}, readable, writable, self.name)
        self.process = subprocess.Popen([*self.base, "run", "--bundle", self._bundle, self.name],
                                        stdin=subprocess.DEVNULL, stdout=log or subprocess.DEVNULL,
                                        stderr=subprocess.STDOUT)

    def running(self) -> bool:
        return self.process.poll() is None

    def stop(self, grace_s: float = 5.0) -> None:
        subprocess.run([*self.base, "kill", self.name, "TERM"], capture_output=True, timeout=30)
        try:
            self.process.wait(timeout=grace_s)
        except subprocess.TimeoutExpired:
            subprocess.run([*self.base, "kill", "--all", self.name, "KILL"], capture_output=True, timeout=30)
            self.process.wait(timeout=30)
        subprocess.run([*self.base, "delete", "--force", self.name], capture_output=True, timeout=30)
        shutil.rmtree(self._bundle, ignore_errors=True)


def capability_map(walls: Walls = Walls(), *, groups: bool = True) -> dict:
    """The map of the bac these walls define, computed from its OCI configuration (D69). Runs nothing."""
    config = oci.config(walls, ["<your command>"], "/work", env=BASE_ENV, cgroup=f"/{GROUP}/{os.getuid()}/map" if groups else None)
    return capabilities.describe(config, timeout_s=walls.timeout_s)
