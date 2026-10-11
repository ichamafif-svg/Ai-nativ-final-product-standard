"""The operator process (§19): assemble K and T from one configuration, serve the gateway, run the passes.

    python -m trusted serve standard.toml

One process, one host, one writer (D06). Every tick: witness (demo only), instruments, departures, readback, proof of
application. Each pass fails alone and is logged; none can admit anything except through the journal.

In a demo installation (`demo = true`) the operator also holds the witness keys and assessed its own installation:
the system runs, nothing physical is qualified, and every view says SELF_ASSESSED (D19).
"""
from __future__ import annotations

import base64
import json
import os
import sys
import threading
import time
import tomllib
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from floors import RELEASE
from kernel import Kernel

from .adapters import GitRepository, Readback
from .boundary import SignedAssessment
from .gateway import AdmissionGateway
from .guard import EffectPort
from .host import Evidence, Host, Series
from .isolation import Isolation
from .journal import Journal, PinStore
from .operator import MAIN_OPS, Instrument, Instruments, Prover, git
from .register import Registers
from .release import code_digest
from .service import TrustedService
from .signing import Signer, entry


def key(keys_dir: Path, identity: str) -> Signer:
    path = keys_dir / f"{identity}.key"
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} must be readable by its owner only")
    return Signer(identity, Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip())))


def now_ms() -> int:
    return int(time.time() * 1000)


class Installation:
    def __init__(self, config_path):
        self.path = Path(config_path).resolve()
        c = self.config = tomllib.loads(self.path.read_text())
        base = self.path.parent
        resolve = lambda p: (base / p).resolve()
        self.demo = c.get("demo") is True
        self.keys = resolve(c["keys"]["dir"])
        self.kernel = Kernel(RELEASE, code_digest())
        pins = PinStore(resolve(c["ledger"]["pins"]))
        self.journal = Journal(resolve(c["ledger"]["journal"]), self.kernel, pins, c["ledger"]["genesis"])
        assessment = json.loads(resolve(c["assessment"]["path"]).read_text())
        assessors = {n: base64.b64decode(k) for n, k in c["assessment"]["assessors"].items()}
        self.clock = self._clock(c.get("clock", {}))
        grants = c["grants"]
        repo = c["repository"]
        if repo["kind"] == "git":
            self.repository = GitRepository(resolve(repo["path"]), resolve(repo["proposals"]))
            self.repo_path, self.proposals = resolve(repo["path"]), resolve(repo["proposals"])
            self.world = None
        else:
            from .github import GitHub
            self.repository = GitHub(repo["name"], resolve(repo["token_file"]).read_text().strip(),
                                     push_from=resolve(repo["mirror"]) if repo.get("api") == "git" else None)
            self.repo_path = self.proposals = resolve(repo["mirror"])
            self.world = self.repository
        run, deploy, data = c.get("run", {}), c.get("deploy"), c.get("data")
        evidence = Evidence(self.path.parent / "evidence")             # D37: what every measure read and returned
        self.host = Host(Path(__file__).resolve().parents[1], evidence, self.repo_path,
                         isolation=Isolation(c.get("tests", {}).get("runner_user")),   # D33: never run their code as us
                         stores={"requests": resolve(c.get("build", {}).get("store", "requests"))},
                         data=(resolve(data["path"]), data["digest"]) if data else None, world=self.world,
                         series=Series(evidence, self.path.parent / "series.json"), clock=self.clock,
                         pinned=RELEASE.floors["instruments"]["tests"]["method"])
        sources = {f"metrics-{i}": ("metrics", url) for i, url in enumerate(run.get("metrics", []))}
        if (deploy or {}).get("runner_metrics"):
            sources["runner"] = ("runner", deploy["runner_metrics"])
        self.releases = Registers(self.repo_path, resolve(deploy["root"]), clock=self.clock,
                                  served=lambda: self.instruments.served,
                                  canary_percent=lambda: self.instruments.canary_percent) if deploy else None
        ports = {op: self.repository.remediate for op in MAIN_OPS} | ({
            "deploy": self.releases.switch, "rollback": self.releases.switch,
            "restart": self.releases.request_restart, "canary": self.releases.canary_switch,
            "abort": self.releases.canary_switch} if self.releases else {})
        self.service = TrustedService(
            self.journal, boundary=SignedAssessment(assessment, assessors), clock=self.clock,
            guard_signer=key(self.keys, "guard"), effect_port=EffectPort(ports),
            reconciliation=Readback(self.repository, key(self.keys, "oracle"), grants["oracle"], self.clock,
                                    releases=self.releases))
        names = {gid: name for name, gid in grants.items()}
        self.instruments = Instruments(
            self.service, Instrument(key(self.keys, "scanner"), grants["scanner"], self.clock), self.host,
            self.repo_path, self.proposals, anchor=repo.get("anchor"), install=c.get("tests", {}).get("install") is True,
            inbox=resolve(repo["inbox"]) if repo.get("inbox") else None, findings=self.path.parent / "findings.json",
            holders=lambda: {names[gid]: g["holder"] for gid, g in self.journal.snapshot()["grants"].items()
                             if gid in names}, sources=sources, production=bool(sources) or deploy is not None,
            registers=self.releases)
        self.prover = Prover(self.service, self.repository, key(self.keys, "oracle"), grants["oracle"], self.clock,
                             releases=self.releases)
        self.socket = resolve(c["socket"]["path"])

    def _clock(self, spec: dict):
        if spec.get("kind", "local") == "local":
            if not self.demo:
                raise ValueError("a local clock is only acceptable in a demo installation (T03 unqualified)")
            return now_ms
        raise ValueError("configure a witness clock (trusted.clock.WitnessClock) for production")

    def witness(self) -> None:
        """Demo only: the operator's witnesses anchor the current head. Production witnesses run elsewhere."""
        if not self.demo:
            return
        state = self.journal.snapshot()
        at = max(self.clock(), state["last_at"] + 1)
        body = {"id": f"checkpoint-{uuid.uuid4().hex}", "at": at, "author": "w1", "size": state["size"],
                "head": state["head"]}
        self.journal.append(entry(state, "checkpoint", body, [key(self.keys, "w1"), key(self.keys, "w2")]))

    def sync(self) -> None:
        if self.world is not None:                          # GitHub: refresh the mirror, proposals included
            git(self.repo_path, "fetch", "-q", "--prune", "origin", "+refs/heads/main:refs/heads/main",
                "+refs/heads/standard/proposals/*:refs/standard/proposals/*")

    def tick(self) -> dict:
        report = {}
        for name, step in (("witness", self.witness), ("sync", self.sync), ("measure", self.instruments.measure),
                           ("witness2", self.witness), ("dispatch", self.service.dispatch_due),
                           ("reconcile", self.service.reconcile_due), ("prove", self.prover.prove_due)):
            try:
                report[name] = step()
            except Exception as exc:
                report[name] = {"blocked": getattr(exc, "code", None) or f"{type(exc).__name__}: {exc}"}
        report["status"] = self.service.status()
        return report

    def serve(self, interval: float = 60.0) -> None:
        self.socket.unlink(missing_ok=True)
        gateway = AdmissionGateway(self.socket, self.service, mode=0o660)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        try:
            while True:
                print(json.dumps({"at": now_ms(), **self.tick()}, default=str), flush=True)
                time.sleep(interval)
        finally:
            gateway.shutdown()
            gateway.server_close()


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    os.umask(0o027)                     # T07: what the guard writes, its group (the agent, for the socket) only reads
    if len(argv) < 2 or argv[0] not in ("serve", "tick"):
        print("usage: python -m trusted serve|tick standard.toml [interval-seconds]")
        return 2
    installation = Installation(argv[1])
    if argv[0] == "tick":
        print(json.dumps(installation.tick(), indent=2, default=str))
    else:
        installation.serve(float(argv[2]) if len(argv) > 2 else 60.0)
    return 0
