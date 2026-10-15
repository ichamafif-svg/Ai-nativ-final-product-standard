"""The operator's own passes on the trusted side: measure (T06, through the host), prove (after T08).

They run in the operator process with their own identities and keys, never an agent's. Each pass admits signed
statements through the same journal and service as anyone else: nothing here bypasses the kernel.

D37, D38: this pass knows no measure. It records what the declared sources return (a capture transaction), gathers
what exists (main, proposals, the inbox, the ledger's extract, the release registers), lets the pinned `plan` program
say what to measure with which inputs, and runs every job as an OBSERVE boundary transaction: only what the job's
contract lets it say is signed, a property the floors pin as a measurement whose method names the contract and whose
artifact is the transaction; any other as an observation. A fact is signed again only when it changed or ages past
a third of its freshness. The proof of application reads the purpose of each effect through RESOLVE.
"""

from __future__ import annotations
import json
import subprocess
import uuid
from pathlib import Path
from fabric.control.bt.host import Host
from engine.catalog import load as load_catalog
from fabric.control.bt.signing import Signer, envelope
import base64
import os
import sys
import threading
import time
import tomllib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from engine.catalog.floors import CONTRACTS, PROGRAMS, RELEASE
from fabric.control.kernel import Kernel
from fabric.control.bt.adapters import GitRepository
from fabric.control.bt.assessment import SignedAssessment
from fabric.control.bt.gateway import AdmissionGateway
from fabric.control.bt.host import Evidence, Series
from fabric.control.bt.isolation import Isolation
from fabric.control.bt.journal import Journal, PinStore
from fabric.control.bt.register import Registers
from fabric.control.runtime import code_digest
from fabric.control.bt.service import TrustedService
from fabric.control.bt.signing import entry
from fabric.control.bt.transactions import Boundary, ledger_of

MAIN_OPS = ("remediate", "integrate", "implement")  # the operations that move main, by the same CAS
DAY = 86_400_000


def git(repo, *args) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError(f"git {args[0]}: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout.decode(errors="replace")


def publish_readings(host, sources: dict, directory, now: int, *, fresh_s: int = 300) -> None:
    """Publish only retained metrics captures, copied from BT evidence. No fetch, keys or admission authority.

    Immutable chunks keep readers off the private evidence store. Retain the preceding manifest's blobs as well
    so an overlapping reader can finish. The public projection is rebuilt from BT's existing retained series.
    """
    directory = Path(directory)
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    index = directory / "index.json"
    try:
        previous = json.loads(index.read_text()).get("objects", [])
    except (OSError, ValueError):
        previous = []
    objects, published = set(), {}

    def copy(ref):
        objects.add(ref)
        path = directory / ref.split(":", 1)[1]
        if not path.exists():
            path.write_bytes(host.evidence.get(ref))
            path.chmod(0o640)

    retained = host.series.chunks(now) if host.series else {}
    for name, (role, url) in sources.items():
        if role != "metrics":
            continue
        chunks = retained.get(name, {}).get("chunks", [])
        for ref in chunks:
            copy(ref)
            for _, value in json.loads(host.evidence.get(ref)):
                if value is not None:
                    copy(value)
        published[name] = {"url": url, "chunks": chunks}
    payload = {
        "schema": "standard-captures/v1",
        "at": now,
        "fresh_s": fresh_s,
        "sources": published,
        "objects": sorted(objects),
        "authority": "copy of BT captures; no authority",
    }
    temporary = index.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True))
    temporary.chmod(0o640)
    temporary.replace(index)
    keep = {ref.split(":", 1)[1] for ref in objects | set(previous)}
    for path in directory.iterdir():
        if len(path.name) == 64 and path.name not in keep and path.is_file():
            path.unlink()


class Instrument:
    """An instrument identity: turns answers into signed statements under its own capability."""

    def __init__(self, signer: Signer, capability: str, clock):
        self.signer, self.capability, self.clock = signer, capability, clock
        self.findings = {}                                  # "resource|property" -> details of the last measure

    def observation(self, domain: str, resource: str, prop: str, status: str, artifact: str | None = None,
                    method: str | None = None) -> dict:
        """A property the floors pin to an instrument (D33) is signed as a measurement of the pinned programs."""
        from engine.catalog.floors import INSTRUMENTS
        at = self.clock()
        body = {"id": f"obs-{uuid.uuid4().hex}", "at": at, "author": self.signer.identity,
                "under": self.capability, "resource": resource, "property": prop, "status": status, "level": "real"}
        if prop not in INSTRUMENTS:
            return envelope(domain, "observation", body, [self.signer])
        pinned, coverage, _ = INSTRUMENTS[prop]
        body.update({"id": f"mes-{uuid.uuid4().hex}", "method": method or pinned, "coverage": coverage,
                     "measured_at": at, "artifact": artifact or "sha256:" + "0" * 64})
        return envelope(domain, "measurement", body, [self.signer])


class Instruments:
    """T06 pass: plan, measure through the host, sign."""

    def __init__(self, service, instrument: Instrument, host: Host, boundary, repo, proposals, *,
                 anchor: str | None = None, inbox=None, findings=None, install: bool = False,
                 sources=None, production: bool = False, registers=None):
        self.service, self.instrument, self.host, self.repo = service, instrument, host, Path(repo)
        self.boundary = boundary
        self.proposals, self.inbox, self.findings_path, self.install = proposals, inbox, findings, install
        self.sources, self.production, self.registers = sources or {}, production, registers
        clock = instrument.clock                          # statements never fall behind the ledger's last instant
        instrument.clock = lambda: max(clock(), service.journal.snapshot()["last_at"] + 1)
        self.anchor = anchor or self._main()
        self.signed, self.fetch, self.served, self.canary_percent = {}, [], {"version": None, "started": None}, 10

    def _main(self) -> str:
        return git(self.repo, "rev-parse", "refs/heads/main").strip()

    def _commits(self, source, pattern: str) -> list:
        """Heads of a source, fetched into the repository from outside (the source's config is not ours)."""
        out = []
        for line in git(self.repo, "ls-remote", str(source), pattern).splitlines():
            head, ref = line.split("\t")
            if subprocess.run(["git", "-C", str(self.repo), "fetch", "-q", "--no-tags", str(source), head],
                              capture_output=True, timeout=300).returncode != 0:
                continue
            parents = git(self.repo, "rev-list", "--parents", "-n", "1", head).split()[1:]
            out.append({"head": head, "ref": ref, "parents": parents,
                        "message": git(self.repo, "log", "-1", "--format=%B", head)})
        return out

    def subjects(self, view=None) -> dict:
        view = view or self.service.view()
        state = self.service.journal.snapshot()
        if (state["size"], state["head"]) != (view["prefix"]["size"], view["prefix"]["head"]):
            raise RuntimeError("instrument plan: journal prefix changed during subject capture")
        return {"main": self._main(), "anchor": self.anchor, "now": self.instrument.clock(),
                "targets": view["law"]["effective"]["targets"], "settings": view["law"]["effective"]["settings"],
                "install": self.install,
                "proposals": self._commits(self.proposals, "refs/standard/proposals/*") if self.proposals else [],
                "inbox": self._commits(self.inbox, "refs/heads/*") if self.inbox else [],
                "entities": state["entities"], "scanner": self.instrument.signer.identity,
                "facts": [{k: o[k] for k in ("resource", "property", "status", "author")}
                          for o in state["observations"].values()],
                "judged": sorted(it["args"]["head"] for i, it in state["intents"].items()
                                 if it["op"] in MAIN_OPS and state["line"].get(i, {}).get("state") == "proving"),
                "production": self.production, "registers": self.registers.read() if self.registers else None,
                "bans": {name: b["bans"] for name, b in load_catalog()["blocks"].items() if b["bans"]},
                "rules": self._rules(view)}

    def _rules(self, view) -> dict:
        """The catalog, the named values in force and the features only the rules declare, for the scanner."""
        from engine.catalog import compact, declared_features, effective
        cat = load_catalog()
        settings = view["law"]["effective"].get("settings", {})
        values = effective(cat, settings.get("values"))
        return {"catalog": compact(cat), "values": values, "declared": declared_features(settings, cat),
                "paths": [str(Path(__file__).resolve().parents[3] / "blocks" / "python")]}

    def _due(self, law, resource: str, prop: str, status: str) -> bool:
        before = self.signed.get((resource, prop))
        if before is None or before[0] != status:
            return True
        fresh = law["instruments"].get(prop, {}).get("fresh_ms") or next(
            (t["fresh_ms"] for t in law["targets"] if t["resource"] == resource and t["property"] == prop), DAY)
        return self.instrument.clock() - before[1] > fresh // 3

    def measure(self) -> dict:
        me = self.instrument.signer.identity
        self.boundary.capture(me, self.host.observe(self.sources, self.fetch))
        view = self.service.view()
        domain, law = view["prefix"]["genesis"], view["law"]["effective"]
        plan = self.boundary.observe(self.host, me, "plan", {"subjects": {"value": self.subjects(view)}}, cache=False)
        if "error" in plan:
            raise RuntimeError(f"plan: {plan['error']}")
        admitted, errors, refused = 0, {}, []
        for job in plan["jobs"]:
            live = job["job"] == "production"
            out = self.boundary.observe(
                self.host, me, job["job"], job["inputs"], network=job.get("network", False), cache=not live
            )
            if "error" in out:
                errors[job["job"]] = out["error"]
                continue
            main_input = job["inputs"].get("main", {})
            provenance = {
                "measure_ref": out["ref"],
                "input_main": main_input.get("commit") or main_input.get("value"),
                "law_digest_at_read": view["law"]["digest"],
            }
            refused += [f"{job['job']}: {r} {p} {st}" for r, p, st, _ in out["refused"]]
            if live:
                extra = out["extra"]
                self.served, self.fetch, self.canary_percent = extra["served"], extra["fetch"], extra["canary_percent"]
                self.instrument.findings.update(
                    {
                        "run:components": {"status": "", "details": extra["components"], **provenance},
                        "run:slos": {"status": "", "details": extra["slos"], **provenance},
                        "run:probes": {"status": str(len(extra["probes"])), "details": extra["probes"], **provenance},
                        "run:sources:all|coverage": {"status": "", "details": extra["silent"], **provenance},
                    }
                )
            for resource, prop, status, details in out["facts"]:
                self.instrument.findings[f"{resource}|{prop}"] = {"status": status, "details": details, **provenance}
                if self._due(law, resource, prop, status):
                    self.service.admit(
                        self.instrument.observation(domain, resource, prop, status, out["ref"], out["method"])
                    )
                    self.signed[(resource, prop)] = (status, self.instrument.clock())
                    admitted += 1
        self.instrument.findings["boundary:refused"] = {"status": str(len(refused)), "details": refused[-50:]}
        try:
            if self.findings_path is not None:
                fresh_ms = next((t["fresh_ms"] for t in law["targets"] if t["id"] == "run-sources"), 300_000)
                publish_readings(
                    self.host,
                    self.sources,
                    Path(self.findings_path).parent / "readings",
                    self.host.clock() // 1000,
                    fresh_s=fresh_ms // 1000,
                )
        except (OSError, ValueError, LookupError) as exc:
            errors["public-readings"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        self.publish()
        return {
            "admitted": admitted,
            "jobs": len(plan["jobs"]),
            **({"errors": errors} if errors else {}),
            **({"refused": len(refused)} if refused else {}),
        }

    def publish(self) -> None:
        """Findings for whoever repairs (agent, human), readable by the agent's group. Information, never a fact."""
        if self.findings_path is None:
            return
        tmp = Path(f"{self.findings_path}.tmp")
        tmp.write_text(json.dumps(self.instrument.findings, indent=1, sort_keys=True, default=str))
        tmp.chmod(0o640)
        tmp.replace(self.findings_path)


class Prover:
    """Proof of application: an independent oracle attests that the purpose of an applied effect holds, as RESOLVE
    reads it (main contains the head, production serves the release, a new process runs)."""

    def __init__(self, service, resolve, signer: Signer, capability: str, clock):
        self.service, self.resolve, self.signer, self.capability, self.clock = service, resolve, signer, capability, clock

    def prove_due(self) -> dict:
        state = self.service.journal.snapshot()
        out = {}
        for name, ob in sorted(state["obligations"].items()):
            if ob["stage"] != "proof":
                continue
            it = state["intents"][ob["intent"]]
            if not self.resolve.satisfied(it):
                continue
            body = {"id": f"proof-{uuid.uuid4().hex}", "at": max(self.clock(), state["last_at"] + 1),
                    "author": self.signer.identity, "under": self.capability, "resource": it["resource"],
                    "subject": it["id"], "level": "real"}
            out[name] = self.service.admit(envelope(state["domain"], "evidence", body, [self.signer]))
        return out


def key(keys_dir: Path, identity: str):
    """The role's signer. `<identity>.service` (JSON: address, token_file, key) names a key held by the key service:
    the private key then never enters this process. Otherwise `<identity>.key` holds it, readable by its owner only."""
    service = keys_dir / f"{identity}.service"
    if service.exists():
        from fabric.control.bt.signing import KeyServiceSigner
        spec = json.loads(service.read_text())
        token = Path(spec["token_file"])
        if token.stat().st_mode & 0o077:
            raise PermissionError(f"{token} must be readable by its owner only")
        return KeyServiceSigner(identity, spec["address"], token.read_text().strip(), spec["key"])
    path = keys_dir / f"{identity}.key"
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} must be readable by its owner only")
    return Signer(identity, Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip())))


def isolation(config: dict, demo: bool) -> Isolation:
    """The runner of candidate code. No runner user means no candidate code at all, unless a demo explicitly accepts
    running it in this very account (`[tests] unconfined = true`), with every key this process can read."""
    tests = config.get("tests", {})
    if tests.get("unconfined") is True:
        if not demo or tests.get("runner_user"):
            raise ValueError("[tests] unconfined is a demo-only setting, exclusive with runner_user")
        print("WARNING: candidate code runs unconfined, as the operator, with its keys (demo only)", file=sys.stderr)
        return Isolation(unconfined=True)
    return Isolation(tests.get("runner_user"))


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
            from fabric.control.bt.adapters import GitHub
            self.repository = GitHub(repo["name"], resolve(repo["token_file"]).read_text().strip(),
                                     push_from=resolve(repo["mirror"]) if repo.get("api") == "git" else None)
            self.repo_path = self.proposals = resolve(repo["mirror"])
            self.world = self.repository
        run, deploy, data = c.get("run", {}), c.get("deploy"), c.get("data")
        evidence = Evidence(self.path.parent / "evidence")             # D37: what every measure read and returned
        self.host = Host(Path(__file__).resolve().parents[3], evidence, self.repo_path,
                         isolation=isolation(c, self.demo),        # D33: never run their code as us
                         stores={"requests": resolve(c.get("build", {}).get("store", "requests"))},
                         data=(resolve(data["path"]), data["digest"]) if data else None, world=self.world,
                         series=Series(evidence, self.path.parent / "series.json"), clock=self.clock,
                         pinned=PROGRAMS)
        sources = {f"metrics-{i}": ("metrics", url) for i, url in enumerate(run.get("metrics", []))}
        if (deploy or {}).get("runner_metrics"):
            sources["runner"] = ("runner", deploy["runner_metrics"])
        if (deploy or {}).get("platform_records"):                     # D68: what the gate and egress recorded
            sources["platform"] = ("platform", deploy["platform_records"])
        self.releases = Registers(self.repo_path, resolve(deploy["root"]), clock=self.clock,
                                  served=lambda: self.instruments.served,
                                  canary_percent=lambda: self.instruments.canary_percent) if deploy else None
        # D38: every exchange with the outside world is a boundary transaction under the floors' contracts.
        self.boundary = Boundary(evidence, self.path.parent / "transactions.jsonl", CONTRACTS, PROGRAMS, self.clock,
                                 ledger=lambda: ledger_of(self.journal))
        effects = {op: self.repository for op in MAIN_OPS} | (self.releases.effects() if self.releases else {})
        self.resolve = self.boundary.resolver(effects, key(self.keys, "oracle"), grants["oracle"])
        self.service = TrustedService(
            self.journal, boundary=SignedAssessment(assessment, assessors), clock=self.clock,
            guard_signer=key(self.keys, "guard"), effect_port=self.boundary.port(effects), reconciliation=self.resolve)
        self.instruments = Instruments(
            self.service, Instrument(key(self.keys, "scanner"), grants["scanner"], self.clock), self.host, self.boundary,
            self.repo_path, self.proposals, anchor=repo.get("anchor"), install=c.get("tests", {}).get("install") is True,
            inbox=resolve(repo["inbox"]) if repo.get("inbox") else None, findings=self.path.parent / "findings.json",
            sources=sources, production=bool(sources) or deploy is not None,
            registers=self.releases)
        self.prover = Prover(self.service, self.resolve, key(self.keys, "oracle"), grants["oracle"], self.clock)
        self.socket = resolve(c["socket"]["path"])

    def _clock(self, spec: dict):
        """[clock] kind = "local": the operator's clock (F0-1: one human, one agent, one witness)."""
        if spec.get("kind", "local") != "local":
            raise ValueError("[clock] kind is local")
        return now_ms

    def witness(self) -> None:
        """The operator's clock anchors the current head."""
        state = self.journal.snapshot()
        if not (self.keys / "clock.key").exists():
            return
        at = max(self.clock(), state["last_at"] + 1)
        body = {"id": f"checkpoint-{uuid.uuid4().hex}", "at": at, "author": "clock", "size": state["size"],
                "head": state["head"]}
        self.journal.append(entry(state, "checkpoint", body, [key(self.keys, "clock")]))

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
        print("usage: python -m fabric.control.runtime serve|tick standard.toml [interval-seconds]")
        return 2
    installation = Installation(argv[1])
    if argv[0] == "tick":
        print(json.dumps(installation.tick(), indent=2, default=str))
    else:
        installation.serve(float(argv[2]) if len(argv) > 2 else 60.0)
    return 0
