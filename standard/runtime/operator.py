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

from bt.host import Host
from bt.signing import Signer, envelope

MAIN_OPS = ("remediate", "integrate", "implement", "configure")   # the operations that move main, by the same CAS
DAY = 86_400_000


def git(repo, *args) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError(f"git {args[0]}: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout.decode(errors="replace")


class Instrument:
    """An instrument identity: turns answers into signed statements under its own capability."""

    def __init__(self, signer: Signer, capability: str, clock):
        self.signer, self.capability, self.clock = signer, capability, clock
        self.findings = {}                                  # "resource|property" -> details of the last measure

    def observation(self, domain: str, resource: str, prop: str, status: str, artifact: str | None = None,
                    method: str | None = None) -> dict:
        """A property the floors pin to an instrument (D33) is signed as a measurement of the pinned programs."""
        from standard.floors import INSTRUMENTS
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
                 anchor: str | None = None, inbox=None, findings=None, install: bool = False, holders=lambda: {},
                 sources=None, production: bool = False, registers=None):
        self.service, self.instrument, self.host, self.repo = service, instrument, host, Path(repo)
        self.boundary = boundary
        self.proposals, self.inbox, self.findings_path, self.install = proposals, inbox, findings, install
        self.holders, self.sources, self.production, self.registers = holders, sources or {}, production, registers
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
                "targets": view["law"]["effective"]["targets"], "install": self.install,
                "proposals": self._commits(self.proposals, "refs/standard/proposals/*") if self.proposals else [],
                "inbox": self._commits(self.inbox, "refs/heads/*") if self.inbox else [],
                "entities": state["entities"], "holders": self.holders(), "scanner": self.instrument.signer.identity,
                "facts": [{k: o[k] for k in ("resource", "property", "status", "author")}
                          for o in state["observations"].values()],
                "judged": sorted(it["args"]["head"] for i, it in state["intents"].items()
                                 if it["op"] in MAIN_OPS and state["line"].get(i, {}).get("state") == "proving"),
                "production": self.production, "registers": self.registers.read() if self.registers else None}

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
            out = self.boundary.observe(self.host, me, job["job"], job["inputs"], network=job.get("network", False),
                                        cache=not live)
            if "error" in out:
                errors[job["job"]] = out["error"]
                continue
            main_input = job["inputs"].get("main", {})
            provenance = {"measure_ref": out["ref"],
                          "input_main": main_input.get("commit") or main_input.get("value"),
                          "law_digest_at_read": view["law"]["digest"]}
            refused += [f"{job['job']}: {r} {p} {st}" for r, p, st, _ in out["refused"]]
            if live:
                extra = out["extra"]
                self.served, self.fetch, self.canary_percent = extra["served"], extra["fetch"], extra["canary_percent"]
                self.instrument.findings.update({
                    "run:components": {"status": "", "details": extra["components"], **provenance},
                    "run:slos": {"status": "", "details": extra["slos"], **provenance},
                    "run:probes": {"status": str(len(extra["probes"])), "details": extra["probes"], **provenance},
                    "run:sources:all|coverage": {"status": "", "details": extra["silent"], **provenance}})
            for resource, prop, status, details in out["facts"]:
                self.instrument.findings[f"{resource}|{prop}"] = {"status": status, "details": details, **provenance}
                if self._due(law, resource, prop, status):
                    self.service.admit(self.instrument.observation(domain, resource, prop, status, out["ref"],
                                                                   out["method"]))
                    self.signed[(resource, prop)] = (status, self.instrument.clock())
                    admitted += 1
        self.instrument.findings["boundary:refused"] = {"status": str(len(refused)), "details": refused[-50:]}
        self.publish()
        return {"admitted": admitted, "jobs": len(plan["jobs"]), **({"errors": errors} if errors else {}),
                **({"refused": len(refused)} if refused else {})}

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
