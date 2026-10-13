"""One non-authoritative read model for law, code, measures, work and evidence.

Every relation names its origin. A candidate code location or external projection never becomes an admitted fact.
The journal, Git and instrument records remain the sources of truth; this model is rebuilt from them.
"""
from __future__ import annotations

import re

from instruments.probes import PROBES
from kernel.floor0 import FLOOR0, floor0_digest

from .projection import project

PROJECTIONS = {
    "ISO 27001": {"vulns", "secrets", "sast", "access", "suppliers", "incident", "backup", "crypto", "monitoring"},
    "DORA": {"continuity", "backup", "incident", "resilience", "suppliers", "monitoring"},
    "NIS2": {"vulns", "secrets", "sast", "deps-age", "incident", "continuity", "suppliers", "access", "crypto", "threat"},
}
EXTERNAL_REFERENCES = {
    "OWASP Agentic Top 10 2026": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    "OWASP Agent Control Standard": "https://genai.owasp.org/resource/agent-control-standard-acs/",
}
LOCATION = re.compile(r"(?P<path>(?!/)(?!\.)[A-Za-z0-9_./-]+):(?P<line>[1-9][0-9]*)(?::|$)")


def locations(details: list) -> list:
    out = []
    for detail in details[:50]:
        raw = str(detail).splitlines()[0][:240]
        loc = {"raw": raw}
        match = LOCATION.match(raw)
        if match and ".." not in match["path"].split("/"):
            loc.update(path=match["path"], line=int(match["line"]))
        out.append(loc)
    return out


def projection_labels(target: dict) -> list:
    resource, ident = target["resource"], target["id"]
    return [name for name, ids in PROJECTIONS.items()
            if ident in ids or (name == "ISO 27001" and resource.startswith("org:"))
            or (name == "DORA" and resource.startswith("run:"))]


def measurement_for(target: dict, law: dict) -> dict:
    """Declared instrument and registered implementation are different claims."""
    prop = target["property"]
    declared = law.get("instruments", {}).get(prop)
    if declared and not (set(target.get("sources", [])) & set(declared.get("sources", []))):
        declared = None
    if target["id"] in PROBES:
        return {"kind": "registered_probe", "method": f"instruments.probes.PROBES[{target['id']}]",
                "declared": declared}
    if target["id"] == "inventory":
        return {"kind": "registered_probe", "method": "instruments.probes.inventory", "declared": declared}
    if target["id"] in ("run-sources", "run-slo", "run-live"):
        return {"kind": "conditional_program", "method": "instruments.production.measure", "declared": declared}
    if declared:
        return {"kind": "law_declared_instrument", "method": declared["method"], "declared": declared}
    if target.get("human") or target["resource"].startswith("org:"):
        return {"kind": "manual", "method": "signed human attestation", "declared": None}
    return {"kind": "unmapped", "method": None, "declared": None}


def target_state(target: dict, finding: dict, debt: list, proven: bool) -> str:
    """Only constitutional proof/debt establishes whether a target is held."""
    if any(item["state"] == "escalated" for item in debt):
        return "escalated"
    if debt:
        status = finding.get("status")
        if status and str(status).startswith("uncovered"):
            return "unmeasured"
        if status is not None and status != target["expect"]:
            return "gap"
        return "open"
    if proven:
        return "held"
    if target.get("human") or target["resource"].startswith("org:"):
        return "attestation_due"
    return "unknown"


class ReadModel:
    """Shared graph of declared, recorded and candidate links at one explicit reading basis."""

    def __init__(self, view: dict, findings=None, routes=(), qualify=None, *, settings=None, main=None, inputs=None,
                 code_index=None):
        self.view, self.law = view, view["law"]["effective"]
        self.findings, self.settings = findings or {}, settings or {}
        self.routes, self.qualify = tuple(routes), qualify or (lambda contracts: None)
        self.basis = {"prefix": view["prefix"], "law_digest": view["law"]["digest"],
                      "main": main, "inputs": inputs or {}}
        self.code_index = code_index
        health = view["health"]
        if all(k in health for k in ("head", "size")) and (
                health["head"], health["size"]) != (view["prefix"]["head"], view["prefix"]["size"]):
            raise ValueError("read model: health and law are from different journal prefixes")
        self._plans = {}
        self._targets = None
        self._graph = None

    def plan(self, mode="RUN") -> dict:
        if mode not in self._plans:
            self._plans[mode] = project(self.view, self.routes, self.qualify, mode=mode)
        return self._plans[mode]

    def targets(self) -> list:
        if self._targets is not None:
            return self._targets
        health = self.view["health"]
        debt = {}
        for state in ("open", "escalated"):
            for item in health.get(state, []):
                if item.get("type") == "target":
                    debt.setdefault(item["target"], []).append({**item, "state": state})
        proof = {p.get("target"): p for p in health.get("proven", [])}
        facts = {}
        for fact in self.view.get("facts", []):
            facts.setdefault((fact.get("resource"), fact.get("property")), []).append(fact)
        rows = []
        for target in self.law.get("targets", []):
            finding = self.findings.get(f"{target['resource']}|{target['property']}", {})
            measure = measurement_for(target, self.law)
            diagnostic = finding.get("status")
            main_at_measure = finding.get("input_main")
            law_at_measure = finding.get("law_digest_at_read")
            if ((self.basis["main"] and main_at_measure and main_at_measure != self.basis["main"])
                    or (law_at_measure and law_at_measure != self.basis["law_digest"])):
                aligned = "stale"
            elif (finding.get("measure_ref") and self.basis["main"] and main_at_measure == self.basis["main"]
                  and law_at_measure == self.basis["law_digest"]):
                aligned = "same_declared_inputs"
            elif finding.get("measure_ref"):
                aligned = "recorded_unbound"
            else:
                aligned = "unverified"
            status = target_state(target, {} if aligned == "stale" else finding,
                                  debt.get(target["id"], []), target["id"] in proof)
            conflict = bool(aligned != "stale" and finding and not str(diagnostic).startswith("uncovered")
                            and (status == "held") != (diagnostic == target["expect"]))
            rows.append({"target": target, "finding": finding, "debt": debt.get(target["id"], []),
                         "proof": proof.get(target["id"]),
                         "facts": facts.get((target["resource"], target["property"]), []),
                         "measurement": measure, "locations": locations(finding.get("details", [])),
                         "projections": projection_labels(target), "state": status,
                         "diagnostic_conflict": conflict, "diagnostic_alignment": aligned})
        self._targets = rows
        return rows

    def target(self, ident: str) -> dict | None:
        return next((row for row in self.targets() if row["target"]["id"] == ident), None)

    def graph(self) -> dict:
        """All effective declarations are nodes; edges never silently upgrade a diagnostic into proof."""
        if self._graph is not None:
            return self._graph
        nodes, edges = {}, []

        def node(ident, kind, value, origin):
            nodes[ident] = {"kind": kind, "value": value, "origin": origin}

        def edge(source, relation, dest, origin, status="certain"):
            for ident in (source, dest):
                if ident not in nodes:
                    node(ident, "reference", None, origin)
            edges.append({"from": source, "relation": relation, "to": dest,
                          "origin": origin, "status": status})

        for section, values in self.law.items():
            node(f"law:{section}", "law_section", {"count": len(values) if isinstance(values, (dict, list)) else 1},
                 "effective_law")
            if isinstance(values, dict):
                for ident, value in values.items():
                    node(f"law:{section}/{ident}", section, value, "effective_law")
            elif isinstance(values, list) and all(isinstance(v, dict) and "id" in v for v in values):
                for value in values:
                    node(f"law:{section}/{value['id']}", section, value, "effective_law")
            else:
                node(f"law:{section}/value", section, values, "effective_law")
        node("journal:prefix", "journal_prefix", self.view["prefix"], "admitted_journal")
        node("journal:assessment", "boundary_assessment", self.view.get("assessment"), "trusted_service")
        if self.law.get("floor0") == floor0_digest():
            for ident, statement in FLOOR0:
                node(f"floor0:{ident}", "floor0_axiom", statement, "pinned_kernel_code")
                edge("law:floor0/value", "pins", f"floor0:{ident}", "effective_law")
        node("settings:main", "system_settings", self.settings, "repository_file")
        if self.basis["main"]:
            node(f"code:{self.basis['main']}", "repository_snapshot", {"commit": self.basis["main"]}, "git")
        if self.code_index is not None:
            for path, definitions in self.code_index.modules.items():
                node(f"code:{path}", "code_module", {"definitions": definitions}, "git_ast_index")
                edge(f"code:{self.basis['main']}", "contains", f"code:{path}", "git_ast_index")
                for imported in sorted(self.code_index.imports[path]):
                    edge(f"code:{path}", "imports", imported, "git_ast_index", "syntactic")
        for label in PROJECTIONS:
            node(f"external:{label}", "external_reference", {"mapping": "coarse_projection_only"},
                 "local_projection")
        for label, url in EXTERNAL_REFERENCES.items():
            node(f"external:{label}", "external_reference", {"url": url, "mapping": "not_established"},
                 "published_framework")
        for op, spec in self.law.get("ops", {}).items():
            if "resource" in spec:
                edge(f"law:ops/{op}", "acts_on", spec["resource"], "effective_law")
        for name, policy in self.law.get("conditions", {}).items():
            for atom in policy.get("all", []):
                for kind in ("observed", "compare"):
                    if kind in atom:
                        edge(f"law:conditions/{name}", "requires_property", atom[kind][0], "effective_law")
        for gid, grant in self.view.get("grants", {}).items():
            node(f"grant:{gid}", "grant", grant, "admitted_journal")
            for condition in grant.get("conditions", []):
                edge(f"grant:{gid}", "constrained_by", f"law:conditions/{condition}", "admitted_journal")
        for route in self.routes:
            node(f"route:{route.id}", "installed_route",
                 {"mode": route.mode, "resource": route.resource, "needs": sorted(route.needs),
                  "required_t": sorted(route.required_t),
                  "target_ids": sorted(route.target_ids) if route.target_ids is not None else None},
                 "operator_configuration")
        for resource, entity in self.view.get("entities", {}).items():
            node(f"entity:{resource}", "entity", entity, "admitted_journal")
            if entity.get("type") in self.law.get("entities", {}):
                edge(f"entity:{resource}", "instantiates", f"law:entities/{entity['type']}",
                     "admitted_journal", "recorded")
        for resource, properties in self.view.get("transitions", {}).items():
            node(f"transition:{resource}", "transition_facts", properties, "admitted_journal")
            for prop, status in properties.items():
                node(f"transition:{resource}|{prop}", "transition_property", status, "admitted_journal")
                edge(f"transition:{resource}", "has_property", f"transition:{resource}|{prop}",
                     "admitted_journal", "recorded")
        for fact in self.view.get("facts", []):
            if fact.get("id"):
                node(f"fact:{fact['id']}", "admitted_observation", fact, "admitted_journal")
                edge(f"fact:{fact['id']}", "observes", fact["resource"], "admitted_journal", "recorded")
                transition = f"transition:{fact['resource']}|{fact['property']}"
                if transition in nodes:
                    edge(f"fact:{fact['id']}", "contributes_to", transition, "admitted_journal", "recorded")
        for key, finding in self.findings.items():
            node(f"finding:{key}", "diagnostic", finding, "published_finding")
            if "|" in key:
                edge(f"finding:{key}", "diagnoses", key.rsplit("|", 1)[0], "published_finding",
                     "informational")
        for state in ("open", "escalated"):
            for item in self.view["health"].get(state, []):
                ident = item.get("obligation") or str(len(nodes))
                node(f"debt:{ident}", "constitutional_debt", {**item, "state": state}, "kernel_accountability")
                if item.get("target"):
                    edge(f"law:targets/{item['target']}", "has_debt", f"debt:{ident}",
                         "kernel_accountability", "constitutional")
        for item in self.view["health"].get("proven", []):
            ident = item.get("target") or str(len(nodes))
            node(f"proof:{ident}", "constitutional_proof", item, "kernel_accountability")
            if item.get("target"):
                edge(f"law:targets/{item['target']}", "has_proof", f"proof:{ident}",
                     "kernel_accountability", "constitutional")
        for task in self.plan()["tasks"]:
            node(f"task:{task['id']}", "projected_task", task, "work_projection")
            if task.get("target"):
                edge(f"law:targets/{task['target']}", "projects", f"task:{task['id']}", "work_projection")
            for choice in task.get("routes", []):
                edge(f"task:{task['id']}", "can_use", f"route:{choice['route']}", "work_projection",
                     choice["state"].lower())
        for row in self.targets():
            target = row["target"]
            tid = f"law:targets/{target['id']}"
            edge(tid, "applies_to", target["resource"], "effective_law")
            if target.get("repair"):
                edge(tid, "repaired_by", f"law:ops/{target['repair']}", "effective_law")
            if target.get("coverage"):
                edge(tid, "covered_by", f"law:targets/{target['coverage']}", "effective_law")
            for source in target.get("sources", []):
                edge(tid, "accepts_source", source, "effective_law")
            measure = row["measurement"]
            if measure["method"]:
                edge(tid, "measurement_method", measure["method"], measure["kind"],
                     "declared" if measure["kind"] == "law_declared_instrument" else "registered")
            if measure["declared"]:
                edge(tid, "declares_instrument", f"law:instruments/{target['property']}", "effective_law")
            for loc in row["locations"]:
                if "path" in loc:
                    edge(tid, "possible_code_location", f"code:{loc['path']}:{loc['line']}",
                         "diagnostic_finding", "candidate")
            for label in row["projections"]:
                edge(tid, "projected_to", f"external:{label}", "coarse_projection", "unverified")
            if row["finding"]:
                edge(tid, "diagnosed_by", f"finding:{target['resource']}|{target['property']}",
                     "published_finding", row["diagnostic_alignment"])
            for fact in row["facts"]:
                if fact.get("id"):
                    edge(tid, "observed_by", f"fact:{fact['id']}", "admitted_journal", "recorded")
            if row["proof"]:
                edge(tid, "accounted_as", "held", "kernel_accountability", "constitutional")
            for item in row["debt"]:
                edge(tid, "accounted_as", f"{item['state']}:{item.get('obligation')}",
                     "kernel_accountability", "constitutional")
        self._graph = {"schema": "standard-read-model/v1", "basis": self.basis,
                       "scope": {"law": "entire_effective_law", "facts": "bounded_gateway_view",
                                 "code": "git_ast_index" if self.code_index is not None else "diagnostic_locations_only",
                                 "external_controls": "coarse_or_unmapped"},
                       "declarations": nodes, "relations": edges,
                       "authority": "derived reading only; the kernel decides from admitted statements"}
        return self._graph
