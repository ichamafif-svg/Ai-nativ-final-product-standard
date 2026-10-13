"""BUILD/RUN projections of one derived reading; no admission or authority."""
from __future__ import annotations

import re
import subprocess

from instruments.suite import claimed, contract_path, load
from standard.autonomy.read_model import ReadModel

BRANCH = re.compile(r"([0-9a-f]{40})\trefs/heads/([a-z0-9][a-z0-9_-]{0,63})/(\S+)")


def git(repo, *args, check=True) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=False, capture_output=True,
                            text=True, timeout=60)
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip()[:300])
    return result.stdout


def requirements(model: ReadModel) -> list:
    out = []
    for row in model.targets():
        target, finding = row["target"], row["finding"]
        state = {"attestation_due": "attest", "unknown": "pending", "open": "pending"}.get(
            row["state"], row["state"])
        who = row["role"]["actor"]
        out.append({"id": target["id"], "domain": target["resource"].split(":")[1],
                    "resource": target["resource"], "property": target["property"], "expect": target["expect"],
                    "measured": finding.get("status"), "state": state,
                    "diagnostic_conflict": row["diagnostic_conflict"],
                    "diagnostic_alignment": row["diagnostic_alignment"], "projections": row["projections"],
                    "who": who, "where": [str(d).splitlines()[0][:200] for d in finding.get("details", [])[:8]]})
    return out


def run(model: ReadModel, proposals: dict, memory: dict) -> dict:
    plan = model.plan()
    targets = {row["target"]["id"]: row["target"] for row in model.targets()}
    repairs = []
    for proposal in proposals.values():
        target = targets.get(proposal["target"], {})
        transition = f"repo:{proposal['area']}:{proposal['item']}/{proposal['base']}/{proposal['head']}"
        facts = model.transition(transition)
        repairs.append({**proposal, "requirement": f"{target.get('property')} = {target.get('expect')}",
                        "facts": facts, "resource": transition, "kind": "repair",
                        "awaiting_review": proposal["route"] == "review" and facts.get("tests") == "green"
                        and facts.get("review") != "approved"})
    gaps = []
    for row in model.targets():
        target, finding = row["target"], row["finding"]
        if finding and finding.get("status") != target["expect"]:
            gaps.append({"kind": "diagnostic_candidate", "source": "published_findings",
                         "authority": "informational; constitutional health decides debt and proof",
                         "target": target["id"], "resource": target["resource"], "expect": target["expect"],
                         "status": finding["status"], "diagnostic_alignment": row["diagnostic_alignment"],
                         "where": [str(d).splitlines()[0][:200] for d in finding.get("details", [])[:8]],
                         "autonomous": row["role"]["level"] == "autonomous", "human": row["role"]["level"] == "human"})
    abandoned = [{"target": key, "dossier": value["abandoned"]["dossier"],
                  "base": value["abandoned"]["base"]}
                 for key, value in memory.items() if value.get("abandoned")]
    return {"tasks": plan["tasks"], "state": plan["state"], "gaps": sorted(gaps, key=lambda gap: gap["target"]),
            "repairs": repairs, "abandoned": abandoned}


def requests_of(model: ReadModel, repo, requests, request_notes: dict, main: str) -> list:
    out = []
    for resource, entity in sorted(model.entities("request"), key=lambda kv: -kv[1].get("created", 0)):
        rid = resource.split("/", 1)[1]
        spec, contract = (load(requests, entity["fields"][key]) for key in ("spec", "contract"))
        features = []
        for transition, facts in model.transitions(f"repo:feature:{rid}/"):
            base, head = transition.split("/")[1:3]
            landed = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", head, "main"],
                                    check=False, capture_output=True, timeout=60).returncode == 0
            features.append({"resource": transition, "base": base, "head": head, "facts": facts,
                             "kind": "feature", "request": rid, "title": entity["fields"]["title"],
                             "landed": landed, "stale": base != main and not landed,
                             "why": [str(detail).splitlines()[0][:200]
                                     for prop in ("acceptance", "tests", "regressions")
                                     for detail in model.finding(transition, prop).get("details", [])[:3]],
                             "awaiting_review": not landed and base == main and facts.get("acceptance") == "green"
                             and facts.get("tests") == "green" and facts.get("regressions") == "none"
                             and facts.get("review") != "approved"})
        out.append({"id": rid, "resource": resource, "title": entity["fields"]["title"],
                    "state": entity["state"], "owner": entity.get("owner"), "created": entity.get("created"),
                    "expected": entity["expected"], "facts": model.transition(resource),
                    "path": contract_path(rid),
                    "contract_details": model.finding(resource, "contract").get("details", []),
                    "spec": spec.decode(errors="replace") if spec else None,
                    "contract": contract.decode(errors="replace") if contract else None,
                    "agent": request_notes.get(rid, {}).get("state"), "features": features})
    return out


def build(model: ReadModel, repo, inbox, requests, request_notes: dict, main: str) -> dict:
    contributions = []
    if inbox:
        for line in git(repo, "ls-remote", str(inbox), "refs/heads/*", check=False).splitlines():
            match = BRANCH.fullmatch(line)
            if not match:
                continue
            head, author, branch = match.groups()
            candidate = next(((resource, facts) for resource, facts in model.transitions(f"repo:contrib:{author}/")
                              if resource.endswith(f"/{head}")), None)
            resource, facts = candidate or (f"repo:contrib:{author}/{main}/{head}", {})
            base = resource.split("/")[1]
            landed = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", head, "main"],
                                    check=False, capture_output=True, timeout=60).returncode == 0
            blocked = [prop for prop, bad in (("tests", facts.get("tests") not in (None, "green")),
                                               ("regressions", facts.get("regressions") not in (None, "none")))
                       if bad]
            contributions.append({
                "author": author, "branch": branch, "head": head, "base": base, "resource": resource,
                "facts": {**facts, "acceptance": facts.get("acceptance")}, "kind": "contribution",
                "landed": landed, "stale": base != main and not landed, "blocked": blocked,
                "why": [str(detail).splitlines()[0][:200] for prop in blocked
                        for detail in model.finding(resource, prop).get("details", [])[:5]],
                "awaiting_review": not landed and not blocked and facts.get("tests") == "green"
                and facts.get("regressions") == "none" and facts.get("review") != "approved",
                "request": claimed(git(repo, "log", "-1", "--format=%B", head, check=False)) if not landed else None,
            })
    return {"contributions": contributions,
            "requests": requests_of(model, repo, requests, request_notes, main)}
