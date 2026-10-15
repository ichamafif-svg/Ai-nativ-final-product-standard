"""The agent process (U), separate from the operator process:

    python -m engine.agents run standard.toml [interval-seconds]
    python -m engine.agents patrol standard.toml [focus]
    python -m engine.agents patrol-results standard.toml

It reads the agent's own key, the gateway socket, the proposals store and, optionally, the Claude API key file. It
never reads the journal, the pins, the guard's key or the provider token.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
import tomllib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from blocks.python.standard_blocks.runtime import read_secret

from engine.verification.data import EMPTY, TrustedData
from fabric.control.bt.gateway import GatewayClient
from fabric.control.bt.signing import Signer

from engine.agents.repair import Agent, Repairer
from engine.agents.build import Builder
from engine.agents.loop import Loop
from engine.agents.work import WorkEngine
from engine.agents.llm import Gate
from engine.agents.memory import Memory
from engine.agents.work import installed_routes

ROUTES = installed_routes(scanner=False)


def git(repo, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          timeout=300).stdout.strip()


def build(config_path):
    """The agent: one capability (`grants.agent`), one loop, a repair producer and, when configured, a builder."""
    path = Path(config_path).resolve()
    c, base = tomllib.loads(path.read_text()), path.parent
    resolve = lambda p: (base / p).resolve()
    keyfile = resolve(c.get("agent", {}).get("key", f'{c["keys"]["dir"]}/agent.key'))
    if keyfile.stat().st_mode & 0o077:
        raise PermissionError(f"{keyfile} must be readable by its owner only")
    signer = Signer("agent", Ed25519PrivateKey.from_private_bytes(base64.b64decode(keyfile.read_text().strip())))
    repo, agent_cfg = c["repository"], c.get("agent", {})
    store = resolve(agent_cfg.get("store", "agent-store"))
    if repo["kind"] == "git":
        source = resolve(repo["path"])
        main = lambda: git(source, "rev-parse", "refs/heads/main")
        refresh = lambda: git(store, "fetch", "-q", str(source), "+refs/heads/main:refs/heads/main")
        publish = None                                    # the operator fetches proposals from this store
    else:
        main = lambda: git(store, "ls-remote", "origin", "refs/heads/main").split()[0]
        refresh = lambda: git(store, "fetch", "-q", "origin", "+refs/heads/main:refs/heads/main")
        publish = lambda head: git(store, "push", "-q", "origin", f"{head}:refs/heads/standard/proposals/{head}")
    data = c.get("data")
    api = agent_cfg.get("api_key_file")
    llm = Gate.from_config(c["llm"], resolve, store.parent / "egress.log") if c.get("llm") else None
    clock = lambda: int(time.time() * 1000)
    service = GatewayClient(resolve(c["socket"]["path"]))
    try:                                                  # the write scopes of the client's own targets: the rules'
        scopes = service.view()["law"]["effective"]["settings"].get("scopes")
    except Exception:
        scopes = None
    agent = Agent(store, data=TrustedData.load(resolve(data["path"]), data["digest"]) if data else EMPTY,
                  api_key=read_secret(resolve(api)) if api and not llm else None, publish=publish, llm=llm,
                  scopes=scopes, research_sources=agent_cfg.get("research_sources"),
                  review=agent_cfg.get("review"), research_steps=agent_cfg.get("research_steps", 8))
    routes = installed_routes(agent.scopes, model=agent.llm is not None, scanner=True)
    repairer = Repairer(service, WorkEngine(store.parent / "work.db"), agent, routes, clock=clock,
                        state_path=store.parent / "proposals.json",
                        findings=resolve(agent_cfg.get("public_context", ".")) / "findings.json",
                        memory=Memory(store.parent / "memory.json", budget=int(agent_cfg.get("attempts", 3))))
    grant = c["grants"]["agent"]
    producers = [repairer]
    if c.get("build"):                                    # D34: build what contracted requests ask for
        producers.append(Builder(service, signer, grant, store, resolve(c["build"].get("store", "requests")),
                                 clock=clock, notes=store.parent / "requests.json", llm=agent.llm, data=agent.data,
                                 research_sources=agent_cfg.get("research_sources"), review=agent_cfg.get("review"),
                                 research_steps=agent_cfg.get("research_steps", 8)))
    from engine.agents.patrol import Patrol
    loop = Loop(service, signer, grant, main=main, clock=clock, notes=store.parent / "moves.json", producers=producers)
    loop.advisors = (Patrol(repairer, main, clock=clock, interval_ms=agent_cfg.get("patrol_interval_ms", 3_600_000)),)
    return loop, repairer, main, refresh


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2 or argv[0] not in ("run", "once", "patrol", "patrol-results", "acceptance"):
        print("usage: python -m engine.agents (run|once|patrol|patrol-results) standard.toml [interval-seconds|focus]\n"
              "       python -m engine.agents acceptance standard.toml SPECIFICATION_FILE [DRAFT_OUT]")
        return 2
    loop, repairer, main_, refresh = build(argv[1])
    if argv[0] == "acceptance":
        from engine.agents.acceptance import DraftError, draft
        from engine.verification.tree import Snapshot
        if len(argv) < 3:
            print("usage: python -m engine.agents acceptance standard.toml SPECIFICATION_FILE [DRAFT_OUT]")
            return 2
        agent = repairer.agent
        try:
            refresh()
            result = draft(agent.research, open(argv[2], encoding="utf-8").read(), Snapshot(agent.store, main_()))
        except (DraftError, OSError, ValueError) as exc:
            print(json.dumps({"error": str(exc)}))
            return 2
        if len(argv) > 3:
            open(argv[3], "w", encoding="utf-8").write(result["tests"])
            result = {**result, "tests": f"written to {argv[3]}"}
        print(json.dumps(result))
        return 0
    if argv[0] == "patrol-results":
        from engine.agents.patrol import patrol_results
        print(json.dumps(patrol_results(repairer, main=main_)))
        return 0
    if argv[0] == "patrol":
        from engine.agents.patrol import run_patrol
        try:
            refresh()
            print(json.dumps(run_patrol(repairer, main=main_, focus=argv[2] if len(argv) > 2 else None)))
            return 0
        except (OSError, ValueError) as exc:
            print(json.dumps({"error": str(exc)}))
            return 2
    interval = float(argv[2]) if len(argv) > 2 else 60.0
    while True:
        try:
            refresh()
            report = loop.run()
        except Exception as exc:
            report = {"blocked": f"{type(exc).__name__}: {exc}"}
        print(json.dumps({"at": int(time.time() * 1000), **report}, default=str), flush=True)
        if argv[0] == "once":
            return 0 if "blocked" not in report else 1
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
