"""The agent process (U), separate from the operator process:

    python -m agent run standard.toml [interval-seconds]
    python -m agent patrol standard.toml [focus]
    python -m agent patrol-results standard.toml

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

from instruments.data import EMPTY, TrustedData
from bt.gateway import GatewayClient
from bt.signing import Signer

from agent.repair import Agent, Repairer
from agent.build import Builder
from agent.loop import Loop
from agent.work import WorkEngine
from agent.llm import Gate
from agent.memory import Memory
from agent.work import installed_routes

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
                  api_key=resolve(api).read_text().strip() if api and not llm else None, publish=publish, llm=llm,
                  scopes=scopes, research_sources=agent_cfg.get("research_sources"),
                  review=agent_cfg.get("review"), research_steps=agent_cfg.get("research_steps", 8))
    routes = installed_routes(agent.scopes, model=agent.llm is not None, scanner=True)
    repairer = Repairer(service, WorkEngine(store.parent / "work.db"), agent, routes, clock=clock,
                        state_path=store.parent / "proposals.json", findings=path.parent / "findings.json",
                        memory=Memory(store.parent / "memory.json", budget=int(agent_cfg.get("attempts", 3))))
    grant = c["grants"]["agent"]
    producers = [repairer]
    if c.get("build"):                                    # D34: build what contracted requests ask for
        producers.append(Builder(service, signer, grant, store, resolve(c["build"].get("store", "requests")),
                                 clock=clock, notes=store.parent / "requests.json", llm=agent.llm, data=agent.data,
                                 research_sources=agent_cfg.get("research_sources"), review=agent_cfg.get("review"),
                                 research_steps=agent_cfg.get("research_steps", 8)))
    from agent.patrol import Patrol
    loop = Loop(service, signer, grant, main=main, clock=clock, notes=store.parent / "moves.json", producers=producers)
    loop.advisors = (Patrol(repairer, main, clock=clock, interval_ms=agent_cfg.get("patrol_interval_ms", 3_600_000)),)
    return loop, repairer, main, refresh


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2 or argv[0] not in ("run", "patrol", "patrol-results"):
        print("usage: python -m agent (run|patrol|patrol-results) standard.toml [interval-seconds|focus]")
        return 2
    loop, repairer, main_, refresh = build(argv[1])
    if argv[0] == "patrol-results":
        from agent.patrol import patrol_results
        print(json.dumps(patrol_results(repairer, main=main_)))
        return 0
    if argv[0] == "patrol":
        from agent.patrol import run_patrol
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
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
