"""The agent process (U), separate from the operator process:

    python -m autonomy run standard.toml [interval-seconds]

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

from trusted.data import EMPTY, TrustedData
from trusted.gateway import GatewayClient
from trusted.signing import Signer

from . import Agent, Cycle, Route, WorkEngine

ROUTES = [Route("agent-remediate", "RUN", "repo:*", frozenset({"repair"}))]


def git(repo, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          timeout=300).stdout.strip()


def build(config_path) -> tuple[Cycle, callable]:
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
    agent = Agent(signer, {"recipe": c["grants"]["agent_recipe"], "review": c["grants"]["agent_review"]}, store,
                  data=TrustedData.load(resolve(data["path"]), data["digest"]) if data else EMPTY,
                  api_key=resolve(api).read_text().strip() if api else None, publish=publish)
    cycle = Cycle(GatewayClient(resolve(c["socket"]["path"])), WorkEngine(store.parent / "work.db"), agent, ROUTES,
                  clock=lambda: int(time.time() * 1000), main=main, state_path=store.parent / "proposals.json")
    if repo.get("inbox") and "agent_integrate" in c["grants"]:
        from .contributions import Integrator
        integrator = Integrator(cycle.service, signer, c["grants"]["agent_integrate"], resolve(repo["inbox"]),
                                main=main, clock=lambda: cycle.clock(), notes=store.parent / "contributions.json")
        run = cycle.run
        cycle.run = lambda mode="RUN": {**run(mode), "integrate": integrator.run()}
    return cycle, refresh


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2 or argv[0] != "run":
        print("usage: python -m autonomy run standard.toml [interval-seconds]")
        return 2
    cycle, refresh = build(argv[1])
    interval = float(argv[2]) if len(argv) > 2 else 60.0
    while True:
        try:
            refresh()
            report = cycle.run()
        except Exception as exc:
            report = {"blocked": f"{type(exc).__name__}: {exc}"}
        print(json.dumps({"at": int(time.time() * 1000), **report}, default=str), flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
