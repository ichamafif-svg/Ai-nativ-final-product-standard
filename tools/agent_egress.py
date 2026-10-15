"""The platform's egress for the agent's own calls (D66 under D68): model providers and research sources.

    python -m tools.agent_egress standard.toml

reads `[agent_egress]`: `destinations` (host[:port] the agent may call), `secrets` ({name: [hosts]}: which provider
key may go where), `bao` (the key service's address) and `bao_token_file` (readable by its owner only). It starts the
egress proxy, writes its CA certificate beside the configuration (`agent-egress-ca.pem`) and prints the two lines to
put under `[llm]`: `egress` and `egress_ca`. Tiers then name their key as `key = "secret:NAME"`: the provider keys
live in the key service and are injected by the proxy; the agent's process never reads them.

Known limit: the agent runs on the host, not in a bac; this routes and keeps its keys, it does not wall its network.
"""
from __future__ import annotations

import json
import shutil
import signal
import sys
import tomllib
from pathlib import Path

from engine.catalog import effective, load
from fabric.network.egress import Egress
from fabric.identity.keys import OpenBao


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    config = Path(argv[0]).resolve()
    spec = tomllib.loads(config.read_text())["agent_egress"]
    token = (config.parent / spec["bao_token_file"]).resolve()
    if token.stat().st_mode & 0o077:
        raise PermissionError(f"{token} must be readable by its owner only")
    values = effective(load(), {"destinations": list(spec["destinations"])})
    egress = Egress(config.parent / "agent-egress", values, secrets=spec.get("secrets", {}),
                    bao=OpenBao(spec["bao"], token.read_text().strip())).start()
    ca = config.parent / "agent-egress-ca.pem"
    shutil.copy(egress.mount / "ca.pem", ca)
    print(json.dumps({"egress": f"http://127.0.0.1:{egress.port}", "egress_ca": str(ca)}), flush=True)
    try:
        signal.sigwait({signal.SIGINT, signal.SIGTERM})
    finally:
        egress.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
