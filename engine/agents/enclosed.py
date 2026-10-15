"""Run the agent loop inside the fixed native enclosure, with an optional egress relay."""
import os
import sys
import threading
import tomllib
from pathlib import Path

from fabric.runtime.agent import command


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2 or argv[0] not in ("launch", "inside"):
        raise SystemExit("usage: python -m engine.agents.enclosed (launch|inside) CONFIG [INTERVAL]")
    mode, config, *interval = argv
    if mode == "launch":
        program = [sys.executable, "-m", "engine.agents.enclosed", "inside", str(Path(config).resolve()), *interval]
        args = command(config, program=program)
        os.execv(args[0], args)
    # No security claim derives from this marker or from calling 'inside' directly.
    # The launch command and native namespaces are the enforcement points.
    spec = tomllib.loads(Path(config).read_text())
    if spec.get("llm"):
        from fabric.network.door import relay_out
        socket_path = str((Path(config).parent / spec["llm"]["egress_socket"]).resolve())
        threading.Thread(target=relay_out, args=(socket_path,), daemon=True).start()
    from engine.agents.__main__ import main as agent_main
    return agent_main(["run", config, *interval])


if __name__ == "__main__":
    sys.exit(main())
