"""One product behind the whole entry path (D68 step 2): Envoy, the gate, the door, the product in its bac.

    stack = Stack(state, values, command, cwd=release, port=8080, envoy="envoy")
    stack.start(); ...; stack.stop()

    client -> Envoy (127.0.0.1:port) -> gate (state/gate.sock) -> door (state/door/http.sock, in the bac)
           -> the product on 127.0.0.1:$PORT of the bac's own empty network

The state directory belongs to the platform: the identity key, the Envoy configuration, the values and the gate's
records live there; only `door/` is mounted into the bac. oauth2-proxy is optional (`oauth2=`): without it every
route is treated as public and no identity reaches the product. With `provider=` (`enclosure/signin.py`) and an
`oauth2=` port, oauth2-proxy runs the sign-in and only @public routes reach the product unauthenticated.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from enclosure import gateway, identity
from enclosure.bac import Bac, Service, Walls
from enclosure.components import where
from enclosure.gate import Gate, Records, serve

DOOR = Path(__file__).with_name("door.py")
PRODUCT_PORT = 8000


def wait_for(check, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.05)
    return False


def _listening(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        return True
    except OSError:
        return False


class Stack:
    def __init__(self, state, values: dict, command: list, *, cwd, port: int, envoy: str | None = None,
                 audience: str = "product", oauth2: int | None = None, walls: Walls = Walls(),
                 readable=(), env=None, provider=None):
        self.state, self.values, self.command, self.cwd = Path(state), values, list(command), Path(cwd)
        self.port, self.audience, self.oauth2, self.walls = port, audience, oauth2, walls
        self.readable, self.env = tuple(readable), dict(env or {})
        self.envoy_bin = envoy or os.environ.get("STANDARD_ENVOY") or where("envoy")
        self.provider = provider
        self.service = self.envoy = self.server = self.signin = None
        self.logs = []
        self.records = self.state / "records.jsonl"

    def start(self) -> "Stack":
        if not self.envoy_bin:
            raise RuntimeError("the gateway needs Envoy: python -m tools.components fetch")
        door = self.state / "door"
        door.mkdir(parents=True, exist_ok=True)
        door.chmod(0o777)
        self.records.touch()
        (self.state / "values.json").write_text(json.dumps(self.values))
        signer = identity.LocalSigner(self.state / "identity.key")
        (self.state / "identity.pub").write_text(signer.public_pem())
        bac = Bac(self.walls)
        socket_in_bac = str(door / "http.sock")
        self.service = Service(bac, [bac.python, "-I", str(DOOR), socket_in_bac, str(PRODUCT_PORT), "--",
                                     *self.command], self.cwd, readable=(DOOR.parent, *self.readable),
                               writable=(door,), env=self.env, log=self._log("product.log"))
        if not wait_for(lambda: os.path.exists(socket_in_bac)):
            self.stop()
            raise RuntimeError("the product's door did not open: " + (self.state / "product.log").read_text()[-500:])
        self.server = serve(str(self.state / "gate.sock"), Gate(door=socket_in_bac, values=self.values,
                                                                audience=self.audience, signer=signer,
                                                                records=Records(self.records)))
        if self.provider is not None:
            from enclosure.signin import args as signin_args
            binary = where("oauth2-proxy")
            if not binary or not self.oauth2:
                self.stop()
                raise RuntimeError("the sign-in needs oauth2-proxy and its port: python -m tools.components fetch")
            self.signin = subprocess.Popen([binary, *signin_args(self.provider, self.values, port=self.oauth2,
                                                                 secrets_dir=self.state / "signin")],
                                           stdout=self._log("signin.log"), stderr=subprocess.STDOUT)
            if not wait_for(lambda: _listening(self.oauth2)):
                self.stop()
                raise RuntimeError("oauth2-proxy did not listen: " + (self.state / "signin.log").read_text()[-500:])
        config = gateway.config(self.values, port=self.port, gate=str(self.state / "gate.sock"), oauth2=self.oauth2)
        (self.state / "envoy.json").write_text(json.dumps(config))
        self.envoy = subprocess.Popen([self.envoy_bin, "-c", str(self.state / "envoy.json"), "--log-level", "error",
                                       "--base-id", str(self.port)],
                                      stdout=self._log("envoy.log"), stderr=subprocess.STDOUT)
        if not wait_for(lambda: _listening(self.port)):
            self.stop()
            raise RuntimeError("Envoy did not listen: " + (self.state / "envoy.log").read_text()[-500:])
        return self

    def _log(self, name: str):
        handle = open(self.state / name, "ab")
        self.logs.append(handle)
        return handle

    def read_records(self) -> list:
        return [json.loads(line) for line in self.records.read_text().splitlines() if line.strip()]

    def stop(self) -> None:
        for process in (self.signin,):
            if process:
                process.terminate()
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    process.kill()
        if self.envoy:
            self.envoy.terminate()
            try:
                self.envoy.wait(10)
            except subprocess.TimeoutExpired:
                self.envoy.kill()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.service:
            self.service.stop()
        for handle in self.logs:
            handle.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


if __name__ == "__main__":
    print(__doc__, file=sys.stderr)
