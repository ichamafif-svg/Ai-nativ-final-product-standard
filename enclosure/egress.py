"""The egress (D68 step 3): the bac's only way out, through mitmproxy and Standard's policy (`egress_addon.py`).

    client code in the bac -> HTTPS_PROXY=127.0.0.1:3128 (the door's relay, inside the bac's empty network)
        -> egress/egress.sock (mounted read-only) -> mitmproxy with the policy -> the destination

Code that ignores the proxy settings has no route at all: the bac's network is empty. The proxy terminates TLS with a
certificate authority made for this platform: its certificate is the only one the bac trusts (SSL_CERT_FILE and its
equivalents), its private key never leaves the platform. The configuration (destinations, which secret may go
where, the key service's address and token) is a file only the platform reads.

mitmproxy runs in its own environment, installed from `egress-requirements.txt` with hashes
(`python -m tools.components fetch`).
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

from enclosure.components import home

ADDON = Path(__file__).with_name("egress_addon.py")
PROXY_PORT_IN_BAC = 3128
CA_ENV = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "PIP_CERT")


def mitmdump() -> str | None:
    path = home() / "egress" / "bin" / "mitmdump"
    return str(path) if path.is_file() else None


def bac_env(ca_in_bac: str) -> dict:
    """What every process in the bac sees: the proxy, and the platform's authority as the only trusted one."""
    proxy = f"http://127.0.0.1:{PROXY_PORT_IN_BAC}"
    return {"HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy,
            "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1",          # the product's own port only
            **{name: ca_in_bac for name in CA_ENV}}


class Relay:
    """Platform side: a Unix socket the bac connects to, relayed to the proxy's local port."""

    def __init__(self, path: str, port: int):
        if os.path.exists(path):
            os.unlink(path)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        os.chmod(path, 0o666)
        self.listener.listen(128)
        self.port = port
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        from enclosure.door import pump
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            try:
                upstream = socket.create_connection(("127.0.0.1", self.port), timeout=5)
                upstream.settimeout(None)
            except OSError:
                client.close()
                continue
            threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
            threading.Thread(target=pump, args=(upstream, client), daemon=True).start()

    def close(self):
        # Wake the accepting thread before the descriptor is freed: otherwise it may wait on a reused number and
        # take connections meant for another server of this process.
        try:
            self.listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.listener.close()


class Egress:
    def __init__(self, state, values: dict, *, secrets: dict | None = None, bao=None, upstream_ca: str | None = None):
        self.state = Path(state) / "egress"
        self.values, self.secrets, self.bao = values, dict(secrets or {}), bao
        self.process = self.relay = self.port = None
        self.upstream_ca = upstream_ca                      # tests only: a private authority for a local destination
        self.records = self.state / "records.jsonl"

    def start(self) -> "Egress":
        binary = mitmdump()
        if not binary:
            raise RuntimeError("the egress needs mitmproxy: python -m tools.components fetch")
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / "mount").mkdir(exist_ok=True)
        self.records.touch()
        config = self.state / "config.json"
        config.write_text(json.dumps({
            "destinations": list(self.values.get("destinations", [])), "secrets": self.secrets,
            "records": str(self.records),
            "files": {"root": str(self.state / "files"), "types": list(self.values.get("upload_types", [])),
                      "max_bytes": int(self.values["upload_max_bytes"]), "quota_bytes": int(self.values["user_quota_bytes"])},
            "bao": {"address": self.bao.address, "token": self.bao.token} if self.bao else {"address": "", "token": ""}}))
        config.chmod(0o600)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        log = open(self.state / "mitmproxy.log", "ab")
        self.process = subprocess.Popen(
            [binary, "--quiet", "--listen-host", "127.0.0.1", "--listen-port", str(port), "-s", str(ADDON),
             "--set", f"confdir={self.state / 'ca'}", "--set", f"body_size_limit={int(self.values['outbound_max_bytes'])}",
             "--set", "connection_strategy=lazy", "--set", "upstream_cert=true",
             *(["--set", f"ssl_verify_upstream_trusted_ca={self.upstream_ca}"] if self.upstream_ca else [])],
            env={**os.environ, "STANDARD_EGRESS": str(config)}, stdout=log, stderr=subprocess.STDOUT)
        log.close()
        ca = self.state / "ca" / "mitmproxy-ca-cert.pem"
        end = time.monotonic() + 30
        while time.monotonic() < end and not (ca.exists() and _listening(port)):
            if self.process.poll() is not None:
                raise RuntimeError("mitmproxy stopped: " + (self.state / "mitmproxy.log").read_text()[-500:])
            time.sleep(0.1)
        (self.state / "mount" / "ca.pem").write_bytes(ca.read_bytes())   # the certificate only, never the key
        self.relay = Relay(str(self.state / "mount" / "egress.sock"), port)
        self.port = port                                    # the platform's own clients (the agent) on this host
        return self

    @property
    def mount(self) -> Path:
        return self.state / "mount"

    def read_records(self) -> list:
        return [json.loads(line) for line in self.records.read_text().splitlines() if line.strip()]

    def stop(self) -> None:
        if self.relay:
            self.relay.close()
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()


def _listening(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        return True
    except OSError:
        return False
