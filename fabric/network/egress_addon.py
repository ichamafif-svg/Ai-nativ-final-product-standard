"""The egress proxy's policy (D68 step 3), loaded by mitmproxy: the only way out of the bac.

Self-contained (stdlib and mitmproxy only): it runs in mitmproxy's own environment, outside the bac, with a
configuration file only the platform can read (STANDARD_EGRESS). For every call the product makes:

    - the destination must be in @destinations (host or host:port; 443 when no port), else 403 and a record;
    - the name must resolve to public addresses only, unless the human listed the address itself (no SSRF to the
      host's or the cloud's private services), and the connection goes to the address that was checked (no DNS
      rebinding between the check and the connection);
    - `secret:NAME` in a header is replaced by the secret's value, fetched from the key service at that moment,
      only for a host the rules allow for that secret; anywhere else (another host, the URL) the call is refused.
      The value is injected outside the bac. Exact response reflections are refused; transformed
      disclosures by an authorized destination remain outside this guarantee;
    - `http://keys.standard/OPERATION/KEY` reaches the key service (encrypt, decrypt, hmac, sign, verify) for the
      explicit key-operation capabilities, without the product ever holding a token;
    - `http://files.standard/` stores and serves the product's files on the platform: PUT a body of a type in
      @upload_types, at most @upload_max_bytes, within @user_quota_bytes in all, and get back its id (its digest);
      GET /ID returns it as an attachment, never rendered. The bac writes no file anywhere it could serve;
    - answers are bounded (mitmproxy's body_size_limit, set from @outbound_max_bytes).

Every refusal is a record the platform reads back as a lesson; a secret sent toward a host it is not for is also an
alarm for the hidden control.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import fcntl
import re
import socket
import threading
import time
import urllib.error
import urllib.request

from mitmproxy import http

SECRET = re.compile(r"secret:([A-Za-z0-9_.-]{1,64})")
KEYS_HOST, FILES_HOST = "keys.standard", "files.standard"
OPERATIONS = ("encrypt", "decrypt", "hmac", "sign", "verify")


class Egress:
    def __init__(self):
        with open(os.environ["STANDARD_EGRESS"], encoding="utf-8") as f:
            self.config = json.load(f)
        self.lock = threading.Lock()
        self.seen = set()

    # ---- records ---------------------------------------------------------------------------------------------------
    def record(self, kind: str, capability: str, route: str, attempt: str) -> None:
        key = (kind, capability, route, attempt)
        with self.lock:
            if key in self.seen:
                return
            self.seen.add(key)
            with open(self.config["records"], "a", encoding="utf-8") as f:
                f.write(json.dumps({"kind": kind, "capability": capability, "held_by": "platform:egress",
                                    "route": route, "attempt": attempt[:240], "at": int(time.time())},
                                   sort_keys=True) + "\n")

    def refuse(self, flow, status: int, capability: str, attempt: str, *, alarm: bool = False) -> None:
        route = f"{flow.request.method} {flow.request.host}"
        self.record("refusal", capability, route, attempt)
        if alarm:
            self.record("alarm", capability, route, attempt)
        flow.response = http.Response.make(status, json.dumps({"error": attempt}).encode(),
                                           {"content-type": "application/json"})

    # ---- policy ----------------------------------------------------------------------------------------------------
    def allowed(self, host: str, port: int) -> bool:
        for entry in self.config["destinations"]:
            name, _, wanted = entry.rpartition(":") if re.search(r":\d+$", entry) else (entry, "", "443")
            if name.lower() == host.lower() and int(wanted) == port:
                return True
        return False

    def literal(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def resolve(self, host: str, port: int) -> str | None:
        """A public address of `host`, or None when any address it resolves to is not public."""
        if self.literal(host):
            return host                                     # the human listed the address itself
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            return None
        addresses = [info[4][0] for info in infos]
        if not addresses or not all(ipaddress.ip_address(a).is_global for a in addresses):
            return None
        return addresses[0]

    def secret(self, name: str) -> str:
        bao = self.config["bao"]
        request = urllib.request.Request(f"{bao['address']}/v1/secret/data/{name}",
                                         headers={"X-Vault-Token": bao["token"]})
        with urllib.request.urlopen(request, timeout=5) as r:
            return json.loads(r.read())["data"]["data"]["value"]

    # ---- hooks -----------------------------------------------------------------------------------------------------
    def http_connect(self, flow: http.HTTPFlow) -> None:
        if not self.allowed(flow.request.host, flow.request.port):
            self.refuse(flow, 403, "egress.destination", f"{flow.request.host}:{flow.request.port} is not in @destinations")

    def request(self, flow: http.HTTPFlow) -> None:
        host, port = flow.request.pretty_host, flow.request.port
        if host == KEYS_HOST:
            return self.keys(flow)
        if host == FILES_HOST:
            return self.files(flow)
        if not self.allowed(host, port):
            return self.refuse(flow, 403, "egress.destination", f"{host}:{port} is not in @destinations")
        if SECRET.search(flow.request.path):
            return self.refuse(flow, 403, "egress.secret", "a secret reference in the URL", alarm=True)
        address = self.resolve(host, port)
        if address is None:
            return self.refuse(flow, 403, "egress.private", f"{host} resolves to an address that is not public")
        injected = []
        for key, value in list(flow.request.headers.items(multi=True)):
            for name in set(SECRET.findall(value)):
                if host.lower() not in [h.lower() for h in self.config["secrets"].get(name, [])]:
                    return self.refuse(flow, 403, "egress.secret", f"secret {name} is not for {host}", alarm=True)
                try:
                    secret = self.secret(name)
                    injected.append(secret)
                    value = value.replace(f"secret:{name}", secret)
                except (OSError, KeyError, ValueError):
                    return self.refuse(flow, 503, "egress.secret", f"secret {name} is not available")
            flow.request.headers[key] = value
        flow.metadata["standard_injected"] = injected
        if address != host:
            header, sni = flow.request.host_header, flow.server_conn.sni
            flow.request.host = address                      # connect to the address that was checked
            flow.request.host_header = header or host       # the destination still sees its own name
            flow.server_conn.sni = sni or host              # and TLS still verifies that name

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # This hook must remain buffered; streaming would disclose the response before inspection.
        if flow.metadata.get("standard_injected"):
            flow.response.stream = False

    def response(self, flow: http.HTTPFlow) -> None:
        """Block exact reflected credentials in decoded bodies and headers. This is a bounded guard,
        not a claim against an authorized provider encoding, transforming or deliberately leaking a secret."""
        secrets = flow.metadata.pop("standard_injected", ())
        if not secrets or flow.response is None:
            return
        try:
            body = flow.response.get_content() or b""
            headers = b"\n".join(k + b":" + v for k, v in flow.response.headers.fields)
            reflected = any(s.encode() in body or s.encode() in headers for s in secrets)
        except (ValueError, UnicodeError):
            reflected = True
        if reflected:
            self.refuse(flow, 502, "egress.secret", "credential-bearing response refused", alarm=True)

    def keys(self, flow: http.HTTPFlow) -> None:
        parts = flow.request.path.strip("/").split("/")
        if flow.request.method != "POST" or len(parts) != 2 or parts[0] not in OPERATIONS \
                or not parts[1].startswith("product-") or parts[0] not in self.config.get("keys", {}).get(parts[1], []):
            return self.refuse(flow, 403, "egress.keys", "not a product key or not a key operation")
        try:
            body = json.loads(flow.request.get_text() or "{}")
            allowed = {k: body[k] for k in ("plaintext", "ciphertext", "input", "signature", "hmac") if k in body}
            bao = self.config["bao"]
            request = urllib.request.Request(f"{bao['address']}/v1/transit/{parts[0]}/{parts[1]}", method="POST",
                                             data=json.dumps(allowed).encode(),
                                             headers={"X-Vault-Token": bao["token"], "content-type": "application/json"})
            with urllib.request.urlopen(request, timeout=5) as r:
                out = json.loads(r.read())["data"]
            flow.response = http.Response.make(200, json.dumps(out).encode(), {"content-type": "application/json"})
        except (urllib.error.HTTPError, ValueError, KeyError) as exc:
            self.refuse(flow, 400, "egress.keys", f"the key service refused the operation ({type(exc).__name__})")


    def files(self, flow: http.HTTPFlow) -> None:
        store = self.config.get("files", {})
        root = store.get("root")
        if not root:
            return self.refuse(flow, 403, "egress.files", "no file store")
        os.makedirs(root, exist_ok=True)
        path = flow.request.path.split("?", 1)[0].strip("/")
        if flow.request.method == "PUT" and path == "":
            kind = flow.request.headers.get("content-type", "").split(";")[0].strip().lower()
            body = flow.request.get_content() or b""
            if kind not in store.get("types", []):
                return self.refuse(flow, 415, "egress.files", f"type {kind or '(none)'} is not in @upload_types")
            if len(body) > int(store["max_bytes"]):
                return self.refuse(flow, 413, "egress.files", "file larger than @upload_max_bytes")
            ident = hashlib.sha256(body).hexdigest()
            # One shared product quota, even across proxy workers. Existing content is charged once.
            with open(os.path.join(root, ".quota.lock"), "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                used = sum(os.path.getsize(os.path.join(root, n)) for n in os.listdir(root)
                           if re.fullmatch(r"[0-9a-f]{64}", n))
                target = os.path.join(root, ident)
                if not os.path.exists(target) and used + len(body) > int(store["quota_bytes"]):
                    return self.refuse(flow, 507, "egress.files", "the product store is full (@user_quota_bytes)")
                temporary = target + ".tmp"
                with open(temporary, "wb") as f:
                    f.write(body)
                    f.flush()
                    os.fsync(f.fileno())
                with open(target + ".type.tmp", "w") as f:
                    f.write(kind)
                os.replace(target + ".type.tmp", target + ".type")
                os.replace(temporary, target)
            flow.response = http.Response.make(201, json.dumps({"id": ident}).encode(), {"content-type": "application/json"})
        elif flow.request.method == "GET" and re.fullmatch(r"[0-9a-f]{64}", path) and os.path.exists(os.path.join(root, path)):
            with open(os.path.join(root, path), "rb") as f, open(os.path.join(root, path + ".type")) as t:
                body, kind = f.read(), t.read()
            flow.response = http.Response.make(200, body, {"content-type": kind, "x-content-type-options": "nosniff",
                                                           "content-disposition": "attachment"})
        else:
            self.refuse(flow, 404, "egress.files", "no such file or operation")


addons = [Egress()]
