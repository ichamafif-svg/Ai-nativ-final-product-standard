"""U — the one door to frontier models (D23, third track; R15).

Sending repository content to a model is an effect of data egress. Every request goes through this gate, which:
- redacts every value a secret rule detects, whatever the caller already did (a detected secret never leaves);
- picks a provider and model by tier: `small` for routine work, `frontier` for what needs judgment;
- appends one line per request to an egress log: when, which provider and model, how many bytes, how many
  redactions, and the SHA-256 of the prompt, never its content;
- refuses a reply that still carries a redaction mark (the model would be writing a placeholder into code).

Providers: Anthropic's Messages API, and any OpenAI-compatible chat completions endpoint (Mistral, a local server…),
each with its own key file. What a model writes is hostile data: the caller confines it to the target's write scope.

Under the platform (D68 for the agent's own calls, `[llm] egress` and `egress_ca`): calls leave through the
platform's egress proxy, which checks the destination and injects the provider's key, and only the platform's
authority is trusted. A tier then names its key by reference (`key = "secret:NAME"`): this process never holds it.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from blocks.python.standard_blocks import Values
from blocks.python.standard_blocks.outbound import request
from blocks.python.standard_blocks.parse import strict_json
from blocks.python.standard_blocks.runtime import read_secret
from blocks.python.standard_blocks.types import Secret

from instruments.probes import SECRETS

REDACTED = "<REDACTED>"
SECRET_REF = re.compile(r"secret:[A-Za-z0-9_.-]{1,64}")
SYSTEM = "You are a careful maintenance engineer. Answer with one JSON object and nothing else."
MAX_REPLY = 8 * 1024 * 1024


class EgressError(RuntimeError):
    pass


def platform_transport(proxy: str, ca: str) -> httpx.AsyncHTTPTransport:
    """Through the platform's egress, trusting its authority only (it terminates TLS to inject the key)."""
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return httpx.AsyncHTTPTransport(proxy=httpx.Proxy(proxy), verify=context, trust_env=False, http1=True,
                                    http2=False)


def _request(endpoint: str, body: dict, headers: dict, egress: tuple | None = None):
    parts = urlsplit(endpoint)
    destination = f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
    try:
        response = request("POST", "model", endpoints={"model": endpoint},
                           values=Values({"destinations": [destination], "outbound_timeout_s": 120,
                                          "outbound_max_bytes": MAX_REPLY}), json=body, headers=headers,
                           transport=platform_transport(*egress) if egress else None)
        return strict_json(response.content, max_bytes=MAX_REPLY, max_depth=64)
    except (httpx.HTTPError, ValueError) as exc:
        raise EgressError(f"model request refused: {type(exc).__name__}") from None


def anthropic(endpoint: str, model: str, key: str, prompt: str, egress: tuple | None = None) -> str:
    body = {"model": model, "max_tokens": 16000, "system": SYSTEM, "messages": [{"role": "user", "content": prompt}]}
    reply = _request(endpoint or "https://api.anthropic.com/v1/messages", body,
                     {"x-api-key": key.reveal() if isinstance(key, Secret) else key,
                      "anthropic-version": "2023-06-01"}, egress)
    return "".join(b.get("text", "") for b in reply["content"])


def openai_compatible(endpoint: str, model: str, key: str, prompt: str, egress: tuple | None = None) -> str:
    body = {"model": model, "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]}
    reply = _request(endpoint, body, {"authorization": "Bearer " +
                                     (key.reveal() if isinstance(key, Secret) else key)}, egress)
    return reply["choices"][0]["message"]["content"]


KINDS = {"anthropic": anthropic, "openai": openai_compatible}


@dataclass(frozen=True)
class Provider:
    name: str
    kind: str
    model: str
    key: Secret
    endpoint: str = ""
    egress: tuple | None = None          # (proxy URL, the platform's CA file): the platform injects the key

    def __post_init__(self):
        if not isinstance(self.key, Secret):
            object.__setattr__(self, "key", Secret(self.key))


def redact(prompt: str) -> tuple[str, int]:
    count = 0
    raw = prompt.encode()
    for rx in SECRETS:
        raw, n = rx.subn(REDACTED.encode(), raw)
        count += n
    return raw.decode(errors="replace"), count


class Gate:
    def __init__(self, tiers: dict, log, *, transport=None, clock=lambda: int(time.time() * 1000)):
        """tiers: {"small": Provider, "frontier": Provider}; one provider may serve both.
        transport(provider, prompt) -> text, for tests; by default the provider's own API."""
        if not tiers:
            raise ValueError("no model provider")
        self.tiers, self.log, self.clock = tiers, Path(log), clock
        self._log_lock = threading.Lock()
        self.transport = transport or (lambda p, prompt: KINDS[p.kind](p.endpoint, p.model, p.key, prompt, p.egress))

    @classmethod
    def from_config(cls, section: dict, resolve, log) -> "Gate":
        """[llm.small] / [llm.frontier] = {kind, model, key_file | key = "secret:NAME", endpoint?};
        [llm] egress, egress_ca: the platform's egress, required for a key held by the platform."""
        egress = (section["egress"], str(resolve(section["egress_ca"]))) if section.get("egress") else None

        def key(spec):
            if "key" in spec:
                if not egress or not SECRET_REF.fullmatch(spec["key"]):
                    raise ValueError("a key held by the platform is `secret:NAME`, with [llm] egress and egress_ca")
                return Secret(spec["key"])
            return read_secret(resolve(spec["key_file"]))
        tiers = {tier: Provider(spec.get("name", spec["kind"]), spec["kind"], spec["model"], key(spec),
                                spec.get("endpoint", ""), egress)
                 for tier, spec in section.items() if isinstance(spec, dict)}
        return cls(tiers, log)

    def ask(self, prompt: str, tier: str = "frontier") -> dict:
        provider = self.tiers.get(tier) or self.tiers.get("frontier") or next(iter(self.tiers.values()))
        clean, redactions = redact(prompt)
        line = {"at": self.clock(), "provider": provider.name, "model": provider.model, "tier": tier,
                "bytes": len(clean.encode()), "redactions": redactions,
                "sha256": hashlib.sha256(clean.encode()).hexdigest()}
        with self._log_lock:                             # parallel reviewers log before anything leaves
            with open(self.log, "a") as f:
                f.write(json.dumps(line) + "\n")
        text = self.transport(provider, clean)
        try:
            if not isinstance(text, str) or len(text.encode()) > MAX_REPLY:
                raise ValueError("model reply is not bounded text")
            reply = strict_json(text[text.find("{"):text.rfind("}") + 1], max_bytes=MAX_REPLY, max_depth=64)
        except ValueError as exc:
            raise EgressError(f"the model did not answer with JSON: {exc}") from exc
        if not isinstance(reply, dict):
            raise EgressError("the model did not answer with a JSON object")
        if REDACTED in json.dumps(reply.get("files", {})):
            raise EgressError("the reply writes a redaction mark into a file")
        return reply
