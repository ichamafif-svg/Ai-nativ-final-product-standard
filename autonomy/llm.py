"""U — the one door to frontier models (D23, third track; R15).

Sending repository content to a model is an effect of data egress. Every request goes through this gate, which:
- redacts every value a secret rule detects, whatever the caller already did (a detected secret never leaves);
- picks a provider and model by tier: `small` for routine work, `frontier` for what needs judgment;
- appends one line per request to an egress log: when, which provider and model, how many bytes, how many
  redactions, and the SHA-256 of the prompt, never its content;
- refuses a reply that still carries a redaction mark (the model would be writing a placeholder into code).

Providers: Anthropic's Messages API, and any OpenAI-compatible chat completions endpoint (Mistral, a local server…),
each with its own key file. What a model writes is hostile data: the caller confines it to the target's write scope.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from trusted.instruments import SECRETS

REDACTED = "<REDACTED>"
SYSTEM = "You are a careful maintenance engineer. Answer with one JSON object and nothing else."


class EgressError(RuntimeError):
    pass


def anthropic(endpoint: str, model: str, key: str, prompt: str) -> str:
    body = {"model": model, "max_tokens": 16000, "system": SYSTEM, "messages": [{"role": "user", "content": prompt}]}
    req = urllib.request.Request(endpoint or "https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
                                 method="POST", headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                                                         "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return "".join(b.get("text", "") for b in json.loads(r.read())["content"])


def openai_compatible(endpoint: str, model: str, key: str, prompt: str) -> str:
    body = {"model": model, "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]}
    req = urllib.request.Request(endpoint, data=json.dumps(body).encode(), method="POST",
                                 headers={"authorization": f"Bearer {key}", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"]


KINDS = {"anthropic": anthropic, "openai": openai_compatible}


@dataclass(frozen=True)
class Provider:
    name: str
    kind: str
    model: str
    key: str
    endpoint: str = ""


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
        self.transport = transport or (lambda p, prompt: KINDS[p.kind](p.endpoint, p.model, p.key, prompt))

    @classmethod
    def from_config(cls, section: dict, resolve, log) -> "Gate":
        """[llm.small] / [llm.frontier] = {kind, model, key_file, endpoint?}"""
        tiers = {tier: Provider(spec.get("name", spec["kind"]), spec["kind"], spec["model"],
                                Path(resolve(spec["key_file"])).read_text().strip(), spec.get("endpoint", ""))
                 for tier, spec in section.items() if isinstance(spec, dict)}
        return cls(tiers, log)

    def ask(self, prompt: str, tier: str = "frontier") -> dict:
        provider = self.tiers.get(tier) or self.tiers.get("frontier") or next(iter(self.tiers.values()))
        clean, redactions = redact(prompt)
        line = {"at": self.clock(), "provider": provider.name, "model": provider.model, "tier": tier,
                "bytes": len(clean.encode()), "redactions": redactions,
                "sha256": hashlib.sha256(clean.encode()).hexdigest()}
        with open(self.log, "a") as f:                     # the log line is written before anything leaves
            f.write(json.dumps(line) + "\n")
        text = self.transport(provider, clean)
        try:
            reply = json.loads(text[text.find("{"):text.rfind("}") + 1])
        except ValueError as exc:
            raise EgressError(f"the model did not answer with JSON: {exc}") from exc
        if not isinstance(reply, dict):
            raise EgressError("the model did not answer with a JSON object")
        if REDACTED in json.dumps(reply.get("files", {})):
            raise EgressError("the reply writes a redaction mark into a file")
        return reply
