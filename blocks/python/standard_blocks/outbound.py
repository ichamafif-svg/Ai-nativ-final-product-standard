"""The one HTTP client to other services (SSRF, TLS-VERIFY, RUN-TIMEOUTS, SERVICE-CONFIG).

    billing = Outbound({"billing": "https://billing.internal:8443"}, values)
    r = await billing.get("billing", "/invoices", params={"id": iid})

A call names a service, never a URL; the service's host must be in @destinations. Certificates are checked,
redirects are not followed, every call has a timeout of at most @outbound_timeout_s.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from . import Values
from . import log


class OutboundRefused(ValueError):
    pass


class Outbound:
    def __init__(self, services: dict, values: Values | None = None, *, transport=None):
        self.values, self.services = values or Values.from_env(), {}
        for name, base in services.items():
            parts = urlsplit(base)
            if parts.scheme != "https" and transport is None:
                raise OutboundRefused(f"{name}: services are reached over https")
            self.services[name] = (base.rstrip("/"), parts.hostname, parts.port)
        self.client = httpx.AsyncClient(transport=transport, verify=True, follow_redirects=False)

    def _url(self, service: str, path: str) -> str:
        if service not in self.services:
            raise OutboundRefused(f"unknown service {service}")
        base, host, port = self.services[service]
        allowed = self.values["destinations"]
        if host not in allowed and f"{host}:{port}" not in allowed:
            log.security("outbound.refused", route=service)
            raise OutboundRefused(f"{host} is not in @destinations")
        if not path.startswith("/") or "://" in path or "\\" in path or path.startswith("//"):
            raise OutboundRefused("a path on the service, never a URL")
        return base + path

    async def request(self, method: str, service: str, path: str, **kw) -> httpx.Response:
        timeout = min(float(kw.pop("timeout", self.values["outbound_timeout_s"])),
                      float(self.values["outbound_timeout_s"]))
        kw.pop("follow_redirects", None)
        kw.pop("verify", None)
        response = await self.client.request(method, self._url(service, path), timeout=timeout, **kw)
        log.event("outbound.call", route=service, status=response.status_code)
        return response

    async def get(self, service: str, path: str, **kw):
        return await self.request("GET", service, path, **kw)

    async def post(self, service: str, path: str, **kw):
        return await self.request("POST", service, path, **kw)

    async def aclose(self):
        await self.client.aclose()
