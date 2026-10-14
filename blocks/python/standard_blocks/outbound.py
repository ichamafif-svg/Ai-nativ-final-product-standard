"""The one HTTP client to other services (SSRF, TLS-VERIFY, RUN-TIMEOUTS, SERVICE-CONFIG).

    billing = Outbound({"billing": "https://billing.internal:8443"}, values)
    r = await billing.get("billing", "/invoices", params={"id": iid})

A call names a service, never a URL; the service's host must be in @destinations. Certificates are checked,
redirects are not followed, every call has a timeout of at most @outbound_timeout_s.

Beyond the checklists (the SSRF that allow-lists miss):
    - the address is checked when the connection is made, on every address the name resolves to, and the
      connection goes to the address that was checked: DNS rebinding cannot swap a public answer for an internal
      one between the check and the call;
    - link-local, cloud metadata, multicast, unspecified and reserved addresses are refused even for an allowed name;
      loopback and private addresses only for a service named with its port in @destinations (host:port);
    - no proxy from the environment (HTTP_PROXY cannot reroute calls), TLS 1.2 at least, HTTP/1.1 only;
    - a response larger than @outbound_max_bytes is refused while it is read, never buffered whole; the whole call,
      not each read, has one deadline (a server dripping bytes cannot hold a worker).
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit

import httpcore
import httpx

from . import Values
from . import log

METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254"),
            ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("169.254.170.2")}


class OutboundRefused(ValueError):
    pass


def refused_address(ip: ipaddress._BaseAddress, private_ok: bool) -> str | None:
    """Why an address may not be reached, or None."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip in METADATA or ip.is_link_local:
        return "link-local or metadata"
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "not a host"
    if (ip.is_loopback or ip.is_private or (isinstance(ip, ipaddress.IPv4Address) and ip in
                                            ipaddress.ip_network("100.64.0.0/10"))) and not private_ok:
        return "internal"
    return None


class _CheckedBackend(httpcore.AsyncNetworkBackend):
    """Resolves, checks every address, and connects to the checked one (TLS still verifies the name)."""

    def __init__(self, private_hosts: set):
        self.inner, self.private_hosts = httpcore.AnyIOBackend(), private_hosts

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            raise httpcore.ConnectError(f"cannot resolve {host}") from None
        addresses = sorted({info[4][0] for info in infos})
        private_ok = f"{host}:{port}" in self.private_hosts
        for a in addresses:
            why = refused_address(ipaddress.ip_address(a.split("%")[0]), private_ok)
            if why:
                log.security("outbound.address", route=host, outcome=why)
                raise httpcore.ConnectError(f"{host} resolves to an address that is {why}")
        last = None
        for a in addresses:
            try:
                return await self.inner.connect_tcp(a, port, timeout=timeout, local_address=local_address,
                                                    socket_options=socket_options)
            except httpcore.ConnectError as exc:
                last = exc
        raise last or httpcore.ConnectError(f"cannot connect to {host}")

    async def connect_unix_socket(self, *a, **kw):
        raise httpcore.ConnectError("no unix sockets")

    async def sleep(self, seconds):
        await self.inner.sleep(seconds)


def _transport(private_hosts: set) -> httpx.AsyncHTTPTransport:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    transport = httpx.AsyncHTTPTransport(verify=context, trust_env=False, http1=True, http2=False)
    transport._pool = httpcore.AsyncConnectionPool(ssl_context=context, http1=True, http2=False,
                                                   network_backend=_CheckedBackend(private_hosts))
    return transport


class Outbound:
    def __init__(self, services: dict, values: Values | None = None, *, transport=None):
        self.values, self.services = values or Values.from_env(), {}
        for name, base in services.items():
            parts = urlsplit(base)
            if parts.scheme != "https" and transport is None:
                raise OutboundRefused(f"{name}: services are reached over https")
            if parts.username or parts.password or parts.query or parts.fragment:
                raise OutboundRefused(f"{name}: a service is scheme://host[:port][/path]")
            self.services[name] = (base.rstrip("/"), parts.hostname, parts.port or 443)
        private = {d for d in self.values["destinations"] if ":" in str(d)}
        self.client = httpx.AsyncClient(transport=transport or _transport(private), follow_redirects=False,
                                        trust_env=False, max_redirects=0)

    def _url(self, service: str, path: str) -> str:
        if service not in self.services:
            raise OutboundRefused(f"unknown service {service}")
        base, host, port = self.services[service]
        allowed = self.values["destinations"]
        if host not in allowed and f"{host}:{port}" not in allowed:
            log.security("outbound.refused", route=service)
            raise OutboundRefused(f"{host} is not in @destinations")
        if not path.startswith("/") or path.startswith("//") or any(c in path for c in ("\\", "\r", "\n", "\t", "\x00")) \
                or "://" in path or "/../" in path + "/" or "%2e%2e" in path.lower() or "@" in path.split("?")[0]:
            raise OutboundRefused("a path on the service, never a URL")
        return base + path

    async def request(self, method: str, service: str, path: str, *, max_bytes: int | None = None,
                      **kw) -> httpx.Response:
        limit = float(self.values["outbound_timeout_s"])
        timeout = min(float(kw.pop("timeout", limit)), limit)
        cap = min(int(max_bytes or self.values["outbound_max_bytes"]), int(self.values["outbound_max_bytes"]))
        for k in ("follow_redirects", "verify", "auth_flow"):
            kw.pop(k, None)
        url = self._url(service, path)

        async def call():
            async with self.client.stream(method, url, timeout=timeout, **kw) as response:
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > cap:
                    raise OutboundRefused(f"{service} answered more than {cap} bytes")
                body = bytearray()
                async for chunk in response.aiter_bytes():       # decoded: a gzip bomb counts at full size
                    body += chunk
                    if len(body) > cap:
                        raise OutboundRefused(f"{service} answered more than {cap} bytes")
                headers = [(k, v) for k, v in response.headers.multi_items()
                           if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")]
                return httpx.Response(response.status_code, headers=headers, content=bytes(body),
                                      request=response.request)
        try:
            response = await asyncio.wait_for(call(), timeout)
        except asyncio.TimeoutError:
            log.security("outbound.timeout", route=service)
            raise httpx.TimeoutException(f"{service} took more than {timeout}s") from None
        log.event("outbound.call", route=service, status=response.status_code)
        return response

    async def get(self, service: str, path: str, **kw):
        return await self.request("GET", service, path, **kw)

    async def post(self, service: str, path: str, **kw):
        return await self.request("POST", service, path, **kw)

    async def aclose(self):
        await self.client.aclose()
