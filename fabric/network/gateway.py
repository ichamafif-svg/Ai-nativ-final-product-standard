"""The gateway's Envoy configuration (D68), derived from the rules of the game, never written by hand.

Envoy is the one way in. It does what a proxy does well: HTTP framing and path normalisation, header and body limits,
timeouts, refused methods, host names, CORS, a rate limit, and the sign-in delegated to oauth2-proxy
(external authorisation): a request that is not public reaches the product only once oauth2-proxy has said who it
is from. Every identity header a client sends is removed before any filter runs. Everything then goes to the gate
(`fabric/network/gate.py`), which applies Standard's own policy (Fetch Metadata isolation against cross-site requests
included, so that clients that are not browsers keep working) and records what it corrects and refuses.

    config(values, port=8080, gate="/run/standard/gate.sock", oauth2=4180)  -> an Envoy bootstrap (dict, JSON)

Known limit: the rate limit is one bucket for the listener; a limit per address needs Envoy's rate-limit service.
"""
from __future__ import annotations

import re

from fabric.network.gate import AUTH_HEADERS
from fabric.identity.identity import HEADER

REFUSED_METHODS = ("TRACE", "TRACK", "CONNECT")
PUBLIC = re.compile(r"(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) (/[A-Za-z0-9._~/-]*)")
HCM = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
EXT_AUTHZ = "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz"
EXT_AUTHZ_PER_ROUTE = "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute"


def _filter(name: str, kind: str, config: dict | None = None) -> dict:
    return {"name": name, "typed_config": {"@type": f"type.googleapis.com/{kind}", **(config or {})}}


def _exact_origins(origins) -> list:
    return [{"exact": o} for o in origins]


def public_routes(values: dict) -> list:
    """`@public` entries ("GET /health") as Envoy routes that skip the sign-in, exact method and path."""
    out = []
    for entry in values.get("public", []):
        found = PUBLIC.fullmatch(entry)
        if not found:
            continue
        method, path = found.groups()
        out.append({"match": {"path": path, "headers": [{"name": ":method", "string_match": {"exact": method}}]},
                    "route": {"cluster": "gate", "timeout": f"{int(values['request_timeout_s']) + 1}s"},
                    "typed_per_filter_config": {"envoy.filters.http.ext_authz": {"@type": EXT_AUTHZ_PER_ROUTE,
                                                                                  "disabled": True}}})
    return out


def config(values: dict, *, port: int, gate: str, oauth2: int | None = None, admin: int | None = None) -> dict:
    # The gate's own deadline answers first, and records it; Envoy's is the backstop one second later.
    timeout = f"{int(values['request_timeout_s']) + 1}s"
    no_authz = {"envoy.filters.http.ext_authz": {"@type": EXT_AUTHZ_PER_ROUTE, "disabled": True}}
    routes = [{"match": {"prefix": "/", "headers": [{"name": ":method", "string_match": {"exact": m}}]},
               "direct_response": {"status": 405}, "typed_per_filter_config": no_authz} for m in REFUSED_METHODS]
    if oauth2:
        routes.append({"match": {"prefix": "/oauth2/"}, "route": {"cluster": "oauth2_proxy", "timeout": timeout},
                       "typed_per_filter_config": no_authz})
    routes += public_routes(values)
    routes.append({"match": {"prefix": "/"}, "route": {"cluster": "gate", "timeout": timeout}})
    origins = list(values.get("origins", []))
    filters = [
        _filter("envoy.filters.http.cors", "envoy.extensions.filters.http.cors.v3.Cors"),
        _filter("envoy.filters.http.local_ratelimit", "envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit", {
            "stat_prefix": "rate",
            "token_bucket": {"max_tokens": int(values["rate_per_minute"]), "tokens_per_fill": int(values["rate_per_minute"]),
                             "fill_interval": "60s"},
            "filter_enabled": {"default_value": {"numerator": 100, "denominator": "HUNDRED"}, "runtime_key": "rate_on"},
            "filter_enforced": {"default_value": {"numerator": 100, "denominator": "HUNDRED"}, "runtime_key": "rate_hard"}}),
        _filter("envoy.filters.http.buffer", "envoy.extensions.filters.http.buffer.v3.Buffer",
                {"max_request_bytes": int(values["body_max_bytes"])}),
    ]
    if oauth2:
        filters.append({"name": "envoy.filters.http.ext_authz", "typed_config": {
            "@type": EXT_AUTHZ, "transport_api_version": "V3", "failure_mode_allow": False,
            "allowed_headers": {"patterns": [{"exact": "cookie"}]},
            "http_service": {
                "server_uri": {"uri": f"http://127.0.0.1:{oauth2}", "cluster": "oauth2_proxy", "timeout": "2s"},
                "path_prefix": "/oauth2/auth",
                "authorization_response": {
                    "allowed_upstream_headers": {"patterns": [{"exact": h} for h in sorted(AUTH_HEADERS)]},
                    "allowed_client_headers": {"patterns": [{"exact": "set-cookie"}, {"exact": "location"}]}}}}})
    filters.append(_filter("envoy.filters.http.router", "envoy.extensions.filters.http.router.v3.Router",
                           {"suppress_envoy_headers": True}))
    vhost = {"name": "product", "domains": list(values.get("hosts") or ["*"]), "routes": routes}
    if origins:
        vhost["typed_per_filter_config"] = {"envoy.filters.http.cors": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
            "allow_origin_string_match": _exact_origins(origins), "allow_credentials": True,
            "allow_methods": "GET, POST, PUT, PATCH, DELETE", "allow_headers": "content-type, x-csrf-token",
            "max_age": "600"}}
    hcm = {
        "@type": HCM, "stat_prefix": "ingress", "codec_type": "AUTO",
        "normalize_path": True, "merge_slashes": True, "path_with_escaped_slashes_action": "REJECT_REQUEST",
        "use_remote_address": True, "xff_num_trusted_hops": len(values.get("trusted_proxies", [])),
        "server_header_transformation": "PASS_THROUGH",
        "max_request_headers_kb": 32, "request_headers_timeout": "10s", "request_timeout": timeout,
        "stream_idle_timeout": timeout,
        "common_http_protocol_options": {"headers_with_underscores_action": "REJECT_REQUEST", "max_headers_count": 100,
                                         "idle_timeout": "60s"},
        "early_header_mutation_extensions": [{
            "name": "envoy.http.early_header_mutation.header_mutation",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.http.early_header_mutation.header_mutation.v3.HeaderMutation",
                "mutations": [{"remove": h} for h in sorted({HEADER, *AUTH_HEADERS})]}}],
        "route_config": {"name": "product", "virtual_hosts": [vhost]},
        "http_filters": filters,
    }
    clusters = [{"name": "gate", "connect_timeout": "2s", "type": "STATIC",
                 "load_assignment": {"cluster_name": "gate", "endpoints": [{"lb_endpoints": [
                     {"endpoint": {"address": {"pipe": {"path": gate}}}}]}]}}]
    if oauth2:
        clusters.append({"name": "oauth2_proxy", "connect_timeout": "2s", "type": "STATIC",
                         "load_assignment": {"cluster_name": "oauth2_proxy", "endpoints": [{"lb_endpoints": [
                             {"endpoint": {"address": {"socket_address": {"address": "127.0.0.1",
                                                                          "port_value": oauth2}}}}]}]}})
    bootstrap = {"static_resources": {
        "listeners": [{"name": "ingress", "address": {"socket_address": {"address": "127.0.0.1", "port_value": port}},
                       "filter_chains": [{"filters": [{"name": "envoy.filters.network.http_connection_manager",
                                                       "typed_config": hcm}]}]}],
        "clusters": clusters}}
    if admin:
        bootstrap["admin"] = {"address": {"socket_address": {"address": "127.0.0.1", "port_value": admin}}}
    return bootstrap


def mtls_cluster(name: str, host: str, port: int, *, cert: str, key: str, ca: str, server_name: str) -> dict:
    """A cluster toward a platform service on another machine: TLS 1.3 only, the peer's certificate checked against
    the platform's authority and name, ours presented (mutual TLS). Paths are files the platform owns."""
    return {"name": name, "connect_timeout": "2s", "type": "STRICT_DNS",
            "load_assignment": {"cluster_name": name, "endpoints": [{"lb_endpoints": [
                {"endpoint": {"address": {"socket_address": {"address": host, "port_value": port}}}}]}]},
            "transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                "sni": server_name,
                "common_tls_context": {
                    "tls_params": {"tls_minimum_protocol_version": "TLSv1_3"},
                    "tls_certificates": [{"certificate_chain": {"filename": cert}, "private_key": {"filename": key}}],
                    "validation_context": {"trusted_ca": {"filename": ca},
                                           "match_typed_subject_alt_names": [
                                               {"san_type": "DNS", "matcher": {"exact": server_name}}]}}}}}
