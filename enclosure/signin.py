"""The sign-in (D68): oauth2-proxy, configured from the rules of the game and the client's identity provider.

oauth2-proxy runs OpenID Connect with PKCE (S256) against the client's own provider, keeps the session in a cookie
it encrypts (`__Host-` prefix, Secure, HttpOnly, SameSite=Lax), and answers Envoy's external authorisation: who the
request is from, as `x-auth-request-*` headers that only Envoy can pass on. Session lifetimes come from the values
(@session_idle_min, @session_max_hours). The provider is the client's: Standard reads its settings, never runs it.

    args(provider, values, port=4180, secrets=dir)  -> oauth2-proxy's command line
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Provider:
    """The client's OpenID Connect provider. Discovery is used unless the endpoints are given."""
    issuer: str
    client_id: str
    redirect_url: str
    login_url: str | None = None
    redeem_url: str | None = None
    jwks_url: str | None = None
    groups_claim: str = "groups"


def secrets(directory) -> dict:
    """The cookie secret (32 random bytes) and the client secret file, created 0600 in a platform-owned directory.
    The client secret comes from the broker once it exists; until then it is written there by the operator."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    cookie = directory / "cookie.secret"
    if not cookie.exists():
        cookie.write_text(base64.urlsafe_b64encode(os.urandom(32)).decode())
        cookie.chmod(0o600)
    client = directory / "client.secret"
    if not client.exists():
        client.write_text("")
        client.chmod(0o600)
    return {"cookie": cookie, "client": client}


def args(provider: Provider, values: dict, *, port: int, secrets_dir) -> list:
    files = secrets(secrets_dir)
    out = [
        f"--http-address=127.0.0.1:{port}", "--provider=oidc", f"--oidc-issuer-url={provider.issuer}",
        f"--client-id={provider.client_id}", f"--client-secret-file={files['client']}",
        f"--cookie-secret-file={files['cookie']}", f"--redirect-url={provider.redirect_url}",
        "--code-challenge-method=S256", "--cookie-name=__Host-session", "--cookie-secure=true",
        "--cookie-httponly=true", "--cookie-samesite=lax", "--cookie-path=/",
        f"--cookie-expire={int(values['session_max_hours'])}h", f"--cookie-refresh={int(values['session_idle_min'])}m",
        "--set-xauthrequest=true", "--reverse-proxy=true",
        "--email-domain=*", f"--oidc-groups-claim={provider.groups_claim}", "--skip-provider-button=true",
        "--upstream=static://200", "--api-route=^/api/",
    ]
    if provider.login_url:
        out += ["--skip-oidc-discovery=true", f"--login-url={provider.login_url}",
                f"--redeem-url={provider.redeem_url}", f"--oidc-jwks-url={provider.jwks_url}"]
    return out
