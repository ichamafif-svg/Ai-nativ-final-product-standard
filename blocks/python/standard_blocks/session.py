"""Sign-in through the identity provider, and the product's own sessions (NO-OWN-AUTH, NO-OWN-AS, SESSION-TOKEN,
SESSION-ROTATE, SESSION-TIMEOUT, SESSION-END, SESSION-LIST, REAUTH, FED-SESSION, OAUTH-FLOW, OAUTH-MIXUP,
OIDC-IDTOKEN, JWT-VERIFY, JWT-AUDIENCE, OAUTH-EXPOSURE, FEDERATION).

    oidc = Oidc(issuer, client_id, redirect_uri, values, client_secret=secret("oidc"))
    app.include_router(oidc.router)                     # /auth/login, /auth/callback, /auth/logout, /auth/sessions
    user: User = Depends(oidc.current_user)
    dependencies=[Depends(oidc.fresh())]               # re-authentication before @sensitive_actions

The provider authenticates; the product never sees a password. Code flow with PKCE (S256), state and nonce; the ID
token's signature (algorithms from an allow-list, keys from the provider's JWKS), issuer, audience, expiry and nonce
are checked. Tokens stay on the server: the browser only holds a 256-bit session id in a __Host- cookie.
"""
from __future__ import annotations

import base64
import hashlib
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse, RedirectResponse

from . import Values
from . import log
from .crypto import same, token
from .web import SESSION_COOKIE

ALGORITHMS = ["RS256", "PS256", "ES256", "EdDSA"]
PENDING_S = 600


@dataclass(frozen=True)
class User:
    sub: str
    issuer: str
    roles: tuple = ()
    tenant: str | None = None
    auth_time: float = 0.0
    session: str = field(default="", repr=False)

    @property
    def id(self) -> str:
        return f"{self.issuer}|{self.sub}"                  # never the e-mail (OIDC-IDTOKEN, FEDERATION)


class Sessions:
    """Server-side sessions: id -> record. Replace with a shared store behind the same methods for several
    processes; the rules hold as long as ids stay random and records stay on the server."""

    def __init__(self):
        self.lock, self.by_id = threading.Lock(), {}

    def create(self, user: User) -> str:
        sid = token(32)
        with self.lock:
            self.by_id[sid] = {"user": user, "created": time.time(), "seen": time.time()}
        return sid

    def get(self, sid: str, idle_s: float, max_s: float):
        now = time.time()
        with self.lock:
            rec = self.by_id.get(sid)
            if rec is None:
                return None
            if now - rec["seen"] > idle_s or now - rec["created"] > max_s:
                del self.by_id[sid]
                return None
            rec["seen"] = now
            return rec

    def end(self, sid: str) -> None:
        with self.lock:
            self.by_id.pop(sid, None)

    def end_user(self, user_id: str, keep: str | None = None) -> int:
        with self.lock:
            gone = [s for s, r in self.by_id.items() if r["user"].id == user_id and s != keep]
            for s in gone:
                del self.by_id[s]
            return len(gone)

    def of_user(self, user_id: str) -> list:
        with self.lock:
            return [{"id": s[:8], "created": r["created"], "seen": r["seen"]}
                    for s, r in self.by_id.items() if r["user"].id == user_id]


class Oidc:
    def __init__(self, issuer: str, client_id: str, redirect_uri: str, values: Values | None = None, *,
                 client_secret: str | None = None, scopes=("openid",), transport=None, sessions: Sessions | None = None,
                 roles_claim: str = "roles", tenant_claim: str | None = None):
        if not issuer.startswith("https://") and transport is None:
            raise ValueError("the issuer is reached over https")
        self.issuer, self.client_id, self.redirect_uri = issuer.rstrip("/"), client_id, redirect_uri
        self.client_secret, self.scopes = client_secret, " ".join(scopes)
        self.values, self.sessions = values or Values.from_env(), sessions or Sessions()
        self.roles_claim, self.tenant_claim = roles_claim, tenant_claim
        self.http = httpx.AsyncClient(transport=transport, timeout=10, follow_redirects=False)
        self.pending, self.lock, self._meta, self._jwks = {}, threading.Lock(), None, None
        self.router = self._routes()

    # -- provider ------------------------------------------------------------------------------------------------
    async def meta(self) -> dict:
        if self._meta is None:
            r = await self.http.get(f"{self.issuer}/.well-known/openid-configuration")
            r.raise_for_status()
            meta = r.json()
            if meta.get("issuer", "").rstrip("/") != self.issuer:
                raise RuntimeError("the provider's configuration names another issuer")
            self._meta = meta
        return self._meta

    async def keys(self, refresh: bool = False) -> dict:
        if self._jwks is None or refresh:
            r = await self.http.get((await self.meta())["jwks_uri"])
            r.raise_for_status()
            self._jwks = {k["kid"]: k for k in r.json()["keys"] if "kid" in k}
        return self._jwks

    async def verify(self, token_: str, *, audience: str | None = None, nonce: str | None = None,
                     typ: str | None = None) -> dict:
        """A token's claims after its signature, issuer, audience, expiry (and nonce) are checked."""
        try:
            header = jwt.get_unverified_header(token_)
        except jwt.PyJWTError:
            raise HTTPException(401, "invalid token") from None
        if header.get("alg") not in ALGORITHMS:
            raise HTTPException(401, "invalid token")
        keys = await self.keys()
        if header.get("kid") not in keys:
            keys = await self.keys(refresh=True)
        jwk = keys.get(header.get("kid"))
        if jwk is None:
            raise HTTPException(401, "invalid token")
        try:
            claims = jwt.decode(token_, key=jwt.PyJWK(jwk).key, algorithms=ALGORITHMS,
                                audience=audience or self.client_id, issuer=self.issuer,
                                options={"require": ["exp", "iat", "iss", "aud", "sub"]}, leeway=30)
        except jwt.PyJWTError:
            raise HTTPException(401, "invalid token") from None
        if nonce is not None and not same(str(claims.get("nonce", "")), nonce):
            raise HTTPException(401, "invalid token")
        if typ is not None and str(header.get("typ", claims.get("typ", ""))).lower() not in (typ.lower(), f"{typ}+jwt"):
            raise HTTPException(401, "invalid token")
        return claims

    def _user(self, claims: dict, sid: str = "") -> User:
        roles = claims.get(self.roles_claim) or (claims.get("realm_access") or {}).get("roles") or []
        return User(sub=str(claims["sub"]), issuer=self.issuer, roles=tuple(sorted(map(str, roles))),
                    tenant=str(claims[self.tenant_claim]) if self.tenant_claim and self.tenant_claim in claims else None,
                    auth_time=float(claims.get("auth_time", claims.get("iat", time.time()))), session=sid)

    # -- routes --------------------------------------------------------------------------------------------------
    def _routes(self) -> APIRouter:
        router = APIRouter(prefix="/auth")

        @router.get("/login")
        async def login(request: Request, prompt: str | None = None):
            meta = await self.meta()
            state, nonce, verifier = token(), token(), token(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            with self.lock:
                now = time.time()
                self.pending = {k: v for k, v in self.pending.items() if v["at"] > now - PENDING_S}
                self.pending[state] = {"nonce": nonce, "verifier": verifier, "at": now}
            query = {"response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
                     "scope": self.scopes, "state": state, "nonce": nonce, "code_challenge": challenge,
                     "code_challenge_method": "S256"}
            if prompt == "login":
                query["prompt"], query["max_age"] = "login", "0"
            out = RedirectResponse(f"{meta['authorization_endpoint']}?{urlencode(query)}", status_code=303)
            out.set_cookie("__Host-oidc", state, max_age=PENDING_S, path="/", secure=True, httponly=True,
                           samesite="lax")
            return out

        @router.get("/callback")
        async def callback(request: Request, code: str = "", state: str = "", iss: str | None = None):
            if iss is not None and iss.rstrip("/") != self.issuer:
                log.security("oidc.mixup", route="/auth/callback")
                raise HTTPException(400, "sign-in failed")
            bound = request.cookies.get("__Host-oidc", "")
            with self.lock:
                pend = self.pending.pop(state, None)
            if not code or pend is None or not same(bound or "-", state or "+") or time.time() - pend["at"] > PENDING_S:
                log.security("oidc.state", route="/auth/callback")
                raise HTTPException(400, "sign-in failed")
            meta = await self.meta()
            form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri,
                    "client_id": self.client_id, "code_verifier": pend["verifier"]}
            auth = (self.client_id, self.client_secret) if self.client_secret else None
            r = await self.http.post(meta["token_endpoint"], data=form, auth=auth)
            if r.status_code != 200 or "id_token" not in r.json():
                log.security("oidc.token", route="/auth/callback", status=r.status_code)
                raise HTTPException(400, "sign-in failed")
            claims = await self.verify(r.json()["id_token"], nonce=pend["nonce"])
            old = request.cookies.get(SESSION_COOKIE)
            if old:
                self.sessions.end(old)                       # SESSION-ROTATE: a new id at every sign-in
            user = self._user(claims)
            sid = self.sessions.create(user)
            log.security("signin", who=user.id, outcome="ok")
            out = RedirectResponse("/", status_code=303)
            out.set_cookie(SESSION_COOKIE, sid, path="/", secure=True, httponly=True, samesite="lax")
            out.delete_cookie("__Host-oidc", path="/", secure=True)
            return out

        @router.post("/logout")
        async def logout(request: Request, everywhere: bool = False):
            sid = request.cookies.get(SESSION_COOKIE, "")
            rec = self.sessions.get(sid, *self._limits()) if sid else None
            if rec:
                if everywhere:
                    self.sessions.end_user(rec["user"].id)
                self.sessions.end(sid)
                log.security("signout", who=rec["user"].id, outcome="ok")
            out = JSONResponse({"signed_out": True})
            out.delete_cookie(SESSION_COOKIE, path="/", secure=True)
            out.headers["clear-site-data"] = '"cache", "cookies", "storage"'
            return out

        @router.get("/sessions")
        async def sessions(request: Request):
            user = await self.current_user(request)
            return {"sessions": self.sessions.of_user(user.id)}

        @router.delete("/sessions")
        async def end_others(request: Request):
            user = await self.current_user(request)
            return {"ended": self.sessions.end_user(user.id, keep=user.session)}

        return router

    # -- dependencies --------------------------------------------------------------------------------------------
    def _limits(self):
        return float(self.values["session_idle_min"]) * 60, float(self.values["session_max_hours"]) * 3600

    async def current_user(self, request: Request) -> User:
        sid = request.cookies.get(SESSION_COOKIE, "")
        rec = self.sessions.get(sid, *self._limits()) if sid else None
        if rec is None:
            raise HTTPException(401, "sign in")
        user = rec["user"]
        return User(user.sub, user.issuer, user.roles, user.tenant, user.auth_time, sid)

    def fresh(self, max_age_s: int = 300):
        """A dependency: the user signed in less than `max_age_s` ago, else 401 asking for a new sign-in."""
        async def check(request: Request) -> User:
            user = await self.current_user(request)
            if time.time() - user.auth_time > max_age_s:
                raise HTTPException(401, "sign in again", headers={"x-reauth": "/auth/login?prompt=login"})
            return user
        return check

    def bearer(self, audience: str):
        """A dependency for a resource server: a verified access token for this audience (RS-CLAIMS, JWT-AUDIENCE)."""
        async def check(request: Request) -> User:
            auth = request.headers.get("authorization", "")
            if not auth.lower().startswith("bearer "):
                raise HTTPException(401, "sign in")
            claims = await self.verify(auth[7:], audience=audience)
            return self._user(claims)
        return check
