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

Beyond the checklists: the store keeps only hashes of session ids; a session presented by another client (user
agent) is ended; the provider's keys expire within the hour and an unknown key id refreshes them at most once a
minute; a token naming or carrying its own key, or of another kind (access, logout), is refused; @mfa is checked on
the ID token's amr; the provider can end sessions by back-channel logout; the pending sign-ins are bounded.
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
from .types import Secret
from .web import SESSION_COOKIE

ALGORITHMS = ["RS256", "PS256", "ES256", "EdDSA"]
PENDING_S = 600
JWKS_TTL_S, JWKS_REFRESH_S, META_TTL_S = 3600, 60, 86400
MAX_TOKEN = 16_384
EMBEDDED_KEYS = ("jku", "jwk", "x5u", "x5c", "crit")      # a token never names or carries its own key
SECOND_FACTORS = {"mfa", "otp", "hwk", "sc", "fpt", "face", "iris", "retina", "vbm"}   # RFC 8176
BACKCHANNEL = "http://schemas.openid.net/event/backchannel-logout"


@dataclass(frozen=True)
class User:
    sub: str
    issuer: str
    roles: tuple = ()
    tenant: str | None = None
    auth_time: float = 0.0
    session: str = field(default="", repr=False)
    amr: tuple = ()

    @property
    def id(self) -> str:
        return f"{self.issuer}|{self.sub}"                  # never the e-mail (OIDC-IDTOKEN, FEDERATION)

    def record(self) -> dict:
        return {"sub": self.sub, "issuer": self.issuer, "roles": list(self.roles), "tenant": self.tenant,
                "auth_time": self.auth_time, "amr": list(self.amr)}

    @classmethod
    def of(cls, rec: dict, session: str = "") -> "User":
        return cls(rec["sub"], rec["issuer"], tuple(rec.get("roles", ())), rec.get("tenant"),
                   float(rec.get("auth_time", 0)), session, tuple(rec.get("amr", ())))


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Sessions:
    """Server-side sessions in a store (store.py): one process in memory, several on Redis. The store holds the
    SHA-256 of each id, never the id: reading the store does not give a live session. A session is bound to the
    client that opened it (its user agent): presented by another client, it is ended."""

    def __init__(self, store=None):
        from .store import from_env
        self.store = store or from_env()

    def create(self, user: User, *, client: str = "", idp_sid: str | None = None, ttl: float = 86400) -> str:
        sid = token(32)
        key, now = _h(sid), time.time()
        self.store.set(f"s:{key}", {"user": user.record(), "created": now, "seen": now, "client": client,
                                    "idp_sid": idp_sid}, ttl)
        self.store.add(f"u:{_h(user.id)}", key, ttl)
        if idp_sid:
            self.store.add(f"i:{_h(user.issuer + '|' + idp_sid)}", key, ttl)
        return sid

    def get(self, sid: str, idle_s: float, max_s: float, *, client: str | None = None):
        if not sid or len(sid) > 100:
            return None
        key, now = _h(sid), time.time()
        rec = self.store.get(f"s:{key}")
        if rec is None:
            return None
        if now - rec["seen"] > idle_s or now - rec["created"] > max_s:
            self._end(key, rec)
            return None
        if client is not None and rec.get("client") and not same(rec["client"], client):
            log.security("session.other_client", who=User.of(rec["user"]).id)
            self._end(key, rec)
            return None
        rec["seen"] = now
        self.store.set(f"s:{key}", rec, max(1.0, max_s - (now - rec["created"])))
        return {**rec, "user": User.of(rec["user"], sid)}

    def _end(self, key: str, rec: dict | None = None) -> None:
        rec = rec or self.store.get(f"s:{key}")
        self.store.delete(f"s:{key}")
        if rec:
            self.store.discard(f"u:{_h(User.of(rec['user']).id)}", key)

    def end(self, sid: str) -> None:
        self._end(_h(sid))

    def end_user(self, user_id: str, keep: str | None = None) -> int:
        keep_key = _h(keep) if keep else None
        gone = [k for k in self.store.members(f"u:{_h(user_id)}") if k != keep_key]
        for k in gone:
            self._end(k)
        return len(gone)

    def end_provider_session(self, issuer: str, idp_sid: str) -> int:
        """Back-channel logout: every session opened by this provider session."""
        index = f"i:{_h(issuer + '|' + idp_sid)}"
        gone = self.store.members(index)
        for k in gone:
            self._end(k)
        self.store.delete(index)
        return len(gone)

    def of_user(self, user_id: str) -> list:
        out = []
        for k in self.store.members(f"u:{_h(user_id)}"):
            rec = self.store.get(f"s:{k}")
            if rec:
                out.append({"id": k[:8], "created": rec["created"], "seen": rec["seen"]})
        return out

    def backdate(self, sid: str, seconds: float) -> bool:
        """Make a session look `seconds` older (Standard's timeout probe)."""
        key = _h(sid)
        rec = self.store.get(f"s:{key}")
        if rec is None:
            return False
        rec["seen"] -= seconds
        rec["created"] -= seconds
        self.store.set(f"s:{key}", rec, 3600)
        return True


def client_of(request) -> str:
    """What binds a session to the client that opened it: the user agent, hashed."""
    return _h(request.headers.get("user-agent", ""))[:32]


class Oidc:
    def __init__(self, issuer: str, client_id: str, redirect_uri: str, values: Values | None = None, *,
                 client_secret: str | None = None, scopes=("openid",), transport=None, sessions: Sessions | None = None,
                 roles_claim: str = "roles", tenant_claim: str | None = None, store=None):
        if not issuer.startswith("https://") and transport is None:
            raise ValueError("the issuer is reached over https")
        if not redirect_uri.startswith("https://") and transport is None:
            raise ValueError("the redirect URI is https")
        self.issuer, self.client_id, self.redirect_uri = issuer.rstrip("/"), client_id, redirect_uri
        self.client_secret = client_secret.reveal() if isinstance(client_secret, Secret) else client_secret
        self.scopes = " ".join(scopes)
        self.values, self.sessions = values or Values.from_env(), sessions or Sessions(store)
        self.roles_claim, self.tenant_claim = roles_claim, tenant_claim
        self.http = httpx.AsyncClient(transport=transport, timeout=10, follow_redirects=False, trust_env=False)
        self.pending, self.lock, self._meta, self._jwks = {}, threading.Lock(), None, None
        self._meta_at = self._jwks_at = self._refresh_at = 0.0
        self.router = self._routes()

    def bind(self, app):
        """Mount /auth on the app and let Standard's session probes find it. Returns self."""
        app.include_router(self.router)
        app.state.standard_session = self
        return self

    # -- provider ------------------------------------------------------------------------------------------------
    async def meta(self) -> dict:
        if self._meta is None or time.time() - self._meta_at > META_TTL_S:
            r = await self.http.get(f"{self.issuer}/.well-known/openid-configuration")
            r.raise_for_status()
            meta = r.json()
            if meta.get("issuer", "").rstrip("/") != self.issuer:
                raise RuntimeError("the provider's configuration names another issuer")
            for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if self.issuer.startswith("https://") and not str(meta.get(name, "")).startswith("https://"):
                    raise RuntimeError(f"the provider's {name} is not https")
            self._meta, self._meta_at = meta, time.time()
        return self._meta

    async def keys(self, refresh: bool = False) -> dict:
        """The provider's keys, cached an hour (a revoked key stops working within the hour); a refresh for an
        unknown key id happens at most once a minute, so forged key ids cannot hammer the provider."""
        now = time.time()
        stale = self._jwks is None or now - self._jwks_at > JWKS_TTL_S
        if stale or (refresh and now - self._refresh_at > JWKS_REFRESH_S):
            self._refresh_at = now
            r = await self.http.get((await self.meta())["jwks_uri"])
            r.raise_for_status()
            keys = {}
            for k in r.json().get("keys", []):
                if "kid" in k and k.get("use", "sig") == "sig" and "d" not in k and k.get("kty") in ("RSA", "EC", "OKP"):
                    keys[k["kid"]] = k                      # public signing keys only
            self._jwks, self._jwks_at = keys, now
        return self._jwks

    async def verify(self, token_: str, *, audience: str | None = None, nonce: str | None = None,
                     typ: str | None = None, kind: str = "id") -> dict:
        """A token's claims after its signature, issuer, audience, expiry (and nonce) are checked. The token may not
        name or carry its own key (jku, jwk, x5u, x5c), declare critical extensions, or be of another kind than
        asked (an access token is not an ID token, a logout token is neither)."""
        def refuse():
            return HTTPException(401, "invalid token")
        if not isinstance(token_, str) or len(token_) > MAX_TOKEN or token_.count(".") != 2:
            raise refuse()
        try:
            header = jwt.get_unverified_header(token_)
        except jwt.PyJWTError:
            raise refuse() from None
        if header.get("alg") not in ALGORITHMS or any(k in header for k in EMBEDDED_KEYS):
            raise refuse()
        declared = str(header.get("typ", "")).lower()
        if kind == "id" and declared in ("at+jwt", "logout+jwt"):
            raise refuse()
        if kind == "logout" and declared not in ("", "jwt", "logout+jwt"):
            raise refuse()
        keys = await self.keys()
        if header.get("kid") not in keys:
            keys = await self.keys(refresh=True)
        jwk = keys.get(header.get("kid"))
        if jwk is None or (jwk.get("alg") and jwk["alg"] != header["alg"]):
            raise refuse()
        try:
            claims = jwt.decode(token_, key=jwt.PyJWK(jwk).key, algorithms=[header["alg"]],
                                audience=audience or self.client_id, issuer=self.issuer,
                                options={"require": ["exp", "iat", "iss", "aud", "sub"] if kind != "logout"
                                         else ["iat", "iss", "aud", "jti"]}, leeway=30)
        except jwt.PyJWTError:
            raise refuse() from None
        if claims.get("iat", 0) > time.time() + 60:
            raise refuse()
        aud = claims.get("aud")
        if kind == "id" and isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.client_id:
            raise refuse()
        if nonce is not None and not same(str(claims.get("nonce", "")), nonce):
            raise refuse()
        if typ is not None and declared not in (typ.lower(), f"{typ.lower()}+jwt"):
            raise refuse()
        return claims

    def _user(self, claims: dict, sid: str = "") -> User:
        roles = claims.get(self.roles_claim) or (claims.get("realm_access") or {}).get("roles") or []
        if not isinstance(roles, (list, tuple)):
            roles = []
        amr = claims.get("amr") if isinstance(claims.get("amr"), list) else []
        return User(sub=str(claims["sub"]), issuer=self.issuer, roles=tuple(sorted(map(str, roles))),
                    tenant=str(claims[self.tenant_claim]) if self.tenant_claim and self.tenant_claim in claims else None,
                    auth_time=float(claims.get("auth_time", claims.get("iat", time.time()))), session=sid,
                    amr=tuple(map(str, amr)))

    def _second_factor(self, user: User) -> bool:
        """@mfa: all (everyone shows a second factor in amr), admins (admins do), provider (the identity provider
        enforces it for everyone and the product takes its word). Unknown values require it of everyone."""
        rule = str(self.values.get("mfa", "all"))
        if rule == "provider":
            return True
        needed = rule != "admins" or "admin" in user.roles
        return not needed or bool(set(user.amr) & SECOND_FACTORS)

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
                if len(self.pending) > 10_000:               # a flood of half-open sign-ins keeps the newest
                    self.pending = dict(sorted(self.pending.items(), key=lambda kv: kv[1]["at"])[-5_000:])
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
            if not code or len(code) > 2048 or pend is None or not same(bound or "-", state or "+") \
                    or time.time() - pend["at"] > PENDING_S:
                log.security("oidc.state", route="/auth/callback")
                raise HTTPException(400, "sign-in failed")
            meta = await self.meta()
            form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri,
                    "client_id": self.client_id, "code_verifier": pend["verifier"]}
            auth = (self.client_id, self.client_secret) if self.client_secret else None
            r = await self.http.post(meta["token_endpoint"], data=form, auth=auth)
            try:
                body = r.json() if r.status_code == 200 and len(r.content) < 65_536 else {}
            except ValueError:
                body = {}
            if not isinstance(body, dict) or not isinstance(body.get("id_token"), str):
                log.security("oidc.token", route="/auth/callback", status=r.status_code)
                raise HTTPException(400, "sign-in failed")
            claims = await self.verify(body["id_token"], nonce=pend["nonce"])
            user = self._user(claims)
            if not self._second_factor(user):
                log.security("signin", who=user.id, outcome="no second factor")
                raise HTTPException(403, "a second factor is required")
            old = request.cookies.get(SESSION_COOKIE)
            if old:
                self.sessions.end(old)                       # SESSION-ROTATE: a new id at every sign-in
            sid = self.sessions.create(user, client=client_of(request), idp_sid=claims.get("sid"),
                                       ttl=float(self.values["session_max_hours"]) * 3600)
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

        @router.post("/backchannel-logout")
        async def backchannel(request: Request):
            """OpenID Connect Back-Channel Logout: the provider ends the product's sessions when the user signs out
            there (or an administrator ends them). The logout token is verified like any token, used once."""
            form = await request.form()
            token_ = form.get("logout_token", "")
            try:
                claims = await self.verify(str(token_), kind="logout")
            except HTTPException:
                log.security("oidc.backchannel", outcome="invalid token")
                return JSONResponse({"error": "invalid_request"}, status_code=400)
            events = claims.get("events")
            if not isinstance(events, dict) or BACKCHANNEL not in events or "nonce" in claims \
                    or not (claims.get("sid") or claims.get("sub")):
                return JSONResponse({"error": "invalid_request"}, status_code=400)
            jti = f"jti:{_h(str(claims['jti']))}"
            if self.sessions.store.get(jti) is not None:
                return JSONResponse({"error": "invalid_request"}, status_code=400)       # replayed
            self.sessions.store.set(jti, 1, 3600)
            ended = 0
            if claims.get("sid"):
                ended += self.sessions.end_provider_session(self.issuer, str(claims["sid"]))
            if claims.get("sub") and not claims.get("sid"):
                ended += self.sessions.end_user(f"{self.issuer}|{claims['sub']}")
            log.security("signout", who=f"{self.issuer}|{claims.get('sub', '?')}", outcome=f"backchannel:{ended}")
            return JSONResponse({}, headers={"cache-control": "no-store"})

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
        rec = self.sessions.get(sid, *self._limits(), client=client_of(request)) if sid else None
        if rec is None:
            raise HTTPException(401, "sign in")
        return rec["user"]

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
            claims = await self.verify(auth[7:].strip(), audience=audience, kind="access")
            return self._user(claims)
        return check
