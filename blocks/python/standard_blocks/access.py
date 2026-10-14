"""Who may call which route (AUTHZ, AUTH-CRITICAL, AUTHZ-IMMEDIATE, FIELD-AUTHZ, LOG-SECURITY-EVENTS).

    @app.get("/orders/{oid}", dependencies=[Depends(access.allow("orders.read"))])

Every route names an id; @access maps ids to roles, read on every call. A route missing from @access is admin-only;
a route in @public ("METHOD /path") needs no sign-in; every other route needs one (@critical = '*').

Beyond the checklists:
    - a route that names no id cannot ship: at start-up `bind` walks every route, and in production a route without
      an id (outside @public, /health and the sign-in routes) stops the app; elsewhere it is logged;
    - finer rules (owner, tenant, time, amount) are added with `also=`: predicates that can only refuse, run after
      the matrix allowed the role; a predicate that raises refuses;
    - every refusal is the same 403 whatever the reason, so a caller cannot map what exists.
"""
from __future__ import annotations

import asyncio
import os

from fastapi import HTTPException, Request

from . import Values
from . import log

ADMIN = "admin"
MARK = "__standard_access__"


class Access:
    def __init__(self, current_user, values: Values | None = None):
        """current_user: the session block's dependency (Oidc.current_user) or any async request -> User."""
        self.current_user, self.values = current_user, values or Values.from_env()

    def bind(self, app):
        """Let Standard's access probe find this matrix on the app, and refuse to start with an unnamed route.
        Returns self."""
        app.state.standard_access = self

        async def every_route_is_named():
            missing = unnamed(app, self.values)
            for key in missing:
                log.security("access.unnamed", route=key)
            if missing and os.environ.get("STANDARD_ENV") == "production":
                raise RuntimeError(f"routes without an access id: {', '.join(missing[:5])}")
        app.router.on_startup.append(every_route_is_named)
        return self

    def _public(self, request: Request) -> bool:
        route = request.scope.get("route")
        template = getattr(route, "path", request.url.path)
        return f"{request.method.upper()} {template}" in self.values["public"]

    def allow(self, route_id: str, *, also=()):
        """A dependency: the caller's role is allowed for `route_id`, then every `also(user, request)` agrees."""
        values = self.values
        also = tuple(also) if isinstance(also, (list, tuple)) else (also,)

        async def check(request: Request):
            if self._public(request):
                return None
            try:
                user = await self.current_user(request)
            except HTTPException:
                log.security("access.unauthenticated", route=route_id)
                raise
            roles = values["access"].get(route_id)
            allowed = [ADMIN] if roles is None else list(roles) if isinstance(roles, list) else [str(roles)]
            if "*" in allowed or set(allowed) & set(user.roles):
                for predicate in also:
                    try:
                        ok = predicate(user, request)
                        if asyncio.iscoroutine(ok):
                            ok = await ok
                    except Exception:
                        ok = False                              # a predicate that breaks refuses
                    if ok is not True:
                        log.security("access.refused", who=user.id, route=route_id, outcome="predicate")
                        raise HTTPException(403, "not allowed")
                return user
            log.security("access.refused", who=user.id, route=route_id)
            raise HTTPException(403, "not allowed")
        setattr(check, MARK, route_id)
        return check


def route_ids(app) -> dict:
    """'METHOD /path' -> the access id its dependencies declare, or None: what the access probe walks."""
    out = {}
    for route in getattr(app, "routes", []):
        methods = getattr(route, "methods", None)
        if not methods:
            continue
        dependant = getattr(route, "dependant", None)
        ids = []
        stack = list(getattr(dependant, "dependencies", []) or [])
        while stack:
            d = stack.pop()
            fid = getattr(d.call, MARK, None)
            if fid:
                ids.append(fid)
            stack += list(getattr(d, "dependencies", []) or [])
        for m in sorted(methods - {"HEAD", "OPTIONS"}):
            out[f"{m} {route.path}"] = ids[0] if ids else None
    return out


def unnamed(app, values) -> list:
    """'METHOD /path' of routes that name no access id and are not public, /health or sign-in."""
    public = set(values["public"])
    return [key for key, rid in sorted(route_ids(app).items()) if rid is None and key not in public
            and not key.split(" ", 1)[1].startswith(("/auth/", "/health", "/.well-known/"))]


def visible(model_by_role: dict, user, default):
    """FIELD-AUTHZ: the response model for the user's highest listed role, else `default` (the narrowest)."""
    for role, model in model_by_role.items():
        if user is not None and role in user.roles:
            return model
    return default
