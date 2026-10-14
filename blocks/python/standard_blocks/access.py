"""Who may call which route (AUTHZ, AUTH-CRITICAL, AUTHZ-IMMEDIATE, FIELD-AUTHZ, LOG-SECURITY-EVENTS).

    @app.get("/orders/{oid}", dependencies=[Depends(access.allow("orders.read"))])

Every route names an id; @access maps ids to roles, read on every call. A route missing from @access is admin-only;
a route in @public ("METHOD /path") needs no sign-in; every other route needs one (@critical = '*').
"""
from __future__ import annotations

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
        """Let Standard's access probe find this matrix on the app. Returns self."""
        app.state.standard_access = self
        return self

    def _public(self, request: Request) -> bool:
        route = request.scope.get("route")
        template = getattr(route, "path", request.url.path)
        return f"{request.method.upper()} {template}" in self.values["public"]

    def allow(self, route_id: str):
        values = self.values

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


def visible(model_by_role: dict, user, default):
    """FIELD-AUTHZ: the response model for the user's highest listed role, else `default` (the narrowest)."""
    for role, model in model_by_role.items():
        if user is not None and role in user.roles:
            return model
    return default
