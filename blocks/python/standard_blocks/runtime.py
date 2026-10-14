"""Running the product (RUN-PROBE, RUN-SHUTDOWN, RUN-CONFIG-ENV, RUN-BOUNDED, SECRETS-MGMT, NO-DEBUG, FAIL-SECURE,
DOS-HEAVY).

    settings = load(Settings)                 # fields from the environment, validated
    key = secret("billing-key")               # from the vault folder, by reference
    install(app, checks={"db": db_ok})        # GET /health, clean shutdown, debug refused in production
    q = bounded_queue()                       # never unbounded
"""
from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

from . import Values
from . import log

NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,99}")


class RuntimeRefused(RuntimeError):
    pass


def load(model):
    """A pydantic model filled from the environment: field `db_url` from DB_URL. Missing required fields refuse."""
    data = {}
    for name in model.model_fields:
        value = os.environ.get(name.upper())
        if value is not None:
            data[name] = value
    return model.model_validate(data)


def secret(name: str) -> str:
    """A secret from the vault folder (STANDARD_SECRETS_DIR, default /run/secrets): the environment only names it."""
    if not NAME.fullmatch(name):
        raise RuntimeRefused("a secret name is lower-case letters, digits, . _ -")
    root = Path(os.environ.get("STANDARD_SECRETS_DIR", "/run/secrets"))
    path = root / name
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        raise RuntimeRefused(f"secret {name} is not in the vault") from None


def bounded_queue(maxsize: int | None = None, values: Values | None = None) -> asyncio.Queue:
    limit = int((values or Values.from_env())["queue_max"])
    return asyncio.Queue(maxsize=min(maxsize or limit, limit))


def install(app, *, checks: dict | None = None, closers=()):
    """GET /health (every check must answer True within 2 s; 503 while stopping), refuse debug in production, run
    `closers` when the server shuts down (uvicorn and hypercorn do so on SIGTERM, after in-flight requests)."""
    from starlette.responses import JSONResponse
    if os.environ.get("STANDARD_ENV") == "production" and (getattr(app, "debug", False) or
                                                           os.environ.get("DEBUG", "").lower() in ("1", "true")):
        raise RuntimeRefused("debug is off in production")
    checks = dict(checks or {})
    state = {"stopping": False}

    @app.get("/health", include_in_schema=False)
    async def health():
        if state["stopping"]:
            return JSONResponse({"status": "stopping"}, status_code=503)
        results = {}
        for name, check in sorted(checks.items()):
            try:
                result = check()
                if asyncio.iscoroutine(result):
                    result = await asyncio.wait_for(result, 2)
                results[name] = "ok" if result else "down"
            except Exception:
                results[name] = "down"
        ok = all(v == "ok" for v in results.values())
        return JSONResponse({"status": "ok" if ok else "down", "checks": results}, status_code=200 if ok else 503)

    async def on_shutdown():
        state["stopping"] = True
        for close in closers:
            try:
                result = close()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                log.event("shutdown.error", kind=type(exc).__name__)
        log.event("shutdown.done")

    app.router.on_shutdown.append(on_shutdown)        # the ASGI server turns SIGTERM into a graceful shutdown
    return app
