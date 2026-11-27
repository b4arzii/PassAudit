"""FastAPI application factory.

``create_app`` assembles the local-only PassAudit API:

* routes (``passaudit.api.v1``) - thin wrappers around :mod:`passaudit.analysis`;
* a uniform error format (``passaudit.api.errors``);
* a middleware stack that enforces privacy and resource rules (``passaudit.api.middleware``).

Middleware order, outermost first::

    RequestContext -> CORS -> HostGuard -> RateLimit -> RequestGuard -> router

``RequestContext`` is outermost so *every* response - including CORS, host, rate-limit and
body-size rejections - gets a request id and the security headers. CORS sits above the
rejecting layers so browsers can read their error responses.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from passaudit import __version__
from passaudit.api import v1
from passaudit.api.errors import install_exception_handlers
from passaudit.api.middleware import (
    EXPOSED_HEADERS,
    SECURITY_HEADERS,
    HostGuardMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
    RequestGuardMiddleware,
    access_log,
)
from passaudit.api.ratelimit import TokenBucketLimiter
from passaudit.api.service import AnalysisService
from passaudit.config import Settings, get_settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

API_PREFIX = "/api/v1"
BATCH_PATH = f"{API_PREFIX}/audit/batch"
REPORT_PATH = f"{API_PREFIX}/audit/report"
RATE_LIMIT_EXEMPT = frozenset({f"{API_PREFIX}/health", "/docs", "/openapi.json"})

DESCRIPTION = """
Local-only password auditing API. **Do not expose it publicly** - it has no authentication.

### Privacy
* Passwords travel **only in JSON request bodies** (`POST`). Query parameters are rejected.
* Passwords are analysed in memory and are never stored, logged, cached or returned.
  Results contain positions, scores and fixed-text advice only.
* Error responses never echo request content; validation errors give the *location* of a
  problem, not the rejected value.
* Request bodies are size-limited, and requests are rate-limited per client.
* **External lookups are opt-in twice**: the operator must enable them in the server settings
  *and* a request must ask for one. Only a 5-character hash prefix is ever sent; never a
  password or a full hash.

### Errors
Every error has the shape `{"error": {"code", "message", "request_id", "details?"}}`.
Quote `request_id` (also in the `X-Request-ID` header) when reporting a problem.
"""


def configure_access_logging(level: str) -> None:
    """Silence uvicorn's access log (it records query strings) and use ours (it does not)."""
    logging.getLogger("uvicorn.access").disabled = True
    if not access_log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        access_log.addHandler(handler)
        access_log.propagate = False
    access_log.setLevel(level.upper())


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. Accepts explicit settings to keep tests hermetic."""
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        configure_access_logging(settings.log_level)
        yield

    app = FastAPI(
        title="PassAudit API",
        version=__version__,
        description=DESCRIPTION,
        openapi_tags=v1.TAGS_METADATA,
        servers=[{"url": f"http://127.0.0.1:{settings.port}", "description": "Local only"}],
        lifespan=lifespan,
        # Interactive docs are a development convenience only.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    app.state.settings = settings
    app.state.service = AnalysisService(settings)
    app.state.rate_limiter = (
        TokenBucketLimiter(
            capacity=settings.rate_limit_burst,
            refill_per_second=settings.rate_limit_per_minute / 60,
        )
        if settings.rate_limit_enabled
        else None
    )

    install_exception_handlers(app)
    app.include_router(v1.router, prefix=API_PREFIX)
    # Not ``app.routes``: recent FastAPI wraps included routers, hiding their paths there.
    known_paths = {
        f"{API_PREFIX}{route.path}" for route in v1.router.routes if hasattr(route, "path")
    }
    known_paths |= {"/docs", "/openapi.json"}

    # ``add_middleware`` makes the last-added the outermost layer.
    app.add_middleware(
        RequestGuardMiddleware,
        default_limit=settings.max_body_bytes,
        path_limits={
            BATCH_PATH: settings.batch_max_body_bytes,
            REPORT_PATH: settings.batch_max_body_bytes,
        },
    )
    if app.state.rate_limiter is not None:
        app.add_middleware(
            RateLimitMiddleware, limiter=app.state.rate_limiter, exempt_paths=RATE_LIMIT_EXEMPT
        )
    app.add_middleware(HostGuardMiddleware, allowed_hosts=settings.effective_allowed_hosts)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        expose_headers=EXPOSED_HEADERS,
        allow_credentials=False,
        max_age=600,
    )
    app.add_middleware(RequestContextMiddleware, known_paths=known_paths)
    return app


app = create_app()

__all__ = ["SECURITY_HEADERS", "app", "create_app"]
