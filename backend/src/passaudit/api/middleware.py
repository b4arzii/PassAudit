"""Pure-ASGI middleware: request context, Host guard, rate limit, request guard.

Order (outermost first), set up in ``passaudit.main.create_app``::

    RequestContext -> CORS -> HostGuard -> RateLimit -> RequestGuard -> router

They are pure ASGI (not ``BaseHTTPMiddleware``) so request bodies stream through untouched and
size limits can be enforced while the body is being received.

Privacy rules implemented here (docs/api.md, "Request-body privacy"):

* the body is never read, copied, stored or logged by any middleware;
* the access log records the method, a *known* route path, the status and the duration -
  never the query string, headers, body, or an unknown path (a password typed into a URL by
  mistake would otherwise be logged);
* unexpected exceptions are logged by class name only;
* query strings are refused on state-changing requests, and bodies must be JSON and bounded.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import TYPE_CHECKING

from starlette.datastructures import Headers, MutableHeaders

from passaudit.api.errors import ApiError, ErrorCode, error_response

if TYPE_CHECKING:
    from collections.abc import Collection, Mapping

    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from passaudit.api.ratelimit import RateLimiter

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}
# The interactive docs load external assets, so they are exempt from the strict CSP.
CSP_EXEMPT_PATHS = frozenset({"/docs", "/openapi.json"})
EXPOSED_HEADERS = [
    "X-Request-ID",
    "Retry-After",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
]
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
KNOWN_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

access_log = logging.getLogger("passaudit.access")
error_log = logging.getLogger("passaudit.api")


def _request_id(scope: Scope) -> str | None:
    value = scope.get("state", {}).get("request_id")
    return value if isinstance(value, str) else None


async def _send_error(  # noqa: PLR0913, PLR0917 - small internal helper
    scope: Scope,
    receive: Receive,
    send: Send,
    status: int,
    code: ErrorCode,
    message: str,
    headers: Mapping[str, str] | None = None,
) -> None:
    response = error_response(status, code, message, request_id=_request_id(scope), headers=headers)
    await response(scope, receive, send)


# ------------------------------------------------------------------ request context


class RequestContextMiddleware:
    """Outermost layer: request id, security headers, access log, last-resort 500."""

    def __init__(self, app: ASGIApp, *, known_paths: Collection[str]) -> None:
        self.app = app
        self.known_paths = frozenset(known_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex  # always server-generated: never trust client ids in logs
        scope.setdefault("state", {})["request_id"] = request_id
        path = scope.get("path", "")
        started = False
        status = 500
        began = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal started, status
            if message["type"] == "http.response.start":
                started = True
                status = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                for name, value in SECURITY_HEADERS.items():
                    if name == "Content-Security-Policy" and path in CSP_EXEMPT_PATHS:
                        continue
                    headers.setdefault(name, value)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            # Only the class name: the message or traceback could contain request content.
            error_log.error("unhandled %s rid=%s", type(exc).__name__, request_id)
            if started:
                raise
            await _send_error(
                scope,
                receive,
                send_wrapper,
                500,
                ErrorCode.INTERNAL_ERROR,
                "An unexpected error occurred. No details are returned.",
            )
        finally:
            method = scope.get("method", "")
            access_log.info(
                "%s %s -> %d (%.1f ms) rid=%s",
                method if method in KNOWN_METHODS else "[other]",
                path if path in self.known_paths else "[unmatched]",
                status,
                (time.perf_counter() - began) * 1000,
                request_id,
            )


# ----------------------------------------------------------------------- host guard


def host_without_port(value: str) -> str:
    """``localhost:8000`` -> ``localhost``; ``[::1]:8000`` -> ``[::1]``."""
    value = value.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[: end + 1] if end != -1 else value
    return value.rsplit(":", 1)[0] if ":" in value else value


class HostGuardMiddleware:
    """Reject requests whose ``Host`` header is not allow-listed (DNS-rebinding defence)."""

    def __init__(self, app: ASGIApp, *, allowed_hosts: Collection[str]) -> None:
        self.app = app
        self.allowed = frozenset(h.lower() for h in allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            host = Headers(scope=scope).get("host")
            if host is None or host_without_port(host) not in self.allowed:
                # The offending value is not echoed back.
                await _send_error(
                    scope,
                    receive,
                    send,
                    400,
                    ErrorCode.HOST_NOT_ALLOWED,
                    "The Host header is not allowed for this service.",
                )
                return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------- rate limiting


def client_key(scope: Scope) -> str:
    """The rate-limit key: the socket peer. ``X-Forwarded-For`` is deliberately ignored."""
    client = scope.get("client")
    return str(client[0]) if client else "unknown"


def rate_limit_headers(limit: int, remaining: int, reset_after: int) -> dict[str, str]:
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset_after),
    }


class RateLimitMiddleware:
    """Charge one cost unit per request before any body is read; routes add extra cost."""

    def __init__(
        self, app: ASGIApp, *, limiter: RateLimiter, exempt_paths: Collection[str]
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.exempt = frozenset(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") == "OPTIONS"
            or scope["path"] in self.exempt
        ):
            await self.app(scope, receive, send)
            return
        key = client_key(scope)
        state = scope.setdefault("state", {})
        state["rate_limit_key"] = key
        decision = await self.limiter.acquire(key, 1)
        state["rate_limit_decision"] = decision  # routes that charge more update this
        headers = rate_limit_headers(decision.limit, decision.remaining, decision.reset_after)
        if not decision.allowed:
            await _send_error(
                scope,
                receive,
                send,
                429,
                ErrorCode.RATE_LIMITED,
                f"Too many requests. Retry after {decision.retry_after} seconds.",
                {**headers, "Retry-After": str(decision.retry_after)},
            )
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                latest = state.get("rate_limit_decision", decision)
                out = MutableHeaders(scope=message)
                for name, value in rate_limit_headers(
                    latest.limit, latest.remaining, latest.reset_after
                ).items():
                    out.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_wrapper)


# -------------------------------------------------------------------- request guard


class RequestGuardMiddleware:
    """Privacy and resource rules for state-changing requests (see module docstring)."""

    def __init__(
        self, app: ASGIApp, *, default_limit: int, path_limits: Mapping[str, int] | None = None
    ) -> None:
        self.app = app
        self.default_limit = default_limit
        self.path_limits = dict(path_limits or {})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in STATE_CHANGING:
            await self.app(scope, receive, send)
            return

        limit = self.path_limits.get(scope["path"], self.default_limit)
        headers = Headers(scope=scope)

        if scope.get("query_string"):
            await _send_error(
                scope, receive, send, 400, ErrorCode.QUERY_NOT_ALLOWED,
                "Query parameters are not accepted; send data in the JSON request body.",
            )  # fmt: skip
            return
        content_type = headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            await _send_error(
                scope, receive, send, 415, ErrorCode.UNSUPPORTED_MEDIA_TYPE,
                "The request body must be sent with Content-Type: application/json.",
            )  # fmt: skip
            return
        declared = headers.get("content-length")
        if declared is not None:
            # ``str.isdigit`` accepts superscripts (``\xb2``), which ``int`` then refuses.
            if not (declared.isascii() and declared.isdigit()):
                await _send_error(
                    scope, receive, send, 400, ErrorCode.BAD_REQUEST,
                    "The Content-Length header is not valid.",
                )  # fmt: skip
                return
            if int(declared) > limit:
                await _send_error(
                    scope, receive, send, 413, ErrorCode.PAYLOAD_TOO_LARGE, _too_large(limit)
                )
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # ApiError passes through FastAPI's body parsing (it is an HTTPException).
                    raise ApiError(413, ErrorCode.PAYLOAD_TOO_LARGE, _too_large(limit))
            return message

        await self.app(scope, limited_receive, send)


def _too_large(limit: int) -> str:
    return f"The request body exceeds the {limit}-byte limit for this endpoint."


__all__ = [
    "SECURITY_HEADERS",
    "HostGuardMiddleware",
    "RateLimitMiddleware",
    "RequestContextMiddleware",
    "RequestGuardMiddleware",
    "client_key",
    "rate_limit_headers",
]
