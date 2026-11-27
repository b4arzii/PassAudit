"""One error format for the whole API, built so it can never echo request content.

Every non-2xx response has this shape (the same whether it comes from a route, FastAPI's
validation, the router, or a middleware)::

    {"error": {"code": "validation_error", "message": "...", "request_id": "...",
               "details": [{"loc": ["body", "x"], "type": "...", "message": "..."}]}}

``details`` is present only for validation failures. It carries the *location* and a fixed
description of each problem - never the rejected value - because the rejected value may be a
password. Messages are fixed templates plus counts and limits.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import TYPE_CHECKING, Any, cast

from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException

if TYPE_CHECKING:
    from collections.abc import Mapping

    from fastapi import FastAPI, Request

MAX_ERROR_DETAILS = 20
UNKNOWN_FIELD = "<unknown field>"
_LOC_PART = re.compile(r"[^\w .:@-]")


class ErrorCode(StrEnum):
    """Stable, machine-readable error identifiers (part of the API contract)."""

    VALIDATION_ERROR = "validation_error"
    PASSWORD_TOO_LONG = "password_too_long"  # noqa: S105  # an error id  # nosec B105
    BATCH_TOO_LARGE = "batch_too_large"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    QUERY_NOT_ALLOWED = "query_string_not_allowed"
    HOST_NOT_ALLOWED = "host_not_allowed"
    RATE_LIMITED = "rate_limited"
    SERVER_BUSY = "server_busy"
    EXTERNAL_LOOKUPS_DISABLED = "external_lookups_disabled"
    FEATURE_UNAVAILABLE = "feature_unavailable"
    UNKNOWN_PROFILE = "unknown_profile"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    BAD_REQUEST = "bad_request"
    HTTP_ERROR = "http_error"
    INTERNAL_ERROR = "internal_error"


class ErrorDetail(BaseModel):
    model_config = ConfigDict(frozen=True)

    loc: list[str | int]
    type: str
    message: str


class ErrorBody(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    request_id: str | None = None
    details: list[ErrorDetail] | None = None


class ErrorResponse(BaseModel):
    """The body of every error response."""

    model_config = ConfigDict(frozen=True)

    error: ErrorBody


class ApiError(HTTPException):
    """An error with a stable ``code``. Subclasses ``HTTPException`` so FastAPI's body parsing
    lets it through instead of converting it to a generic 400."""

    def __init__(
        self,
        status_code: int,
        code: ErrorCode,
        message: str,
        *,
        details: list[ErrorDetail] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message, headers=dict(headers or {}))
        self.code = code
        self.message = message
        self.details = details


def error_response(  # noqa: PLR0913 - keyword-only response fields
    status_code: int,
    code: ErrorCode,
    message: str,
    *,
    request_id: str | None,
    details: list[ErrorDetail] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorBody(code=code.value, message=message, request_id=request_id, details=details)
    )
    return JSONResponse(
        body.model_dump(mode="json", exclude_none=True),
        status_code=status_code,
        headers=dict(headers or {}),
    )


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) else None


def _clean_loc(part: Any) -> str | int:
    """A location element, bounded and stripped of control characters (log/terminal safe)."""
    if isinstance(part, int):
        return part
    return _LOC_PART.sub("?", str(part))[:64]


def validation_details(exc: RequestValidationError) -> list[ErrorDetail]:
    """Location + type + message for each problem. The rejected input is never included."""
    details: list[ErrorDetail] = []
    for error in exc.errors()[:MAX_ERROR_DETAILS]:
        loc = [_clean_loc(part) for part in error.get("loc", ())]
        if error.get("type") == "extra_forbidden" and loc:
            # The unknown field's *name* is caller data - it could even be a password used as a
            # key by mistake - so it is not echoed. Compare against the OpenAPI schema.
            loc[-1] = UNKNOWN_FIELD
        details.append(
            ErrorDetail(
                loc=loc,
                type=str(error.get("type", "invalid")),
                message=str(error.get("msg", "Invalid value")).removeprefix("Value error, "),
            )
        )
    return details


_STATUS_CODES: dict[int, tuple[ErrorCode, str]] = {
    400: (ErrorCode.BAD_REQUEST, "The request could not be understood."),
    404: (ErrorCode.NOT_FOUND, "The requested resource does not exist."),
    405: (ErrorCode.METHOD_NOT_ALLOWED, "This method is not allowed for the resource."),
}


async def _api_error_handler(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(ApiError, exc)  # registered for ApiError only
    return error_response(
        exc.status_code,
        exc.code,
        exc.message,
        request_id=_request_id(request),
        details=exc.details,
        headers=exc.headers,
    )


async def _validation_handler(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(RequestValidationError, exc)  # registered for it only
    return error_response(
        422,
        ErrorCode.VALIDATION_ERROR,
        "The request body failed validation.",
        request_id=_request_id(request),
        details=validation_details(exc),
    )


async def _http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(StarletteHTTPException, exc)  # registered for it only
    code, message = _STATUS_CODES.get(
        exc.status_code, (ErrorCode.HTTP_ERROR, "The request could not be completed.")
    )
    # ``exc.detail`` is deliberately not echoed: framework messages can quote request content.
    allow = (exc.headers or {}).get("Allow")
    return error_response(
        exc.status_code,
        code,
        message,
        request_id=_request_id(request),
        headers={"Allow": allow} if allow else None,
    )


def install_exception_handlers(app: FastAPI) -> None:
    """Register the handlers. Unhandled exceptions are caught by ``RequestContextMiddleware``."""
    app.add_exception_handler(ApiError, _api_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)


# Reusable OpenAPI ``responses`` entries ---------------------------------------------------


def _doc(description: str) -> dict[str, Any]:
    return {"model": ErrorResponse, "description": description}


COMMON_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: _doc("Bad request: unsupported query string or Host header."),
    403: _doc("An opt-in external lookup was requested but is disabled on this server."),
    413: _doc("The request body exceeds the size limit for this endpoint."),
    415: _doc("The body must be sent as `application/json`."),
    422: _doc("The body failed validation, or a size limit was exceeded."),
    429: _doc("Rate limit exceeded; see the `Retry-After` header."),
    500: _doc("Unexpected server error; no details are returned."),
    503: _doc("The analysis queue is full; retry later."),
}
