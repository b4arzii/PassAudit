"""Defence-in-depth branches: failures that should never happen, handled safely anyway."""

from __future__ import annotations

import asyncio
import logging

import anyio
import pytest
from pydantic import SecretStr

from passaudit.analysis import AnalysisRequest, AnalyzerConfig, PasswordAnalyzer
from passaudit.api.errors import ApiError
from passaudit.api.middleware import RequestContextMiddleware
from passaudit.api.service import AnalysisService

from .conftest import CANARY, make_settings


def test_engine_length_error_is_mapped_to_a_content_free_422() -> None:
    """If the engine's own limit trips, the client still gets a clean, password-free error."""
    strict = PasswordAnalyzer(AnalyzerConfig(max_input_length=10))
    service = AnalysisService(make_settings(max_password_length=1024), analyzer=strict)
    request = AnalysisRequest(password=SecretStr(CANARY))

    async def scenario() -> ApiError:
        service._check_length(request)  # the API-level limit (1024) lets it through...
        with pytest.raises(ApiError) as caught:  # ...the engine's (10) does not
            await service._run(strict.analyze, request)
        return caught.value

    error = anyio.run(scenario)
    assert error.status_code == 422
    assert error.code == "password_too_long"
    assert CANARY not in error.message


def test_failure_after_the_response_started_is_not_turned_into_a_second_response() -> None:
    sent: list[str] = []

    async def failing_app(scope, receive, send):  # type: ignore[no-untyped-def]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError("late failure")

    async def send(message):  # type: ignore[no-untyped-def]
        sent.append(message["type"])

    scope = {"type": "http", "method": "GET", "path": "/x", "headers": [], "query_string": b""}
    middleware = RequestContextMiddleware(failing_app, known_paths={"/x"})
    logging.getLogger("passaudit.api").disabled = True
    try:
        with pytest.raises(RuntimeError, match="late failure"):
            asyncio.run(middleware(scope, None, send))  # type: ignore[arg-type]
    finally:
        logging.getLogger("passaudit.api").disabled = False
    assert sent == ["http.response.start"]  # no extra response was attempted


def test_non_http_scopes_pass_through_untouched() -> None:
    seen: list[str] = []

    async def inner(scope, receive, send):  # type: ignore[no-untyped-def]
        seen.append(scope["type"])

    middleware = RequestContextMiddleware(inner, known_paths=set())
    asyncio.run(middleware({"type": "lifespan"}, None, None))  # type: ignore[arg-type]
    assert seen == ["lifespan"]
