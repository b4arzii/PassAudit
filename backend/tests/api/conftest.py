"""Shared fixtures for the API integration tests."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterator, Sequence
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from passaudit.config import Settings
from passaudit.main import create_app

# Random-looking, in no dictionary: if it appears in any response or log, a password leaked.
CANARY = "Zq7!xKp#9mWv$L2nRb"
OTHER_STRONG = "Qw8$yL3!pN6#zT1vHd"
PERSONAL = "Zebulon-Quillfeather"

JSON = {"Content-Type": "application/json"}

MakeApp = Callable[..., FastAPI]
MakeClient = Callable[..., TestClient]


def make_settings(**overrides: Any) -> Settings:
    """Hermetic settings: never reads a developer's .env."""
    return Settings(_env_file=None, **{"env": "test", **overrides})  # type: ignore[call-arg]


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """The app's lifespan reconfigures logging globally; undo that after every test."""
    yield
    access = logging.getLogger("passaudit.access")
    for handler in list(access.handlers):
        access.removeHandler(handler)
    access.propagate = True
    access.setLevel(logging.NOTSET)
    logging.getLogger("uvicorn.access").disabled = False


@pytest.fixture
def make_app() -> MakeApp:
    def _make(**overrides: Any) -> FastAPI:
        return create_app(make_settings(**overrides))

    return _make


@pytest.fixture
def make_client(make_app: MakeApp) -> MakeClient:
    def _make(**overrides: Any) -> TestClient:
        return TestClient(make_app(**overrides))

    return _make


@pytest.fixture
def client(make_client: MakeClient) -> TestClient:
    return make_client()


async def asgi_call_async(  # noqa: PLR0913 - a test helper with many optional knobs
    app: FastAPI,
    *,
    method: str = "POST",
    path: str = "/api/v1/audit",
    chunks: Sequence[bytes] = (b"{}",),
    headers: Sequence[tuple[str, str]] | None = (("content-type", "application/json"),),
    host: str | None = "localhost",
    query: bytes = b"",
    client_addr: tuple[str, int] | None = ("203.0.113.9", 4242),
) -> tuple[int, dict[str, str], bytes]:
    """Drive the app at ASGI level (chunked bodies, odd headers, chosen client address)."""
    # Header values are latin-1 on the wire (what ASGI servers hand to the app).
    raw_headers = [(k.lower().encode(), v.encode("latin-1")) for k, v in (headers or ())]
    if host is not None:
        raw_headers.append((b"host", host.encode()))
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "root_path": "",
        "headers": raw_headers,
        "client": client_addr,
        "server": ("localhost", 8000),
    }
    pending = list(chunks)
    status = 0
    response_headers: dict[str, str] = {}
    body = bytearray()

    async def receive() -> dict[str, Any]:
        if pending:
            chunk = pending.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
            for key, value in message["headers"]:
                response_headers[key.decode().lower()] = value.decode()
        elif message["type"] == "http.response.body":
            body.extend(message.get("body", b""))

    await app(scope, receive, send)  # type: ignore[arg-type]
    return status, response_headers, bytes(body)


def asgi_call(app: FastAPI, **kwargs: Any) -> tuple[int, dict[str, str], bytes]:
    """Synchronous wrapper: one request on its own event loop."""
    return asyncio.run(asgi_call_async(app, **kwargs))
