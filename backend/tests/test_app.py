"""Smoke tests for the Phase 1 application skeleton."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from passaudit import __version__
from passaudit.config import Settings
from passaudit.main import SECURITY_HEADERS, create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(Settings(env="test")))


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_security_headers_are_applied(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_cors_rejects_unlisted_origin(client: TestClient) -> None:
    response = client.get("/api/v1/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers


def test_cors_allows_configured_origin(client: TestClient) -> None:
    response = client.get("/api/v1/health", headers={"Origin": "http://localhost:5173"})
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_docs_disabled_in_production() -> None:
    prod = TestClient(create_app(Settings(env="production")), base_url="http://localhost")
    assert prod.get("/docs").status_code == 404
    assert prod.get("/openapi.json").status_code == 404


def test_default_settings_are_conservative() -> None:
    settings = Settings(_env_file=None)
    assert settings.host == "127.0.0.1"
    assert settings.external_lookups_enabled is False


def test_invalid_port_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(port=70000)
