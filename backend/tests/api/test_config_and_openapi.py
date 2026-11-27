"""Settings validators (local-only enforcement) and the OpenAPI document."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from passaudit import __version__
from passaudit.config import Settings, is_loopback_host

from .conftest import MakeApp, make_settings

# ----------------------------------------------------------------- local-only enforcement


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", "127.0.0.5", "127.255.255.254"]
)
def test_loopback_hosts_are_accepted(host: str) -> None:
    assert is_loopback_host(host)
    assert Settings(_env_file=None, host=host).host == host  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "::", "192.168.1.10", "10.0.0.1", "8.8.8.8", "example.com", "", "128.0.0.1"],  # noqa: S104
)
def test_non_loopback_hosts_are_refused(host: str) -> None:
    assert not is_loopback_host(host)
    with pytest.raises(ValidationError, match="loopback"):
        Settings(_env_file=None, host=host)  # type: ignore[call-arg]


def test_non_loopback_bind_needs_an_explicit_opt_in() -> None:
    settings = Settings(_env_file=None, host="0.0.0.0", allow_non_loopback_bind=True)  # type: ignore[call-arg]  # noqa: S104
    assert settings.allow_non_loopback_bind is True
    assert Settings(_env_file=None).allow_non_loopback_bind is False  # type: ignore[call-arg]


def test_defaults_are_local_and_conservative() -> None:
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.host == "127.0.0.1"
    assert s.allowed_hosts == ["localhost", "127.0.0.1", "[::1]"]
    assert s.cors_origins == ["http://localhost:5173"]
    assert s.rate_limit_enabled is True
    assert (s.max_body_bytes, s.batch_max_items, s.batch_max_body_bytes) == (65536, 50, 1048576)
    assert s.max_password_length == 1024


def test_host_can_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PASSAUDIT_HOST", "0.0.0.0")  # noqa: S104
    with pytest.raises(ValidationError, match="loopback"):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_empty_environment_values_mean_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Docker Compose / .env templates write ``NAME=`` for "unset"; it must not become ``.``."""
    for name in (
        "BREACH_LOCAL_FILE",
        "REUSE_INDEX_PATH",
        "REUSE_KEY_FILE",
        "REUSE_AUTHORIZATION_REFERENCE",
        "POLICY_PROFILES_PATH",
    ):
        monkeypatch.setenv(f"PASSAUDIT_{name}", "")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.breach_local_file is None
    assert s.reuse_index_path is None
    assert s.reuse_key_file is None
    assert s.reuse_authorization_reference is None
    assert s.policy_profiles_path is None


@pytest.mark.parametrize(
    "origin",
    ["*", "null", "http://localhost:5173/", "http://localhost:5173/app", "localhost:5173",
     "ftp://localhost", "http://", "", "http://*.example.com"],
)  # fmt: skip
def test_invalid_cors_origins_are_refused(origin: str) -> None:
    with pytest.raises(ValidationError, match="exact origins"):
        Settings(_env_file=None, cors_origins=[origin])  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "origin", ["http://localhost:5173", "https://app.example.com", "http://127.0.0.1:3000"]
)
def test_exact_cors_origins_are_accepted(origin: str) -> None:
    assert Settings(_env_file=None, cors_origins=[origin]).cors_origins == [origin]  # type: ignore[call-arg]


@pytest.mark.parametrize("hosts", [["*"], ["localhost:8000"], ["a/b"], [""], [], ["*.example.com"]])
def test_invalid_allowed_hosts_are_refused(hosts: list[str]) -> None:
    with pytest.raises(ValidationError, match="allowed_hosts"):
        Settings(_env_file=None, allowed_hosts=hosts)  # type: ignore[call-arg]


def test_allowed_hosts_are_normalised_and_accept_bracketed_ipv6() -> None:
    s = Settings(_env_file=None, allowed_hosts=["LocalHost", "[::1]"])  # type: ignore[call-arg]
    assert s.allowed_hosts == ["localhost", "[::1]"]


def test_testserver_host_is_only_added_for_the_test_environment() -> None:
    assert "testserver" in make_settings().effective_allowed_hosts
    assert "testserver" not in make_settings(env="production").effective_allowed_hosts
    assert "testserver" not in make_settings(env="development").effective_allowed_hosts


@pytest.mark.parametrize(
    "overrides",
    [
        {"rate_limit_burst": 5, "batch_max_items": 6},  # a full batch could never be afforded
        {"batch_max_body_bytes": 2048, "max_body_bytes": 4096},
        {"max_body_bytes": 100},
        {"batch_max_items": 0},
        {"batch_max_items": 1001},
        {"rate_limit_per_minute": 0},
        {"max_concurrent_analyses": 0},
        {"analysis_queue_timeout_seconds": 0},
        {"max_password_length": 7},
    ],
)
def test_inconsistent_limits_are_refused(overrides: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def test_burst_exactly_equal_to_batch_size_is_allowed() -> None:
    Settings(_env_file=None, rate_limit_burst=50, batch_max_items=50)  # type: ignore[call-arg]


# ----------------------------------------------------------------------------- OpenAPI


@pytest.fixture
def schema(client: TestClient) -> dict:  # type: ignore[type-arg]
    return client.get("/openapi.json").json()


def test_docs_are_available_in_development_only(make_app: MakeApp) -> None:
    dev = TestClient(make_app(env="development"), base_url="http://localhost")
    assert dev.get("/docs").status_code == 200
    assert dev.get("/openapi.json").status_code == 200
    prod = TestClient(make_app(env="production"), base_url="http://localhost")
    assert prod.get("/docs").status_code == 404
    assert prod.get("/openapi.json").status_code == 404
    assert prod.get("/redoc").status_code == 404


def test_schema_metadata(schema: dict) -> None:  # type: ignore[type-arg]
    assert schema["info"]["title"] == "PassAudit API"
    assert schema["info"]["version"] == __version__
    assert "Do not expose it publicly" in schema["info"]["description"]
    assert schema["servers"][0]["url"].startswith("http://127.0.0.1")
    assert {t["name"] for t in schema["tags"]} == {"audit", "policy", "meta"}


def test_all_endpoints_are_documented_under_v1(schema: dict) -> None:  # type: ignore[type-arg]
    operations = {
        (path, method): op["operationId"]
        for path, item in schema["paths"].items()
        for method, op in item.items()
    }
    assert operations == {
        ("/api/v1/health", "get"): "getHealth",
        ("/api/v1/limits", "get"): "getLimits",
        ("/api/v1/audit", "post"): "auditPassword",
        ("/api/v1/audit/batch", "post"): "auditBatch",
        ("/api/v1/policy/validate", "post"): "validatePolicy",
        ("/api/v1/policy/default", "get"): "getDefaultPolicy",
        ("/api/v1/capabilities", "get"): "getCapabilities",
        ("/api/v1/audit/report", "post"): "auditReport",
        ("/api/v1/policy/profiles", "get"): "listPolicyProfiles",
        ("/api/v1/policy/profiles/{name}", "get"): "getPolicyProfile",
    }
    assert len(set(operations.values())) == len(operations)


def test_every_operation_has_summary_description_and_tag(schema: dict) -> None:  # type: ignore[type-arg]
    for path, item in schema["paths"].items():
        for method, op in item.items():
            assert op["summary"], (path, method)
            assert op["tags"], (path, method)
            assert op["responses"]["200"], (path, method)


@pytest.mark.parametrize(
    "path", ["/api/v1/audit", "/api/v1/audit/batch", "/api/v1/policy/validate"]
)
def test_post_endpoints_document_the_error_responses(schema: dict, path: str) -> None:  # type: ignore[type-arg]
    responses = schema["paths"][path]["post"]["responses"]
    for status in ("400", "413", "415", "422", "429", "500", "503"):
        assert status in responses, (path, status)
        ref = responses[status]["content"]["application/json"]["schema"]["$ref"]
        assert ref.endswith("/ErrorResponse")
    assert "HTTPValidationError" not in str(responses["422"])


def test_error_schema_shape(schema: dict) -> None:  # type: ignore[type-arg]
    components = schema["components"]["schemas"]
    assert set(components["ErrorResponse"]["properties"]) == {"error"}
    assert set(components["ErrorBody"]["properties"]) == {
        "code",
        "message",
        "request_id",
        "details",
    }
    assert set(components["ErrorDetail"]["properties"]) == {"loc", "type", "message"}


def test_passwords_are_marked_write_only_in_the_schema(schema: dict) -> None:  # type: ignore[type-arg]
    components = schema["components"]["schemas"]
    for name in ("AuditRequest", "PolicyValidationRequest", "BatchItem"):
        prop = components[name]["properties"]["password"]
        assert prop["format"] == "password", name
        assert prop["writeOnly"] is True, name
    assert "password" not in components["PasswordAnalysis"]["properties"]


def test_request_examples_exist_and_are_fake(schema: dict) -> None:  # type: ignore[type-arg]
    components = schema["components"]["schemas"]
    for name in ("AuditRequest", "PolicyValidationRequest", "BatchAuditRequest"):
        assert components[name]["examples"], name
    assert "example-not-a-real-Passw0rd" in str(components["AuditRequest"]["examples"])


def test_request_models_forbid_extra_fields_in_the_schema(schema: dict) -> None:  # type: ignore[type-arg]
    components = schema["components"]["schemas"]
    for name in (
        "AuditRequest",
        "BatchAuditRequest",
        "BatchItem",
        "PasswordPolicy",
        "AnalysisContext",
    ):
        assert components[name]["additionalProperties"] is False, name


def test_batch_schema_documents_hard_cap_and_minimum(schema: dict) -> None:  # type: ignore[type-arg]
    items = schema["components"]["schemas"]["BatchAuditRequest"]["properties"]["items"]
    assert items["minItems"] == 1
    assert items["maxItems"] == 1000


def test_response_schemas_are_the_engine_models(schema: dict) -> None:  # type: ignore[type-arg]
    ok = schema["paths"]["/api/v1/audit"]["post"]["responses"]["200"]["content"]["application/json"]
    assert ok["schema"]["$ref"].endswith("/PasswordAnalysis")
