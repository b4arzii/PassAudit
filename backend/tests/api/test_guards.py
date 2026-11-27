"""Request guard (size/type/query), Host guard, error envelope, CORS, unexpected failures."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from passaudit.api.service import AnalysisService
from passaudit.main import SECURITY_HEADERS

from .conftest import CANARY, JSON, MakeApp, MakeClient, asgi_call

AUDIT = "/api/v1/audit"
BATCH = "/api/v1/audit/batch"
HEX32 = re.compile(r"^[0-9a-f]{32}$")


def _error(response: object) -> dict[str, object]:
    body = response.json()  # type: ignore[attr-defined]
    assert set(body) == {"error"}
    error = body["error"]
    assert {"code", "message", "request_id"} <= set(error)
    assert error["request_id"] == response.headers["x-request-id"]  # type: ignore[attr-defined]
    return error  # type: ignore[no-any-return]


def _body_of_size(size: int) -> str:
    """A valid audit request whose JSON text is exactly ``size`` bytes."""
    base = json.dumps({"password": CANARY})
    assert len(base) <= size
    return base[:-1] + " " * (size - len(base)) + "}"


# ------------------------------------------------------------------------ request guard


def test_query_string_is_refused_on_post_and_not_echoed(client: TestClient) -> None:
    response = client.post(f"{AUDIT}?password={CANARY}", json={"password": "x"})
    assert response.status_code == 400
    assert _error(response)["code"] == "query_string_not_allowed"
    assert CANARY not in response.text


def test_query_string_is_refused_on_every_post_route(client: TestClient) -> None:
    for path in (AUDIT, BATCH, "/api/v1/policy/validate"):
        assert client.post(f"{path}?x=1", json={}).status_code == 400


def test_query_string_is_fine_on_get(client: TestClient) -> None:
    assert client.get("/api/v1/health?probe=1").status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/plain"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"Content-Type": "multipart/form-data; boundary=x"},
        {"Content-Type": "application/jsonx"},
        {"Content-Type": "application/json5"},
        {},
    ],
)
def test_non_json_content_type_is_415(client: TestClient, headers: dict[str, str]) -> None:
    response = client.post(AUDIT, content=f"password={CANARY}", headers=headers)
    assert response.status_code == 415
    assert _error(response)["code"] == "unsupported_media_type"
    assert CANARY not in response.text


@pytest.mark.parametrize(("extra", "status"), [(0, 200), (1, 413)])
def test_body_size_boundary_via_content_length(
    make_client: MakeClient, extra: int, status: int
) -> None:
    client = make_client(max_body_bytes=1024)
    response = client.post(AUDIT, content=_body_of_size(1024 + extra), headers=JSON)
    assert response.status_code == status
    if status == 413:
        error = _error(response)
        assert error["code"] == "payload_too_large"
        assert "1024-byte limit" in str(error["message"])


def test_oversized_body_is_rejected_without_being_parsed(make_client: MakeClient) -> None:
    client = make_client(max_body_bytes=1024)
    response = client.post(AUDIT, content=b"{" + b"x" * 5000, headers=JSON)  # not even valid JSON
    assert response.status_code == 413


def test_chunked_body_over_the_limit_is_cut_off_while_streaming(make_app: MakeApp) -> None:
    app = make_app(max_body_bytes=1024)
    chunks = [b'{"password": "' + b"a" * 600, b"a" * 600 + b'"}']  # no Content-Length at all
    status, headers, body = asgi_call(app, chunks=chunks)
    assert status == 413
    assert json.loads(body)["error"]["code"] == "payload_too_large"
    assert headers["x-request-id"]


def test_chunked_body_within_the_limit_is_accepted(make_app: MakeApp) -> None:
    app = make_app(max_body_bytes=1024)
    payload = json.dumps({"password": CANARY}).encode()
    status, _, body = asgi_call(app, chunks=[payload[:10], payload[10:]])
    assert status == 200
    assert json.loads(body)["length"] == len(CANARY)


def test_invalid_content_length_header_is_400(make_app: MakeApp) -> None:
    status, _, body = asgi_call(
        make_app(),
        headers=[("content-type", "application/json"), ("content-length", "12abc")],
    )
    assert status == 400
    assert json.loads(body)["error"]["code"] == "bad_request"


@pytest.mark.parametrize("value", ["\xb2", "\xb9", "\xb3", "1\xb2"])
def test_non_ascii_digits_in_content_length_are_400_not_a_crash(
    make_app: MakeApp, value: str
) -> None:
    """``str.isdigit`` is true for superscripts, which ``int`` then refuses to parse."""
    status, _, body = asgi_call(
        make_app(),
        headers=[("content-type", "application/json"), ("content-length", value)],
    )
    assert status == 400
    assert json.loads(body)["error"]["code"] == "bad_request"


def test_get_requests_skip_the_body_guard(make_app: MakeApp) -> None:
    status, _, _ = asgi_call(
        make_app(), method="GET", path="/api/v1/health", headers=None, chunks=()
    )
    assert status == 200


# --------------------------------------------------------------------------- host guard


def test_unknown_host_is_rejected_and_not_echoed(client: TestClient) -> None:
    response = client.get("/api/v1/health", headers={"Host": "evil.example"})
    assert response.status_code == 400
    assert _error(response)["code"] == "host_not_allowed"
    assert "evil.example" not in response.text


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "localhost:8000",
        "LOCALHOST:9999",
        "127.0.0.1",
        "127.0.0.1:8000",
        "[::1]:8000",
        "[::1]",
    ],
)
def test_loopback_hosts_are_allowed(make_app: MakeApp, host: str) -> None:
    app = make_app(env="production")  # no 'testserver' allowance here
    status, _, _ = asgi_call(
        app, method="GET", path="/api/v1/health", host=host, headers=None, chunks=()
    )
    assert status == 200, host


@pytest.mark.parametrize(
    "host",
    ["evil.example", "localhost.evil.example", "0.0.0.0", "10.0.0.5", ""],  # noqa: S104
)
def test_non_allow_listed_hosts_are_rejected(make_app: MakeApp, host: str) -> None:
    app = make_app(env="production")
    status, _, body = asgi_call(
        app, method="GET", path="/api/v1/health", host=host, headers=None, chunks=()
    )
    assert status == 400, host
    assert json.loads(body)["error"]["code"] == "host_not_allowed"


def test_missing_host_header_is_rejected(make_app: MakeApp) -> None:
    status, _, _ = asgi_call(
        make_app(), method="GET", path="/api/v1/health", host=None, headers=None, chunks=()
    )
    assert status == 400


def test_custom_allowed_hosts(make_app: MakeApp) -> None:
    app = make_app(env="production", allowed_hosts=["audit.local"])
    ok, _, _ = asgi_call(
        app, method="GET", path="/api/v1/health", host="audit.local:8000", headers=None, chunks=()
    )
    no, _, _ = asgi_call(
        app, method="GET", path="/api/v1/health", host="localhost", headers=None, chunks=()
    )
    assert (ok, no) == (200, 400)


def test_testserver_is_only_allowed_in_the_test_environment(make_app: MakeApp) -> None:
    prod = make_app(env="production")
    status, _, _ = asgi_call(
        prod, method="GET", path="/api/v1/health", host="testserver", headers=None, chunks=()
    )
    assert status == 400


# --------------------------------------------------------------------- error envelope


def test_validation_error_envelope(client: TestClient) -> None:
    response = client.post(AUDIT, json={"password": 5, "unknown_field": CANARY})
    assert response.status_code == 422
    error = _error(response)
    assert error["code"] == "validation_error"
    details = error["details"]
    assert {
        "loc": ["body", "password"],
        "type": "string_type",
        "message": "Input should be a valid string",
    } in details  # type: ignore[operator]
    assert any(d["type"] == "extra_forbidden" for d in details)  # type: ignore[union-attr]
    assert CANARY not in response.text


def test_validation_details_are_capped(client: TestClient) -> None:
    response = client.post(AUDIT, json={f"extra{i}": CANARY for i in range(60)})
    details = _error(response)["details"]
    assert len(details) == 20  # type: ignore[arg-type]


def test_validation_messages_from_the_engine_are_clean(client: TestClient) -> None:
    response = client.post(
        AUDIT, json={"password": CANARY, "policy": {"min_length": 50, "max_length": 5}}
    )
    message = json.dumps(_error(response)["details"])
    assert "max_length must be greater than or equal to min_length" in message
    assert "Value error" not in message


def test_invalid_json_is_a_validation_error_without_echo(client: TestClient) -> None:
    response = client.post(AUDIT, content=f'{{"password": "{CANARY}", oops', headers=JSON)
    assert response.status_code == 422
    assert _error(response)["code"] == "validation_error"
    assert CANARY not in response.text


@pytest.mark.parametrize("body", ["[]", "null", '"letmein"', "42", ""])
def test_non_object_bodies_are_rejected(client: TestClient, body: str) -> None:
    response = client.post(AUDIT, content=body, headers=JSON)
    assert response.status_code == 422
    assert "letmein" not in response.text


def test_personal_info_limits_are_validated(client: TestClient) -> None:
    ok = {"password": CANARY, "context": {"personal_info": ["abc"] * 50}}
    assert client.post(AUDIT, json=ok).status_code == 200
    too_many = {"password": CANARY, "context": {"personal_info": ["secret-name"] * 51}}
    response = client.post(AUDIT, json=too_many)
    assert response.status_code == 422
    assert "secret-name" not in response.text
    too_long = {"password": CANARY, "context": {"personal_info": ["secret-name" * 40]}}
    response = client.post(AUDIT, json=too_long)
    assert response.status_code == 422
    assert "secret-name" not in response.text


def test_unknown_path_is_a_json_404_that_does_not_echo_the_path(client: TestClient) -> None:
    response = client.get(f"/api/v1/{CANARY}")
    assert response.status_code == 404
    assert _error(response)["code"] == "not_found"
    assert CANARY not in response.text


def test_wrong_method_is_a_json_405_with_allow_header(client: TestClient) -> None:
    response = client.get(AUDIT)
    assert response.status_code == 405
    assert _error(response)["code"] == "method_not_allowed"
    assert "POST" in response.headers["allow"]
    assert client.delete(AUDIT).status_code == 405 or client.delete(AUDIT).status_code == 415


def test_every_error_has_a_unique_server_generated_request_id(client: TestClient) -> None:
    ids = {
        client.get("/api/v1/nope", headers={"X-Request-ID": "client-chosen"}).headers[
            "x-request-id"
        ],
        client.post(AUDIT, json={}).headers["x-request-id"],
        client.post(AUDIT, content="x").headers["x-request-id"],
        client.get("/api/v1/health").headers["x-request-id"],
    }
    assert len(ids) == 4
    assert all(HEX32.match(i) for i in ids)
    assert "client-chosen" not in ids


@pytest.mark.parametrize(
    "send",
    [
        lambda c: c.get("/api/v1/health"),
        lambda c: c.post(AUDIT, json={"password": CANARY}),
        lambda c: c.post(AUDIT, json={}),
        lambda c: c.get("/api/v1/missing"),
        lambda c: c.post(AUDIT, content="x"),
        lambda c: c.post(f"{AUDIT}?q=1", json={}),
        lambda c: c.get("/api/v1/health", headers={"Host": "evil.example"}),
    ],
    ids=["200", "audit", "422", "404", "415", "400-query", "400-host"],
)
def test_security_headers_on_every_response_including_errors(client: TestClient, send) -> None:  # type: ignore[no-untyped-def]
    response = send(client)
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert "set-cookie" not in response.headers
    assert response.headers["content-type"].startswith("application/json")


def test_responses_are_never_cached(client: TestClient) -> None:
    assert client.post(AUDIT, json={"password": CANARY}).headers["cache-control"] == "no-store"


# --------------------------------------------------------------- unexpected failures


def test_unexpected_exception_is_a_generic_500(
    make_app: MakeApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(self: AnalysisService, request: object) -> None:
        raise RuntimeError(f"internal failure while handling {CANARY}")

    monkeypatch.setattr(AnalysisService, "audit", boom)
    client = TestClient(make_app())
    response = client.post(AUDIT, json={"password": CANARY})
    assert response.status_code == 500
    error = _error(response)
    assert error["code"] == "internal_error"
    assert CANARY not in response.text
    assert "RuntimeError" not in response.text
    assert "Traceback" not in response.text
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_the_server_keeps_working_after_an_unexpected_exception(
    make_app: MakeApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = AnalysisService.audit
    calls = {"n": 0}

    async def flaky(self: AnalysisService, request):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("first call fails")
        return await original(self, request)

    monkeypatch.setattr(AnalysisService, "audit", flaky)
    client = TestClient(make_app())
    assert client.post(AUDIT, json={"password": CANARY}).status_code == 500
    assert client.post(AUDIT, json={"password": CANARY}).status_code == 200


# ----------------------------------------------------------------------------- CORS


ORIGIN = "http://localhost:5173"


def test_cors_allows_the_configured_origin_without_credentials(client: TestClient) -> None:
    response = client.post(AUDIT, json={"password": CANARY}, headers={"Origin": ORIGIN})
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert "access-control-allow-credentials" not in response.headers
    exposed = response.headers["access-control-expose-headers"].lower()
    assert "x-request-id" in exposed
    assert "retry-after" in exposed


def test_cors_rejects_other_origins(client: TestClient) -> None:
    for origin in (
        "http://evil.example",
        "http://localhost:5174",
        "https://localhost:5173",
        "null",
    ):
        response = client.post(AUDIT, json={"password": CANARY}, headers={"Origin": origin})
        assert "access-control-allow-origin" not in response.headers, origin


def test_cors_preflight(client: TestClient) -> None:
    response = client.options(
        AUDIT,
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "DELETE" not in response.headers["access-control-allow-methods"]
    assert "content-type" in response.headers["access-control-allow-headers"].lower()
    assert response.headers["access-control-max-age"] == "600"


def test_cors_preflight_for_disallowed_origin_or_header_is_refused(client: TestClient) -> None:
    bad_origin = client.options(
        AUDIT, headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"}
    )
    assert bad_origin.status_code == 400
    bad_header = client.options(
        AUDIT,
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert bad_header.status_code == 400


@pytest.mark.parametrize(
    ("send", "status"),
    [
        (lambda c, h: c.post(AUDIT, json={}, headers=h), 422),
        (lambda c, h: c.post(AUDIT, content="x", headers=h), 415),
        (lambda c, h: c.post(f"{AUDIT}?q=1", json={}, headers=h), 400),
        (lambda c, h: c.get("/api/v1/missing", headers=h), 404),
    ],
)
def test_browsers_can_read_error_responses(client: TestClient, send, status: int) -> None:  # type: ignore[no-untyped-def]
    response = send(client, {"Origin": ORIGIN})
    assert response.status_code == status
    assert response.headers["access-control-allow-origin"] == ORIGIN


def test_cors_origins_come_from_settings(make_client: MakeClient) -> None:
    client = make_client(cors_origins=["http://127.0.0.1:3000"])
    ok = client.get("/api/v1/health", headers={"Origin": "http://127.0.0.1:3000"})
    no = client.get("/api/v1/health", headers={"Origin": ORIGIN})
    assert ok.headers["access-control-allow-origin"] == "http://127.0.0.1:3000"
    assert "access-control-allow-origin" not in no.headers


def _drain(iterator: Iterator[bytes]) -> bytes:
    return b"".join(iterator)


def test_unknown_field_names_are_not_echoed(client: TestClient) -> None:
    """A secret used as a JSON *key* by mistake must not come back in the error."""
    response = client.post(AUDIT, json={"password": CANARY, "hunter2-secret": CANARY})
    assert response.status_code == 422
    details = _error(response)["details"]
    assert {
        "loc": ["body", "<unknown field>"],
        "type": "extra_forbidden",
        "message": "Extra inputs are not permitted",
    } in details  # type: ignore[operator]
    assert "hunter2-secret" not in response.text
    nested = client.post(AUDIT, json={"password": CANARY, "policy": {"min_lenght": 5}})
    assert nested.json()["error"]["details"][0]["loc"] == ["body", "policy", "<unknown field>"]
