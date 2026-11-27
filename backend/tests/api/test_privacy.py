"""Request-body privacy: nothing sent to the API may leak into logs, output or responses."""

from __future__ import annotations

import json
import logging

import pytest
from fastapi.testclient import TestClient

from passaudit.api.service import AnalysisService
from passaudit.main import create_app

from .conftest import (
    CANARY,
    JSON,
    OTHER_STRONG,
    PERSONAL,
    MakeApp,
    MakeClient,
    asgi_call,
    make_settings,
)

AUDIT = "/api/v1/audit"
BATCH = "/api/v1/audit/batch"
POLICY = "/api/v1/policy/validate"
SECRETS = [CANARY, OTHER_STRONG, PERSONAL, "Quillfeather", "hunter2-secret", "letmein"]


def _traffic(client: TestClient) -> list:  # type: ignore[type-arg]
    """A mix of valid and invalid requests that all carry secrets in different places."""
    ctx = {"personal_info": [PERSONAL, "q@example.org"], "usage": "online_account"}
    return [
        client.post(AUDIT, json={"password": CANARY, "context": ctx}),
        client.post(AUDIT, json={"password": "letmein"}),
        client.post(POLICY, json={"password": CANARY, "policy": {"min_length": 99}}),
        client.post(BATCH, json={"items": [{"id": OTHER_STRONG, "password": OTHER_STRONG}]}),
        client.post(BATCH, json={"items": [{"id": "row", "password": "letmein"}] * 3}),
        # invalid requests that still carry secrets
        client.post(AUDIT, json={"password": 12345, "hunter2-secret": CANARY}),
        client.post(AUDIT, json={"password": CANARY, "policy": {"min_length": "hunter2-secret"}}),
        client.post(AUDIT, content=f'{{"password": "{CANARY}",', headers=JSON),
        client.post(AUDIT, content=f"password={CANARY}", headers={"Content-Type": "text/plain"}),
        client.post(f"{AUDIT}?password={CANARY}&token=hunter2-secret", json={"password": CANARY}),
        client.post(f"/api/v1/{CANARY}/hunter2-secret", json={"password": CANARY}),
        client.get(f"/api/v1/health?x={CANARY}"),
        client.get(f"/api/v1/{CANARY}"),
        client.post(
            AUDIT,
            json={"password": CANARY},
            headers={"X-Custom": CANARY, "Authorization": f"Bearer {CANARY}"},
        ),
    ]


def test_no_response_contains_any_secret(client: TestClient) -> None:
    for response in _traffic(client):
        blob = response.text + str(dict(response.headers))
        for secret in SECRETS:
            assert secret not in blob, (response.request.url.path, secret)


def test_no_fragment_of_a_password_appears_in_any_response(client: TestClient) -> None:
    for response in _traffic(client):
        for i in range(len(CANARY) - 5):
            assert CANARY[i : i + 6] not in response.text


def test_nothing_is_logged_that_contains_a_secret(
    make_app: MakeApp, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    with TestClient(make_app()) as client:  # run the lifespan (configures access logging)
        logging.getLogger("passaudit.access").addHandler(caplog.handler)  # propagate is off there
        _traffic(client)
    server = ("passaudit", "uvicorn", "fastapi", "starlette", "anyio")  # not the client's own logs
    server_records = [r for r in caplog.records if r.name.split(".")[0] in server]
    assert "passaudit.access" in {r.name for r in server_records}  # the access log was exercised
    text = "\n".join(f"{r.name} {r.getMessage()} {r.exc_text or ''}" for r in server_records)
    for secret in SECRETS:
        assert secret not in text, secret
    for i in range(len(CANARY) - 5):
        assert CANARY[i : i + 6] not in text


def test_nothing_is_printed(client: TestClient, capsys: pytest.CaptureFixture[str]) -> None:
    _traffic(client)
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == ""


def test_access_log_records_route_status_and_request_id_only(
    make_app: MakeApp, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="passaudit.access")
    with TestClient(make_app()) as client:
        logging.getLogger("passaudit.access").addHandler(caplog.handler)
        ok = client.post(AUDIT, json={"password": CANARY}, headers={"Origin": "http://x"})
        client.post(f"{AUDIT}?token=hunter2-secret", json={})
        client.get(f"/api/v1/{CANARY}")
    lines = [r.getMessage() for r in caplog.records if r.name == "passaudit.access"]
    assert "POST /api/v1/audit -> 200" in lines[0]
    assert f"rid={ok.headers['x-request-id']}" in lines[0]
    assert lines[1].startswith("POST /api/v1/audit -> 400")  # query string not logged
    assert lines[2].startswith("GET [unmatched] -> 404")  # unknown path not logged
    assert all("hunter2" not in line and "?" not in line for line in lines)
    assert all("ms)" in line for line in lines)


def test_unknown_http_methods_are_not_logged_verbatim(
    make_app: MakeApp, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="passaudit.access")
    asgi_call(make_app(), method="PASSWORD-hunter2", path="/api/v1/health", headers=None, chunks=())
    assert all("hunter2" not in r.getMessage() for r in caplog.records)
    assert any("[other]" in r.getMessage() for r in caplog.records)


def test_unexpected_exception_logs_only_the_class_name(
    make_app: MakeApp, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(self, request):  # type: ignore[no-untyped-def]
        raise RuntimeError(f"failed on {CANARY}")

    monkeypatch.setattr(AnalysisService, "audit", boom)
    caplog.set_level(logging.DEBUG)
    response = TestClient(make_app()).post(AUDIT, json={"password": CANARY})
    assert response.status_code == 500
    records = [r for r in caplog.records if r.name == "passaudit.api"]
    assert len(records) == 1
    message = records[0].getMessage()
    assert "RuntimeError" in message
    assert CANARY not in message
    assert records[0].exc_info is None  # no traceback attached


def test_lifespan_silences_uvicorns_query_string_access_log(make_app: MakeApp) -> None:
    uvicorn_access = logging.getLogger("uvicorn.access")
    assert uvicorn_access.disabled is False
    with TestClient(make_app()):
        assert uvicorn_access.disabled is True


def test_passwords_in_a_url_are_rejected_before_any_processing(
    make_app: MakeApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[bool] = []

    async def spy(self, request):  # type: ignore[no-untyped-def]
        called.append(True)

    monkeypatch.setattr(AnalysisService, "audit", spy)
    client = TestClient(make_app())
    assert client.post(f"{AUDIT}?password={CANARY}", json={"password": CANARY}).status_code == 400
    assert called == []


def test_get_endpoints_do_not_accept_secrets_in_any_meaningful_way(client: TestClient) -> None:
    # A query string on GET is ignored, never reflected.
    response = client.get(f"/api/v1/limits?password={CANARY}")
    assert response.status_code == 200
    assert CANARY not in response.text


def test_results_for_different_passwords_are_independent(client: TestClient) -> None:
    """No state leaks between requests: personal info from one is not applied to the next."""
    with_ctx = client.post(
        AUDIT,
        json={"password": f"{PERSONAL}-x9", "context": {"personal_info": [PERSONAL]}},
    ).json()
    without = client.post(AUDIT, json={"password": f"{PERSONAL}-x9"}).json()
    assert "personal_info" in {f["kind"] for f in with_ctx["findings"]}
    assert "personal_info" not in {f["kind"] for f in without["findings"]}
    assert with_ctx["strength"]["guesses_log10"] < without["strength"]["guesses_log10"]


def test_openapi_examples_contain_no_real_looking_secret(client: TestClient) -> None:
    text = json.dumps(client.get("/openapi.json").json())
    for secret in SECRETS:
        assert secret not in text


def test_create_app_does_not_reconfigure_logging_at_import_time() -> None:
    uvicorn_access = logging.getLogger("uvicorn.access")
    create_app(make_settings())
    assert uvicorn_access.disabled is False  # only the lifespan changes global logging


def test_make_client_fixture_works(make_client: MakeClient) -> None:
    assert make_client().get("/api/v1/health").status_code == 200
