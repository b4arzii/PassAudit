"""The five functional endpoints: health/meta, audit, policy validation, batch."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from passaudit import __version__
from passaudit.analysis import (
    AnalysisContext,
    PasswordAnalysis,
    PasswordPolicy,
    PasswordUsage,
    analyze_password,
)

from .conftest import CANARY, JSON, OTHER_STRONG, PERSONAL, MakeClient

AUDIT = "/api/v1/audit"
BATCH = "/api/v1/audit/batch"
POLICY = "/api/v1/policy/validate"


# ------------------------------------------------------------------------- health / meta


def test_health(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_limits_reflect_settings(make_client: MakeClient) -> None:
    client = make_client(
        max_password_length=64,
        max_body_bytes=2048,
        batch_max_items=7,
        batch_max_body_bytes=4096,
        rate_limit_burst=20,
        rate_limit_per_minute=120,
    )
    data = client.get("/api/v1/limits").json()
    assert data["max_password_length"] == 64
    assert data["max_body_bytes"] == 2048
    assert data["batch_max_items"] == 7
    assert data["batch_max_body_bytes"] == 4096
    assert data["max_personal_info_items"] == 50
    assert data["max_personal_info_item_length"] == 256
    assert data["rate_limit"] == {
        "enabled": True,
        "burst": 20,
        "refill_per_minute": 120,
        "cost_per_password": 1,
    }


def test_default_policy_endpoint(client: TestClient) -> None:
    response = client.get("/api/v1/policy/default")
    assert response.status_code == 200
    assert response.json() == PasswordPolicy().model_dump(mode="json")


def test_default_policy_is_a_valid_request_policy(client: TestClient) -> None:
    template = client.get("/api/v1/policy/default").json()
    response = client.post(AUDIT, json={"password": CANARY, "policy": template})
    assert response.status_code == 200
    assert response.json()["policy"]["compliant"] is True


# --------------------------------------------------------------------------------- audit


def test_audit_strong_password(client: TestClient) -> None:
    response = client.post(AUDIT, json={"password": CANARY})
    assert response.status_code == 200
    data = response.json()
    assert data["risk"]["score"] == 0
    assert data["risk"]["level"] == "low"
    assert data["length"] == len(CANARY)
    assert data["policy"]["compliant"] is True
    assert data["recommendations"][0]["code"] == "looks_good"


def test_audit_weak_password(client: TestClient) -> None:
    data = client.post(AUDIT, json={"password": "letmein"}).json()
    assert data["risk"]["level"] == "critical"
    assert data["findings"][0]["kind"] == "common_password"
    assert data["policy"]["compliant"] is False
    assert {"start": 0, "length": 7}.items() <= data["findings"][0].items()


def test_audit_result_is_exactly_the_engine_result(client: TestClient) -> None:
    """The API adds no analysis logic: its output is the engine's output."""
    for password in ("letmein", "Summer2024!", CANARY, "aaaa-qwerty-1234", ""):
        body = client.post(AUDIT, json={"password": password}).json()
        assert PasswordAnalysis.model_validate(body) == analyze_password(password), password


def test_audit_policy_and_context_are_passed_through(client: TestClient) -> None:
    payload = {
        "password": f"{PERSONAL}-{CANARY}",
        "policy": {"min_length": 60, "min_digits": 1, "forbid_personal_info": True},
        "context": {
            "usage": "encryption_key",
            "personal_info": [PERSONAL, "someone@example.org"],
            "reused_elsewhere": True,
        },
    }
    data = client.post(AUDIT, json=payload).json()
    expected = analyze_password(
        f"{PERSONAL}-{CANARY}",
        policy=PasswordPolicy(min_length=60, min_digits=1),
        context=AnalysisContext(
            usage=PasswordUsage.ENCRYPTION_KEY,
            personal_info=(PERSONAL, "someone@example.org"),  # type: ignore[arg-type]
            reused_elsewhere=True,
        ),
    )
    assert PasswordAnalysis.model_validate(data) == expected
    assert "personal_info" in {f["kind"] for f in data["findings"]}
    assert "unique_per_service" in {r["code"] for r in data["recommendations"]}


def test_audit_unicode_and_empty_passwords(client: TestClient) -> None:
    assert client.post(AUDIT, json={"password": "пароль密码🔑"}).json()["length"] == 9
    empty = client.post(AUDIT, json={"password": ""}).json()
    assert empty["length"] == 0
    assert empty["risk"]["score"] == 100


@pytest.mark.parametrize(("length", "status"), [(19, 200), (20, 200), (21, 422)])
def test_audit_password_length_boundary(make_client: MakeClient, length: int, status: int) -> None:
    client = make_client(max_password_length=20)
    response = client.post(AUDIT, json={"password": "x" * length})
    assert response.status_code == status
    if status == 422:
        error = response.json()["error"]
        assert error["code"] == "password_too_long"
        assert "21 characters (maximum 20)" in error["message"]
        assert "x" * 5 not in response.text


def test_audit_accepts_json_content_type_variants(client: TestClient) -> None:
    for content_type in ("application/json", "application/json; charset=utf-8", "APPLICATION/JSON"):
        response = client.post(
            AUDIT, content=json.dumps({"password": CANARY}), headers={"Content-Type": content_type}
        )
        assert response.status_code == 200, content_type


# ------------------------------------------------------------------------------ policy


def test_policy_validation_pass(client: TestClient) -> None:
    data = client.post(POLICY, json={"password": CANARY}).json()
    assert data["compliant"] is True
    assert data["violations"] == []
    assert [r["rule"] for r in data["rules"]] == [
        "min_length",
        "block_common_passwords",
        "forbid_personal_info",
        "min_strength_score",
    ]
    assert {r["status"] for r in data["rules"]} == {"pass"}


def test_policy_validation_failures_are_explained(client: TestClient) -> None:
    payload = {"password": "letmein", "policy": {"min_digits": 2, "min_uppercase": 1}}
    data = client.post(POLICY, json=payload).json()
    assert data["compliant"] is False
    failed = {r["rule"]: r for r in data["rules"] if r["status"] == "fail"}
    assert failed["min_length"]["required"] == 12
    assert failed["min_length"]["actual"] == 7
    assert failed["min_digits"]["requirement"] == "At least 2 digits"
    assert failed["min_uppercase"]["requirement"] == "At least 1 uppercase letter"
    assert {v["rule"] for v in data["violations"]} == set(failed)
    assert "letmein" not in json.dumps(data)


@pytest.mark.parametrize(("length", "compliant"), [(11, False), (12, True), (13, True)])
def test_policy_min_length_boundary(client: TestClient, length: int, compliant: bool) -> None:
    password = CANARY[:length] if length <= len(CANARY) else CANARY + "x" * (length - len(CANARY))
    payload = {"password": password, "policy": {"min_strength_score": 0}}
    data = client.post(POLICY, json=payload).json()
    min_length = next(r for r in data["rules"] if r["rule"] == "min_length")
    assert (min_length["status"] == "pass") is compliant


def test_policy_only_enabled_rules_are_listed(client: TestClient) -> None:
    payload = {
        "password": CANARY,
        "policy": {
            "min_length": 0,
            "min_strength_score": 0,
            "block_common_passwords": False,
            "forbid_personal_info": False,
            "allow_whitespace": False,
            "max_keyboard_run": 4,
        },
    }
    data = client.post(POLICY, json=payload).json()
    assert [r["rule"] for r in data["rules"]] == ["max_keyboard_run", "forbid_whitespace"] or [
        r["rule"] for r in data["rules"]
    ] == ["forbid_whitespace", "max_keyboard_run"]


def test_policy_matches_the_engine(client: TestClient) -> None:
    policy = PasswordPolicy(min_length=20, min_symbols=4)
    analysis = analyze_password("Summer2024!", policy=policy)
    data = client.post(
        POLICY, json={"password": "Summer2024!", "policy": policy.model_dump(mode="json")}
    ).json()
    assert data["compliant"] == analysis.policy.compliant
    assert [v["rule"] for v in data["violations"]] == [
        v.rule.value for v in analysis.policy.violations
    ]


# ------------------------------------------------------------------------------- batch


def _batch(*items: tuple[str | None, str], **extra: object) -> dict[str, object]:
    return {"items": [{"id": i, "password": p} for i, p in items], **extra}


def test_batch_basic_and_order(client: TestClient) -> None:
    payload = _batch(("a", CANARY), ("b", "letmein"), ("c", OTHER_STRONG))
    response = client.post(BATCH, json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 3
    assert [r["id"] for r in data["results"]] == ["a", "b", "c"]
    assert [r["index"] for r in data["results"]] == [1, 2, 3]
    assert [r["risk_level"] for r in data["results"]] == ["low", "critical", "low"]
    assert [r["policy_compliant"] for r in data["results"]] == [True, False, True]
    assert all("analysis" not in r or r["analysis"] is None for r in data["results"])
    summary = data["summary"]
    assert summary["analyzed"] == 3
    assert summary["policy_compliant"] == 2
    assert summary["policy_violations"] == 1
    assert summary["risk_levels"] == {"low": 2, "moderate": 0, "high": 0, "critical": 1}
    assert summary["max_risk_score"] == 85
    assert summary["average_risk_score"] == pytest.approx(85 / 3, abs=0.1)
    assert summary["reused_in_batch"] == 0


def test_batch_detects_reuse_and_applies_it_to_the_analysis(client: TestClient) -> None:
    payload = _batch(("a", "letmein"), ("b", CANARY), ("c", "letmein"), detail="full")
    data = client.post(BATCH, json=payload).json()
    assert [r["reused_in_batch"] for r in data["results"]] == [True, False, True]
    assert data["summary"]["reused_in_batch"] == 2
    first = data["results"][0]["analysis"]
    codes = {r["code"] for r in first["recommendations"]}
    assert "unique_per_service" in codes
    assert "unique_per_service" not in {
        r["code"] for r in data["results"][1]["analysis"]["recommendations"]
    }


def test_batch_full_detail_equals_single_audits(client: TestClient) -> None:
    payload = _batch(("a", "Summer2024!"), ("b", CANARY), detail="full")
    results = client.post(BATCH, json=payload).json()["results"]
    for result, password in zip(results, ("Summer2024!", CANARY), strict=True):
        assert PasswordAnalysis.model_validate(result["analysis"]) == analyze_password(password)


def test_batch_summary_record_fields(client: TestClient) -> None:
    result = client.post(BATCH, json=_batch(("x", "letmein"))).json()["results"][0]
    assert set(result) == {
        "index", "id", "length", "reused_in_batch", "risk_score", "risk_level", "strength_score",
        "strength_label", "guesses_log10", "estimated_bits", "policy_compliant",
        "policy_violations", "findings", "recommendations", "analysis", "breach", "reuse_datasets",
    }  # fmt: skip
    assert result["findings"] == ["common_password"]
    assert "block_common_passwords" in result["policy_violations"]
    assert result["analysis"] is None


def test_batch_policy_and_context_apply_to_every_item(client: TestClient) -> None:
    payload = _batch(
        ("a", f"{PERSONAL}-{CANARY}"),
        ("b", OTHER_STRONG),
        policy={"min_length": 30},
        context={"personal_info": [PERSONAL], "usage": "online_account"},
    )
    results = client.post(BATCH, json=payload).json()["results"]
    assert "personal_info" in results[0]["findings"]
    assert "min_length" in results[1]["policy_violations"]
    assert "personal_info" not in results[1]["findings"]


@pytest.mark.parametrize(("count", "status"), [(1, 200), (3, 200), (4, 422)])
def test_batch_item_count_boundary(make_client: MakeClient, count: int, status: int) -> None:
    client = make_client(batch_max_items=3, rate_limit_burst=10)
    items = [(None, f"{OTHER_STRONG}{i}") for i in range(count)]
    response = client.post(BATCH, json=_batch(*items))
    assert response.status_code == status
    if status == 422:
        error = response.json()["error"]
        assert error["code"] == "batch_too_large"
        assert "at most 3" in error["message"]


def test_batch_default_limit_is_fifty(client: TestClient) -> None:
    ok = client.post(BATCH, json=_batch(*[(None, f"pw-{i}-{CANARY}") for i in range(50)]))
    assert ok.status_code == 200
    assert ok.json()["count"] == 50
    too_many = client.post(BATCH, json=_batch(*[(None, f"pw-{i}") for i in range(51)]))
    assert too_many.status_code == 422
    assert too_many.json()["error"]["code"] == "batch_too_large"


def test_batch_empty_and_malformed_requests(client: TestClient) -> None:
    for payload in (
        {"items": []},
        {},
        {"items": [{}]},
        {"items": [{"password": 5}]},
        {"items": "letmein"},
        {"items": [{"password": CANARY, "extra": 1}]},
        {"items": [{"password": CANARY}], "detail": "everything"},
    ):
        response = client.post(BATCH, json=payload)
        assert response.status_code == 422, payload
        assert response.json()["error"]["code"] == "validation_error"
        assert CANARY not in response.text


def test_batch_over_long_password_rejects_the_whole_request(make_client: MakeClient) -> None:
    client = make_client(max_password_length=20)
    payload = _batch((None, CANARY), (None, "y" * 21), (None, "z" * 40))
    response = client.post(BATCH, json=payload)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "password_too_long"
    assert [d["loc"] for d in error["details"]] == [
        ["body", "items", 1, "password"],
        ["body", "items", 2, "password"],
    ]
    assert "y" * 5 not in response.text
    assert "z" * 5 not in response.text


def test_batch_ids_are_sanitised_and_redacted(client: TestClient) -> None:
    payload = _batch(
        (CANARY, CANARY),  # id equals the password
        (f"acct-{OTHER_STRONG}", OTHER_STRONG),  # id contains the password
        ("ok-id", "letmein"),
        ("tab\there\x1b[31m", "letmein"),
        (None, "letmein"),
        ("x" * 100, "letmein"),
    )
    results = client.post(BATCH, json=payload).json()["results"]
    ids = [r["id"] for r in results]
    assert ids[:3] == ["[redacted]", "[redacted]", "ok-id"]
    assert "\x1b" not in ids[3]
    assert ids[4] is None
    assert len(ids[5]) == 64


def test_batch_id_longer_than_128_is_rejected(client: TestClient) -> None:
    response = client.post(BATCH, json=_batch(("x" * 129, "letmein")))
    assert response.status_code == 422


def test_batch_accepts_bodies_up_to_the_batch_limit(make_client: MakeClient) -> None:
    client = make_client(max_body_bytes=1024, batch_max_body_bytes=8192, batch_max_items=10)
    items = [(f"id{i}-" + "x" * 100, f"{OTHER_STRONG}-{i}") for i in range(10)]
    body = json.dumps(_batch(*items))
    assert 1024 < len(body) < 8192
    assert client.post(BATCH, content=body, headers=JSON).status_code == 200
    # ...while the same size is refused on the single-password endpoint's smaller limit
    big = json.dumps({"password": CANARY, "context": {"personal_info": ["a" * 100] * 11}})
    assert len(big) > 1024
    assert client.post(AUDIT, content=big, headers=JSON).status_code == 413
