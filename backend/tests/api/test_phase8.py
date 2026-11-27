"""Phase 8 over HTTP: opt-in gating, k-anonymity on the wire, reuse, profiles, sealed reports."""

from __future__ import annotations

import dataclasses
import json
import logging
import re
import socket
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from passaudit.analysis import PasswordAnalysis
from passaudit.api.integrations import IntegrationError
from passaudit.breach import (
    BreachChecker,
    BreachLookupError,
    MemoryRangeProvider,
    sha1_hex,
    split_hash,
)
from passaudit.reporting import verify_seal
from passaudit.reuse import ReuseIndexBuilder, generate_key, write_key_file

from .conftest import CANARY, JSON, OTHER_STRONG, PERSONAL, MakeApp, MakeClient, make_settings

AUDIT = "/api/v1/audit"
BATCH = "/api/v1/audit/batch"
REPORT = "/api/v1/audit/report"
POLICY = "/api/v1/policy/validate"
PREFIX = re.compile(r"^[0-9A-F]{5}$")


class SpyProvider:
    """A fake online range service that records exactly what it is asked."""

    source = "online"

    def __init__(self, breached: dict[str, int] | None = None, *, fail: bool = False) -> None:
        self.corpus = MemoryRangeProvider({sha1_hex(pw): n for pw, n in (breached or {}).items()})
        self.requests: list[str] = []
        self.fail = fail

    def fetch_range(self, prefix: str) -> dict[str, int]:
        self.requests.append(prefix)
        if self.fail:
            raise BreachLookupError("network")
        return self.corpus.fetch_range(prefix)


def _online_client(make_app: MakeApp, spy: SpyProvider, **settings: Any) -> TestClient:
    app = make_app(external_lookups_enabled=True, rate_limit_enabled=False, **settings)
    service = app.state.service
    service.integrations = dataclasses.replace(
        service.integrations,
        checker=BreachChecker(
            online=spy, local=service.integrations.checker._providers.get("local")
        ),
        online_host="range.example",
    )
    return TestClient(app)


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fail loudly (and record) if anything opens a connection to a non-loopback address.

    Loopback is allowed because the event loop itself builds a socket pair on Windows.
    """
    attempts: list[str] = []
    real_connect = socket.socket.connect
    real_getaddrinfo = socket.getaddrinfo

    def is_local(host: object) -> bool:
        return host in {"127.0.0.1", "::1", "localhost", None, ""}

    def guarded_connect(self: socket.socket, address: Any) -> None:
        host = address[0] if isinstance(address, tuple) else address
        if not is_local(host):
            attempts.append(str(host))
            raise AssertionError("a network connection was attempted")
        return real_connect(self, address)

    def guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if not is_local(host):
            attempts.append(str(host))
            raise AssertionError("a name lookup was attempted")
        return real_getaddrinfo(host, *args, **kwargs)

    def no_open(*_a: object, **_k: object) -> None:
        attempts.append("open")
        raise AssertionError("an HTTP request was attempted")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", no_open)
    return attempts


def _hash_file(path: Path, passwords: dict[str, int]) -> Path:
    path.write_bytes(
        (
            "\n".join(f"{h}:{c}" for h, c in sorted((sha1_hex(p), n) for p, n in passwords.items()))
            + "\n"
        ).encode()
    )
    return path


# ------------------------------------------------------------------- opt-in by default


def test_nothing_external_is_available_by_default(
    client: TestClient, no_network: list[str]
) -> None:
    caps = client.get("/api/v1/capabilities").json()
    assert caps["external_lookups_enabled"] is False
    assert caps["breach"] == {
        "local": False,
        "online": False,
        "online_host": None,
        "protocol": caps["breach"]["protocol"],
    }
    assert "5 hex characters" in caps["breach"]["protocol"]
    assert caps["reuse_index"] == {
        "available": False,
        "datasets": [],
        "authorization_reference": None,
    }
    assert {p["name"] for p in caps["profiles"]} >= {"default", "nist-inspired", "high-security"}
    assert caps["dictionaries"]["words"] > 100
    assert no_network == []


def test_an_audit_without_options_performs_no_lookup_and_reports_none(
    make_app: MakeApp, no_network: list[str]
) -> None:
    spy = SpyProvider()
    client = _online_client(make_app, spy)
    body = client.post(AUDIT, json={"password": CANARY}).json()
    assert body["exposure"] is None
    assert spy.requests == []  # enabled on the server, but never requested -> never used
    assert no_network == []


def test_an_online_check_is_refused_when_the_server_has_not_enabled_it(
    client: TestClient, no_network: list[str]
) -> None:
    response = client.post(AUDIT, json={"password": CANARY, "exposure": {"breach": "online"}})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "external_lookups_disabled"
    assert "nothing was sent" in response.json()["error"]["message"]
    assert CANARY not in response.text
    for path in (BATCH, REPORT):
        batch = client.post(
            path, json={"items": [{"password": CANARY}], "exposure": {"breach": "online"}}
        )
        assert batch.status_code == 403
    assert (
        client.post(POLICY, json={"password": CANARY, "exposure": {"breach": "online"}}).status_code
        == 403
    )
    assert no_network == []


def test_unconfigured_local_sources_are_refused_with_a_clear_error(client: TestClient) -> None:
    local = client.post(AUDIT, json={"password": CANARY, "exposure": {"breach": "local"}})
    assert (local.status_code, local.json()["error"]["code"]) == (422, "feature_unavailable")
    reuse = client.post(AUDIT, json={"password": CANARY, "exposure": {"reuse": True}})
    assert (reuse.status_code, reuse.json()["error"]["code"]) == (422, "feature_unavailable")


def test_exposure_options_are_strictly_validated(client: TestClient) -> None:
    for bad in ({"breach": "maybe"}, {"reuse": "yes"}, {"breach": "online", "extra": 1}):
        response = client.post(AUDIT, json={"password": CANARY, "exposure": bad})
        assert response.status_code == 422
        assert CANARY not in response.text


# --------------------------------------------------------- k-anonymity on the wire


def test_the_online_service_only_ever_sees_a_five_character_prefix(make_app: MakeApp) -> None:
    spy = SpyProvider({CANARY: 4242})
    client = _online_client(make_app, spy)
    body = client.post(AUDIT, json={"password": CANARY, "exposure": {"breach": "online"}}).json()

    assert spy.requests == [split_hash(sha1_hex(CANARY))[0]]
    assert all(PREFIX.fullmatch(p) for p in spy.requests)
    assert body["exposure"]["breach"] == {"status": "breached", "source": "online", "count": 4242}
    assert body["risk"]["score"] >= 85
    assert body["recommendations"][0]["code"] == "change_breached_password"
    text = json.dumps(body)
    digest = sha1_hex(CANARY)
    for needle in (CANARY, digest, digest[:5], digest[5:], digest[:8]):
        assert needle not in text


def test_a_clean_result_and_an_unavailable_service(make_app: MakeApp) -> None:
    clean = _online_client(make_app, SpyProvider()).post(
        AUDIT, json={"password": CANARY, "exposure": {"breach": "online"}}
    )
    assert clean.json()["exposure"]["breach"] == {"status": "clean", "source": "online", "count": 0}
    down = _online_client(make_app, SpyProvider(fail=True)).post(
        AUDIT, json={"password": CANARY, "exposure": {"breach": "online"}}
    )
    assert down.status_code == 200  # the audit itself still succeeds
    assert down.json()["exposure"]["breach"] == {
        "status": "unavailable",
        "source": "online",
        "count": None,
    }
    assert down.json()["risk"]["score"] < 20  # unchecked is not treated as breached or clean


def test_batches_group_by_prefix_and_report_per_item_status(make_app: MakeApp) -> None:
    spy = SpyProvider({CANARY: 9})
    client = _online_client(make_app, spy)
    items = [
        {"id": "a", "password": CANARY},
        {"id": "b", "password": OTHER_STRONG},
        {"id": "c", "password": CANARY},
    ]
    body = client.post(BATCH, json={"items": items, "exposure": {"breach": "online"}}).json()
    assert [r["breach"] for r in body["results"]] == ["breached", "clean", "breached"]
    assert body["summary"]["breached"] == 2
    assert len(spy.requests) == 2  # CANARY appears twice but its prefix is asked for once
    assert len(set(spy.requests)) == 2
    assert all(PREFIX.fullmatch(p) for p in spy.requests)


def test_online_checks_cost_extra_rate_limit_units(make_app: MakeApp) -> None:
    def remaining(path: str, body: dict[str, Any]) -> int:
        app = make_app(external_lookups_enabled=True, rate_limit_burst=100)
        service = app.state.service
        service.integrations = dataclasses.replace(
            service.integrations, checker=BreachChecker(online=SpyProvider())
        )
        return int(TestClient(app).post(path, json=body).headers["x-ratelimit-remaining"])

    plain = remaining(AUDIT, {"password": CANARY})
    online = remaining(AUDIT, {"password": CANARY, "exposure": {"breach": "online"}})
    assert plain - online == 1
    items = [{"password": f"{OTHER_STRONG}{i}"} for i in range(5)]
    batch_plain = remaining(BATCH, {"items": items})
    batch_online = remaining(BATCH, {"items": items, "exposure": {"breach": "online"}})
    assert batch_plain - batch_online == 5
    # Phase 9: every route that can trigger a lookup pays for it, not only /audit and /batch.
    policy_plain = remaining(POLICY, {"password": CANARY})
    policy_online = remaining(POLICY, {"password": CANARY, "exposure": {"breach": "online"}})
    assert policy_plain - policy_online == 1
    report_plain = remaining(REPORT, {"items": items})
    report_online = remaining(REPORT, {"items": items, "exposure": {"breach": "online"}})
    assert report_plain - report_online == 5


def test_nothing_secret_reaches_the_logs_during_online_checks(
    make_app: MakeApp, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    spy = SpyProvider({CANARY: 5})
    client = _online_client(make_app, spy, log_level="debug")
    client.post(
        AUDIT,
        json={
            "password": CANARY,
            "exposure": {"breach": "online"},
            "context": {"personal_info": [PERSONAL]},
        },
    )
    client.post(
        REPORT, json={"items": [{"id": "x", "password": CANARY}], "exposure": {"breach": "online"}}
    )
    out = capsys.readouterr()
    digest = sha1_hex(CANARY)
    blob = caplog.text + out.out + out.err + repr(caplog.records)
    for needle in (CANARY, PERSONAL, digest, digest[:5], digest[5:]):
        assert needle not in blob


# ------------------------------------------------------------------------ local corpus


def test_a_local_breach_file_works_without_enabling_external_lookups(
    make_app: MakeApp, tmp_path: Path, no_network: list[str]
) -> None:
    corpus = _hash_file(tmp_path / "pwned.txt", {CANARY: 77, "letmein": 3_000_000})
    client = TestClient(make_app(breach_local_file=corpus))
    assert client.get("/api/v1/capabilities").json()["breach"]["local"] is True
    hit = client.post(AUDIT, json={"password": CANARY, "exposure": {"breach": "local"}}).json()
    assert hit["exposure"]["breach"] == {"status": "breached", "source": "local", "count": 77}
    miss = client.post(
        AUDIT, json={"password": OTHER_STRONG, "exposure": {"breach": "local"}}
    ).json()
    assert miss["exposure"]["breach"]["status"] == "clean"
    assert no_network == []
    assert (
        client.post(AUDIT, json={"password": CANARY, "exposure": {"breach": "online"}}).status_code
        == 403
    )


def test_a_bad_local_breach_file_stops_start_up_without_naming_the_path(
    make_app: MakeApp, tmp_path: Path
) -> None:
    unsorted = tmp_path / "unsorted.txt"
    unsorted.write_bytes(b"\n".join(f"{n:040X}:1".encode() for n in range(300, 0, -1)) + b"\n")
    with pytest.raises(IntegrationError, match="not sorted") as caught:
        make_app(breach_local_file=unsorted)
    assert str(tmp_path) not in str(caught.value)
    with pytest.raises(IntegrationError, match="could not be read"):
        make_app(breach_local_file=tmp_path / "missing.txt")


# ------------------------------------------------------------------------------ reuse


@pytest.fixture
def reuse_settings(tmp_path: Path) -> dict[str, Any]:
    key = generate_key()
    key_file = tmp_path / "reuse.key"
    write_key_file(key_file, key)
    builder = ReuseIndexBuilder(key, authorization_reference="TICKET-9")
    builder.add_source("hr-export", [CANARY, "shared-Zq9!"])
    builder.add_source("vpn", ["shared-Zq9!"])
    index = tmp_path / "reuse.idx"
    builder.write(index)
    return {
        "reuse_index_path": index,
        "reuse_key_file": key_file,
        "reuse_authorization_reference": "TICKET-9",
    }


def test_reuse_auditing_reports_dataset_names_and_nothing_else(
    make_client: MakeClient, reuse_settings: dict[str, Any]
) -> None:
    client = make_client(**reuse_settings)
    caps = client.get("/api/v1/capabilities").json()["reuse_index"]
    assert caps == {
        "available": True,
        "datasets": ["hr-export", "vpn"],
        "authorization_reference": "TICKET-9",
    }
    for path in (reuse_settings["reuse_index_path"], reuse_settings["reuse_key_file"]):
        assert str(path) not in json.dumps(caps)

    body = client.post(AUDIT, json={"password": "shared-Zq9!", "exposure": {"reuse": True}}).json()
    assert body["exposure"]["reuse"] == {"status": "reused", "sources": ["hr-export", "vpn"]}
    assert "unique_per_service" in {r["code"] for r in body["recommendations"]}
    assert "shared-Zq9!" not in json.dumps(body)
    clean = client.post(AUDIT, json={"password": OTHER_STRONG, "exposure": {"reuse": True}}).json()
    assert clean["exposure"]["reuse"] == {"status": "clean", "sources": []}

    batch = client.post(
        BATCH,
        json={
            "items": [{"password": CANARY}, {"password": OTHER_STRONG}],
            "exposure": {"reuse": True},
        },
    ).json()
    assert [r["reuse_datasets"] for r in batch["results"]] == [["hr-export"], []]
    assert batch["summary"]["reused_in_datasets"] == 1


def test_reuse_needs_an_explicit_authorisation_statement_to_start(
    make_app: MakeApp, reuse_settings: dict[str, Any]
) -> None:
    for missing in ("reuse_key_file", "reuse_authorization_reference"):
        partial = {k: v for k, v in reuse_settings.items() if k != missing}
        with pytest.raises(ValueError, match="reuse_index_path requires"):
            make_settings(**partial)
    blank = {**reuse_settings, "reuse_authorization_reference": "   "}
    with pytest.raises(ValueError, match="authorisation"):
        make_settings(**blank)


def test_a_wrong_key_or_broken_index_stops_start_up(
    make_app: MakeApp, reuse_settings: dict[str, Any], tmp_path: Path
) -> None:
    other_key = tmp_path / "other.key"
    write_key_file(other_key, generate_key())
    with pytest.raises(IntegrationError, match="does not match") as caught:
        make_app(**{**reuse_settings, "reuse_key_file": other_key})
    assert str(tmp_path) not in str(caught.value)
    broken = tmp_path / "broken.idx"
    broken.write_text("garbage\n")
    with pytest.raises(IntegrationError, match="could not be loaded"):
        make_app(**{**reuse_settings, "reuse_index_path": broken})


# --------------------------------------------------------------------------- profiles


def test_profiles_are_listed_and_fetched(client: TestClient) -> None:
    profiles = client.get("/api/v1/policy/profiles").json()
    assert {"default", "enterprise", "high-security"} <= {p["name"] for p in profiles}
    one = client.get("/api/v1/policy/profiles/high-security").json()
    assert one["policy"]["block_dictionary_words"] is True
    assert one["usage"] == "privileged_account"
    assert one["builtin"] is True


def test_an_unknown_profile_name_is_never_echoed(client: TestClient) -> None:
    for response in (
        client.get(f"/api/v1/policy/profiles/{CANARY}"),
        client.post(AUDIT, json={"password": "x" * 12, "profile": CANARY}),
        client.post(BATCH, json={"items": [{"password": "x" * 12}], "profile": CANARY}),
    ):
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "unknown_profile"
        assert CANARY not in response.text


def test_a_profile_replaces_the_policy_and_supplies_the_usage(client: TestClient) -> None:
    short = "Zq7!xKp#9mWv"  # 12 characters: fine by default, too short for high-security
    default = client.post(AUDIT, json={"password": short}).json()
    strict = client.post(AUDIT, json={"password": short, "profile": "high-security"}).json()
    assert default["policy"]["compliant"] is True
    assert "min_length" in {v["rule"] for v in strict["policy"]["violations"]}
    privileged = client.post(AUDIT, json={"password": short, "profile": "high-security"}).json()
    explicit = client.post(
        AUDIT,
        json={"password": short, "profile": "high-security", "context": {"usage": "general"}},
    ).json()
    assert (
        privileged["meets_usage_target"] != explicit["meets_usage_target"] or privileged != explicit
    )


def test_profile_and_policy_are_mutually_exclusive(client: TestClient) -> None:
    response = client.post(
        AUDIT, json={"password": CANARY, "profile": "default", "policy": {"min_length": 20}}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert CANARY not in response.text


def test_custom_profiles_load_from_a_file_and_bad_files_stop_start_up(
    make_app: MakeApp, tmp_path: Path
) -> None:
    good = tmp_path / "profiles.json"
    good.write_text(
        json.dumps([{"name": "payroll", "title": "Payroll", "policy": {"min_length": 30}}])
    )
    client = TestClient(make_app(policy_profiles_path=good))
    assert client.get("/api/v1/policy/profiles/payroll").json()["builtin"] is False
    result = client.post(AUDIT, json={"password": CANARY, "profile": "payroll"}).json()
    assert "min_length" in {v["rule"] for v in result["policy"]["violations"]}

    shadow = tmp_path / "shadow.json"
    shadow.write_text(json.dumps([{"name": "default", "title": "x"}]))
    with pytest.raises(IntegrationError, match="built-in name") as caught:
        make_app(policy_profiles_path=shadow)
    assert str(tmp_path) not in str(caught.value)


def test_breach_rules_show_as_unchecked_until_a_check_runs(make_app: MakeApp) -> None:
    client = _online_client(make_app, SpyProvider({CANARY: 5}))
    unchecked = client.post(
        POLICY, json={"password": OTHER_STRONG + "xyz", "profile": "nist-inspired"}
    ).json()
    rule = next(r for r in unchecked["rules"] if r["rule"] == "block_breached_passwords")
    assert rule["status"] == "unchecked"
    breached = client.post(
        POLICY,
        json={"password": CANARY, "profile": "nist-inspired", "exposure": {"breach": "online"}},
    ).json()
    assert (
        next(r for r in breached["rules"] if r["rule"] == "block_breached_passwords")["status"]
        == "fail"
    )
    assert breached["compliant"] is False


# --------------------------------------------------------------------------- dictionaries


def test_operator_dictionaries_extend_detection(make_app: MakeApp, tmp_path: Path) -> None:
    words = tmp_path / "company.txt"
    words.write_text("quillfeather\nzebulonic\n")
    client = TestClient(make_app(dictionary_paths=[words]))
    found = client.post(AUDIT, json={"password": "Zq7!Quillfeather-Zebulonic!9"}).json()["findings"]
    assert any(f.get("dictionary") == "words" for f in found)
    baseline = TestClient(make_app()).get("/api/v1/capabilities").json()["dictionaries"]["words"]
    assert client.get("/api/v1/capabilities").json()["dictionaries"]["words"] == baseline + 2
    with pytest.raises(IntegrationError, match="dictionary file"):
        make_app(dictionary_paths=[tmp_path / "missing.txt"])


# ------------------------------------------------------------------------------ reports


def test_the_report_endpoint_returns_a_sealed_sanitized_report(make_app: MakeApp) -> None:
    spy = SpyProvider({CANARY: 5})
    client = _online_client(make_app, spy)
    response = client.post(
        REPORT,
        json={
            "items": [{"id": "alice", "password": CANARY}, {"id": "bob", "password": "password"}],
            "profile": "enterprise",
            "exposure": {"breach": "online"},
            "context": {"personal_info": [PERSONAL]},
        },
    )
    assert response.status_code == 200
    report = response.json()
    assert verify_seal(report)
    assert report["report"]["schema_version"] == "2"
    assert report["audit"]["profile"] == "enterprise"
    assert report["audit"]["external_checks"]["breach_check"] == "online"
    assert report["audit"]["external_checks"]["breach_service_host"] == "range.example"
    assert [r["breach"]["status"] for r in report["results"]] == ["breached", "clean"]
    assert report["summary"]["breached"] == 1
    text = response.text
    digest = sha1_hex(CANARY)
    for needle in (CANARY, PERSONAL, digest, digest[:5], digest[5:]):
        assert needle not in text
    assert '"password"' not in text.replace("common_password", "").replace("passwords", "")
    assert len(report["limitations"]) >= 5


def test_the_report_records_the_reuse_authorisation(
    make_client: MakeClient, reuse_settings: dict[str, Any]
) -> None:
    client = make_client(**reuse_settings)
    report = client.post(
        REPORT, json={"items": [{"password": CANARY}], "exposure": {"reuse": True}}
    ).json()
    external = report["audit"]["external_checks"]
    assert external["reuse_datasets"] == ["hr-export", "vpn"]
    assert external["reuse_authorization_reference"] == "TICKET-9"
    assert report["results"][0]["reuse_datasets"] == ["hr-export"]


def test_a_report_is_refused_rather_than_leak_a_personal_detail(client: TestClient) -> None:
    response = client.post(
        REPORT,
        json={
            "items": [{"id": PERSONAL, "password": CANARY}],
            "context": {"personal_info": [PERSONAL]},
        },
    )
    assert response.status_code == 422
    assert PERSONAL not in response.text
    assert CANARY not in response.text


def test_a_password_used_as_its_own_label_is_redacted_not_reported(client: TestClient) -> None:
    report = client.post(REPORT, json={"items": [{"id": CANARY, "password": CANARY}]}).json()
    assert report["results"][0]["label"] == "[redacted]"
    assert CANARY not in json.dumps(report)


def test_report_detail_full_embeds_password_free_analyses(client: TestClient) -> None:
    report = client.post(REPORT, json={"items": [{"password": CANARY}], "detail": "full"}).json()
    PasswordAnalysis.model_validate(report["results"][0]["analysis"])
    assert CANARY not in json.dumps(report)


def test_new_endpoints_keep_every_existing_guard(client: TestClient) -> None:
    assert (
        client.post(f"{REPORT}?x={CANARY}", json={"items": [{"password": CANARY}]}).status_code
        == 400
    )
    assert (
        client.post(
            REPORT, content="password=1", headers={"Content-Type": "text/plain"}
        ).status_code
        == 415
    )
    assert client.post(REPORT, content=b"{", headers=JSON).status_code == 422
    assert client.get("/api/v1/capabilities?x=1").status_code == 200  # GET queries are harmless
    huge = {"items": [{"password": "x" * 100}] * 60}
    assert client.post(REPORT, json=huge).status_code == 422  # over the batch limit
