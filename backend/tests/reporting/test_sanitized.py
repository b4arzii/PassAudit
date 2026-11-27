"""Sanitized reports: whitelisting, the leak guard, integrity sealing."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from passaudit.analysis import (
    AnalysisContext,
    BreachExposure,
    ExposureSignals,
    PasswordAnalysis,
    PasswordAnalyzer,
    PasswordPolicy,
    ReuseExposure,
    summarize_analyses,
)
from passaudit.cli.reports import compact
from passaudit.cli.results import PasswordResult, Verdict
from passaudit.reporting import (
    LIMITATIONS,
    ReportLeakError,
    analysis_summary,
    assert_clean,
    assert_report_clean,
    build_audit_report,
    contains_secret,
    describe_external,
    entry_from_result,
    report_vocabulary,
    seal,
    verify_seal,
)
from passaudit.reporting import sanitized as sanitized_module

CANARY = "Zq7!xKp#9mWv$L2nRb"
OTHER = "Qw8$yL3!pN6#zT1vHd"
PERSONAL = "Zebulon-Quillfeather"
NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _analysis(analyzer: PasswordAnalyzer, password: str, **kwargs: object) -> PasswordAnalysis:
    return analyzer.analyze_password(password, **kwargs)  # type: ignore[arg-type]


def _report(
    analyzer: PasswordAnalyzer, passwords: list[str], secrets: list[str] | None = None, **kw: object
) -> dict[str, object]:
    analyses = [_analysis(analyzer, pw) for pw in passwords]
    entries = [
        entry_from_result(index=i, label=f"Row {i}", analysis=a, reused_in_batch=False)
        for i, a in enumerate(analyses, 1)
    ]
    return build_audit_report(
        kind="batch",
        entries=entries,
        summary=summarize_analyses(analyses).model_dump(),
        policy=PasswordPolicy().model_dump(mode="json"),
        profile=kw.get("profile"),  # type: ignore[arg-type]
        usage="general",
        external=describe_external(
            breach="off", online_host=None, reuse_datasets=None, authorization_reference=None
        ),
        secrets=secrets if secrets is not None else passwords,
        now=NOW,
    )


# ------------------------------------------------------------------------------ guard


def test_contains_secret_matches_case_insensitively_and_by_head_or_tail() -> None:
    assert contains_secret("xx Hunter2-Long-Secret-Value yy", ["hunter2-long-secret-value"])
    assert contains_secret("...Hunter2-L...", ["Hunter2-Long-Secret-Value"])  # 8-char head
    assert contains_secret("...ret-Value", ["Hunter2-Long-Secret-Value"])  # 8-char tail
    assert not contains_secret("nothing here", ["Hunter2-Long-Secret-Value"])
    assert not contains_secret("true low abc", ["abc", "low", ""])  # too short to be meaningful


def test_short_fragments_of_a_short_secret_are_not_flagged() -> None:
    assert not contains_secret("Zq7!xKp#", ["Zq7!xKp#9mW"])  # 8 chars of an 11-char secret


def test_the_vocabulary_lets_weak_passwords_through_without_hiding_real_leaks() -> None:
    text = json.dumps({"findings": ["common_password"], "rule": "block_common_passwords"})
    assert contains_secret(text, ["password"], vocabulary=[])  # without it, a false alarm
    assert not contains_secret(
        text, ["password"], vocabulary={"common_password", "block_common_passwords"}
    )
    leaked = json.dumps({"label": "my password is hunter22"})
    assert contains_secret(leaked, ["hunter22"], vocabulary={"common_password"})


def test_assert_clean_raises_a_message_that_never_names_the_secret() -> None:
    with pytest.raises(ReportLeakError) as caught:
        assert_clean(f"oops {CANARY} oops", [CANARY])
    assert CANARY not in str(caught.value)
    assert_clean("fine", [CANARY])


# --------------------------------------------------------------------------- reports


def test_a_report_is_whitelisted_password_free_and_sealed(analyzer: PasswordAnalyzer) -> None:
    report = _report(analyzer, [CANARY, OTHER, "password", "letmein"])
    text = json.dumps(report)
    for password in (CANARY, OTHER):
        assert password not in text
    assert set(report) == {"report", "audit", "summary", "results", "limitations", "integrity"}
    assert report["report"]["sanitized"] is True  # type: ignore[index]
    assert report["report"]["schema_version"] == "2"  # type: ignore[index]
    assert report["report"]["generated_at"] == "2026-01-02T03:04:05+00:00"  # type: ignore[index]
    assert list(report["limitations"]) == list(LIMITATIONS)  # type: ignore[call-overload]
    assert verify_seal(report)


def test_weak_common_passwords_still_produce_a_report(analyzer: PasswordAnalyzer) -> None:
    """The guard must not refuse a report merely because it says 'common_password'."""
    report = _report(analyzer, ["password", "letmein", "123456"])
    assert len(report["results"]) == 3  # type: ignore[arg-type]


def test_entries_have_exactly_the_whitelisted_fields(analyzer: PasswordAnalyzer) -> None:
    exposure = ExposureSignals(
        breach=BreachExposure(status="breached", source="online", count=777),
        reuse=ReuseExposure(status="reused", sources=("hr-export",)),
    )
    analysis = _analysis(analyzer, CANARY, exposure=exposure)
    entry = entry_from_result(index=1, label="x", analysis=analysis, reused_in_batch=True)
    assert set(entry) == {
        "index", "label", "length", "reused_in_batch", "risk", "strength", "estimated_bits",
        "policy", "findings", "recommendations", "breach", "reuse_datasets",
    }  # fmt: skip
    assert entry["breach"] == {"status": "breached", "source": "online"}  # no counts, no prefix
    assert entry["reuse_datasets"] == ["hr-export"]
    blob = json.dumps(entry)
    assert CANARY not in blob


def test_api_and_cli_reports_share_one_analysis_summary(analyzer: PasswordAnalyzer) -> None:
    """Phase 9: both sanitized formats take these fields from ``analysis_summary``."""
    analysis = _analysis(analyzer, CANARY)
    summary = analysis_summary(analysis)
    assert set(summary) == {
        "risk", "strength", "estimated_bits", "policy", "findings", "recommendations",
    }  # fmt: skip
    assert CANARY not in json.dumps(summary)
    api = entry_from_result(index=1, label=None, analysis=analysis, reused_in_batch=False)
    cli_result = PasswordResult(
        index=1, length=analysis.length, verdict=Verdict(False, ()), analysis=analysis
    )
    cli = compact(cli_result)
    for key, value in summary.items():
        assert api[key] == value
        assert cli[key] == value


def test_unchecked_exposure_is_null_not_clean(analyzer: PasswordAnalyzer) -> None:
    entry = entry_from_result(
        index=1, label=None, analysis=_analysis(analyzer, CANARY), reused_in_batch=False
    )
    assert entry["breach"] is None
    assert entry["reuse_datasets"] is None


def test_the_analysis_can_be_embedded_and_is_still_clean(analyzer: PasswordAnalyzer) -> None:
    analysis = _analysis(analyzer, CANARY, context=AnalysisContext())
    entry = entry_from_result(
        index=1, label=None, analysis=analysis, reused_in_batch=False, include_analysis=True
    )
    assert "analysis" in entry
    assert CANARY not in json.dumps(entry)


def test_a_leaked_label_or_setting_makes_the_report_refuse_to_exist(
    analyzer: PasswordAnalyzer,
) -> None:
    analysis = _analysis(analyzer, CANARY)
    leaky = entry_from_result(
        index=1, label=f"login for {CANARY}", analysis=analysis, reused_in_batch=False
    )
    with pytest.raises(ReportLeakError) as caught:
        build_audit_report(
            kind="batch", entries=[leaky], summary={}, policy={}, profile=None, usage="general",
            external={}, secrets=[CANARY], now=NOW,
        )  # fmt: skip
    assert CANARY not in str(caught.value)
    with pytest.raises(ReportLeakError):
        build_audit_report(
            kind="batch", entries=[], summary={}, policy={}, profile=f"p-{PERSONAL}",
            usage="general", external={}, secrets=[PERSONAL], now=NOW,
        )  # fmt: skip


def test_personal_information_is_checked_too(analyzer: PasswordAnalyzer) -> None:
    report = _report(analyzer, [f"{PERSONAL}-9"], secrets=[f"{PERSONAL}-9", PERSONAL])
    assert PERSONAL.lower() not in json.dumps(report).lower()


# --------------------------------------------------------------------------- sealing


def test_the_seal_detects_any_change(analyzer: PasswordAnalyzer) -> None:
    report = _report(analyzer, [CANARY, OTHER])
    assert verify_seal(report)
    tampered = copy.deepcopy(report)
    tampered["results"][0]["risk"]["score"] += 1  # type: ignore[index]
    assert not verify_seal(tampered)
    removed = copy.deepcopy(report)
    removed["results"].pop()  # type: ignore[attr-defined]
    assert not verify_seal(removed)
    renamed = copy.deepcopy(report)
    renamed["integrity"]["algorithm"] = "md5"  # type: ignore[index]
    assert not verify_seal(renamed)
    assert not verify_seal({"results": []})


def test_the_seal_is_deterministic_and_not_a_signature(analyzer: PasswordAnalyzer) -> None:
    one = _report(analyzer, [CANARY])
    two = _report(analyzer, [CANARY])
    assert one["integrity"] == two["integrity"]
    assert "not a signature" in one["integrity"]["note"]  # type: ignore[index]
    # ...anyone can recompute it, which is exactly what the note says:
    forged = copy.deepcopy(one)
    forged["results"] = []
    assert verify_seal(seal(forged))


def test_the_limitations_are_always_present_and_honest(analyzer: PasswordAnalyzer) -> None:
    report = _report(analyzer, [CANARY])
    text = " ".join(report["limitations"])  # type: ignore[arg-type]
    for phrase in (
        "estimates",
        "not found in the consulted corpus",
        "unavailable",
        "not a compliance",
    ):
        assert phrase in text


def test_external_checks_describe_what_ran_without_data() -> None:
    online = describe_external(
        breach="online", online_host="api.pwnedpasswords.com", reuse_datasets=None,
        authorization_reference=None,
    )  # fmt: skip
    assert online["breach_check"] == "online"
    assert online["breach_service_host"] == "api.pwnedpasswords.com"
    assert "5-character" in online["breach_protocol"]
    off = describe_external(
        breach="off", online_host="api.pwnedpasswords.com", reuse_datasets=None,
        authorization_reference="T-1",
    )  # fmt: skip
    assert off["breach_service_host"] is None  # not consulted, so not named
    assert off["reuse_authorization_reference"] is None
    reuse = describe_external(
        breach="local", online_host=None, reuse_datasets=["a", "b"], authorization_reference="T-1"
    )
    assert reuse["reuse_datasets"] == ["a", "b"]
    assert reuse["reuse_authorization_reference"] == "T-1"


def test_vocabulary_contains_enum_values_and_field_names() -> None:
    vocabulary = report_vocabulary({"results": [{"custom_field": 1}]})
    assert {"common_password", "block_common_passwords", "custom_field"} <= vocabulary
    assert "password" not in vocabulary
    assert_report_clean({"findings": ["common_password"]}, ["password"])


def test_module_has_no_io_logging_or_network() -> None:
    source = sanitized_module.__file__
    assert source is not None
    text = Path(source).read_text(encoding="utf-8")
    for needle in ("import logging", "import socket", "urllib", "open(", "print("):
        assert needle not in text
