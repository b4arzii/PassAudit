"""Exposure signals (breach / reuse), policy profiles and the batch reuse tracker."""

from __future__ import annotations

import json

import pytest
from pydantic import SecretStr, ValidationError

from passaudit.analysis import (
    BUILTIN_PROFILES,
    AnalysisContext,
    BreachExposure,
    ExposureSignals,
    PasswordAnalyzer,
    PasswordPolicy,
    PasswordUsage,
    PolicyProfile,
    PolicyProfileError,
    ReuseExposure,
    ReuseTracker,
    UnknownProfileError,
    analyze_batch,
    evaluate_rules,
)

from .conftest import CANARY

BREACHED = ExposureSignals(breach=BreachExposure(status="breached", source="online", count=12345))
CLEAN = ExposureSignals(breach=BreachExposure(status="clean", source="local", count=0))
UNAVAILABLE = ExposureSignals(breach=BreachExposure(status="unavailable", source="online"))
REUSED = ExposureSignals(reuse=ReuseExposure(status="reused", sources=("hr-export", "vpn")))


# ----------------------------------------------------------------------------- exposure


def test_a_breached_password_gets_the_known_weak_floor_even_if_it_looks_strong(
    analyzer: PasswordAnalyzer,
) -> None:
    plain = analyzer.analyze_password(CANARY)
    breached = analyzer.analyze_password(CANARY, exposure=BREACHED)
    assert plain.risk.score < 20
    assert breached.risk.score >= 85
    assert breached.risk.level.value == "critical"
    floor = next(c for c in breached.risk.components if c.factor.value == "known_weak_floor")
    assert "breach" in floor.explanation
    assert breached.risk.score == sum(c.points for c in breached.risk.components)


def test_a_clean_or_unavailable_check_never_lowers_or_raises_risk(
    analyzer: PasswordAnalyzer,
) -> None:
    base = analyzer.analyze_password(CANARY).risk.score
    assert analyzer.analyze_password(CANARY, exposure=CLEAN).risk.score == base
    assert analyzer.analyze_password(CANARY, exposure=UNAVAILABLE).risk.score == base


def test_breach_advice_comes_first(analyzer: PasswordAnalyzer) -> None:
    result = analyzer.analyze_password(CANARY, exposure=BREACHED)
    assert result.recommendations[0].code.value == "change_breached_password"
    assert result.recommendations[0].priority.value == "high"


def test_dataset_reuse_counts_as_reuse_in_the_advice(analyzer: PasswordAnalyzer) -> None:
    result = analyzer.analyze_password(CANARY, exposure=REUSED)
    assert "unique_per_service" in {r.code.value for r in result.recommendations}
    assert result.exposure is not None
    assert result.exposure.reuse is not None
    assert result.exposure.reuse.sources == ("hr-export", "vpn")


def test_exposure_is_echoed_and_the_result_stays_password_free(analyzer: PasswordAnalyzer) -> None:
    result = analyzer.analyze_password(CANARY, exposure=BREACHED)
    assert result.exposure == BREACHED
    assert CANARY not in result.model_dump_json()
    assert analyzer.analyze_password(CANARY).exposure is None


def test_block_breached_rule_fails_only_on_a_breach(analyzer: PasswordAnalyzer) -> None:
    policy = PasswordPolicy(block_breached_passwords=True, min_strength_score=0)
    assert not analyzer.analyze_password(CANARY, policy=policy, exposure=BREACHED).policy.compliant
    assert analyzer.analyze_password(CANARY, policy=policy, exposure=CLEAN).policy.compliant


def test_block_breached_rule_is_reported_unchecked_not_passed_when_no_check_ran(
    analyzer: PasswordAnalyzer,
) -> None:
    policy = PasswordPolicy(block_breached_passwords=True, min_strength_score=0)
    for exposure in (None, UNAVAILABLE, ExposureSignals()):
        analysis = analyzer.analyze_password(CANARY, policy=policy, exposure=exposure)
        rule = next(
            r
            for r in evaluate_rules(policy, analysis)
            if r.rule.value == "block_breached_passwords"
        )
        assert rule.status == "unchecked"
        assert rule.message is not None
    checked = analyzer.analyze_password(CANARY, policy=policy, exposure=CLEAN)
    assert (
        next(
            r for r in evaluate_rules(policy, checked) if r.rule.value == "block_breached_passwords"
        ).status
        == "pass"
    )


def test_exposure_models_are_strict() -> None:
    with pytest.raises(ValidationError):
        BreachExposure(status="maybe", source="online")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ReuseExposure(status="reused", sources=tuple(f"s{i}" for i in range(21)))
    with pytest.raises(ValidationError):
        ExposureSignals(breach=None, reuse=None, extra=1)  # type: ignore[call-arg]


# ----------------------------------------------------------------------------- profiles


def test_builtin_profiles_are_valid_unique_and_documented() -> None:
    profiles = BUILTIN_PROFILES.all()
    assert {p.name for p in profiles} >= {
        "default", "nist-inspired", "enterprise", "high-security", "passphrase",
        "legacy-complexity", "minimal",
    }  # fmt: skip
    assert len({p.name for p in profiles}) == len(profiles)
    assert all(p.builtin and p.title and p.description for p in profiles)
    assert BUILTIN_PROFILES.get("default").policy == PasswordPolicy()


def test_profiles_say_inspired_by_not_compliant() -> None:
    nist = BUILTIN_PROFILES.get("nist-inspired")
    assert "not a compliance claim" in nist.description
    assert nist.references


def test_high_security_profile_enables_the_new_rules() -> None:
    policy = BUILTIN_PROFILES.get("high-security").policy
    assert policy.block_dictionary_words
    assert policy.block_breached_passwords
    assert BUILTIN_PROFILES.get("high-security").usage is PasswordUsage.PRIVILEGED_ACCOUNT


def test_unknown_profile_error_does_not_echo_the_name() -> None:
    with pytest.raises(UnknownProfileError) as caught:
        BUILTIN_PROFILES.get(CANARY)
    assert CANARY not in str(caught.value)
    assert "unknown" not in CANARY


@pytest.mark.parametrize("name", ["", "Has Space", "UPPER", "-lead", "x" * 49, "a/b", "../etc"])
def test_profile_names_must_be_slugs(name: str) -> None:
    with pytest.raises(ValidationError):
        PolicyProfile(name=name, title="t")


def test_custom_profiles_cannot_shadow_or_pose_as_builtin() -> None:
    mine = PolicyProfile(name="payroll", title="Payroll", policy=PasswordPolicy(min_length=18))
    registry = BUILTIN_PROFILES.with_custom([mine])
    assert registry.get("payroll").policy.min_length == 18
    assert "payroll" not in BUILTIN_PROFILES
    with pytest.raises(PolicyProfileError):
        BUILTIN_PROFILES.with_custom([PolicyProfile(name="strict-ish", title="x", builtin=True)])
    with pytest.raises(PolicyProfileError):
        BUILTIN_PROFILES.with_custom([PolicyProfile(name="default", title="shadow")])
    with pytest.raises(PolicyProfileError):
        BUILTIN_PROFILES.with_custom([mine, mine])


def test_profiles_reject_unknown_policy_fields() -> None:
    with pytest.raises(ValidationError):
        PolicyProfile.model_validate({"name": "x", "title": "t", "policy": {"min_lenght": 9}})


def test_every_builtin_profile_can_audit_a_password(analyzer: PasswordAnalyzer) -> None:
    for profile in BUILTIN_PROFILES.all():
        result = analyzer.analyze_password(
            CANARY, policy=profile.policy, context=AnalysisContext(usage=profile.usage)
        )
        assert 0 <= result.risk.score <= 100


# ------------------------------------------------------------------------ reuse tracker


def test_reuse_tracker_flags_duplicates_without_keeping_plaintext() -> None:
    tracker = ReuseTracker(["alpha-Zq7", "beta-Zq7", "alpha-Zq7"])
    assert tracker.is_reused("alpha-Zq7")
    assert not tracker.is_reused("beta-Zq7")
    assert not tracker.is_reused("never-added")
    assert tracker.reused_count() == 1
    blob = repr(tracker) + repr(vars_of(tracker))
    assert "alpha" not in blob
    assert "beta" not in blob


def vars_of(tracker: ReuseTracker) -> object:
    return {name: getattr(tracker, name) for name in ReuseTracker.__slots__}


def test_reuse_tracker_digests_depend_on_a_per_instance_key() -> None:
    one, two = ReuseTracker(["x" * 8]), ReuseTracker(["x" * 8])
    assert one._counts.keys() != two._counts.keys()  # proving the key is random


def test_reuse_tracker_can_be_cleared_and_handles_odd_text() -> None:
    tracker = ReuseTracker(["same", "same", "\ud800lone", "\ud800lone"])
    assert tracker.is_reused("\ud800lone")
    tracker.clear()
    assert not tracker.is_reused("same")


def test_batch_marks_reuse_and_threads_exposure_per_entry(analyzer: PasswordAnalyzer) -> None:
    entries = [
        ("a", SecretStr(CANARY)),
        ("b", SecretStr(CANARY)),
        ("c", SecretStr("other-Zq9!kX2m")),
    ]
    results = analyze_batch(
        analyzer, entries, PasswordPolicy(), AnalysisContext(), exposures=[BREACHED, None, CLEAN]
    )
    assert [r.reused_in_batch for r in results] == [True, True, False]
    assert [r.analysis.exposure for r in results] == [BREACHED, None, CLEAN]
    assert results[0].analysis.risk.score >= 85
    with pytest.raises(ValueError, match="one item per entry"):
        analyze_batch(analyzer, entries, PasswordPolicy(), AnalysisContext(), exposures=[None])


def test_batch_results_never_contain_the_passwords(analyzer: PasswordAnalyzer) -> None:
    entries = [(CANARY, SecretStr(CANARY)), ("x", SecretStr(CANARY))]
    results = analyze_batch(analyzer, entries, PasswordPolicy(), AnalysisContext())
    blob = json.dumps([r.analysis.model_dump(mode="json") for r in results]) + repr(results)
    assert CANARY not in blob
    assert results[0].label == "[redacted]"
