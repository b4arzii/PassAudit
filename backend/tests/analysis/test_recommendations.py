"""Context-aware recommendations."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from passaudit.analysis import (
    AnalysisContext,
    PasswordAnalysis,
    PasswordPolicy,
    PasswordUsage,
    Priority,
    RecommendationCode,
)
from passaudit.analysis.recommendations import (
    USAGE_TARGET_LOG10,
    meets_usage_target,
)
from passaudit.analysis.strength import estimate_strength

Analyze = Callable[..., PasswordAnalysis]
STRONG = "Zq7!xKp#9mWv$L2nRb"  # 18 chars, random
PASSPHRASE = "correct horse battery staple"


def _codes(result: PasswordAnalysis) -> list[RecommendationCode]:
    return [r.code for r in result.recommendations]


def _ctx(**kwargs: object) -> AnalysisContext:
    return AnalysisContext(**kwargs)  # type: ignore[arg-type]


def _rec(result: PasswordAnalysis, code: RecommendationCode):  # type: ignore[no-untyped-def]
    return next(r for r in result.recommendations if r.code is code)


# ------------------------------------------------------------------------ happy path


def test_strong_password_gets_only_the_all_clear(analyze: Analyze) -> None:
    result = analyze(PASSPHRASE)
    assert _codes(result) == [RecommendationCode.LOOKS_GOOD]
    assert result.recommendations[0].priority is Priority.LOW


def test_all_clear_is_never_mixed_with_problems(analyze: Analyze) -> None:
    for pw in ["password", "abc", "", STRONG]:
        codes = _codes(analyze(pw))
        if RecommendationCode.LOOKS_GOOD in codes:
            assert codes == [RecommendationCode.LOOKS_GOOD]


def test_recommendations_are_sorted_by_priority(analyze: Analyze) -> None:
    order = {Priority.HIGH: 0, Priority.MEDIUM: 1, Priority.LOW: 2}
    for pw in ["password", "qwerty", "aaaa", "abc123", STRONG, ""]:
        ranks = [order[r.priority] for r in analyze(pw).recommendations]
        assert ranks == sorted(ranks)


# ------------------------------------------------------------------ finding-driven


def test_common_password_advice_priority_depends_on_match_type(analyze: Analyze) -> None:
    whole = _rec(analyze("letmein"), RecommendationCode.AVOID_COMMON_PASSWORD)
    assert whole.priority is Priority.HIGH
    embedded = _rec(analyze("xxdragonxxQ7!zK"), RecommendationCode.AVOID_COMMON_PASSWORD)
    assert embedded.priority is Priority.MEDIUM


def test_pattern_advice(analyze: Analyze) -> None:
    codes = _codes(analyze("aaaXqwerXabcdXabab"))
    assert RecommendationCode.AVOID_REPEATS in codes
    assert RecommendationCode.AVOID_KEYBOARD_PATTERNS in codes
    assert RecommendationCode.AVOID_SEQUENCES in codes
    assert RecommendationCode.AVOID_REPEATS not in _codes(analyze(STRONG))


def test_personal_info_advice(analyze: Analyze) -> None:
    result = analyze("jane-Zq7!xKp#9mWv", context=_ctx(personal_info=("Jane",)))
    assert _rec(result, RecommendationCode.AVOID_PERSONAL_INFO).priority is Priority.HIGH
    assert RecommendationCode.AVOID_PERSONAL_INFO not in _codes(analyze("jane-Zq7!xKp#9mWv"))


def test_policy_advice_counts_violations(analyze: Analyze) -> None:
    result = analyze("Zq7!xKp", policy=PasswordPolicy(min_length=12, min_digits=3))
    rec = _rec(result, RecommendationCode.MEET_POLICY)
    assert rec.priority is Priority.HIGH
    assert f"{len(result.policy.violations)} rule" in rec.message
    singular = analyze(STRONG, policy=PasswordPolicy(min_length=40, min_strength_score=0))
    assert "1 rule " in _rec(singular, RecommendationCode.MEET_POLICY).message


# ---------------------------------------------------------------- context-driven


def test_reuse_flag_produces_top_priority_advice(analyze: Analyze) -> None:
    result = analyze(STRONG, context=_ctx(reused_elsewhere=True))
    assert _codes(result)[0] is RecommendationCode.UNIQUE_PER_SERVICE
    assert result.recommendations[0].priority is Priority.HIGH
    assert RecommendationCode.UNIQUE_PER_SERVICE not in _codes(analyze(STRONG))


@pytest.mark.parametrize(
    ("usage", "expects_mfa"),
    [
        (PasswordUsage.GENERAL, False),
        (PasswordUsage.ONLINE_ACCOUNT, True),
        (PasswordUsage.PRIVILEGED_ACCOUNT, True),
        (PasswordUsage.MASTER_PASSWORD, False),
        (PasswordUsage.ENCRYPTION_KEY, False),
    ],
)
def test_mfa_advice_depends_on_usage(
    analyze: Analyze, usage: PasswordUsage, expects_mfa: bool
) -> None:
    result = analyze(PASSPHRASE, context=_ctx(usage=usage))
    assert (RecommendationCode.ENABLE_MFA in _codes(result)) is expects_mfa


def test_mfa_is_more_urgent_for_privileged_accounts(analyze: Analyze) -> None:
    online = _rec(analyze(PASSPHRASE, context=_ctx(usage=PasswordUsage.ONLINE_ACCOUNT)),
                  RecommendationCode.ENABLE_MFA)  # fmt: skip
    admin = _rec(analyze(PASSPHRASE, context=_ctx(usage=PasswordUsage.PRIVILEGED_ACCOUNT)),
                 RecommendationCode.ENABLE_MFA)  # fmt: skip
    assert online.priority is Priority.LOW
    assert admin.priority is Priority.MEDIUM


def test_master_passwords_get_passphrase_advice_not_manager_advice(analyze: Analyze) -> None:
    codes = _codes(analyze("tigger1", context=_ctx(usage=PasswordUsage.MASTER_PASSWORD)))
    assert RecommendationCode.USE_PASSPHRASE in codes
    assert RecommendationCode.USE_PASSWORD_MANAGER not in codes


def test_weak_everyday_passwords_get_manager_advice_not_passphrase(analyze: Analyze) -> None:
    codes = _codes(analyze("tigger1", context=_ctx(usage=PasswordUsage.ONLINE_ACCOUNT)))
    assert RecommendationCode.USE_PASSWORD_MANAGER in codes
    assert RecommendationCode.USE_PASSPHRASE not in codes


def test_strong_master_passphrase_needs_no_passphrase_advice(analyze: Analyze) -> None:
    result = analyze(PASSPHRASE, context=_ctx(usage=PasswordUsage.MASTER_PASSWORD))
    assert RecommendationCode.USE_PASSPHRASE not in _codes(result)


@pytest.mark.parametrize(
    ("usage", "length", "wants_lengthen"),
    [
        (PasswordUsage.GENERAL, 11, True),
        (PasswordUsage.GENERAL, 12, False),
        (PasswordUsage.PRIVILEGED_ACCOUNT, 15, True),
        (PasswordUsage.PRIVILEGED_ACCOUNT, 16, False),
        (PasswordUsage.ENCRYPTION_KEY, 19, True),
        (PasswordUsage.ENCRYPTION_KEY, 20, False),
    ],
)
def test_length_advice_boundaries_per_usage(
    analyze: Analyze, usage: PasswordUsage, length: int, wants_lengthen: bool
) -> None:
    password = "Zq7!xKp#9mWv$L2nRbT4&yU1"[:length]
    result = analyze(password, context=_ctx(usage=usage), policy=PasswordPolicy(min_length=0))
    assert (RecommendationCode.LENGTHEN in _codes(result)) is wants_lengthen


def test_policy_minimum_can_raise_the_length_target(analyze: Analyze) -> None:
    result = analyze(STRONG, policy=PasswordPolicy(min_length=24))
    assert "24 characters" in _rec(result, RecommendationCode.LENGTHEN).message


def test_below_usage_target_advice(analyze: Analyze) -> None:
    weak = analyze("Tr0ub4dor&3", context=_ctx(usage=PasswordUsage.ENCRYPTION_KEY))
    assert not weak.meets_usage_target
    assert RecommendationCode.BELOW_USAGE_TARGET in _codes(weak)
    ok = analyze(PASSPHRASE, context=_ctx(usage=PasswordUsage.ENCRYPTION_KEY))
    assert ok.meets_usage_target
    assert RecommendationCode.BELOW_USAGE_TARGET not in _codes(ok)


def test_same_password_is_judged_differently_per_usage(analyze: Analyze) -> None:
    pw = "Tr0ub4dor&3"  # ~1e11 guesses
    assert analyze(pw, context=_ctx(usage=PasswordUsage.ONLINE_ACCOUNT)).meets_usage_target
    assert not analyze(pw, context=_ctx(usage=PasswordUsage.ENCRYPTION_KEY)).meets_usage_target


# ----------------------------------------------------------------- usage targets


def test_usage_targets_get_stricter_as_exposure_grows() -> None:
    ladder = [
        PasswordUsage.GENERAL,
        PasswordUsage.ONLINE_ACCOUNT,
        PasswordUsage.PRIVILEGED_ACCOUNT,
        PasswordUsage.MASTER_PASSWORD,
        PasswordUsage.ENCRYPTION_KEY,
    ]
    targets = [USAGE_TARGET_LOG10[u] for u in ladder]
    assert targets == sorted(targets)
    assert targets[0] < targets[-1]


@pytest.mark.parametrize("usage", list(PasswordUsage))
def test_meets_usage_target_boundary(usage: PasswordUsage) -> None:
    base = estimate_strength("password")
    target = USAGE_TARGET_LOG10[usage]
    assert meets_usage_target(base.model_copy(update={"guesses_log10": target}), usage)
    assert not meets_usage_target(base.model_copy(update={"guesses_log10": target - 0.01}), usage)


# --------------------------------------------------------------------- hygiene


def test_messages_never_contain_password_or_personal_info(analyze: Analyze) -> None:
    pw = "Zebulon-Zq7!xKp#9mWv"
    result = analyze(pw, context=_ctx(personal_info=("Zebulon",), reused_elsewhere=True,
                                      usage=PasswordUsage.PRIVILEGED_ACCOUNT))  # fmt: skip
    text = " ".join(r.message for r in result.recommendations).lower()
    assert "zebulon" not in text
    assert pw.lower() not in text
    assert "zq7!xkp" not in text
