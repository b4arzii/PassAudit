"""Policy validation: every rule, each at and either side of its boundary."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from passaudit.analysis import (
    AnalysisContext,
    PasswordAnalysis,
    PasswordPolicy,
    PolicyRule,
)

from .conftest import only_rule_policy

Analyze = Callable[..., PasswordAnalysis]


def _rules(result: PasswordAnalysis) -> set[PolicyRule]:
    return {v.rule for v in result.policy.violations}


# -------------------------------------------------------------------------- model


def test_default_policy_values() -> None:
    p = PasswordPolicy()
    assert p.min_length == 12
    assert p.max_length is None
    assert p.block_common_passwords is True
    assert p.forbid_personal_info is True
    assert p.min_strength_score == 2
    # NIST-style: no mandatory composition rules by default.
    assert (p.min_lowercase, p.min_uppercase, p.min_digits, p.min_symbols) == (0, 0, 0, 0)


def test_policy_is_frozen_and_rejects_unknown_fields() -> None:
    p = PasswordPolicy()
    with pytest.raises(ValidationError):
        p.min_length = 3  # type: ignore[misc]
    with pytest.raises(ValidationError):
        PasswordPolicy(nonsense=1)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"min_length": -1},
        {"min_length": 1025},
        {"max_length": 0},
        {"min_strength_score": 5},
        {"min_strength_score": -1},
        {"max_repeat_run": 0},
        {"max_sequence_length": 1},
        {"max_keyboard_run": 1},
        {"min_digits": -1},
    ],
)
def test_policy_rejects_out_of_range_values(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        PasswordPolicy(**kwargs)


def test_policy_max_length_must_not_be_below_min_length() -> None:
    with pytest.raises(ValidationError, match="max_length"):
        PasswordPolicy(min_length=20, max_length=10)
    PasswordPolicy(min_length=10, max_length=10)  # equal is fine


# ----------------------------------------------------------------------- length rules


@pytest.mark.parametrize(
    ("password", "ok"), [("a" * 11, False), ("a" * 12, True), ("a" * 13, True)]
)
def test_min_length_boundary(analyze: Analyze, password: str, ok: bool) -> None:
    result = analyze(password, policy=only_rule_policy(min_length=12))
    assert (PolicyRule.MIN_LENGTH not in _rules(result)) is ok


def test_min_length_violation_details(analyze: Analyze) -> None:
    (v,) = analyze("abc", policy=only_rule_policy(min_length=12)).policy.violations
    assert (v.rule, v.required, v.actual) == (PolicyRule.MIN_LENGTH, 12, 3)
    assert "12" in v.message


@pytest.mark.parametrize(("length", "ok"), [(19, True), (20, True), (21, False)])
def test_max_length_boundary(analyze: Analyze, length: int, ok: bool) -> None:
    result = analyze("a" * length, policy=only_rule_policy(max_length=20))
    assert (PolicyRule.MAX_LENGTH not in _rules(result)) is ok


def test_min_length_zero_accepts_empty_password(analyze: Analyze) -> None:
    assert analyze("", policy=only_rule_policy(min_length=0)).policy.compliant


def test_empty_password_fails_default_policy(analyze: Analyze) -> None:
    result = analyze("")
    assert not result.policy.compliant
    assert PolicyRule.MIN_LENGTH in _rules(result)


# ------------------------------------------------------------------ composition rules


@pytest.mark.parametrize(
    ("rule", "field", "good", "bad"),
    [
        (PolicyRule.MIN_LOWERCASE, "min_lowercase", "abC", "aBC"),
        (PolicyRule.MIN_UPPERCASE, "min_uppercase", "ABc", "Abc"),
        (PolicyRule.MIN_DIGITS, "min_digits", "a12", "a1b"),
        (PolicyRule.MIN_SYMBOLS, "min_symbols", "a!?", "a!b"),
    ],
)
def test_minimum_class_counts_boundary(
    analyze: Analyze, rule: PolicyRule, field: str, good: str, bad: str
) -> None:
    policy = only_rule_policy(**{field: 2})
    assert rule not in _rules(analyze(good, policy=policy))  # exactly 2: passes
    assert rule in _rules(analyze(bad, policy=policy))  # 1 of 2: fails
    assert rule in _rules(analyze("zzz" if field != "min_lowercase" else "123", policy=policy))


def test_minimum_class_counts_off_by_default(analyze: Analyze) -> None:
    result = analyze("a" * 20, policy=only_rule_policy())
    assert result.policy.compliant


@pytest.mark.parametrize(("password", "ok"), [("abcd", False), ("abcde", True), ("abcdef", True)])
def test_min_unique_characters_boundary(analyze: Analyze, password: str, ok: bool) -> None:
    result = analyze(password, policy=only_rule_policy(min_unique_characters=5))
    assert (PolicyRule.MIN_UNIQUE_CHARACTERS not in _rules(result)) is ok


def test_unique_characters_counts_distinct_not_total(analyze: Analyze) -> None:
    result = analyze("aaaaaaaaab", policy=only_rule_policy(min_unique_characters=3))
    assert PolicyRule.MIN_UNIQUE_CHARACTERS in _rules(result)


# --------------------------------------------------------------------- pattern rules


@pytest.mark.parametrize(("password", "ok"), [("xaay", True), ("xaaay", True), ("xaaaay", False)])
def test_max_repeat_run_boundary(analyze: Analyze, password: str, ok: bool) -> None:
    result = analyze(password, policy=only_rule_policy(max_repeat_run=3))
    assert (PolicyRule.MAX_REPEAT_RUN not in _rules(result)) is ok


def test_max_repeat_run_is_case_insensitive(analyze: Analyze) -> None:
    result = analyze("aAaA", policy=only_rule_policy(max_repeat_run=3))
    assert PolicyRule.MAX_REPEAT_RUN in _rules(result)


def test_max_repeat_run_of_one_forbids_any_doubled_character(analyze: Analyze) -> None:
    policy = only_rule_policy(max_repeat_run=1)
    assert PolicyRule.MAX_REPEAT_RUN in _rules(analyze("aab", policy=policy))
    assert PolicyRule.MAX_REPEAT_RUN not in _rules(analyze("abab", policy=policy))


@pytest.mark.parametrize(("password", "ok"), [("x1z", True), ("xabz", True), ("xabcz", False)])
def test_max_sequence_length_boundary(analyze: Analyze, password: str, ok: bool) -> None:
    result = analyze(password, policy=only_rule_policy(max_sequence_length=2))
    assert (PolicyRule.MAX_SEQUENCE_LENGTH not in _rules(result)) is ok


def test_max_sequence_length_covers_descending_and_digits(analyze: Analyze) -> None:
    policy = only_rule_policy(max_sequence_length=3)
    assert PolicyRule.MAX_SEQUENCE_LENGTH in _rules(analyze("4321", policy=policy))
    assert PolicyRule.MAX_SEQUENCE_LENGTH not in _rules(analyze("321", policy=policy))


@pytest.mark.parametrize(
    ("password", "ok"), [("xasdz", True), ("xasdfz", True), ("xasdfgz", False)]
)
def test_max_keyboard_run_boundary(analyze: Analyze, password: str, ok: bool) -> None:
    result = analyze(password, policy=only_rule_policy(max_keyboard_run=4))
    assert (PolicyRule.MAX_KEYBOARD_RUN not in _rules(result)) is ok


def test_pattern_rules_are_off_by_default(analyze: Analyze) -> None:
    result = analyze("aaaa abcd qwer", policy=only_rule_policy())
    assert not (
        _rules(result)
        & {PolicyRule.MAX_REPEAT_RUN, PolicyRule.MAX_SEQUENCE_LENGTH, PolicyRule.MAX_KEYBOARD_RUN}
    )


# -------------------------------------------------------------- whitespace / lists


def test_whitespace_rule(analyze: Analyze) -> None:
    forbid = only_rule_policy(allow_whitespace=False)
    assert PolicyRule.FORBID_WHITESPACE in _rules(analyze("two words", policy=forbid))
    assert PolicyRule.FORBID_WHITESPACE in _rules(analyze("tab\there", policy=forbid))
    assert PolicyRule.FORBID_WHITESPACE not in _rules(analyze("nospaces", policy=forbid))
    assert PolicyRule.FORBID_WHITESPACE not in _rules(
        analyze("two words", policy=only_rule_policy())
    )


def test_block_common_passwords(analyze: Analyze) -> None:
    on = only_rule_policy(block_common_passwords=True)
    assert PolicyRule.BLOCK_COMMON_PASSWORDS in _rules(analyze("letmein", policy=on))
    assert PolicyRule.BLOCK_COMMON_PASSWORDS in _rules(analyze("Letmein99!", policy=on))
    assert PolicyRule.BLOCK_COMMON_PASSWORDS not in _rules(analyze("Zq7!xKp#9mWv", policy=on))
    assert PolicyRule.BLOCK_COMMON_PASSWORDS not in _rules(
        analyze("letmein", policy=only_rule_policy(block_common_passwords=False))
    )


def test_forbid_personal_info(analyze: Analyze) -> None:
    ctx = AnalysisContext(personal_info=("Jane Doe",))  # type: ignore[arg-type]
    on = only_rule_policy(forbid_personal_info=True)
    assert PolicyRule.FORBID_PERSONAL_INFO in _rules(
        analyze("jane-2024-zzz", policy=on, context=ctx)
    )
    assert PolicyRule.FORBID_PERSONAL_INFO not in _rules(
        analyze("Zq7!xKp#9mWv", policy=on, context=ctx)
    )
    off = only_rule_policy(forbid_personal_info=False)
    assert PolicyRule.FORBID_PERSONAL_INFO not in _rules(
        analyze("jane-2024-zzz", policy=off, context=ctx)
    )


def test_forbid_personal_info_without_context_never_fires(analyze: Analyze) -> None:
    result = analyze("jane-2024-zzz", policy=only_rule_policy(forbid_personal_info=True))
    assert PolicyRule.FORBID_PERSONAL_INFO not in _rules(result)


# ------------------------------------------------------------------- strength score


@pytest.mark.parametrize("minimum", [1, 2, 3, 4])
def test_min_strength_score_boundary(analyze: Analyze, minimum: int) -> None:
    policy = only_rule_policy(min_strength_score=minimum)
    result = analyze("tigger1", policy=policy)  # zxcvbn score is low and stable
    score = result.strength.score
    assert (PolicyRule.MIN_STRENGTH_SCORE in _rules(result)) is (score < minimum)


def test_min_strength_score_zero_disables_rule(analyze: Analyze) -> None:
    assert PolicyRule.MIN_STRENGTH_SCORE not in _rules(
        analyze("a", policy=only_rule_policy(min_strength_score=0))
    )


def test_violation_messages_never_contain_the_password(analyze: Analyze) -> None:
    pw = "Zq7!xKp#9mWv"
    result = analyze(pw, policy=PasswordPolicy(min_length=30, min_digits=9, max_repeat_run=1))
    assert result.policy.violations
    assert all(pw not in v.message for v in result.policy.violations)


def test_pattern_rules_accept_an_empty_password(analyze: Analyze) -> None:
    policy = only_rule_policy(max_repeat_run=1, max_sequence_length=2, max_keyboard_run=2)
    assert analyze("", policy=policy).policy.compliant
