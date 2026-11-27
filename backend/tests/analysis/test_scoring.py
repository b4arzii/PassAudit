"""Transparent risk scoring: levels, components, the known-weak floor, and invariants."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from passaudit.analysis import (
    FindingKind,
    PasswordAnalysis,
    PasswordPolicy,
    RiskFactor,
    RiskLevel,
)
from passaudit.analysis.scoring import (
    COMMON_PASSWORD_MAX,
    GUESSABILITY_MAX,
    KNOWN_WEAK_FLOOR,
    LENGTH_MAX,
    PATTERNS_MAX,
    PERSONAL_INFO_MAX,
    POLICY_MAX,
    guessability_points,
    length_points,
)

Analyze = Callable[..., PasswordAnalysis]
STRONG = "Zq7!xKp#9mWv$L2nRb"


def _component(result: PasswordAnalysis, factor: RiskFactor) -> int:
    return next(c.points for c in result.risk.components if c.factor is factor)


# ---------------------------------------------------------------------- risk levels


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, RiskLevel.LOW),
        (19, RiskLevel.LOW),
        (20, RiskLevel.MODERATE),
        (39, RiskLevel.MODERATE),
        (40, RiskLevel.HIGH),
        (69, RiskLevel.HIGH),
        (70, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_boundaries(score: int, level: RiskLevel) -> None:
    assert RiskLevel.from_score(score) is level


# ------------------------------------------------------------------ point functions


@pytest.mark.parametrize(
    ("log10", "points"),
    [(-5.0, 50), (0.0, 50), (6.0, 25), (12.0, 0), (13.0, 0), (1000.0, 0), (3.0, 38)],
)
def test_guessability_points(log10: float, points: int) -> None:
    assert guessability_points(log10) == points


def test_guessability_points_never_increase_with_strength() -> None:
    values = [guessability_points(x / 2) for x in range(0, 40)]
    assert values == sorted(values, reverse=True)


@pytest.mark.parametrize(
    ("length", "points"),
    [(0, 10), (7, 10), (8, 6), (11, 6), (12, 3), (15, 3), (16, 0), (17, 0), (1024, 0)],
)
def test_length_points_boundaries(length: int, points: int) -> None:
    assert length_points(length) == points


def test_component_caps_sum_to_exactly_one_hundred() -> None:
    caps = GUESSABILITY_MAX + LENGTH_MAX + COMMON_PASSWORD_MAX + PATTERNS_MAX
    caps += PERSONAL_INFO_MAX + POLICY_MAX
    assert caps == 100


# -------------------------------------------------------------------- transparency


@pytest.mark.parametrize(
    "password",
    ["", "a", "password", "Password123!", "abcd1234", "qwertyuiop", "aaaaaaaaaaaa",
     "Tr0ub4dor&3", "correct horse battery staple", STRONG, "jane1990!", "x" * 300],
)  # fmt: skip
def test_score_is_exactly_the_sum_of_components(analyze: Analyze, password: str) -> None:
    risk = analyze(password).risk
    assert risk.score == sum(c.points for c in risk.components)
    assert 0 <= risk.score <= 100
    assert risk.level is RiskLevel.from_score(risk.score)


def test_every_factor_is_always_listed(analyze: Analyze) -> None:
    factors = [c.factor for c in analyze(STRONG).risk.components]
    assert factors == [
        RiskFactor.GUESSABILITY,
        RiskFactor.LENGTH,
        RiskFactor.COMMON_PASSWORD,
        RiskFactor.PATTERNS,
        RiskFactor.PERSONAL_INFO,
        RiskFactor.POLICY,
    ]


def test_components_stay_within_their_caps(analyze: Analyze) -> None:
    for password in ["", "password", "aaaabbbbccccdddd", STRONG]:
        for c in analyze(password).risk.components:
            if c.max_points is not None:
                assert 0 <= c.points <= c.max_points
            assert c.explanation


def test_scoring_is_deterministic(analyze: Analyze) -> None:
    assert analyze("Password123!").risk == analyze("Password123!").risk


# -------------------------------------------------------------------- calibration


def test_strong_random_password_has_zero_risk(analyze: Analyze) -> None:
    result = analyze(STRONG)
    assert result.risk.score == 0
    assert result.risk.level is RiskLevel.LOW


def test_long_passphrase_is_low_risk(analyze: Analyze) -> None:
    assert analyze("correct horse battery staple").risk.level is RiskLevel.LOW


def test_empty_password_is_the_worst_possible(analyze: Analyze) -> None:
    risk = analyze("").risk
    assert risk.score == 100
    assert risk.level is RiskLevel.CRITICAL
    assert any(c.factor is RiskFactor.KNOWN_WEAK_FLOOR for c in risk.components)


def test_risk_decreases_as_a_password_gets_longer_and_stronger(analyze: Analyze) -> None:
    scores = [analyze(p).risk.score for p in ["a", "q7Xp", "q7Xp#m2K", "xK9#mQ2$vL7!zR4&"]]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] > scores[-1]


# ------------------------------------------------------------------ known-weak floor


@pytest.mark.parametrize(
    "password",
    ["password", "PASSWORD", "drowssap", "p4ssw0rd", "Password123!", "letmein99", "!!dragon!!"],
)
def test_known_weak_passwords_are_floored(analyze: Analyze, password: str) -> None:
    risk = analyze(password).risk
    assert risk.score >= KNOWN_WEAK_FLOOR
    assert risk.level is RiskLevel.CRITICAL


def test_floor_component_appears_only_when_it_changes_the_score(analyze: Analyze) -> None:
    floored = analyze("password").risk
    assert any(c.factor is RiskFactor.KNOWN_WEAK_FLOOR and c.points > 0 for c in floored.components)
    clean = analyze(STRONG).risk
    assert all(c.factor is not RiskFactor.KNOWN_WEAK_FLOOR for c in clean.components)


def test_common_word_inside_a_long_random_string_is_not_floored(analyze: Analyze) -> None:
    result = analyze("password" + "Xk9#mQ2$vL7!zR4&nB6")
    kinds = {f.kind for f in result.findings}
    assert FindingKind.COMMON_PASSWORD in kinds  # still reported...
    assert result.risk.score < KNOWN_WEAK_FLOOR  # ...but not treated as a bare common password
    assert result.risk.level is not RiskLevel.CRITICAL


def test_floor_coverage_boundary(analyze: Analyze) -> None:
    # "dragon" is 6 characters; decoration makes it a DECORATED match covering 6/n.
    assert analyze("dragon1234").risk.score >= KNOWN_WEAK_FLOOR  # 6/10 = 0.6: floored
    assert analyze("dragon12345").risk.score < KNOWN_WEAK_FLOOR  # 6/11 < 0.6: not floored


def test_embedded_matches_never_trigger_the_floor(analyze: Analyze) -> None:
    result = analyze("dragonXkQm")  # 6/10 covered, but only as an embedded word
    assert {f.match_type.value for f in result.findings if f.match_type} == {"embedded"}
    assert result.risk.score < KNOWN_WEAK_FLOOR


# ---------------------------------------------------------------- component details


def test_common_password_points_by_match_type(analyze: Analyze) -> None:
    assert _component(analyze("password"), RiskFactor.COMMON_PASSWORD) == 15  # exact
    assert _component(analyze("drowssap"), RiskFactor.COMMON_PASSWORD) == 12  # reversed
    assert _component(analyze("Password1!!"), RiskFactor.COMMON_PASSWORD) == 10  # decorated
    assert _component(analyze("xxdragonxx"), RiskFactor.COMMON_PASSWORD) == 5  # embedded
    assert _component(analyze(STRONG), RiskFactor.COMMON_PASSWORD) == 0


def test_pattern_points_accumulate_then_cap(analyze: Analyze) -> None:
    assert _component(analyze("xK9#mQ2$vL7!zR4&nB"), RiskFactor.PATTERNS) == 0
    one = _component(analyze("zzzK9#mQ2$vL7!r4&nB"), RiskFactor.PATTERNS)
    assert one == 3
    many = _component(analyze("aaaXbbbXcccXdddXeee"), RiskFactor.PATTERNS)
    assert many == PATTERNS_MAX


def test_policy_points_one_per_violation_capped(analyze: Analyze) -> None:
    harsh = PasswordPolicy(min_length=40, min_digits=9, min_uppercase=9, min_symbols=9,
                           min_lowercase=40, min_unique_characters=40)  # fmt: skip
    result = analyze("abc", policy=harsh)
    assert len(result.policy.violations) > POLICY_MAX
    assert _component(result, RiskFactor.POLICY) == POLICY_MAX
    one = analyze(STRONG, policy=PasswordPolicy(min_length=40))
    assert _component(one, RiskFactor.POLICY) == 1
