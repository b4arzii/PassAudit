"""Transparent risk scoring.

The risk score runs from 0 (no detected risk) to 100 (certainly compromised). It is the sum of
a fixed, published set of components, each capped, whose caps add up to exactly 100:

=================  =====  ===============================================================
Factor             Max    How points are earned
=================  =====  ===============================================================
guessability        50    ``50 * (1 - min(guesses_log10, 12) / 12)`` - zxcvbn's estimate
length              10    <8 chars: 10, <12: 6, <16: 3, otherwise 0
common_password     15    exact 15, reversed 12, leet 12, decorated 10, embedded 5
                          (summed, capped)
patterns            10    repeat 3, sequence 3, keyboard 4 per finding (summed, capped)
personal_info       10    10 if the password contains supplied personal information
policy               5    1 per violated policy rule (capped)
=================  =====  ===============================================================

A *floor* then applies: a password that **is** (or is a trivial variation of) a known common
password can never score below ``KNOWN_WEAK_FLOOR``, however long it is. The floor shows up as
its own component so ``score == sum(component.points)`` always holds.

Risk levels: 0-19 low, 20-39 moderate, 40-69 high, 70-100 critical.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from passaudit.analysis.models import (
    FindingKind,
    RiskAssessment,
    RiskComponent,
    RiskFactor,
    RiskLevel,
    WordMatchType,
)

if TYPE_CHECKING:
    from passaudit.analysis.models import (
        ExposureSignals,
        Finding,
        PolicyResult,
        StrengthEstimate,
    )

GUESSABILITY_MAX = 50
GUESSABILITY_TARGET_LOG10 = 12.0  # 1e12 guesses earns zero guessability risk
LENGTH_MAX = 10
COMMON_PASSWORD_MAX = 15
PATTERNS_MAX = 10
PERSONAL_INFO_MAX = 10
POLICY_MAX = 5
KNOWN_WEAK_FLOOR = 85
FLOOR_MIN_COVERAGE = 0.6  # fraction of the password a whole-word match must cover

# (upper bound exclusive, points); the last row catches everything longer.
LENGTH_BANDS: tuple[tuple[int, int], ...] = ((8, 10), (12, 6), (16, 3))

WORD_POINTS: dict[WordMatchType, int] = {
    WordMatchType.EXACT: 15,
    WordMatchType.REVERSED: 12,
    WordMatchType.LEET: 12,
    WordMatchType.DECORATED: 10,
    WordMatchType.EMBEDDED: 5,
}
_FLOOR_TYPES = frozenset(
    {
        WordMatchType.EXACT,
        WordMatchType.REVERSED,
        WordMatchType.LEET,
        WordMatchType.DECORATED,
    }
)
PATTERN_POINTS: dict[FindingKind, int] = {
    FindingKind.REPEATED_CHARACTERS: 3,
    FindingKind.REPEATED_BLOCK: 3,
    FindingKind.SEQUENCE: 3,
    FindingKind.KEYBOARD_PATTERN: 4,
    FindingKind.DATE: 2,
    FindingKind.DICTIONARY_WORD: 2,
}


def guessability_points(guesses_log10: float) -> int:
    ratio = min(max(guesses_log10, 0.0), GUESSABILITY_TARGET_LOG10) / GUESSABILITY_TARGET_LOG10
    return round(GUESSABILITY_MAX * (1 - ratio))


def length_points(length: int) -> int:
    for upper, points in LENGTH_BANDS:
        if length < upper:
            return points
    return 0


def _plural(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def assess_risk(
    *,
    length: int,
    strength: StrengthEstimate,
    findings: tuple[Finding, ...],
    policy: PolicyResult,
    exposure: ExposureSignals | None = None,
) -> RiskAssessment:
    """Build the transparent risk assessment. Inputs contain no password text."""
    components: list[RiskComponent] = []

    guess = guessability_points(strength.guesses_log10)
    components.append(
        RiskComponent(
            factor=RiskFactor.GUESSABILITY,
            points=guess,
            max_points=GUESSABILITY_MAX,
            explanation=(
                f"Estimated {strength.guesses_log10:.1f} (log10) guesses needed; "
                f"{GUESSABILITY_TARGET_LOG10:.0f} or more earns no risk."
            ),
        )
    )

    components.append(
        RiskComponent(
            factor=RiskFactor.LENGTH,
            points=length_points(length),
            max_points=LENGTH_MAX,
            explanation=f"{_plural(length, 'character')} (under 16 adds risk, under 8 the most).",
        )
    )

    word_findings = [
        f for f in findings if f.kind is FindingKind.COMMON_PASSWORD and f.match_type is not None
    ]
    word_points = min(
        COMMON_PASSWORD_MAX, sum(WORD_POINTS[f.match_type] for f in word_findings if f.match_type)
    )
    components.append(
        RiskComponent(
            factor=RiskFactor.COMMON_PASSWORD,
            points=word_points,
            max_points=COMMON_PASSWORD_MAX,
            explanation=(
                f"{_plural(len(word_findings), 'match')} against the common-password list."
                if word_findings
                else "No match against the common-password list."
            ),
        )
    )

    pattern_findings = [f for f in findings if f.kind in PATTERN_POINTS]
    pattern_points = min(PATTERNS_MAX, sum(PATTERN_POINTS[f.kind] for f in pattern_findings))
    components.append(
        RiskComponent(
            factor=RiskFactor.PATTERNS,
            points=pattern_points,
            max_points=PATTERNS_MAX,
            explanation=(
                f"{_plural(len(pattern_findings), 'predictable pattern')} found "
                "(repeats, sequences, keyboard paths, dates, dictionary words)."
                if pattern_findings
                else "No repeats, sequences, keyboard paths, dates or dictionary words found."
            ),
        )
    )

    has_personal = any(f.kind is FindingKind.PERSONAL_INFO for f in findings)
    components.append(
        RiskComponent(
            factor=RiskFactor.PERSONAL_INFO,
            points=PERSONAL_INFO_MAX if has_personal else 0,
            max_points=PERSONAL_INFO_MAX,
            explanation=(
                "Contains information an attacker could learn about the owner."
                if has_personal
                else "No supplied personal information found."
            ),
        )
    )

    violations = len(policy.violations)
    components.append(
        RiskComponent(
            factor=RiskFactor.POLICY,
            points=min(POLICY_MAX, violations),
            max_points=POLICY_MAX,
            explanation=f"{_plural(violations, 'policy rule')} violated (1 point each).",
        )
    )

    subtotal = sum(c.points for c in components)

    covered = max(
        (f.length for f in word_findings if f.match_type in _FLOOR_TYPES),
        default=0,
    )
    breached = (
        exposure is not None
        and exposure.breach is not None
        and exposure.breach.status == "breached"
    )
    if length == 0:
        floor, reason = 100, "An empty password offers no protection."
    elif breached:
        floor, reason = KNOWN_WEAK_FLOOR, "Appears in known data-breach data."
    elif covered and covered / length >= FLOOR_MIN_COVERAGE:
        floor, reason = (
            KNOWN_WEAK_FLOOR,
            "Is, or is a trivial variation of, a known common password.",
        )
    else:
        floor, reason = 0, ""
    if floor > subtotal:
        components.append(
            RiskComponent(
                factor=RiskFactor.KNOWN_WEAK_FLOOR,
                points=floor - subtotal,
                max_points=None,
                explanation=f"{reason} Raised to the minimum score of {floor}.",
            )
        )

    score = sum(c.points for c in components)
    return RiskAssessment(
        score=score, level=RiskLevel.from_score(score), components=tuple(components)
    )
