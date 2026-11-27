"""Configurable password-policy validation.

Validation is a pure function of (password facts, policy). Violation messages are fixed
templates containing only rule parameters and counts - never password text.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from passaudit.analysis.keyboard import find_keyboard_runs
from passaudit.analysis.models import (
    FindingKind,
    PolicyResult,
    PolicyRule,
    PolicyViolation,
)
from passaudit.analysis.patterns import find_sequences
from passaudit.analysis.text import Span, fold, merge_spans

if TYPE_CHECKING:
    from passaudit.analysis.charsets import CharacterProfile
    from passaudit.analysis.models import (
        ExposureSignals,
        Finding,
        PasswordPolicy,
        StrengthEstimate,
    )


#: A password whose characters are at least this percentage common words/names violates
#: ``block_dictionary_words``.
DICTIONARY_COVERAGE_LIMIT = 60


def dictionary_coverage_percent(findings: tuple[Finding, ...], length: int) -> int:
    """Percentage (0-100) of the password covered by dictionary-word findings."""
    if length <= 0:
        return 0
    spans = merge_spans(
        [Span(f.start, f.length) for f in findings if f.kind is FindingKind.DICTIONARY_WORD]
    )
    return round(100 * sum(s.length for s in spans) / length)


def _longest_repeat_run(password: str) -> int:
    """Longest run of one repeated character (``0`` for an empty password)."""
    if not password:
        return 0
    longest = current = 1
    folded = fold(password)
    prev = folded[0]
    for lowered in folded[1:]:
        current = current + 1 if lowered == prev else 1
        longest = max(longest, current)
        prev = lowered
    return longest


def _longest_sequence(password: str) -> int:
    matches = find_sequences(password, min_length=2)
    return max((m.span.length for m in matches), default=0)


def _longest_keyboard_run(password: str) -> int:
    matches = find_keyboard_runs(password, min_length=2)
    return max((m.span.length for m in matches), default=0)


def _minimum(rule: PolicyRule, label: str, actual: int, required: int) -> PolicyViolation | None:
    if actual >= required:
        return None
    return PolicyViolation(
        rule=rule,
        message=f"Must contain at least {required} {label} (found {actual}).",
        required=required,
        actual=actual,
    )


def _maximum(rule: PolicyRule, label: str, actual: int, allowed: int) -> PolicyViolation | None:
    if actual <= allowed:
        return None
    return PolicyViolation(
        rule=rule,
        message=f"Must not contain {label} longer than {allowed} (found {actual}).",
        required=allowed,
        actual=actual,
    )


def validate_policy(  # noqa: PLR0913 - keyword-only facts, one per detector input
    password: str,
    profile: CharacterProfile,
    policy: PasswordPolicy,
    *,
    strength: StrengthEstimate,
    findings: tuple[Finding, ...],
    exposure: ExposureSignals | None = None,
) -> PolicyResult:
    """Check ``password`` against ``policy`` and list every violated rule."""
    found: list[PolicyViolation | None] = []

    found.append(_minimum(PolicyRule.MIN_LENGTH, "characters", profile.length, policy.min_length))
    if policy.max_length is not None and profile.length > policy.max_length:
        found.append(
            PolicyViolation(
                rule=PolicyRule.MAX_LENGTH,
                message=(
                    f"Must be at most {policy.max_length} characters (found {profile.length})."
                ),
                required=policy.max_length,
                actual=profile.length,
            )
        )
    found.append(
        _minimum(
            PolicyRule.MIN_LOWERCASE, "lowercase letters", profile.lowercase, policy.min_lowercase
        )
    )
    found.append(
        _minimum(
            PolicyRule.MIN_UPPERCASE, "uppercase letters", profile.uppercase, policy.min_uppercase
        )
    )
    found.append(_minimum(PolicyRule.MIN_DIGITS, "digits", profile.digits, policy.min_digits))
    found.append(_minimum(PolicyRule.MIN_SYMBOLS, "symbols", profile.symbols, policy.min_symbols))
    found.append(
        _minimum(
            PolicyRule.MIN_UNIQUE_CHARACTERS,
            "distinct characters",
            profile.unique,
            policy.min_unique_characters,
        )
    )

    if policy.max_repeat_run is not None:
        found.append(
            _maximum(
                PolicyRule.MAX_REPEAT_RUN,
                "runs of one repeated character",
                _longest_repeat_run(password),
                policy.max_repeat_run,
            )
        )
    if policy.max_sequence_length is not None:
        found.append(
            _maximum(
                PolicyRule.MAX_SEQUENCE_LENGTH,
                "ascending/descending sequences",
                _longest_sequence(password),
                policy.max_sequence_length,
            )
        )
    if policy.max_keyboard_run is not None:
        found.append(
            _maximum(
                PolicyRule.MAX_KEYBOARD_RUN,
                "keyboard runs",
                _longest_keyboard_run(password),
                policy.max_keyboard_run,
            )
        )

    if not policy.allow_whitespace and profile.whitespace:
        found.append(
            PolicyViolation(
                rule=PolicyRule.FORBID_WHITESPACE,
                message="Must not contain whitespace.",
                actual=profile.whitespace,
            )
        )

    kinds = {f.kind for f in findings}
    if policy.block_common_passwords and FindingKind.COMMON_PASSWORD in kinds:
        found.append(
            PolicyViolation(
                rule=PolicyRule.BLOCK_COMMON_PASSWORDS,
                message="Must not be, or be built from, a commonly used password.",
            )
        )
    if policy.forbid_personal_info and FindingKind.PERSONAL_INFO in kinds:
        found.append(
            PolicyViolation(
                rule=PolicyRule.FORBID_PERSONAL_INFO,
                message="Must not contain personal information.",
            )
        )
    if policy.block_dictionary_words:
        percent = dictionary_coverage_percent(findings, profile.length)
        if percent >= DICTIONARY_COVERAGE_LIMIT:
            found.append(
                PolicyViolation(
                    rule=PolicyRule.BLOCK_DICTIONARY_WORDS,
                    message=(
                        "Must not be made mostly of common words or names "
                        f"({percent}% of the characters; the limit is "
                        f"{DICTIONARY_COVERAGE_LIMIT - 1}%)."
                    ),
                    required=DICTIONARY_COVERAGE_LIMIT - 1,
                    actual=percent,
                )
            )
    if (
        policy.block_breached_passwords
        and exposure is not None
        and exposure.breach is not None
        and exposure.breach.status == "breached"
    ):
        found.append(
            PolicyViolation(
                rule=PolicyRule.BLOCK_BREACHED_PASSWORDS,
                message="Must not appear in known data breaches.",
            )
        )
    if policy.min_strength_score and strength.score < policy.min_strength_score:
        found.append(
            PolicyViolation(
                rule=PolicyRule.MIN_STRENGTH_SCORE,
                message=(
                    f"Strength score must be at least {policy.min_strength_score} of 4 "
                    f"(found {strength.score})."
                ),
                required=policy.min_strength_score,
                actual=strength.score,
            )
        )

    violations = tuple(v for v in found if v is not None)
    return PolicyResult(compliant=not violations, violations=violations)
