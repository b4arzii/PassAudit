"""Which policy rules apply, and how one analysed password fared against each.

Shared by every front end (CLI tables, API responses) so the wording and the pass/fail logic
exist exactly once. Contains no password text: requirements are templates over policy values
and failure details come from the engine's own (password-free) violations.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict

from passaudit.analysis.models import PasswordAnalysis, PasswordPolicy, PolicyRule


class PolicyRuleResult(BaseModel):
    """The outcome of one *enabled* policy rule for one password."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule: PolicyRule
    requirement: str
    #: ``unchecked``: the rule needs an opt-in lookup (breach check) that was not run.
    status: Literal["pass", "fail", "unchecked"]
    required: int | None = None
    actual: int | None = None
    message: str | None = None


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


_Describe = tuple[PolicyRule, Callable[[PasswordPolicy], bool], Callable[[PasswordPolicy], str]]

# (rule, is_enabled(policy), requirement text(policy))
_RULES: tuple[_Describe, ...] = (
    (
        PolicyRule.MIN_LENGTH,
        lambda p: p.min_length > 0,
        lambda p: f"At least {_plural(p.min_length, 'character')}",
    ),
    (
        PolicyRule.MAX_LENGTH,
        lambda p: p.max_length is not None,
        lambda p: f"At most {_plural(p.max_length or 0, 'character')}",
    ),
    (
        PolicyRule.MIN_LOWERCASE,
        lambda p: p.min_lowercase > 0,
        lambda p: f"At least {_plural(p.min_lowercase, 'lowercase letter')}",
    ),
    (
        PolicyRule.MIN_UPPERCASE,
        lambda p: p.min_uppercase > 0,
        lambda p: f"At least {_plural(p.min_uppercase, 'uppercase letter')}",
    ),
    (
        PolicyRule.MIN_DIGITS,
        lambda p: p.min_digits > 0,
        lambda p: f"At least {_plural(p.min_digits, 'digit')}",
    ),
    (
        PolicyRule.MIN_SYMBOLS,
        lambda p: p.min_symbols > 0,
        lambda p: f"At least {_plural(p.min_symbols, 'symbol')}",
    ),
    (
        PolicyRule.MIN_UNIQUE_CHARACTERS,
        lambda p: p.min_unique_characters > 0,
        lambda p: f"At least {_plural(p.min_unique_characters, 'distinct character')}",
    ),
    (
        PolicyRule.MAX_REPEAT_RUN,
        lambda p: p.max_repeat_run is not None,
        lambda p: f"No more than {p.max_repeat_run} identical characters in a row",
    ),
    (
        PolicyRule.MAX_SEQUENCE_LENGTH,
        lambda p: p.max_sequence_length is not None,
        lambda p: f"No ascending/descending sequence longer than {p.max_sequence_length}",
    ),
    (
        PolicyRule.MAX_KEYBOARD_RUN,
        lambda p: p.max_keyboard_run is not None,
        lambda p: f"No keyboard run longer than {p.max_keyboard_run}",
    ),
    (
        PolicyRule.FORBID_WHITESPACE,
        lambda p: not p.allow_whitespace,
        lambda _p: "No whitespace characters",
    ),
    (
        PolicyRule.BLOCK_COMMON_PASSWORDS,
        lambda p: p.block_common_passwords,
        lambda _p: "Not a common password (or a simple variation of one)",
    ),
    (
        PolicyRule.FORBID_PERSONAL_INFO,
        lambda p: p.forbid_personal_info,
        lambda _p: "Contains no supplied personal information",
    ),
    (
        PolicyRule.MIN_STRENGTH_SCORE,
        lambda p: p.min_strength_score > 0,
        lambda p: f"Strength score of at least {p.min_strength_score} (scale 0-4)",
    ),
    (
        PolicyRule.BLOCK_DICTIONARY_WORDS,
        lambda p: p.block_dictionary_words,
        lambda _p: "Not made mostly of common words or names",
    ),
    (
        PolicyRule.BLOCK_BREACHED_PASSWORDS,
        lambda p: p.block_breached_passwords,
        lambda _p: "Not found in known data breaches",
    ),
)


def _breach_checked(analysis: PasswordAnalysis) -> bool:
    exposure = analysis.exposure
    return (
        exposure is not None
        and exposure.breach is not None
        and exposure.breach.status != "unavailable"
    )


def evaluate_rules(policy: PasswordPolicy, analysis: PasswordAnalysis) -> list[PolicyRuleResult]:
    """One result per *enabled* rule: requirement text, pass/fail, and failure details."""
    violations = {v.rule: v for v in analysis.policy.violations}
    results: list[PolicyRuleResult] = []
    for rule, enabled, requirement in _RULES:
        if not enabled(policy):
            continue
        violation = violations.get(rule)
        if rule is PolicyRule.BLOCK_BREACHED_PASSWORDS and not _breach_checked(analysis):
            results.append(
                PolicyRuleResult(
                    rule=rule,
                    requirement=requirement(policy),
                    status="unchecked",
                    message="No breach check was run (it is opt-in); this rule was not evaluated.",
                )
            )
            continue
        results.append(
            PolicyRuleResult(
                rule=rule,
                requirement=requirement(policy),
                status="fail" if violation else "pass",
                required=violation.required if violation else None,
                actual=violation.actual if violation else None,
                message=violation.message if violation else None,
            )
        )
    return results
