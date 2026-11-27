"""Context-aware recommendations.

Every message is a fixed template (optionally interpolating counts and rule parameters); none
contains password text or the caller's personal information. Output is ordered by priority,
then by a stable rule order.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from passaudit.analysis.models import (
    FindingKind,
    PasswordUsage,
    Priority,
    Recommendation,
    RecommendationCode,
    RiskLevel,
    WordMatchType,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from passaudit.analysis.charsets import CharacterProfile
    from passaudit.analysis.models import (
        AnalysisContext,
        ExposureSignals,
        Finding,
        PasswordPolicy,
        PolicyResult,
        RiskAssessment,
        StrengthEstimate,
    )

#: Minimum recommended length per usage (the policy minimum can only raise it).
USAGE_MIN_LENGTH: dict[PasswordUsage, int] = {
    PasswordUsage.GENERAL: 12,
    PasswordUsage.ONLINE_ACCOUNT: 12,
    PasswordUsage.PRIVILEGED_ACCOUNT: 16,
    PasswordUsage.MASTER_PASSWORD: 16,
    PasswordUsage.ENCRYPTION_KEY: 20,
}

#: Target ``log10(guesses)`` per usage. Throttled online targets need far fewer guesses to
#: resist than secrets an attacker can test offline against a stolen hash or ciphertext.
USAGE_TARGET_LOG10: dict[PasswordUsage, float] = {
    PasswordUsage.GENERAL: 8.0,
    PasswordUsage.ONLINE_ACCOUNT: 8.0,
    PasswordUsage.PRIVILEGED_ACCOUNT: 10.0,
    PasswordUsage.MASTER_PASSWORD: 12.0,
    PasswordUsage.ENCRYPTION_KEY: 14.0,
}

_USAGE_NAME: dict[PasswordUsage, str] = {
    PasswordUsage.GENERAL: "general use",
    PasswordUsage.ONLINE_ACCOUNT: "an online account",
    PasswordUsage.PRIVILEGED_ACCOUNT: "a privileged (admin, financial or recovery) account",
    PasswordUsage.MASTER_PASSWORD: "a password-manager master password",
    PasswordUsage.ENCRYPTION_KEY: "an encryption key or disk/vault passphrase",
}

_PRIORITY_ORDER = {Priority.HIGH: 0, Priority.MEDIUM: 1, Priority.LOW: 2}
_OFFLINE_USAGES = (PasswordUsage.MASTER_PASSWORD, PasswordUsage.ENCRYPTION_KEY)
_MFA_USAGES = (PasswordUsage.ONLINE_ACCOUNT, PasswordUsage.PRIVILEGED_ACCOUNT)


def meets_usage_target(strength: StrengthEstimate, usage: PasswordUsage) -> bool:
    """Whether estimated guessability reaches the target for ``usage``."""
    return strength.guesses_log10 >= USAGE_TARGET_LOG10[usage]


@dataclass(frozen=True, slots=True)
class _Facts:
    """Everything the rules look at. Contains no password text."""

    profile: CharacterProfile
    strength: StrengthEstimate
    findings: tuple[Finding, ...]
    policy: PasswordPolicy
    policy_result: PolicyResult
    risk: RiskAssessment
    context: AnalysisContext
    exposure: ExposureSignals | None = None

    @property
    def usage(self) -> PasswordUsage:
        return self.context.usage

    @property
    def kinds(self) -> set[FindingKind]:
        return {f.kind for f in self.findings}

    @property
    def word_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.kind is FindingKind.COMMON_PASSWORD]

    @property
    def below_target(self) -> bool:
        return not meets_usage_target(self.strength, self.usage)


def _rec(code: RecommendationCode, priority: Priority, message: str) -> Recommendation:
    return Recommendation(code=code, priority=priority, message=message)


# --------------------------------------------------------------------------- rules
# Each rule returns zero or more recommendations. Their order below is the tie-break order
# within a priority tier.


def _breached(f: _Facts) -> list[Recommendation]:
    breach = f.exposure.breach if f.exposure else None
    if breach is None or breach.status != "breached":
        return []
    return [
        _rec(
            RecommendationCode.CHANGE_BREACHED_PASSWORD,
            Priority.HIGH,
            "This password appears in known data-breach data, so attackers already have it. "
            "Stop using it everywhere and choose a new, unique one.",
        )
    ]


def _reuse(f: _Facts) -> list[Recommendation]:
    if not f.context.reused_elsewhere:
        return []
    return [
        _rec(
            RecommendationCode.UNIQUE_PER_SERVICE,
            Priority.HIGH,
            "Never reuse a password across services: one breach exposes every account that "
            "shares it. Give each service its own password.",
        )
    ]


def _common_password(f: _Facts) -> list[Recommendation]:
    if not f.word_findings:
        return []
    whole = any(w.match_type is not WordMatchType.EMBEDDED for w in f.word_findings)
    return [
        _rec(
            RecommendationCode.AVOID_COMMON_PASSWORD,
            Priority.HIGH if whole else Priority.MEDIUM,
            "This password is, or is built around, a commonly used password. Attackers try "
            "these first, including with digits, symbols and letter substitutions added. "
            "Choose something unrelated to common words and phrases.",
        )
    ]


def _personal_info(f: _Facts) -> list[Recommendation]:
    if FindingKind.PERSONAL_INFO not in f.kinds:
        return []
    return [
        _rec(
            RecommendationCode.AVOID_PERSONAL_INFO,
            Priority.HIGH,
            "The password contains personal information (such as a name, username or e-mail "
            "fragment). Anyone who knows you can guess it; remove it.",
        )
    ]


def _policy(f: _Facts) -> list[Recommendation]:
    if f.policy_result.compliant:
        return []
    count = len(f.policy_result.violations)
    return [
        _rec(
            RecommendationCode.MEET_POLICY,
            Priority.HIGH,
            f"The password breaks {count} rule{'s' if count != 1 else ''} of the required "
            "password policy; see the policy result for details.",
        )
    ]


def _length(f: _Facts) -> list[Recommendation]:
    target = max(f.policy.min_length, USAGE_MIN_LENGTH[f.usage])
    if f.profile.length >= target:
        return []
    urgent = f.profile.length < 8 or f.usage is not PasswordUsage.GENERAL
    return [
        _rec(
            RecommendationCode.LENGTHEN,
            Priority.HIGH if urgent else Priority.MEDIUM,
            f"Use at least {target} characters for {_USAGE_NAME[f.usage]}; length adds "
            "more protection than any other change.",
        )
    ]


def _usage_target(f: _Facts) -> list[Recommendation]:
    if not f.below_target:
        return []
    return [
        _rec(
            RecommendationCode.BELOW_USAGE_TARGET,
            Priority.HIGH,
            f"The estimated strength is below what {_USAGE_NAME[f.usage]} needs. Treat this "
            "password as unsafe for that purpose.",
        )
    ]


def _patterns(f: _Facts) -> list[Recommendation]:
    out: list[Recommendation] = []
    if FindingKind.KEYBOARD_PATTERN in f.kinds:
        out.append(
            _rec(
                RecommendationCode.AVOID_KEYBOARD_PATTERNS,
                Priority.MEDIUM,
                "Keyboard runs like 'asdf' or '1qaz' are among the first things attackers "
                "try. Avoid typing along the keyboard.",
            )
        )
    if f.kinds & {FindingKind.REPEATED_CHARACTERS, FindingKind.REPEATED_BLOCK}:
        out.append(
            _rec(
                RecommendationCode.AVOID_REPEATS,
                Priority.MEDIUM,
                "Repeated characters or repeated blocks add length without adding "
                "unpredictability. Replace them with unrelated characters or words.",
            )
        )
    if FindingKind.SEQUENCE in f.kinds:
        out.append(
            _rec(
                RecommendationCode.AVOID_SEQUENCES,
                Priority.MEDIUM,
                "Sequences such as 'abc' or '4321' are trivially guessed. Avoid counting up "
                "or down through letters and digits.",
            )
        )
    return out


def _passphrase_or_manager(f: _Facts) -> list[Recommendation]:
    if f.usage in _OFFLINE_USAGES:
        if f.below_target or f.profile.length < 20:
            return [
                _rec(
                    RecommendationCode.USE_PASSPHRASE,
                    Priority.MEDIUM,
                    "For a secret you must memorise, use a passphrase of five or more "
                    "randomly chosen words (for example generated with dice). It is both "
                    "stronger and easier to remember than a short complex password.",
                )
            ]
        return []
    if f.risk.level is not RiskLevel.LOW or f.below_target:
        return [
            _rec(
                RecommendationCode.USE_PASSWORD_MANAGER,
                Priority.MEDIUM,
                "Let a password manager generate and store a long random password for this "
                "service, so you do not have to remember or invent it.",
            )
        ]
    return []


def _mfa(f: _Facts) -> list[Recommendation]:
    if f.usage not in _MFA_USAGES:
        return []
    return [
        _rec(
            RecommendationCode.ENABLE_MFA,
            Priority.MEDIUM if f.usage is PasswordUsage.PRIVILEGED_ACCOUNT else Priority.LOW,
            "Turn on multi-factor authentication (a passkey or authenticator app is best) so "
            "a guessed or leaked password alone is not enough to get in.",
        )
    ]


def _variety(f: _Facts) -> list[Recommendation]:
    if f.profile.length >= 12 or f.profile.class_count > 2 or f.word_findings:
        return []
    return [
        _rec(
            RecommendationCode.ADD_VARIETY,
            Priority.LOW,
            "A short password drawn from only one or two character types has a small search "
            "space. Adding length, or mixing in other character types, enlarges it.",
        )
    ]


def _dates_and_words(f: _Facts) -> list[Recommendation]:
    out: list[Recommendation] = []
    if FindingKind.DATE in f.kinds:
        out.append(
            _rec(
                RecommendationCode.AVOID_DATES,
                Priority.MEDIUM,
                "Dates and years (birthdays, anniversaries, the current year) are among the "
                "first guesses an attacker makes. Leave them out.",
            )
        )
    if FindingKind.DICTIONARY_WORD in f.kinds and f.below_target:
        out.append(
            _rec(
                RecommendationCode.AVOID_DICTIONARY_WORDS,
                Priority.LOW,
                "Common words and first names shrink the search space, and this password is not "
                "strong enough for its purpose. Use a longer passphrase of several unrelated, "
                "randomly chosen words, or a random password from a manager.",
            )
        )
    return out


_RULES: tuple[Callable[[_Facts], list[Recommendation]], ...] = (
    _breached,
    _reuse,
    _common_password,
    _personal_info,
    _policy,
    _length,
    _usage_target,
    _patterns,
    _dates_and_words,
    _passphrase_or_manager,
    _mfa,
    _variety,
)


def build_recommendations(  # noqa: PLR0913 - keyword-only; mirrors the analysis facts
    *,
    profile: CharacterProfile,
    strength: StrengthEstimate,
    findings: tuple[Finding, ...],
    policy: PasswordPolicy,
    policy_result: PolicyResult,
    risk: RiskAssessment,
    context: AnalysisContext,
    exposure: ExposureSignals | None = None,
) -> tuple[Recommendation, ...]:
    """Produce prioritised advice from the analysis facts and the caller's context."""
    facts = _Facts(
        profile=profile,
        strength=strength,
        findings=findings,
        policy=policy,
        policy_result=policy_result,
        risk=risk,
        context=context,
        exposure=exposure,
    )
    out = [rec for rule in _RULES for rec in rule(facts)]
    if not out:
        out.append(
            _rec(
                RecommendationCode.LOOKS_GOOD,
                Priority.LOW,
                "No specific weaknesses were detected. Keep this password unique to one "
                "service and store it in a password manager.",
            )
        )
    out.sort(key=lambda r: _PRIORITY_ORDER[r.priority])  # stable within a tier
    return tuple(out)
