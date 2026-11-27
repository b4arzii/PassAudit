"""Verdicts (pass/fail) and the per-password result record shared by every command."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from passaudit.analysis import PasswordAnalysis, RiskLevel, summarize_analyses

if TYPE_CHECKING:
    from collections.abc import Sequence


class FailOn(StrEnum):
    """Lowest risk level that makes a password *fail* (``none`` disables the risk gate)."""

    NONE = "none"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


_LEVEL_RANK = {
    RiskLevel.LOW: 0,
    RiskLevel.MODERATE: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


@dataclass(frozen=True, slots=True)
class Verdict:
    failed: bool
    reasons: tuple[str, ...]


def judge(analysis: PasswordAnalysis, fail_on: FailOn) -> Verdict:
    """Fail on any policy violation, or when the risk level reaches ``fail_on``."""
    reasons: list[str] = []
    if not analysis.policy.compliant:
        reasons.append("policy_violations")
    if (
        fail_on is not FailOn.NONE
        and _LEVEL_RANK[analysis.risk.level] >= _LEVEL_RANK[RiskLevel(fail_on.value)]
    ):
        reasons.append(f"risk_level_{analysis.risk.level.value}")
    return Verdict(failed=bool(reasons), reasons=tuple(reasons))


@dataclass(slots=True)
class PasswordResult:
    """The outcome for one password. Holds the analysis, never the password."""

    index: int
    length: int
    verdict: Verdict
    analysis: PasswordAnalysis | None = None
    line: int | None = None
    label: str | None = None
    error: str | None = None  # machine-readable code, e.g. "too_long"
    reused_in_batch: bool = False
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        return "error" if self.error else "ok"


def error_result(
    index: int, line: int | None, label: str | None, length: int, code: str
) -> PasswordResult:
    return PasswordResult(
        index=index,
        line=line,
        label=label,
        length=length,
        verdict=Verdict(failed=True, reasons=(f"input_{code}",)),
        error=code,
    )


def summarize(results: Sequence[PasswordResult], *, skipped_blank: int = 0) -> dict[str, Any]:
    """Aggregate statistics for a batch. Contains counts and averages only."""
    shared = summarize_analyses([r.analysis for r in results if r.analysis is not None])
    exposures = [r.analysis.exposure for r in results if r.analysis and r.analysis.exposure]
    return {
        "entries": len(results),
        "analyzed": shared.analyzed,
        "errors": len(results) - shared.analyzed,
        "skipped_blank": skipped_blank,
        "passed": sum(1 for r in results if not r.verdict.failed),
        "failed": sum(1 for r in results if r.verdict.failed),
        "reused_in_batch": sum(1 for r in results if r.reused_in_batch),
        "breach_checked": any(e.breach for e in exposures),
        "breached": sum(1 for e in exposures if e.breach and e.breach.status == "breached"),
        "reuse_checked": any(e.reuse for e in exposures),
        "reused_in_datasets": sum(1 for e in exposures if e.reuse and e.reuse.status == "reused"),
        "average_risk_score": shared.average_risk_score,
        "max_risk_score": shared.max_risk_score,
        "risk_levels": shared.risk_levels,
        "strength_scores": shared.strength_scores,
        "finding_kinds": shared.finding_kinds,
        "recommendation_codes": shared.recommendation_codes,
    }
