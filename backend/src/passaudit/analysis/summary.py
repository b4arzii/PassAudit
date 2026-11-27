"""Aggregate statistics over many analyses (counts and averages only, no password data)."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from passaudit.analysis.models import RiskLevel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from passaudit.analysis.models import PasswordAnalysis


class AnalysisSummary(BaseModel):
    """Roll-up of a set of :class:`PasswordAnalysis` results."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    analyzed: int
    policy_compliant: int
    policy_violations: int  # passwords that violate at least one rule
    average_risk_score: float | None
    max_risk_score: int | None
    risk_levels: dict[str, int]
    strength_scores: dict[str, int]
    finding_kinds: dict[str, int]  # passwords exhibiting each kind of finding
    recommendation_codes: dict[str, int]


def summarize_analyses(analyses: Sequence[PasswordAnalysis]) -> AnalysisSummary:
    levels: Counter[str] = Counter()
    scores: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    advice: Counter[str] = Counter()
    for analysis in analyses:
        levels[analysis.risk.level.value] += 1
        scores[str(analysis.strength.score)] += 1
        kinds.update({f.kind.value for f in analysis.findings})
        advice.update(rec.code.value for rec in analysis.recommendations)
    risk_values = [a.risk.score for a in analyses]
    compliant = sum(1 for a in analyses if a.policy.compliant)
    return AnalysisSummary(
        analyzed=len(analyses),
        policy_compliant=compliant,
        policy_violations=len(analyses) - compliant,
        average_risk_score=round(sum(risk_values) / len(risk_values), 1) if risk_values else None,
        max_risk_score=max(risk_values) if risk_values else None,
        risk_levels={lvl.value: levels.get(lvl.value, 0) for lvl in RiskLevel},
        strength_scores={str(n): scores.get(str(n), 0) for n in range(5)},
        finding_kinds=dict(sorted(kinds.items())),
        recommendation_codes=dict(sorted(advice.items())),
    )
