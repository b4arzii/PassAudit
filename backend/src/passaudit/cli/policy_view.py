"""Dict view of the engine's per-rule policy results, for the terminal and CSV/JSON reports."""

from __future__ import annotations

from typing import Any

from passaudit.analysis import PasswordAnalysis, PasswordPolicy, evaluate_rules


def rule_rows(policy: PasswordPolicy, analysis: PasswordAnalysis) -> list[dict[str, Any]]:
    """One record per *enabled* rule (see :func:`passaudit.analysis.evaluate_rules`)."""
    return [result.model_dump(mode="json") for result in evaluate_rules(policy, analysis)]
