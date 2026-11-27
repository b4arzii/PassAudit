"""Shared fixtures for the analysis-engine tests."""

from __future__ import annotations

import pytest

from passaudit.analysis import (
    AnalysisContext,
    PasswordAnalysis,
    PasswordAnalyzer,
    PasswordPolicy,
)

# A random-looking string that appears in no dictionary; used to prove nothing leaks.
CANARY = "Zq7!xKp#9mWv$L2nRb"


@pytest.fixture(scope="session")
def analyzer() -> PasswordAnalyzer:
    return PasswordAnalyzer()


@pytest.fixture
def analyze(analyzer: PasswordAnalyzer):  # type: ignore[no-untyped-def]
    """``analyze(password, policy=None, context=None) -> PasswordAnalysis``."""

    def _analyze(
        password: str,
        *,
        policy: PasswordPolicy | None = None,
        context: AnalysisContext | None = None,
    ) -> PasswordAnalysis:
        return analyzer.analyze_password(password, policy=policy, context=context)

    return _analyze


def only_rule_policy(**rules: object) -> PasswordPolicy:
    """A policy with every default rule switched off except the ones given."""
    base: dict[str, object] = {
        "min_length": 0,
        "min_strength_score": 0,
        "block_common_passwords": False,
        "forbid_personal_info": False,
    }
    base.update(rules)
    return PasswordPolicy(**base)  # type: ignore[arg-type]
