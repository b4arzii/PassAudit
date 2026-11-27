"""PassAudit password-analysis engine.

A pure, self-contained library: it knows nothing about HTTP, FastAPI or any UI, performs no
I/O while analysing (the bundled word list is read once, lazily), and never logs, prints,
persists or returns the password. See ``docs/analysis-engine.md``.

Typical use::

    from passaudit.analysis import analyze_password

    result = analyze_password("correct horse battery staple")
    result.risk.score, result.risk.level, result.recommendations
"""

from passaudit.analysis.analyzer import (
    ANALYSIS_VERSION,
    AnalyzerConfig,
    PasswordAnalyzer,
    analyze_password,
)
from passaudit.analysis.batch import (
    BatchItemResult,
    ReuseTracker,
    analyze_batch,
    safe_label,
    sanitize_label,
)
from passaudit.analysis.dictionaries import DictionaryKind, DictionarySet
from passaudit.analysis.errors import AnalysisError, PasswordTooLongError
from passaudit.analysis.models import (
    AnalysisContext,
    AnalysisRequest,
    BreachExposure,
    CrackTimeEstimates,
    EntropyEstimate,
    ExposureSignals,
    Finding,
    FindingKind,
    PasswordAnalysis,
    PasswordPolicy,
    PasswordUsage,
    PolicyResult,
    PolicyRule,
    PolicyViolation,
    Priority,
    Recommendation,
    RecommendationCode,
    ReuseExposure,
    RiskAssessment,
    RiskComponent,
    RiskFactor,
    RiskLevel,
    StrengthEstimate,
    StrengthLabel,
    StrengthSegment,
    WordMatchType,
)
from passaudit.analysis.policy_view import PolicyRuleResult, evaluate_rules
from passaudit.analysis.profiles import (
    BUILTIN_PROFILES,
    PolicyProfile,
    PolicyProfileError,
    ProfileRegistry,
    UnknownProfileError,
)
from passaudit.analysis.summary import AnalysisSummary, summarize_analyses
from passaudit.analysis.wordlist import WordList

__all__ = [
    "ANALYSIS_VERSION",
    "BUILTIN_PROFILES",
    "AnalysisContext",
    "AnalysisError",
    "AnalysisRequest",
    "AnalysisSummary",
    "AnalyzerConfig",
    "BatchItemResult",
    "BreachExposure",
    "CrackTimeEstimates",
    "DictionaryKind",
    "DictionarySet",
    "EntropyEstimate",
    "ExposureSignals",
    "Finding",
    "FindingKind",
    "PasswordAnalysis",
    "PasswordAnalyzer",
    "PasswordPolicy",
    "PasswordTooLongError",
    "PasswordUsage",
    "PolicyProfile",
    "PolicyProfileError",
    "PolicyResult",
    "PolicyRule",
    "PolicyRuleResult",
    "PolicyViolation",
    "Priority",
    "ProfileRegistry",
    "Recommendation",
    "RecommendationCode",
    "ReuseExposure",
    "ReuseTracker",
    "RiskAssessment",
    "RiskComponent",
    "RiskFactor",
    "RiskLevel",
    "StrengthEstimate",
    "StrengthLabel",
    "StrengthSegment",
    "UnknownProfileError",
    "WordList",
    "WordMatchType",
    "analyze_batch",
    "analyze_password",
    "evaluate_rules",
    "safe_label",
    "sanitize_label",
    "summarize_analyses",
]
