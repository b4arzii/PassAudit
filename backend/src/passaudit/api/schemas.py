"""Request and response models of API v1.

The engine's models are reused as they are: ``AnalysisRequest`` is the request body of
``/audit`` and ``/policy/validate`` (the API classes below only add OpenAPI examples), and
``PasswordAnalysis`` is the response of ``/audit``. Only the batch endpoint needs new shapes.

Every model that can carry a password uses ``SecretStr`` and ``hide_input_in_errors``, so
neither ``repr`` nor a validation error can echo it.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, SecretStr, model_validator

from passaudit import __version__
from passaudit.analysis import (
    AnalysisContext,
    AnalysisRequest,
    AnalysisSummary,
    BatchItemResult,
    FindingKind,
    PasswordAnalysis,
    PasswordPolicy,
    PolicyRule,
    PolicyRuleResult,
    PolicyViolation,
    RecommendationCode,
    RiskLevel,
    StrengthLabel,
)

# Obviously fake values for the interactive docs. Never a real credential.
_EXAMPLE_PASSWORD = "example-not-a-real-Passw0rd"  # noqa: S105  # OpenAPI example  # nosec B105
_EXAMPLE_REQUEST: dict[str, JsonValue] = {
    "password": _EXAMPLE_PASSWORD,
    "policy": {"min_length": 12, "min_strength_score": 2},
    "context": {
        "usage": "online_account",
        "personal_info": ["Jane Doe"],
        "reused_elsewhere": False,
    },
}

_EXAMPLE_PASSWORD_2 = "another-fake-password-1"  # noqa: S105  # OpenAPI example  # nosec B105
BATCH_HARD_CAP = 1_000  # absolute schema ceiling; the configured limit is usually lower


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


# --------------------------------------------------------------------------- requests


class ExposureOptions(_Strict):
    """Opt-in lookups for this request. Everything defaults to **off**.

    * ``breach``: ``local`` searches a hash file configured on the server (no network);
      ``online`` asks a k-anonymity range service about the password's 5-character SHA-1
      prefix (needs ``PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED=true``; see docs/security.md).
    * ``reuse``: compare against the server's authorised local reuse index.
    """

    breach: Literal["off", "local", "online"] = "off"
    reuse: bool = False


def _profile_xor_policy[M: BaseModel](model: M) -> M:
    if getattr(model, "profile", None) is not None and "policy" in model.model_fields_set:
        raise ValueError("give either 'profile' or 'policy', not both")
    return model


class AuditRequest(AnalysisRequest):
    """Analyse one password. ``policy`` and ``context`` are optional.

    ``profile`` selects a named policy (``GET /policy/profiles``) instead of ``policy``; the
    profile's usage applies unless ``context.usage`` is given. ``exposure`` requests opt-in
    breach / reuse lookups.
    """

    profile: Annotated[str | None, Field(max_length=48)] = None
    exposure: ExposureOptions = Field(default_factory=ExposureOptions)

    model_config = ConfigDict(json_schema_extra={"examples": [_EXAMPLE_REQUEST]})

    @model_validator(mode="after")
    def _exclusive(self) -> AuditRequest:
        return _profile_xor_policy(self)


class PolicyValidationRequest(AuditRequest):
    """Check one password against a policy (defaults apply when ``policy`` is omitted)."""

    model_config = ConfigDict(json_schema_extra={"examples": [_EXAMPLE_REQUEST]})


class BatchItem(_Strict):
    password: SecretStr
    #: Optional label to correlate results. Sanitised; replaced by ``[redacted]`` if it
    #: contains the password. Never logged.
    id: Annotated[str | None, Field(max_length=128)] = None


class BatchAuditRequest(_Strict):
    """Analyse several passwords. One ``policy`` and ``context`` apply to every item."""

    items: Annotated[list[BatchItem], Field(min_length=1, max_length=BATCH_HARD_CAP)]
    policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    context: AnalysisContext = Field(default_factory=AnalysisContext)
    #: ``summary`` returns a compact record per item; ``full`` embeds the whole analysis.
    detail: Literal["summary", "full"] = "summary"
    profile: Annotated[str | None, Field(max_length=48)] = None
    exposure: ExposureOptions = Field(default_factory=ExposureOptions)

    @model_validator(mode="after")
    def _exclusive(self) -> BatchAuditRequest:
        return _profile_xor_policy(self)

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "items": [
                        {"id": "alice", "password": _EXAMPLE_PASSWORD},
                        {"id": "bob", "password": _EXAMPLE_PASSWORD_2},
                    ],
                    "policy": {"min_length": 12},
                    "detail": "summary",
                }
            ]
        }
    )


# -------------------------------------------------------------------------- responses


class HealthResponse(_Strict):
    status: Literal["ok"]
    version: str = __version__


class PolicyValidationResponse(_Strict):
    compliant: bool
    length: int
    #: One entry per *enabled* rule, with a human-readable requirement and pass/fail.
    rules: list[PolicyRuleResult]
    #: The engine's raw violations (rule, message, required, actual) for the failed rules.
    violations: list[PolicyViolation]


class BatchItemSummary(_Strict):
    index: int
    id: str | None
    length: int
    reused_in_batch: bool
    risk_score: int
    risk_level: RiskLevel
    strength_score: int
    strength_label: StrengthLabel
    guesses_log10: float
    estimated_bits: float
    policy_compliant: bool
    policy_violations: list[PolicyRule]
    findings: list[FindingKind]
    recommendations: list[RecommendationCode]
    #: ``None`` = no breach check was requested; ``unavailable`` = requested but not completed.
    breach: Literal["clean", "breached", "unavailable"] | None = None
    #: Names of the authorised reuse datasets containing this password (``None`` = not checked).
    reuse_datasets: list[str] | None = None
    #: Present only when the request asked for ``detail: "full"``.
    analysis: PasswordAnalysis | None = None

    @classmethod
    def from_result(cls, result: BatchItemResult, *, full: bool) -> BatchItemSummary:
        a = result.analysis
        return cls(
            index=result.index,
            id=result.label,
            length=a.length,
            reused_in_batch=result.reused_in_batch,
            risk_score=a.risk.score,
            risk_level=a.risk.level,
            strength_score=a.strength.score,
            strength_label=a.strength.label,
            guesses_log10=round(a.strength.guesses_log10, 2),
            estimated_bits=round(a.entropy.estimated_bits, 1),
            policy_compliant=a.policy.compliant,
            policy_violations=[v.rule for v in a.policy.violations],
            findings=sorted({f.kind for f in a.findings}, key=lambda kind: kind.value),
            recommendations=[r.code for r in a.recommendations],
            breach=a.exposure.breach.status if a.exposure and a.exposure.breach else None,
            reuse_datasets=list(a.exposure.reuse.sources)
            if a.exposure and a.exposure.reuse
            else None,
            analysis=a if full else None,
        )


class BatchSummary(AnalysisSummary):
    """The engine's roll-up plus batch-level facts."""

    reused_in_batch: int
    #: Passwords found in breach data / in an authorised reuse dataset (0 when not checked).
    breached: int = 0
    reused_in_datasets: int = 0


class BatchAuditResponse(_Strict):
    count: int
    summary: BatchSummary
    results: list[BatchItemSummary]


class ReportRequest(BatchAuditRequest):
    """Build a sanitized, sealed audit report. ``detail: full`` embeds each full analysis."""


class BreachCapabilities(_Strict):
    local: bool
    online: bool
    #: The service the online check talks to (host only), when enabled.
    online_host: str | None = None
    protocol: str = (
        "k-anonymity range query: only the first 5 hex characters of the password's SHA-1 "
        "hash are sent; matching happens locally."
    )


class ReuseCapabilities(_Strict):
    available: bool
    datasets: list[str] = Field(default_factory=list)
    authorization_reference: str | None = None


class ProfileSummary(_Strict):
    name: str
    title: str
    description: str
    usage: str
    builtin: bool


class DictionaryInfo(_Strict):
    words: int
    names: int
    passwords: int


class CapabilitiesResponse(_Strict):
    """What this server can do beyond the basics, so a client can offer only real options."""

    external_lookups_enabled: bool
    breach: BreachCapabilities
    reuse_index: ReuseCapabilities
    profiles: list[ProfileSummary]
    dictionaries: DictionaryInfo


class RateLimitInfo(_Strict):
    enabled: bool
    burst: int
    refill_per_minute: int
    cost_per_password: int = 1


class LimitsResponse(_Strict):
    """The limits this server enforces, so clients can size their requests."""

    max_password_length: int
    max_body_bytes: int
    batch_max_items: int
    batch_max_body_bytes: int
    max_personal_info_items: int
    max_personal_info_item_length: int
    rate_limit: RateLimitInfo
