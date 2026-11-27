"""API v1 routes. Mounted at ``/api/v1`` by ``passaudit.main.create_app``."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request

from passaudit.analysis import PasswordAnalysis, PasswordPolicy, PolicyProfile
from passaudit.analysis.models import MAX_PERSONAL_ITEM_LENGTH, MAX_PERSONAL_ITEMS
from passaudit.api.errors import COMMON_ERROR_RESPONSES, ApiError, ErrorCode
from passaudit.api.middleware import rate_limit_headers
from passaudit.api.schemas import (
    AuditRequest,
    BatchAuditRequest,
    BatchAuditResponse,
    CapabilitiesResponse,
    HealthResponse,
    LimitsResponse,
    PolicyValidationRequest,
    PolicyValidationResponse,
    RateLimitInfo,
    ReportRequest,
)
from passaudit.api.service import AnalysisService

TAGS_METADATA = [
    {"name": "audit", "description": "Analyse passwords: strength, weaknesses, risk and advice."},
    {"name": "policy", "description": "Check passwords against a configurable password policy."},
    {"name": "meta", "description": "Health and server limits. No password data involved."},
]

router = APIRouter()


def get_service(request: Request) -> AnalysisService:
    service: AnalysisService = request.app.state.service
    return service


ServiceDep = Annotated[AnalysisService, Depends(get_service)]


async def charge_rate_limit(request: Request, cost: int) -> None:
    """Spend extra rate-limit cost units (the middleware already charged one)."""
    limiter = request.app.state.rate_limiter
    key = getattr(request.state, "rate_limit_key", None)
    if limiter is None or key is None or cost <= 0:
        return
    decision = await limiter.acquire(key, cost)
    if decision.allowed:
        request.state.rate_limit_decision = decision  # the response headers report this balance
    else:
        raise ApiError(
            429,
            ErrorCode.RATE_LIMITED,
            f"Too many requests. Retry after {decision.retry_after} seconds.",
            headers={
                **rate_limit_headers(decision.limit, decision.remaining, decision.reset_after),
                "Retry-After": str(decision.retry_after),
            },
        )


# ------------------------------------------------------------------------------- meta


@router.get(
    "/health",
    tags=["meta"],
    summary="Liveness probe",
    operation_id="getHealth",
    response_model=HealthResponse,
)
def health() -> HealthResponse:
    """Returns `ok` and the version. Exempt from rate limiting; carries no sensitive data."""
    return HealthResponse(status="ok")


@router.get(
    "/limits",
    tags=["meta"],
    summary="Server limits",
    operation_id="getLimits",
    response_model=LimitsResponse,
)
def limits(request: Request) -> LimitsResponse:
    """The size and rate limits this server enforces, so clients can size their requests."""
    s = request.app.state.settings
    return LimitsResponse(
        max_password_length=s.max_password_length,
        max_body_bytes=s.max_body_bytes,
        batch_max_items=s.batch_max_items,
        batch_max_body_bytes=s.batch_max_body_bytes,
        max_personal_info_items=MAX_PERSONAL_ITEMS,
        max_personal_info_item_length=MAX_PERSONAL_ITEM_LENGTH,
        rate_limit=RateLimitInfo(
            enabled=s.rate_limit_enabled,
            burst=s.rate_limit_burst,
            refill_per_minute=s.rate_limit_per_minute,
        ),
    )


@router.get(
    "/capabilities",
    tags=["meta"],
    summary="Optional features of this server",
    operation_id="getCapabilities",
    response_model=CapabilitiesResponse,
)
def capabilities(service: ServiceDep) -> CapabilitiesResponse:
    """Which opt-in checks (breach, reuse), policy profiles and dictionaries are available."""
    return service.capabilities()


# ------------------------------------------------------------------------------ audit


@router.post(
    "/audit",
    tags=["audit"],
    summary="Audit one password",
    operation_id="auditPassword",
    response_model=PasswordAnalysis,
    responses=COMMON_ERROR_RESPONSES,
)
async def audit_password(
    body: AuditRequest, service: ServiceDep, request: Request
) -> PasswordAnalysis:
    """Analyse a password with the PassAudit engine.

    Returns strength (zxcvbn), entropy estimates with their limitations, detected weaknesses
    (positions only), policy compliance, a transparent 0-100 risk score and recommendations.

    **The password must be in the JSON body.** It is analysed in memory and never stored,
    logged, or included in the response. Query parameters are rejected.

    `exposure` requests opt-in breach / reuse lookups (default: none). An online breach
    check sends only a 5-character hash prefix to the configured service and costs one extra
    rate-limit unit.
    """
    service.check_options(body.exposure)
    if body.exposure.breach == "online":
        await charge_rate_limit(request, 1)
    return await service.audit(body)


@router.post(
    "/audit/batch",
    tags=["audit"],
    summary="Audit several passwords",
    operation_id="auditBatch",
    response_model=BatchAuditResponse,
    responses=COMMON_ERROR_RESPONSES,
)
async def audit_batch(
    body: BatchAuditRequest, service: ServiceDep, request: Request
) -> BatchAuditResponse:
    """Analyse up to `batch_max_items` passwords (see `GET /limits`) in one request.

    Identical passwords in the batch are flagged `reused_in_batch`. Each password costs one
    rate-limit unit. A single over-long password rejects the whole request (`422`).
    """
    service.check_batch(body)
    await charge_rate_limit(request, _batch_cost(body) - 1)
    return await service.audit_batch(body)


def _batch_cost(body: BatchAuditRequest) -> int:
    """One unit per password, doubled when each also triggers an online breach lookup."""
    per_item = 2 if body.exposure.breach == "online" else 1
    return len(body.items) * per_item


@router.post(
    "/audit/report",
    tags=["audit"],
    summary="Build a sanitized audit report",
    operation_id="auditReport",
    response_model=dict[str, Any],
    responses=COMMON_ERROR_RESPONSES,
)
async def audit_report(
    body: ReportRequest, service: ServiceDep, request: Request
) -> dict[str, Any]:
    """Audit a batch and return a **sanitized, sealed JSON report** (schema version 2).

    The report holds scores, finding kinds, rule ids, advice codes and dataset names only, lists
    what external checks ran, carries fixed limitations text and a SHA-256 integrity digest, and
    is refused (`422`) if it would contain any submitted password or personal detail.
    """
    service.check_batch(body)
    await charge_rate_limit(request, _batch_cost(body) - 1)
    return await service.audit_report(body)


# ----------------------------------------------------------------------------- policy


@router.post(
    "/policy/validate",
    tags=["policy"],
    summary="Check one password against a policy",
    operation_id="validatePolicy",
    response_model=PolicyValidationResponse,
    responses=COMMON_ERROR_RESPONSES,
)
async def validate_policy(
    body: PolicyValidationRequest, service: ServiceDep, request: Request
) -> PolicyValidationResponse:
    """Evaluate every enabled policy rule and report pass/fail with requirements.

    The default policy applies when `policy` is omitted (see `GET /policy/default`). Like
    `/audit`, an `exposure` request is opt-in and an online check costs one extra rate-limit unit.
    """
    service.check_options(body.exposure)
    if body.exposure.breach == "online":
        await charge_rate_limit(request, 1)
    return await service.validate_policy(body)


@router.get(
    "/policy/profiles",
    tags=["policy"],
    summary="List policy profiles",
    operation_id="listPolicyProfiles",
    response_model=list[PolicyProfile],
)
def list_profiles(service: ServiceDep) -> list[PolicyProfile]:
    """Built-in and operator-defined policy profiles, each with its full policy."""
    return service.integrations.profiles.all()


@router.get(
    "/policy/profiles/{name}",
    tags=["policy"],
    summary="One policy profile",
    operation_id="getPolicyProfile",
    response_model=PolicyProfile,
    responses=COMMON_ERROR_RESPONSES,
)
def get_profile(name: str, service: ServiceDep) -> PolicyProfile:
    """A profile by name. An unknown name is a `422` (`unknown_profile`) that does not echo it."""
    return service.get_profile(name)


@router.get(
    "/policy/default",
    tags=["policy"],
    summary="The default policy",
    operation_id="getDefaultPolicy",
    response_model=PasswordPolicy,
)
def default_policy() -> PasswordPolicy:
    """The policy applied when a request does not supply one. A template for custom policies."""
    return PasswordPolicy()
