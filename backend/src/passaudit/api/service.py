"""The analysis service: limits, thread offloading, and mapping engine results to responses.

All analysis is delegated to ``passaudit.analysis`` - nothing is re-implemented here. Its job
is the API-specific concerns around it:

* enforce the configured per-password and per-batch limits *before* doing any work;
* run the CPU-bound analysis off the event loop, with bounded concurrency and a queue
  timeout, so a burst of requests degrades into ``503`` instead of exhausting threads;
* turn engine exceptions (which are content-free) into ``ApiError`` values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import anyio
import anyio.to_thread

from passaudit.analysis import (
    AnalysisContext,
    AnalysisRequest,
    AnalyzerConfig,
    ExposureSignals,
    PasswordAnalyzer,
    PasswordPolicy,
    PasswordTooLongError,
    PolicyProfile,
    ReuseExposure,
    UnknownProfileError,
    analyze_batch,
    evaluate_rules,
    summarize_analyses,
)
from passaudit.api.errors import ApiError, ErrorCode, ErrorDetail
from passaudit.api.integrations import Integrations, build_integrations
from passaudit.api.schemas import (
    AuditRequest,
    BatchAuditRequest,
    BatchAuditResponse,
    BatchItemSummary,
    BatchSummary,
    BreachCapabilities,
    CapabilitiesResponse,
    DictionaryInfo,
    ExposureOptions,
    PolicyValidationResponse,
    ProfileSummary,
    ReportRequest,
    ReuseCapabilities,
)
from passaudit.reporting import (
    ReportLeakError,
    build_audit_report,
    describe_external,
    entry_from_result,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from passaudit.analysis import BatchItemResult, PasswordAnalysis
    from passaudit.config import Settings


class AnalysisService:
    def __init__(
        self,
        settings: Settings,
        analyzer: PasswordAnalyzer | None = None,
        integrations: Integrations | None = None,
    ) -> None:
        self.settings = settings
        self.integrations = integrations or build_integrations(settings)
        self.analyzer = analyzer or PasswordAnalyzer(
            AnalyzerConfig(max_input_length=settings.max_password_length),
            dictionaries=self.integrations.dictionaries,
        )
        self._slots = anyio.CapacityLimiter(settings.max_concurrent_analyses)

    # ---------------------------------------------------------------- execution

    async def _run[T](self, func: Callable[..., T], *args: Any) -> T:
        """Run ``func`` in a worker thread, waiting at most the configured queue time."""
        try:
            with anyio.fail_after(self.settings.analysis_queue_timeout_seconds):
                await self._slots.acquire()
        except TimeoutError:
            raise ApiError(
                503,
                ErrorCode.SERVER_BUSY,
                "The server is busy analysing other requests. Retry shortly.",
                headers={"Retry-After": "2"},
            ) from None
        try:
            return await anyio.to_thread.run_sync(func, *args)
        except PasswordTooLongError as exc:  # defence in depth; limits are checked up front
            raise _too_long(exc.length, exc.maximum) from None
        finally:
            self._slots.release()

    # ------------------------------------------------------------------- checks

    def _check_length(self, request: AnalysisRequest) -> None:
        length = len(request.password.get_secret_value())
        if length > self.settings.max_password_length:
            raise _too_long(length, self.settings.max_password_length)

    def _check_batch(self, request: BatchAuditRequest) -> None:
        limit = self.settings.batch_max_items
        if len(request.items) > limit:
            raise ApiError(
                422,
                ErrorCode.BATCH_TOO_LARGE,
                f"A batch may contain at most {limit} passwords (received {len(request.items)}).",
            )
        maximum = self.settings.max_password_length
        too_long = [
            ErrorDetail(
                loc=["body", "items", index, "password"],
                type="too_long",
                message=f"Password is longer than the {maximum}-character limit.",
            )
            for index, item in enumerate(request.items)
            if len(item.password.get_secret_value()) > maximum
        ]
        if too_long:
            raise ApiError(
                422,
                ErrorCode.PASSWORD_TOO_LONG,
                f"{len(too_long)} password(s) exceed the {maximum}-character limit.",
                details=too_long,
            )

    def _resolve(
        self, profile: str | None, policy: PasswordPolicy, context: AnalysisContext
    ) -> tuple[PasswordPolicy, AnalysisContext]:
        """The effective policy and context: a named profile replaces ``policy`` (its usage
        applies unless the caller set one). The unknown name is never echoed."""
        if profile is None:
            return policy, context
        try:
            chosen = self.integrations.profiles.get(profile)
        except UnknownProfileError:
            raise ApiError(
                422,
                ErrorCode.UNKNOWN_PROFILE,
                "Unknown policy profile. List the available ones with GET /policy/profiles.",
            ) from None
        if "usage" not in context.model_fields_set and chosen.usage != context.usage:
            context = context.model_copy(update={"usage": chosen.usage})
        return chosen.policy, context

    def get_profile(self, name: str) -> PolicyProfile:
        try:
            return self.integrations.profiles.get(name)
        except UnknownProfileError:
            raise ApiError(
                422,
                ErrorCode.UNKNOWN_PROFILE,
                "Unknown policy profile. List the available ones with GET /policy/profiles.",
            ) from None

    def check_options(self, options: ExposureOptions) -> None:
        self._check_options(options)

    def _check_options(self, options: ExposureOptions) -> None:
        """Refuse opt-in lookups this server was not configured for (before any work)."""
        checker = self.integrations.checker
        if options.breach == "online" and not (
            self.settings.external_lookups_enabled and checker.available("online")
        ):
            raise ApiError(
                403,
                ErrorCode.EXTERNAL_LOOKUPS_DISABLED,
                "Online breach checks are disabled on this server. The operator must set "
                "PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED=true; nothing was sent anywhere.",
            )
        if options.breach == "local" and not checker.available("local"):
            raise ApiError(
                422,
                ErrorCode.FEATURE_UNAVAILABLE,
                "No local breach dataset is configured on this server.",
            )
        if options.reuse and self.integrations.reuse_index is None:
            raise ApiError(
                422,
                ErrorCode.FEATURE_UNAVAILABLE,
                "No authorised reuse index is configured on this server.",
            )

    def _exposures(
        self, passwords: list[str], options: ExposureOptions
    ) -> list[ExposureSignals | None]:
        """Run the requested opt-in lookups for ``passwords`` (worker thread)."""
        if options.breach == "off" and not options.reuse:
            return [None] * len(passwords)
        breach = None
        if options.breach != "off":
            breach = self.integrations.checker.check_many(
                passwords,
                options.breach,
                deadline_seconds=self.settings.breach_batch_deadline_seconds,
                max_prefixes=self.settings.batch_max_items,
            )
        reuse = None
        index = self.integrations.reuse_index
        if options.reuse and index is not None:
            reuse = []
            for password in passwords:
                sources = index.lookup(password)
                reuse.append(
                    ReuseExposure(status="reused" if sources else "clean", sources=sources)
                )
        return [
            ExposureSignals(
                breach=breach[i] if breach is not None else None,
                reuse=reuse[i] if reuse is not None else None,
            )
            for i in range(len(passwords))
        ]

    # ---------------------------------------------------------------- operations

    def _analyze_one(
        self,
        request: AuditRequest,
        policy: PasswordPolicy,
        context: AnalysisContext,
    ) -> PasswordAnalysis:
        password = request.password
        exposure = self._exposures([password.get_secret_value()], request.exposure)[0]
        return self.analyzer.analyze(
            AnalysisRequest(password=password, policy=policy, context=context), exposure=exposure
        )

    async def audit(self, request: AuditRequest) -> PasswordAnalysis:
        self._check_length(request)
        self._check_options(request.exposure)
        policy, context = self._resolve(request.profile, request.policy, request.context)
        return await self._run(self._analyze_one, request, policy, context)

    async def validate_policy(self, request: AuditRequest) -> PolicyValidationResponse:
        self._check_length(request)
        self._check_options(request.exposure)
        policy, context = self._resolve(request.profile, request.policy, request.context)
        analysis = await self._run(self._analyze_one, request, policy, context)
        return PolicyValidationResponse(
            compliant=analysis.policy.compliant,
            length=analysis.length,
            rules=evaluate_rules(policy, analysis),
            violations=list(analysis.policy.violations),
        )

    def check_batch(self, request: BatchAuditRequest) -> None:
        """Validate batch limits and options (call before charging rate-limit cost)."""
        self._check_batch(request)
        self._check_options(request.exposure)
        self._resolve(request.profile, request.policy, request.context)

    def _run_batch(
        self, request: BatchAuditRequest, policy: PasswordPolicy, context: AnalysisContext
    ) -> list[BatchItemResult]:
        entries = [(item.id, item.password) for item in request.items]
        exposures = self._exposures([p.get_secret_value() for _, p in entries], request.exposure)
        return analyze_batch(self.analyzer, entries, policy, context, exposures=exposures)

    @staticmethod
    def _summary(results: list[BatchItemResult]) -> BatchSummary:
        shared = summarize_analyses([r.analysis for r in results])
        exposures = [r.analysis.exposure for r in results]
        return BatchSummary(
            **shared.model_dump(),
            reused_in_batch=sum(1 for r in results if r.reused_in_batch),
            breached=sum(1 for e in exposures if e and e.breach and e.breach.status == "breached"),
            reused_in_datasets=sum(
                1 for e in exposures if e and e.reuse and e.reuse.status == "reused"
            ),
        )

    async def audit_batch(self, request: BatchAuditRequest) -> BatchAuditResponse:
        policy, context = self._resolve(request.profile, request.policy, request.context)
        results = await self._run(self._run_batch, request, policy, context)
        return BatchAuditResponse(
            count=len(results),
            summary=self._summary(results),
            results=[
                BatchItemSummary.from_result(r, full=request.detail == "full") for r in results
            ],
        )

    async def audit_report(self, request: ReportRequest) -> dict[str, Any]:
        """A sanitized, sealed report for the batch. Refused if it would contain submitted text."""
        policy, context = self._resolve(request.profile, request.policy, request.context)
        results = await self._run(self._run_batch, request, policy, context)
        secrets = [item.password.get_secret_value() for item in request.items]
        secrets += [p.get_secret_value() for p in context.personal_info]
        index = self.integrations.reuse_index
        reuse_datasets = [s.id for s in index.sources] if request.exposure.reuse and index else None
        try:
            return build_audit_report(
                kind="batch",
                entries=[
                    entry_from_result(
                        index=r.index,
                        label=r.label,
                        analysis=r.analysis,
                        reused_in_batch=r.reused_in_batch,
                        include_analysis=request.detail == "full",
                    )
                    for r in results
                ],
                summary=self._summary(results).model_dump(mode="json"),
                policy=policy.model_dump(mode="json"),
                profile=request.profile,
                usage=context.usage.value,
                external=describe_external(
                    breach=request.exposure.breach,
                    online_host=self.integrations.online_host,
                    reuse_datasets=reuse_datasets,
                    authorization_reference=self.integrations.reuse_authorization_reference,
                ),
                secrets=secrets,
            )
        except ReportLeakError:
            raise ApiError(
                422,
                ErrorCode.VALIDATION_ERROR,
                "The report was refused because a label or setting contained submitted secret "
                "text (a password or personal detail). Remove it and try again.",
            ) from None

    def capabilities(self) -> CapabilitiesResponse:
        checker = self.integrations.checker
        index = self.integrations.reuse_index
        return CapabilitiesResponse(
            external_lookups_enabled=self.settings.external_lookups_enabled,
            breach=BreachCapabilities(
                local=checker.available("local"),
                online=self.settings.external_lookups_enabled and checker.available("online"),
                online_host=self.integrations.online_host,
            ),
            reuse_index=ReuseCapabilities(
                available=index is not None,
                datasets=[s.id for s in index.sources] if index else [],
                authorization_reference=self.integrations.reuse_authorization_reference,
            ),
            profiles=[
                ProfileSummary(
                    name=p.name,
                    title=p.title,
                    description=p.description,
                    usage=p.usage.value,
                    builtin=p.builtin,
                )
                for p in self.integrations.profiles.all()
            ],
            dictionaries=DictionaryInfo(
                words=len(self.analyzer.dictionaries.words),
                names=len(self.analyzer.dictionaries.names),
                passwords=len(self.analyzer.wordlist),
            ),
        )


def _too_long(length: int, maximum: int) -> ApiError:
    return ApiError(
        422,
        ErrorCode.PASSWORD_TOO_LONG,
        f"The password is too long: {length} characters (maximum {maximum}).",
    )
