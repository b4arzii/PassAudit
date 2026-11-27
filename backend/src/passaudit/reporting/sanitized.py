"""Build, guard and seal a sanitized audit report.

Three independent layers keep secrets out of a report:

1. **By construction** - entries are whitelisted fields of password-free analysis results
   (scores, finding *kinds*, rule ids, recommendation codes, dataset *names*). There is no field
   that could hold a password, a hash, a hash prefix, a personal-info string or a file path.
2. **By inspection** - :func:`assert_clean` scans the finished JSON text for every secret that
   was supplied for the audit (and for the head and tail of long ones) and refuses to return
   the report if one is found. It is a safety net for mistakes, not the primary control.
3. **By integrity** - :func:`seal` adds a SHA-256 digest of the report body, so accidental
   edits (or a truncated copy) are detectable. It is **not** a signature: anyone can recompute
   it, so it proves nothing about who made the report.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from passaudit import __version__
from passaudit.analysis import (
    ANALYSIS_VERSION,
    FindingKind,
    PasswordUsage,
    PolicyRule,
    RecommendationCode,
    RiskFactor,
    RiskLevel,
    StrengthLabel,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from passaudit.analysis import PasswordAnalysis

REPORT_SCHEMA_VERSION = "2"
MIN_SECRET_LENGTH = 4  # shorter strings match innocent text ("true", "low") by chance
FRAGMENT_LENGTH = 8
NOTE = "Contains no passwords, no password-derived values and no personal information."

#: Fixed statements every report carries, so a reader does not over-trust the numbers.
LIMITATIONS: tuple[str, ...] = (
    "Strength, entropy and crack-time figures are estimates, not guarantees.",
    "Pattern and dictionary detection use bundled sample lists (plus any lists the operator "
    "supplied); a password that is not listed can still be weak.",
    "A 'clean' breach result means the password was not found in the consulted corpus at the "
    "time of the check, not that it has never been exposed.",
    "Breach checks marked 'unavailable' or 'not checked' say nothing about the password.",
    "Reuse results only cover the named local datasets the operator was authorised to index.",
    "This report is not a compliance attestation. The integrity checksum detects accidental "
    "change; it is not a signature.",
)


class ReportLeakError(Exception):
    """A finished report contained an input secret. The message never says which."""

    def __init__(self) -> None:
        super().__init__("The report was refused because it contained submitted secret text.")


# ----------------------------------------------------------------------------- guarding


def _enum_values() -> set[str]:
    enums = (
        FindingKind, PolicyRule, RecommendationCode, RiskFactor, RiskLevel, StrengthLabel,
        PasswordUsage,
    )  # fmt: skip
    return {member.value for enum in enums for member in enum}


def _keys(node: Any) -> set[str]:
    """Every dictionary key in a nested structure (the report's fixed field names)."""
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(str(key))
            found |= _keys(value)
    elif isinstance(node, list):
        for item in node:
            found |= _keys(item)
    return found


def contains_secret(text: str, secrets: Iterable[str], *, vocabulary: Iterable[str] = ()) -> bool:
    """True if ``text`` contains any secret (case-insensitively), or the first/last
    ``FRAGMENT_LENGTH`` characters of a long one. Secrets shorter than 4 are ignored.

    ``vocabulary`` lists fixed strings the report is *allowed* to contain (enum values, field
    names, the standard limitation text). They are removed (longest first) before scanning, so
    auditing the weak password ``password`` does not trip over the legitimate finding name
    ``common_password``.
    """
    haystack = text.casefold()
    for word in sorted({v.casefold() for v in vocabulary if v}, key=len, reverse=True):
        haystack = haystack.replace(word, "\0")
    for secret in secrets:
        if len(secret) < MIN_SECRET_LENGTH:
            continue
        folded = secret.casefold()
        if folded in haystack:
            return True
        if len(folded) >= 2 * FRAGMENT_LENGTH and (
            folded[:FRAGMENT_LENGTH] in haystack or folded[-FRAGMENT_LENGTH:] in haystack
        ):
            return True
    return False


def assert_clean(text: str, secrets: Iterable[str], *, vocabulary: Iterable[str] = ()) -> None:
    """Raise :class:`ReportLeakError` if ``text`` contains any of ``secrets``."""
    if contains_secret(text, secrets, vocabulary=vocabulary):
        raise ReportLeakError


#: Keys whose subtrees are produced by the engine from fixed templates (finding descriptions,
#: advice, violation messages, rule requirements). ``test_security.py`` proves they never
#: contain input, and they legitimately contain ordinary words ("short", "password"), so the
#: guard does not scan them. Everything else in a report - labels, profile names, settings,
#: external-check details - is scanned.
TEMPLATE_KEYS = frozenset({"analysis", "rules", "violations"})


def _template_strings(node: Any, *, inside: bool = False) -> set[str]:
    found: set[str] = set()
    if isinstance(node, str):
        if inside:
            found.add(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            found |= _template_strings(value, inside=inside or key in TEMPLATE_KEYS)
    elif isinstance(node, list):
        for item in node:
            found |= _template_strings(item, inside=inside)
    return found


def report_vocabulary(report: dict[str, Any]) -> set[str]:
    """The fixed strings a sanitized report may legitimately contain."""
    return _enum_values() | _keys(report) | set(LIMITATIONS) | {NOTE} | _template_strings(report)


def assert_report_clean(report: dict[str, Any], secrets: Iterable[str]) -> None:
    """Guard a finished report dict against the secrets that went into the audit."""
    assert_clean(
        json.dumps(report, ensure_ascii=True), secrets, vocabulary=report_vocabulary(report)
    )


# ------------------------------------------------------------------------------ sealing


def _canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def seal(report: dict[str, Any]) -> dict[str, Any]:
    """Return ``report`` with an ``integrity`` block (SHA-256 over everything else)."""
    body = {k: v for k, v in report.items() if k != "integrity"}
    return {
        **body,
        "integrity": {
            "algorithm": "sha256",
            "checksum": hashlib.sha256(_canonical(body)).hexdigest(),
            "covers": "every other top-level field, as canonical JSON",
            "note": "Detects accidental change only; it is not a signature.",
        },
    }


def verify_seal(report: dict[str, Any]) -> bool:
    """True if the report's integrity checksum matches its content."""
    integrity = report.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        return False
    body = {k: v for k, v in report.items() if k != "integrity"}
    expected = hashlib.sha256(_canonical(body)).hexdigest()
    return str(integrity.get("checksum")) == expected


# ---------------------------------------------------------------------------- building


def analysis_summary(analysis: PasswordAnalysis) -> dict[str, Any]:
    """The whitelisted, password-free summary of one analysis.

    The single definition of which analysis fields may appear in a report: the API report and
    the CLI report both build on it, so the two sanitized formats cannot drift apart.
    """
    return {
        "risk": {"score": analysis.risk.score, "level": analysis.risk.level.value},
        "strength": {
            "score": analysis.strength.score,
            "label": analysis.strength.label.value,
            "guesses_log10": round(analysis.strength.guesses_log10, 2),
        },
        "estimated_bits": round(analysis.entropy.estimated_bits, 1),
        "policy": {
            "compliant": analysis.policy.compliant,
            "violations": [v.rule.value for v in analysis.policy.violations],
        },
        "findings": sorted({f.kind.value for f in analysis.findings}),
        "recommendations": [r.code.value for r in analysis.recommendations],
    }


def entry_from_result(
    *,
    index: int,
    label: str | None,
    analysis: PasswordAnalysis,
    reused_in_batch: bool,
    include_analysis: bool = False,
) -> dict[str, Any]:
    """The whitelisted per-password record."""
    exposure = analysis.exposure
    entry: dict[str, Any] = {
        "index": index,
        "label": label,
        "length": analysis.length,
        "reused_in_batch": reused_in_batch,
        **analysis_summary(analysis),
        "breach": None
        if exposure is None or exposure.breach is None
        else {"status": exposure.breach.status, "source": exposure.breach.source},
        "reuse_datasets": None
        if exposure is None or exposure.reuse is None
        else list(exposure.reuse.sources),
    }
    if include_analysis:
        entry["analysis"] = analysis.model_dump(mode="json")
    return entry


def build_audit_report(  # noqa: PLR0913 - a report genuinely has this many independent parts
    *,
    kind: str,
    entries: Sequence[dict[str, Any]],
    summary: dict[str, Any],
    policy: dict[str, Any],
    profile: str | None,
    usage: str,
    external: dict[str, Any],
    secrets: Iterable[str] = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assemble, guard and seal a report.

    ``external`` describes which opt-in checks ran (see :func:`describe_external`); ``secrets``
    are every password / personal string submitted for the audit, used for the final
    inspection. Raises :class:`ReportLeakError` instead of returning a leaking report.
    """
    stamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
    report = {
        "report": {
            "type": kind,
            "schema_version": REPORT_SCHEMA_VERSION,
            "tool": "passaudit",
            "tool_version": __version__,
            "engine_version": ANALYSIS_VERSION,
            "generated_at": stamp,
            "sanitized": True,
            "note": NOTE,
        },
        "audit": {
            "profile": profile,
            "usage": usage,
            "policy": policy,
            "external_checks": external,
        },
        "summary": summary,
        "results": list(entries),
        "limitations": list(LIMITATIONS),
    }
    sealed = seal(report)
    assert_report_clean(sealed, secrets)
    return sealed


def describe_external(
    *,
    breach: str,
    online_host: str | None,
    reuse_datasets: Sequence[str] | None,
    authorization_reference: str | None,
) -> dict[str, Any]:
    """The ``external_checks`` block: what was consulted, never any data sent or received."""
    return {
        "breach_check": breach,
        "breach_service_host": online_host if breach == "online" else None,
        "breach_protocol": "k-anonymity range query (5-character hash prefix)"
        if breach == "online"
        else None,
        "reuse_datasets": list(reuse_datasets) if reuse_datasets is not None else None,
        "reuse_authorization_reference": authorization_reference if reuse_datasets else None,
    }
