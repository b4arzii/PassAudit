"""Sanitized audit reports shared by the API and the CLI.

A report is built only from password-free analysis results, and is then checked against the
secrets that went in (passwords, personal details): if any of them - or a long fragment of one -
appears in the finished text, the report is refused. See :mod:`passaudit.reporting.sanitized`.
"""

from passaudit.reporting.sanitized import (
    LIMITATIONS,
    REPORT_SCHEMA_VERSION,
    ReportLeakError,
    analysis_summary,
    assert_clean,
    assert_report_clean,
    build_audit_report,
    contains_secret,
    describe_external,
    entry_from_result,
    report_vocabulary,
    seal,
    verify_seal,
)

__all__ = [
    "LIMITATIONS",
    "REPORT_SCHEMA_VERSION",
    "ReportLeakError",
    "analysis_summary",
    "assert_clean",
    "assert_report_clean",
    "build_audit_report",
    "contains_secret",
    "describe_external",
    "entry_from_result",
    "report_vocabulary",
    "seal",
    "verify_seal",
]
