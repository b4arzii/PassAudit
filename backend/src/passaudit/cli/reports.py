"""Sanitized JSON and CSV reports.

Reports are built from an explicit whitelist of fields taken from ``PasswordAnalysis`` (which
is itself password-free). No password, no password-derived value (hash, prefix, mask) and no
personal-information string is ever included. The only user-supplied text is an optional batch
*label*, which is sanitized and dropped if it would reveal the password.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from passaudit import __version__
from passaudit.analysis import ANALYSIS_VERSION, PasswordAnalysis, PasswordPolicy
from passaudit.cli.errors import CliError, ExitCode
from passaudit.reporting import ReportLeakError, analysis_summary, assert_report_clean, seal

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from passaudit.cli.results import PasswordResult

REPORT_SCHEMA_VERSION = "2"

CSV_COLUMNS: tuple[str, ...] = (
    "index",
    "line",
    "label",
    "status",
    "error",
    "length",
    "risk_score",
    "risk_level",
    "strength_score",
    "strength_label",
    "guesses_log10",
    "estimated_bits",
    "policy_compliant",
    "policy_violations",
    "findings",
    "recommendations",
    "reused_in_batch",
    "breach",
    "reuse_datasets",
    "failed",
    "fail_reasons",
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def now_utc() -> datetime:
    return datetime.now(UTC)


def header(kind: str, now: datetime) -> dict[str, Any]:
    return {
        "type": kind,
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": "passaudit",
        "tool_version": __version__,
        "engine_version": ANALYSIS_VERSION,
        "generated_at": now.astimezone(UTC).isoformat(timespec="seconds"),
        "sanitized": True,
        "note": "Contains no passwords, no password-derived values and no personal information.",
    }


def dumps(data: dict[str, Any]) -> str:
    """Stable, ASCII-only JSON (safe on any console encoding)."""
    return json.dumps(data, indent=2, ensure_ascii=True) + "\n"


def finish(data: dict[str, Any], *, external: dict[str, Any] | None, secrets: Sequence[str]) -> str:
    """Add the external-checks block and an integrity digest, refuse to emit a report that
    contains any submitted secret, and render it."""
    sealed = seal({**data, "external_checks": external})
    try:
        assert_report_clean(sealed, secrets)
    except ReportLeakError:
        raise CliError(
            "The report was refused because it contained submitted secret text (for example a "
            "label equal to a password). Nothing was written.",
            ExitCode.OUTPUT_ERROR,
        ) from None
    return dumps(sealed)


# --------------------------------------------------------------------- per-password


def compact(result: PasswordResult) -> dict[str, Any]:
    """The summary record used by batch JSON and every CSV row."""
    base: dict[str, Any] = {
        "index": result.index,
        "line": result.line,
        "label": result.label,
        "status": result.status,
        "error": result.error,
        "length": result.length,
        "reused_in_batch": result.reused_in_batch,
        "breach": None,
        "reuse_datasets": None,
        "failed": result.verdict.failed,
        "fail_reasons": list(result.verdict.reasons),
    }
    analysis = result.analysis
    if analysis is not None and analysis.exposure is not None:
        exposure = analysis.exposure
        base["breach"] = exposure.breach.status if exposure.breach else None
        base["reuse_datasets"] = list(exposure.reuse.sources) if exposure.reuse else None
    if analysis is None:
        return base | {
            "risk": None,
            "strength": None,
            "estimated_bits": None,
            "policy": None,
            "findings": [],
            "recommendations": [],
        }
    return base | analysis_summary(analysis)


def _csv_text(value: Any) -> str:
    """Render a cell; neutralise spreadsheet formula injection in text cells."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if isinstance(value, str) and text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def csv_row(record: dict[str, Any]) -> list[str]:
    risk = record["risk"] or {}
    strength = record["strength"] or {}
    policy = record["policy"] or {}
    cells: dict[str, Any] = {
        "index": record["index"],
        "line": record["line"],
        "label": record["label"],
        "status": record["status"],
        "error": record["error"],
        "length": record["length"],
        "risk_score": risk.get("score"),
        "risk_level": risk.get("level"),
        "strength_score": strength.get("score"),
        "strength_label": strength.get("label"),
        "guesses_log10": strength.get("guesses_log10"),
        "estimated_bits": record["estimated_bits"],
        "policy_compliant": policy.get("compliant"),
        "policy_violations": ";".join(policy.get("violations", [])),
        "findings": ";".join(record["findings"]),
        "recommendations": ";".join(record["recommendations"]),
        "reused_in_batch": record["reused_in_batch"],
        "breach": record["breach"],
        "reuse_datasets": ";".join(record["reuse_datasets"] or []),
        "failed": record["failed"],
        "fail_reasons": ";".join(record["fail_reasons"]),
    }
    return [_csv_text(cells[column]) for column in CSV_COLUMNS]


def results_csv(results: Sequence[PasswordResult]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for result in results:
        writer.writerow(csv_row(compact(result)))
    return buffer.getvalue()


# ------------------------------------------------------------------------- reports


def audit_json(
    result: PasswordResult,
    analysis: PasswordAnalysis,
    policy: PasswordPolicy,
    settings: dict[str, Any],
    *,
    now: datetime,
    external: dict[str, Any] | None = None,
    secrets: Sequence[str] = (),
) -> str:
    return finish(
        {
            "report": header("audit", now),
            "settings": settings,
            "policy": policy.model_dump(mode="json"),
            "verdict": {
                "failed": result.verdict.failed,
                "reasons": list(result.verdict.reasons),
            },
            "analysis": analysis.model_dump(mode="json"),
        },
        external=external,
        secrets=secrets,
    )


def batch_json(
    results: Sequence[PasswordResult],
    summary: dict[str, Any],
    policy: PasswordPolicy,
    settings: dict[str, Any],
    *,
    detailed: bool,
    now: datetime,
    external: dict[str, Any] | None = None,
    secrets: Sequence[str] = (),
) -> str:
    entries: list[dict[str, Any]] = []
    for result in results:
        record = compact(result)
        if detailed and result.analysis is not None:
            record["analysis"] = result.analysis.model_dump(mode="json")
        entries.append(record)
    return finish(
        {
            "report": header("batch", now),
            "settings": settings,
            "policy": policy.model_dump(mode="json"),
            "summary": summary,
            "results": entries,
        },
        external=external,
        secrets=secrets,
    )


POLICY_CSV_COLUMNS = ("rule", "requirement", "status", "required", "actual", "message")


def policy_json(
    rules: list[dict[str, Any]],
    result: PasswordResult,
    policy: PasswordPolicy,
    settings: dict[str, Any],
    *,
    now: datetime,
    external: dict[str, Any] | None = None,
    secrets: Sequence[str] = (),
) -> str:
    return finish(
        {
            "report": header("policy_check", now),
            "settings": settings,
            "policy": policy.model_dump(mode="json"),
            "verdict": {
                "failed": result.verdict.failed,
                "reasons": list(result.verdict.reasons),
            },
            "length": result.length,
            "rules": rules,
        },
        external=external,
        secrets=secrets,
    )


def policy_csv(rules: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(POLICY_CSV_COLUMNS)
    for rule in rules:
        writer.writerow([_csv_text(rule.get(column)) for column in POLICY_CSV_COLUMNS])
    return buffer.getvalue()


# ----------------------------------------------------------------------------- IO


def write_report(path: Path, text: str, *, force: bool, input_paths: Sequence[Path] = ()) -> None:
    """Write ``text`` to ``path`` as UTF-8.

    Refuses to overwrite an existing file unless ``force`` is set, and never writes over a
    file that is being used as input (so a mistyped ``-o`` cannot destroy a password list).
    """
    try:
        target = path.resolve()
        for source in input_paths:
            if source.exists() and source.resolve() == target:
                raise CliError(
                    "The report path is the same as an input file; choose a different --output.",
                    ExitCode.USAGE,
                )
        if path.is_dir():
            raise CliError(f"The report path is a directory: {path}", ExitCode.OUTPUT_ERROR)
        if not path.parent.exists():
            raise CliError(
                f"The report directory does not exist: {path.parent}", ExitCode.OUTPUT_ERROR
            )
        mode = "w" if force else "x"
        with path.open(mode, encoding="utf-8", newline="") as handle:
            handle.write(text)
    except FileExistsError as exc:
        raise CliError(
            f"The report file already exists: {path} (use --force to overwrite).",
            ExitCode.OUTPUT_ERROR,
        ) from exc
    except OSError as exc:
        raise CliError(f"The report could not be written: {path}", ExitCode.OUTPUT_ERROR) from exc
