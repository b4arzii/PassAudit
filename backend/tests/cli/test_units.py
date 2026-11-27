"""Unit tests for the CLI's building blocks (inputs, reports, verdicts, rendering)."""

from __future__ import annotations

import io
from datetime import UTC, datetime
from pathlib import Path

import pytest
from rich.console import Console

from passaudit.analysis import (
    PasswordAnalysis,
    PasswordPolicy,
    ReuseTracker,
    RiskLevel,
    analyze_password,
    sanitize_label,
)
from passaudit.cli import inputs, render, reports
from passaudit.cli.errors import CliError, ExitCode
from passaudit.cli.inputs import (
    BatchEntry,
    load_personal_info,
    load_policy,
    read_batch,
)
from passaudit.cli.results import FailOn, PasswordResult, Verdict, error_result, judge, summarize

from .conftest import CANARY

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _analysis(password: str) -> PasswordAnalysis:
    return analyze_password(password)


def _with_level(analysis: PasswordAnalysis, level: RiskLevel) -> PasswordAnalysis:
    return analysis.model_copy(update={"risk": analysis.risk.model_copy(update={"level": level})})


# -------------------------------------------------------------------------- verdicts


@pytest.mark.parametrize("level", list(RiskLevel))
@pytest.mark.parametrize("fail_on", list(FailOn))
def test_judge_risk_gate_matrix(level: RiskLevel, fail_on: FailOn) -> None:
    analysis = _with_level(_analysis(CANARY), level)  # policy-compliant password
    verdict = judge(analysis, fail_on)
    order = [RiskLevel.LOW, RiskLevel.MODERATE, RiskLevel.HIGH, RiskLevel.CRITICAL]
    expected = fail_on is not FailOn.NONE and order.index(level) >= order.index(
        RiskLevel(fail_on.value)
    )
    assert verdict.failed is expected
    assert verdict.reasons == ((f"risk_level_{level.value}",) if expected else ())


def test_judge_reports_policy_violations() -> None:
    verdict = judge(_analysis("short"), FailOn.NONE)
    assert verdict == Verdict(failed=True, reasons=("policy_violations",))


def test_judge_lists_both_reasons() -> None:
    verdict = judge(_analysis("letmein"), FailOn.HIGH)
    assert verdict.reasons == ("policy_violations", "risk_level_critical")


def test_error_result_always_fails() -> None:
    result = error_result(3, 9, "lbl", 5000, "too_long")
    assert result.verdict.failed
    assert result.status == "error"
    assert result.analysis is None
    assert reports.compact(result)["fail_reasons"] == ["input_too_long"]


def test_summarize_empty_analysis_values() -> None:
    summary = summarize([error_result(1, 1, None, 9, "too_long")], skipped_blank=2)
    assert summary["entries"] == 1
    assert summary["analyzed"] == 0
    assert summary["average_risk_score"] is None
    assert summary["max_risk_score"] is None
    assert summary["skipped_blank"] == 2
    assert summary["failed"] == 1


def test_summarize_counts() -> None:
    results = [
        PasswordResult(1, 7, judge(a1 := _analysis("letmein"), FailOn.HIGH), a1),
        PasswordResult(2, 18, judge(a2 := _analysis(CANARY), FailOn.HIGH), a2),
    ]
    summary = summarize(results)
    assert summary["passed"] == 1
    assert summary["failed"] == 1
    assert summary["risk_levels"] == {"low": 1, "moderate": 0, "high": 0, "critical": 1}
    assert sum(summary["strength_scores"].values()) == 2
    assert summary["average_risk_score"] == round((a1.risk.score + a2.risk.score) / 2, 1)
    assert summary["finding_kinds"]["common_password"] == 1


# ------------------------------------------------------------------------- reports


def test_report_header_fields() -> None:
    header = reports.header("audit", NOW)
    assert header["generated_at"] == "2026-01-02T03:04:05+00:00"
    assert header["sanitized"] is True
    assert header["schema_version"] == reports.REPORT_SCHEMA_VERSION
    assert header["tool"] == "passaudit"


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t"])
def test_csv_formula_prefixes_are_neutralised(prefix: str) -> None:
    assert reports._csv_text(prefix + "cmd").startswith("'" + prefix)


def test_csv_text_handles_types() -> None:
    assert reports._csv_text(None) == ""
    assert reports._csv_text(True) == "true"
    assert reports._csv_text(False) == "false"
    assert reports._csv_text(12) == "12"
    assert reports._csv_text(-5) == "-5"  # numbers are not text: left alone
    assert reports._csv_text("plain") == "plain"


def test_audit_json_is_deterministic_for_a_fixed_clock() -> None:
    analysis = _analysis(CANARY)
    result = PasswordResult(1, analysis.length, judge(analysis, FailOn.HIGH), analysis)
    args = (result, analysis, PasswordPolicy(), {"usage": "general"})
    assert reports.audit_json(*args, now=NOW) == reports.audit_json(*args, now=NOW)


def test_compact_record_has_no_password_field() -> None:
    analysis = _analysis(CANARY)
    record = reports.compact(
        PasswordResult(1, 18, judge(analysis, FailOn.HIGH), analysis, label="x")
    )
    assert "password" not in record
    assert CANARY not in str(record)


def test_write_report_modes(tmp_path: Path) -> None:
    target = tmp_path / "r.txt"
    reports.write_report(target, "one", force=False)
    assert target.read_text(encoding="utf-8") == "one"
    with pytest.raises(CliError) as exists:
        reports.write_report(target, "two", force=False)
    assert exists.value.code is ExitCode.OUTPUT_ERROR
    reports.write_report(target, "two", force=True)
    assert target.read_text(encoding="utf-8") == "two"


def test_write_report_refuses_input_paths(tmp_path: Path) -> None:
    source = tmp_path / "passwords.txt"
    source.write_text("secret\n", encoding="utf-8")
    with pytest.raises(CliError) as err:
        reports.write_report(source, "x", force=True, input_paths=[source])
    assert err.value.code is ExitCode.USAGE
    assert source.read_text(encoding="utf-8") == "secret\n"


def test_write_report_missing_parent_and_directory(tmp_path: Path) -> None:
    for bad in (tmp_path / "no" / "r.txt", tmp_path):
        with pytest.raises(CliError) as err:
            reports.write_report(bad, "x", force=True)
        assert err.value.code is ExitCode.OUTPUT_ERROR


def test_write_report_is_utf8_and_keeps_newlines(tmp_path: Path) -> None:
    target = tmp_path / "r.csv"
    reports.write_report(target, "a,b\né,2\n", force=False)
    assert target.read_bytes() == "a,b\né,2\n".encode()


# --------------------------------------------------------------------------- inputs


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        ("plain", "plain"),
        ("  padded  ", "padded"),
        ("tab\there", "tab here"),
        ("esc\x1b[31m", "esc [31m"),
        ("x" * 64, "x" * 64),
        ("x" * 65, "x" * 64),
    ],
)
def test_sanitize_label(raw: str | None, expected: str | None) -> None:
    assert sanitize_label(raw) == expected


def test_batch_entry_repr_hides_the_password() -> None:
    entry = BatchEntry(index=1, line=1, password=CANARY, length=18)
    assert CANARY not in repr(entry)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _read(path: Path, **kw: object) -> inputs.BatchInput:
    params: dict[str, object] = {
        "input_format": "lines",
        "password_column": "password",
        "label_column": "label",
        "max_entries": 100,
        "max_length": 20,
    }
    params.update(kw)
    return read_batch(path, **params)  # type: ignore[arg-type]


def test_read_batch_lines_indexes_and_line_numbers(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.txt", b"aaa\n\nbbb\n\n\nccc")
    batch = _read(path)
    assert [(e.index, e.line, e.password) for e in batch.entries] == [
        (1, 1, "aaa"),
        (2, 3, "bbb"),
        (3, 6, "ccc"),
    ]
    assert batch.skipped_blank == 3


def test_read_batch_length_boundaries(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.txt", b"a" * 20 + b"\n" + b"b" * 21 + b"\n" + b"c" * 22 + b"\n")
    entries = _read(path).entries
    assert [(e.length, e.too_long) for e in entries] == [(20, False), (21, True), (22, True)]
    assert all(e.password == "" for e in entries if e.too_long)  # never retained


def test_read_batch_final_line_exactly_over_limit_without_newline(tmp_path: Path) -> None:
    entries = _read(_write(tmp_path, "a.txt", b"z" * 22)).entries
    assert (entries[0].length, entries[0].too_long) == (22, True)


def test_read_batch_duplicate_counts(tmp_path: Path) -> None:
    batch = _read(_write(tmp_path, "a.txt", b"aaa\nbbb\naaa\n"))
    tracker = ReuseTracker(e.password for e in batch.entries)
    assert [tracker.is_reused(e.password) for e in batch.entries] == [True, False, True]


def test_read_batch_csv_short_rows_are_skipped(tmp_path: Path) -> None:
    batch = _read(_write(tmp_path, "a.csv", b"label,password\nx\ny,pw1\n"), input_format="csv")
    assert [e.password for e in batch.entries] == ["pw1"]
    assert batch.skipped_blank == 1


def test_read_batch_csv_without_label_column(tmp_path: Path) -> None:
    batch = _read(_write(tmp_path, "a.csv", b"password\nabc\n"), input_format="csv")
    assert batch.entries[0].label is None


def test_read_batch_csv_embedded_newline_in_field(tmp_path: Path) -> None:
    batch = _read(_write(tmp_path, "a.csv", b'password\n"ab\ncd"\n'), input_format="csv")
    assert batch.entries[0].password == "ab\ncd"


def test_read_batch_csv_parse_error_has_no_content(tmp_path: Path) -> None:
    data = b"password\n" + b"x" * 200_000 + b"\n"  # exceeds the csv field-size limit
    with pytest.raises(CliError) as err:
        _read(_write(tmp_path, "a.csv", data), input_format="csv", max_length=300_000)
    assert "xxxx" not in err.value.message


def test_load_policy_defaults_and_overrides() -> None:
    assert load_policy(None, {}).min_length == 12
    assert load_policy(None, {"min_length": 5, "max_length": None}).min_length == 5
    assert load_policy(None, {"min_length": None}).min_length == 12


def test_load_policy_file_too_large(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    path.write_text(" " * (inputs.MAX_SMALL_FILE_BYTES + 1), encoding="utf-8")
    with pytest.raises(CliError, match="larger than"):
        load_policy(path, {})


def test_load_policy_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    path.write_bytes(b"\xff\xfe{}")
    with pytest.raises(CliError, match="UTF-8"):
        load_policy(path, {})


def test_load_personal_info_none_and_comments(tmp_path: Path) -> None:
    assert load_personal_info(None) == ()
    path = tmp_path / "me.txt"
    path.write_text("\ufeff# comment\n  Jane  \n\nBob\n", encoding="utf-8")
    items = [s.get_secret_value() for s in load_personal_info(path)]
    assert items == ["Jane", "Bob"]


def test_load_personal_info_boundaries(tmp_path: Path) -> None:
    path = tmp_path / "me.txt"
    path.write_text("\n".join(f"name{i:03d}" for i in range(50)), encoding="utf-8")
    assert len(load_personal_info(path)) == 50  # exactly the limit
    path.write_text("x" * 256, encoding="utf-8")
    assert len(load_personal_info(path)) == 1  # exactly the length limit
    path.write_text("x" * 257, encoding="utf-8")
    with pytest.raises(CliError):
        load_personal_info(path)


# --------------------------------------------------------------------------- render


@pytest.mark.parametrize(
    ("score", "filled"),
    [(-5, 0), (0, 0), (1, 0), (3, 1), (25, 5), (50, 10), (99, 20), (100, 20), (500, 20)],
)
def test_risk_bar(score: int, filled: int) -> None:
    bar = render.risk_bar(score).replace("\\", "")
    assert bar == "[" + "#" * filled + "-" * (20 - filled) + "]"


def test_risk_bar_survives_rich_markup() -> None:
    console = Console(file=io.StringIO(), width=80, no_color=True)
    console.print(f"risk {render.risk_bar(100)}")
    assert "[####################]" in console.file.getvalue()  # type: ignore[attr-defined]


def test_safe_text_escapes_markup_and_replaces_unencodable() -> None:
    console = Console(file=io.TextIOWrapper(io.BytesIO(), encoding="ascii"), width=80)
    cleaned = render.safe_text(console, "[bold]café\U0001f511[/bold]")
    assert cleaned.isascii()
    assert "\\[bold]" in cleaned  # Rich escape for a literal bracket


def test_level_markup_covers_every_level() -> None:
    for level in RiskLevel:
        assert level.value.upper() in render.level_markup(level.value)
