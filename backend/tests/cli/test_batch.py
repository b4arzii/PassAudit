"""`passaudit batch`: file formats, labels, duplicates, limits, reports, exit codes."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from passaudit.cli.reports import CSV_COLUMNS

from .conftest import CANARY, OTHER_STRONG, Cli, everything, parse, write_policy


def _lines(tmp_path: Path, *passwords: str, name: str = "pw.txt", newline: str = "\n") -> Path:
    path = tmp_path / name
    path.write_bytes(newline.join(passwords).encode("utf-8") + newline.encode())
    return path


@pytest.fixture
def mixed(tmp_path: Path) -> Path:
    # entries: 1 weak, 2 strong, 3 weak (duplicate of 1), blank, 5 strong
    return _lines(tmp_path, "letmein", CANARY, "letmein", "", OTHER_STRONG)


# --------------------------------------------------------------------------- text


def test_text_summary_and_exit_code(cli: Cli, mixed: Path) -> None:
    result = cli(["batch", str(mixed)])
    assert result.exit_code == 1
    assert "batch audit" in result.stdout
    assert "Highest-risk entries" in result.stdout
    assert "Risk distribution" in result.stdout
    assert "2 of 4 passwords failed" in result.stdout
    assert "reused" in result.stdout
    for secret in ("letmein", CANARY, OTHER_STRONG):
        assert secret not in everything(result)


def test_all_strong_passwords_exit_zero(cli: Cli, tmp_path: Path) -> None:
    result = cli(["batch", str(_lines(tmp_path, CANARY, OTHER_STRONG))])
    assert result.exit_code == 0
    assert "all 2 passwords passed" in result.stdout


def test_show_limits_the_table(cli: Cli, mixed: Path) -> None:
    result = cli(["batch", str(mixed), "--show", "1"])
    assert "showing 1 of 4" in result.stdout


def test_quiet_prints_nothing(cli: Cli, mixed: Path) -> None:
    result = cli(["batch", str(mixed), "-q"])
    assert result.exit_code == 1
    assert result.stdout == ""


# ---------------------------------------------------------------------------- json


def test_json_report(cli: Cli, mixed: Path) -> None:
    result = cli(["batch", str(mixed), "-f", "json"])
    assert result.exit_code == 1
    data = parse(result)
    assert set(data) == {
        "report", "settings", "policy", "summary", "results", "external_checks", "integrity",
    }  # fmt: skip
    assert data["report"]["type"] == "batch"
    summary = data["summary"]
    assert summary["entries"] == 4
    assert summary["skipped_blank"] == 1
    assert summary["failed"] == 2
    assert summary["passed"] == 2
    assert summary["reused_in_batch"] == 2
    assert sum(summary["risk_levels"].values()) == 4
    assert summary["risk_levels"]["critical"] == 2
    results = data["results"]
    assert [r["index"] for r in results] == [1, 2, 3, 4]
    assert [r["line"] for r in results] == [1, 2, 3, 5]  # source line numbers survive blanks
    assert [r["reused_in_batch"] for r in results] == [True, False, True, False]
    assert [r["failed"] for r in results] == [True, False, True, False]
    assert results[0]["risk"]["level"] == "critical"
    assert results[1]["risk"] == {"score": 0, "level": "low"}
    assert "analysis" not in results[0]  # compact by default
    assert results[0]["findings"] == ["common_password"]
    for secret in ("letmein", CANARY, OTHER_STRONG):
        assert secret not in result.stdout


def test_detailed_json_includes_full_analysis(cli: Cli, mixed: Path) -> None:
    result = cli(["batch", str(mixed), "-f", "json", "--detailed"])
    first = parse(result)["results"][0]
    assert first["analysis"]["risk"]["level"] == "critical"
    assert "letmein" not in result.stdout


def test_reused_passwords_get_the_reuse_recommendation(cli: Cli, mixed: Path) -> None:
    results = parse(cli(["batch", str(mixed), "-f", "json"]))["results"]
    assert "unique_per_service" in results[0]["recommendations"]
    assert "unique_per_service" not in results[1]["recommendations"]


def test_report_file(cli: Cli, mixed: Path, tmp_path: Path) -> None:
    target = tmp_path / "out" / "r.json"
    target.parent.mkdir()
    result = cli(["batch", str(mixed), "-f", "json", "-o", str(target)])
    assert result.exit_code == 1
    assert json.loads(target.read_text(encoding="utf-8"))["summary"]["entries"] == 4
    assert "report written" in result.stderr
    assert "batch audit" in result.stdout


def test_report_never_overwrites_the_input_file(cli: Cli, mixed: Path) -> None:
    before = mixed.read_bytes()
    result = cli(["batch", str(mixed), "-f", "json", "-o", str(mixed), "--force"])
    assert result.exit_code == 2
    assert mixed.read_bytes() == before


def test_existing_report_needs_force(cli: Cli, mixed: Path, tmp_path: Path) -> None:
    target = tmp_path / "r.csv"
    target.write_text("keep", encoding="utf-8")
    assert cli(["batch", str(mixed), "-f", "csv", "-o", str(target)]).exit_code == 4
    assert target.read_text(encoding="utf-8") == "keep"
    assert cli(["batch", str(mixed), "-f", "csv", "-o", str(target), "--force"]).exit_code == 1


# ----------------------------------------------------------------------------- csv


def test_csv_report(cli: Cli, mixed: Path) -> None:
    result = cli(["batch", str(mixed), "-f", "csv"])
    assert result.exit_code == 1
    rows = list(csv.DictReader(io.StringIO(result.stdout)))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert [r["index"] for r in rows] == ["1", "2", "3", "4"]
    assert [r["risk_level"] for r in rows] == ["critical", "low", "critical", "low"]
    assert [r["reused_in_batch"] for r in rows] == ["true", "false", "true", "false"]
    assert "letmein" not in result.stdout


# --------------------------------------------------------------------- input formats


def test_csv_input_with_labels(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "in.csv"
    path.write_text(f"label,password\nalice,letmein\nbob,{CANARY}\n", encoding="utf-8")
    result = cli(["batch", str(path), "--input-format", "csv", "-f", "json"])
    data = parse(result)
    assert [r["label"] for r in data["results"]] == ["alice", "bob"]
    assert [r["line"] for r in data["results"]] == [2, 3]
    assert "letmein" not in result.stdout


def test_csv_input_custom_columns_and_ignored_extra_columns(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "in.csv"
    path.write_text(f"user,secret,note\ncarol,{CANARY},x\n", encoding="utf-8")
    result = cli(["batch", str(path), "--input-format", "csv", "--password-column", "secret",
                  "--label-column", "user", "-f", "json"])  # fmt: skip
    assert parse(result)["results"][0]["label"] == "carol"
    assert result.exit_code == 0


def test_csv_input_quoted_fields_and_blank_passwords(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "in.csv"
    path.write_text(f'label,password\n"a, b","{CANARY}"\nempty,\n', encoding="utf-8")
    data = parse(cli(["batch", str(path), "--input-format", "csv", "-f", "json"]))
    assert data["summary"]["entries"] == 1
    assert data["summary"]["skipped_blank"] == 1
    assert data["results"][0]["label"] == "a, b"


def test_csv_without_the_password_column_does_not_echo_the_header(cli: Cli, tmp_path: Path) -> None:
    # A plain password list fed to --input-format csv: its first line is taken as the header.
    path = _lines(tmp_path, "hunter2-secret", "letmein")
    result = cli(["batch", str(path), "--input-format", "csv"])
    assert result.exit_code == 3
    assert "no column named 'password'" in result.stderr
    assert "hunter2-secret" not in everything(result)


def test_empty_csv(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "e.csv"
    path.write_text("", encoding="utf-8")
    assert cli(["batch", str(path), "--input-format", "csv"]).exit_code == 3


def test_labels_that_reveal_the_password_are_redacted(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "in.csv"
    path.write_text(
        "label,password\n"
        f"{CANARY},{CANARY}\n"
        f"acct-{CANARY}-prod,{CANARY}\n"
        "letmein,letmein\n"
        "ok-label,Qw8$yL3!pN6#zT1vHd\n",
        encoding="utf-8",
    )
    result = cli(["batch", str(path), "--input-format", "csv", "-f", "json"])
    labels = [r["label"] for r in parse(result)["results"]]
    assert labels == ["[redacted]", "[redacted]", "[redacted]", "ok-label"]
    assert CANARY not in result.stdout


def test_labels_are_sanitised_for_terminals_and_length(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "in.csv"
    nasty = "evil\x1b[31mred\x07" + "x" * 200
    path.write_text(f'label,password\n"{nasty}",{CANARY}\n', encoding="utf-8")
    result = cli(["batch", str(path), "--input-format", "csv", "-f", "json"])
    label = parse(result)["results"][0]["label"]
    assert "\x1b" not in label
    assert "\x07" not in label
    assert len(label) <= 64
    text = cli(["batch", str(path), "--input-format", "csv"])
    assert "\x1b" not in text.stdout


def test_csv_report_neutralises_formula_injection(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "in.csv"
    path.write_text(
        f"label,password\n=HYPERLINK(1),{CANARY}\n@SUM(A1),{CANARY}x\n", encoding="utf-8"
    )
    result = cli(["batch", str(path), "--input-format", "csv", "-f", "csv"])
    labels = [r["label"] for r in csv.DictReader(io.StringIO(result.stdout))]
    assert labels == ["'=HYPERLINK(1)", "'@SUM(A1)"]


def test_stdin_source(cli: Cli) -> None:
    result = cli(["batch", "-", "-f", "json"], input=f"letmein\n{CANARY}\n")
    assert parse(result)["summary"]["entries"] == 2
    assert result.exit_code == 1


def test_bom_and_crlf_lines(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "w.txt"
    path.write_bytes(b"\xef\xbb\xbfletmein\r\n" + CANARY.encode() + b"\r\n")
    results = parse(cli(["batch", str(path), "-f", "json"]))["results"]
    assert [r["length"] for r in results] == [7, len(CANARY)]


def test_trailing_spaces_are_part_of_the_password(cli: Cli, tmp_path: Path) -> None:
    path = _lines(tmp_path, "letmein  ")
    assert parse(cli(["batch", str(path), "-f", "json"]))["results"][0]["length"] == 9


# ------------------------------------------------------------------------ limits


def test_over_long_passwords_are_flagged_not_analysed(cli: Cli, tmp_path: Path) -> None:
    path = _lines(tmp_path, CANARY, "x" * 40, OTHER_STRONG)
    result = cli(["batch", str(path), "--max-length", "30", "-f", "json"])
    assert result.exit_code == 1
    data = parse(result)
    middle = data["results"][1]
    assert (middle["status"], middle["error"], middle["length"]) == ("error", "too_long", 40)
    assert middle["fail_reasons"] == ["input_too_long"]
    assert middle["risk"] is None
    assert data["summary"]["errors"] == 1
    assert "x" * 10 not in result.stdout


def test_max_length_boundary_in_batch(cli: Cli, tmp_path: Path) -> None:
    path = _lines(tmp_path, "a" * 30, "b" * 31)
    results = parse(cli(["batch", str(path), "--max-length", "30", "-f", "json"]))["results"]
    assert [r["status"] for r in results] == ["ok", "error"]


def test_a_gigantic_line_is_bounded(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "huge.txt"
    path.write_bytes(b"a" * 3_000_000 + b"\n" + CANARY.encode() + b"\n")
    result = cli(["batch", str(path), "-f", "json"])
    data = parse(result)
    assert data["results"][0]["error"] == "too_long"
    assert data["results"][0]["length"] == 3_000_000
    assert data["results"][1]["status"] == "ok"
    assert data["results"][1]["line"] == 2


def test_max_entries_boundary(cli: Cli, tmp_path: Path) -> None:
    path = _lines(tmp_path, CANARY, OTHER_STRONG, "Mn4#bV9!kJ2$wQ8x")
    assert cli(["batch", str(path), "--max-entries", "3"]).exit_code == 0
    over = cli(["batch", str(path), "--max-entries", "2"])
    assert over.exit_code == 3
    assert "more than 2 passwords" in over.stderr


# -------------------------------------------------------------------------- errors


def test_missing_file(cli: Cli, tmp_path: Path) -> None:
    result = cli(["batch", str(tmp_path / "nope.txt")])
    assert result.exit_code == 3
    assert "not found" in result.stderr


def test_directory_as_input(cli: Cli, tmp_path: Path) -> None:
    assert cli(["batch", str(tmp_path)]).exit_code == 3


@pytest.mark.parametrize("content", [b"", b"\n\n\n", b"\r\n\r\n"])
def test_input_without_passwords(cli: Cli, tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "e.txt"
    path.write_bytes(content)
    result = cli(["batch", str(path)])
    assert result.exit_code == 3
    assert "no passwords" in result.stderr


def test_invalid_utf8(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "bad.txt"
    path.write_bytes(b"letmein\n\xff\xfe\n")
    result = cli(["batch", str(path)])
    assert result.exit_code == 3
    assert "UTF-8" in result.stderr
    assert "letmein" not in everything(result)


# ----------------------------------------------------------------------- fail gate


def test_fail_on_none_with_a_permissive_policy_passes(
    cli: Cli, mixed: Path, permissive_policy: Path
) -> None:
    result = cli(["batch", str(mixed), "--policy", str(permissive_policy), "--fail-on", "none"])
    assert result.exit_code == 0


def test_fail_on_critical_with_a_permissive_policy_fails(
    cli: Cli, mixed: Path, permissive_policy: Path
) -> None:
    result = cli(["batch", str(mixed), "--policy", str(permissive_policy), "--fail-on", "critical"])
    assert result.exit_code == 1


def test_policy_file_applies_to_every_entry(cli: Cli, tmp_path: Path) -> None:
    path = _lines(tmp_path, CANARY, OTHER_STRONG)
    policy = write_policy(tmp_path / "p.json", {"min_length": 30})
    data = parse(cli(["batch", str(path), "--policy", str(policy), "-f", "json"]))
    assert data["summary"]["failed"] == 2
    assert data["policy"]["min_length"] == 30


def test_personal_info_applies_per_entry(cli: Cli, tmp_path: Path) -> None:
    info = tmp_path / "me.txt"
    info.write_text("Zebulon\n", encoding="utf-8")
    path = _lines(tmp_path, "zebulon-" + CANARY, OTHER_STRONG)
    result = cli(["batch", str(path), "--personal-info-file", str(info), "-f", "json"])
    results = parse(result)["results"]
    assert results[0]["findings"] == ["personal_info"]
    assert results[1]["findings"] == []
    assert "zebulon" not in everything(result).lower()


def test_unexpected_failure_during_a_batch_shows_no_password(
    cli: Cli, mixed: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError(f"failed on {CANARY}")

    monkeypatch.setattr("passaudit.cli.commands.analyze_one", boom)
    result = cli(["batch", str(mixed)])
    assert result.exit_code == 70
    assert "RuntimeError" in result.stderr
    assert CANARY not in everything(result)


def test_text_view_shows_unanalysable_entries(cli: Cli, tmp_path: Path) -> None:
    path = _lines(tmp_path, CANARY, "x" * 40)
    result = cli(["batch", str(path), "--max-length", "30"])
    assert result.exit_code == 1
    assert "Unanalysable" in result.stdout
    assert "too long" in result.stdout
    assert "x" * 10 not in result.stdout


def test_text_view_labels_are_terminal_safe(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "in.csv"
    path.write_text(f"label,password\n[bold red]hi[/],{CANARY}\n", encoding="utf-8")
    result = cli(["batch", str(path), "--input-format", "csv"])
    assert "[bold red]hi[/]" in result.stdout  # shown literally, not interpreted as markup
