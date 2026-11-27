"""`passaudit audit`: input handling, output formats, reports, exit codes."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from passaudit.analysis import RiskLevel
from passaudit.cli.reports import CSV_COLUMNS

from .conftest import CANARY, Cli, everything, parse, write_policy

# --------------------------------------------------------------------- hidden prompt


def test_hidden_prompt_strong_password_passes(cli: Cli) -> None:
    result = cli(["audit"], input=CANARY + "\n", tty=True)
    assert result.exit_code == 0
    assert "PassAudit" in result.stdout
    assert "PASS" in result.stdout
    assert "Password" in result.stderr  # the prompt goes to stderr, not stdout
    assert CANARY not in everything(result)


def test_hidden_prompt_weak_password_fails_with_exit_1(cli: Cli) -> None:
    result = cli(["audit"], input="letmein\n", tty=True)
    assert result.exit_code == 1
    assert "CRITICAL" in result.stdout
    assert "FAIL" in result.stdout
    assert "letmein" not in everything(result)


def test_prompt_is_unavailable_without_a_terminal(cli: Cli) -> None:
    result = cli(["audit"], input="letmein\n", tty=False)
    assert result.exit_code == 3
    assert "--stdin" in result.stderr
    assert "letmein" not in everything(result)


def test_prompt_text_goes_to_stderr_so_json_on_stdout_stays_clean(cli: Cli) -> None:
    result = cli(["audit", "--format", "json"], input=CANARY + "\n", tty=True)
    assert result.exit_code == 0
    assert "Password" in result.stderr
    assert parse(result)["report"]["type"] == "audit"


# --------------------------------------------------------------------------- --stdin


def test_stdin_strong_password(cli: Cli) -> None:
    result = cli(["audit", "--stdin"], input=CANARY + "\n")
    assert result.exit_code == 0
    assert CANARY not in everything(result)


def test_stdin_reads_only_the_first_line(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--format", "json"], input=CANARY + "\nignored-second-line\n")
    assert parse(result)["analysis"]["length"] == len(CANARY)


@pytest.mark.parametrize(
    "payload",
    [b"letmein\n", b"letmein\r\n", b"letmein", b"\xef\xbb\xbfletmein\n"],
    ids=["lf", "crlf", "no-newline", "utf8-bom"],
)
def test_stdin_newline_and_bom_handling(cli: Cli, payload: bytes) -> None:
    result = cli(["audit", "--stdin", "--format", "json"], input=payload)
    assert result.exit_code == 1
    assert parse(result)["analysis"]["length"] == 7


def test_stdin_preserves_inner_and_trailing_spaces(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--format", "json"], input="two words \n")
    assert parse(result)["analysis"]["length"] == 10


def test_stdin_non_ascii_password(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--format", "json"], input="пароль密码🔑\n".encode())
    assert parse(result)["analysis"]["length"] == 9


@pytest.mark.parametrize("payload", [b"", b"\n", b"\r\n"])
def test_stdin_empty_input_is_an_input_error(cli: Cli, payload: bytes) -> None:
    result = cli(["audit", "--stdin"], input=payload)
    assert result.exit_code == 3
    assert "No password" in result.stderr


def test_stdin_invalid_utf8_is_an_input_error(cli: Cli) -> None:
    result = cli(["audit", "--stdin"], input=b"\xff\xfe\xfa\n")
    assert result.exit_code == 3
    assert "UTF-8" in result.stderr


def test_max_length_boundary(cli: Cli) -> None:
    ten = "Zq7!xKp#9m"
    ok = cli(["audit", "--stdin", "--max-length", "10"], input=ten + "\n")
    assert ok.exit_code in (0, 1)  # analysed (whatever the verdict)
    too_long = cli(["audit", "--stdin", "--max-length", "10"], input=ten + "x\n")
    assert too_long.exit_code == 3
    assert "too long" in too_long.stderr
    assert ten not in everything(too_long)


def test_enormous_stdin_line_is_rejected_quickly(cli: Cli) -> None:
    result = cli(["audit", "--stdin"], input="a" * 2_000_000 + "\n")
    assert result.exit_code == 3
    assert "too long" in result.stderr or "UTF-8" in result.stderr


# ----------------------------------------------------------------------------- output


def test_json_report_is_sanitized_and_complete(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--format", "json"], input=CANARY + "\n")
    assert result.exit_code == 0
    data = parse(result)
    assert set(data) == {
        "report", "settings", "policy", "verdict", "analysis", "external_checks", "integrity",
    }  # fmt: skip
    assert data["report"]["type"] == "audit"
    assert data["report"]["sanitized"] is True
    assert data["report"]["generated_at"].endswith("+00:00")
    assert data["verdict"] == {"failed": False, "reasons": []}
    assert data["analysis"]["risk"]["score"] == 0
    assert data["analysis"]["length"] == len(CANARY)
    assert data["policy"]["min_length"] == 12
    assert CANARY not in result.stdout


def test_json_report_for_a_failing_password_still_exits_1(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "-f", "json"], input="letmein\n")
    assert result.exit_code == 1
    data = parse(result)
    assert data["verdict"]["failed"] is True
    assert "policy_violations" in data["verdict"]["reasons"]
    assert "risk_level_critical" in data["verdict"]["reasons"]
    assert "letmein" not in result.stdout
    assert data["analysis"]["findings"][0]["kind"] == "common_password"


def test_json_is_ascii_only(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "-f", "json"], input="пароль密码🔑\n".encode())
    assert result.stdout.isascii()


def test_csv_report(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--format", "csv"], input=CANARY + "\n")
    assert result.exit_code == 0
    rows = list(csv.reader(io.StringIO(result.stdout.strip())))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert len(rows) == 2
    row = dict(zip(rows[0], rows[1], strict=True))
    assert row["risk_level"] == "low"
    assert row["policy_compliant"] == "true"
    assert row["length"] == str(len(CANARY))
    assert row["failed"] == "false"
    assert CANARY not in result.stdout


def test_csv_report_for_a_failing_password(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--format", "csv"], input="letmein\n")
    assert result.exit_code == 1
    rows = list(csv.DictReader(io.StringIO(result.stdout)))
    assert rows[0]["risk_level"] == "critical"
    assert "common_password" in rows[0]["findings"]
    assert "block_common_passwords" in rows[0]["policy_violations"]
    assert rows[0]["failed"] == "true"


def test_report_file_is_written_and_terminal_view_still_shown(cli: Cli, tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    result = cli(["audit", "--stdin", "-f", "json", "-o", str(target)], input=CANARY + "\n")
    assert result.exit_code == 0
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["report"]["type"] == "audit"
    assert "PassAudit" in result.stdout  # the normal terminal view
    assert "report written" in result.stderr
    assert CANARY not in target.read_text(encoding="utf-8")
    assert CANARY not in everything(result)


def test_report_csv_file(cli: Cli, tmp_path: Path) -> None:
    target = tmp_path / "report.csv"
    result = cli(["audit", "--stdin", "-f", "csv", "-o", str(target)], input="letmein\n")
    assert result.exit_code == 1
    rows = list(csv.DictReader(io.StringIO(target.read_text(encoding="utf-8"))))
    assert len(rows) == 1
    assert "letmein" not in target.read_text(encoding="utf-8")


def test_quiet_with_report_file_prints_nothing(cli: Cli, tmp_path: Path) -> None:
    target = tmp_path / "q.json"
    result = cli(["audit", "--stdin", "-f", "json", "-o", str(target), "-q"], input=CANARY + "\n")
    assert result.exit_code == 0
    assert result.stdout == ""
    assert target.exists()


def test_quiet_text_prints_nothing_but_keeps_the_exit_code(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "-q"], input="letmein\n")
    assert result.exit_code == 1
    assert result.stdout == ""


def test_existing_report_is_not_overwritten_without_force(cli: Cli, tmp_path: Path) -> None:
    target = tmp_path / "keep.json"
    target.write_text("original", encoding="utf-8")
    result = cli(["audit", "--stdin", "-f", "json", "-o", str(target)], input=CANARY + "\n")
    assert result.exit_code == 4
    assert "--force" in result.stderr
    assert target.read_text(encoding="utf-8") == "original"


def test_force_overwrites_the_report(cli: Cli, tmp_path: Path) -> None:
    target = tmp_path / "keep.json"
    target.write_text("original", encoding="utf-8")
    result = cli(
        ["audit", "--stdin", "-f", "json", "-o", str(target), "--force"], input=CANARY + "\n"
    )
    assert result.exit_code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["report"]["type"] == "audit"


def test_report_into_a_missing_directory_is_an_output_error(cli: Cli, tmp_path: Path) -> None:
    result = cli(["audit", "--stdin", "-f", "json", "-o", str(tmp_path / "nope" / "r.json")],
                 input=CANARY + "\n")  # fmt: skip
    assert result.exit_code == 4


def test_report_path_that_is_a_directory_is_an_output_error(cli: Cli, tmp_path: Path) -> None:
    result = cli(["audit", "--stdin", "-f", "json", "-o", str(tmp_path)], input=CANARY + "\n")
    assert result.exit_code == 4


def test_details_flag_adds_breakdown(cli: Cli) -> None:
    brief = cli(["audit", "--stdin"], input=CANARY + "\n")
    full = cli(["audit", "--stdin", "--details"], input=CANARY + "\n")
    assert "Risk score breakdown" not in brief.stdout
    assert "Risk score breakdown" in full.stdout
    assert "Estimated time to crack" in full.stdout


def test_text_report_shows_findings_with_positions_not_text(cli: Cli) -> None:
    result = cli(["audit", "--stdin"], input="xxabcdxx-Zq7!xKp#9mWv\n")
    assert "sequence" in result.stdout
    assert "3-6" in result.stdout  # 1-based character range of "abcd"
    assert "abcd" not in result.stdout


def test_no_color_option_removes_ansi(cli: Cli) -> None:
    result = cli(["--no-color", "audit", "--stdin"], input="letmein\n")
    assert "\x1b[" not in result.stdout


# ---------------------------------------------------------------- policy & fail-on


def test_policy_file_json(cli: Cli, tmp_path: Path) -> None:
    policy = write_policy(tmp_path / "p.json", {"min_length": 30})
    result = cli(["audit", "--stdin", "-f", "json", "--policy", str(policy)], input=CANARY + "\n")
    assert result.exit_code == 1
    data = parse(result)
    assert data["policy"]["min_length"] == 30
    assert [v["rule"] for v in data["analysis"]["policy"]["violations"]] == ["min_length"]


def test_policy_file_toml_and_nested_table(cli: Cli, tmp_path: Path) -> None:
    path = tmp_path / "p.toml"
    path.write_text("[policy]\nmin_length = 25\nmin_digits = 2\n", encoding="utf-8")
    result = cli(["audit", "--stdin", "-f", "json", "--policy", str(path)], input=CANARY + "\n")
    assert parse(result)["policy"]["min_length"] == 25
    assert parse(result)["policy"]["min_digits"] == 2


def test_policy_file_nested_json_key(cli: Cli, tmp_path: Path) -> None:
    policy = write_policy(tmp_path / "p.json", {"policy": {"min_length": 22}})
    result = cli(["audit", "--stdin", "-f", "json", "--policy", str(policy)], input=CANARY + "\n")
    assert parse(result)["policy"]["min_length"] == 22


def test_command_line_overrides_win_over_the_policy_file(cli: Cli, tmp_path: Path) -> None:
    policy = write_policy(tmp_path / "p.json", {"min_length": 40})
    result = cli(
        ["audit", "--stdin", "-f", "json", "--policy", str(policy), "--min-length", "5"],
        input=CANARY + "\n",
    )
    assert result.exit_code == 0
    assert parse(result)["policy"]["min_length"] == 5


def test_min_strength_override(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "-f", "json", "--min-strength-score", "4"], input="tigger1\n")
    assert parse(result)["policy"]["min_strength_score"] == 4


@pytest.mark.parametrize(
    ("content", "name", "expected"),
    [
        ("{not json", "p.json", "not valid JSON"),
        ('{"min_lenght": 5}', "p.json", "unknown policy field"),
        ('{"min_length": -1}', "p.json", "min_length"),
        ('{"min_length": 20, "max_length": 10}', "p.json", "max_length"),
        ('{"min_length": "S3cr3tValue"}', "p.json", "min_length"),
        ("[1, 2]", "p.json", "object"),
        ("x = ", "p.toml", "not valid TOML"),
        ("{}", "p.yaml", ".json or .toml"),
    ],
)
def test_invalid_policy_files_are_input_errors(
    cli: Cli, tmp_path: Path, content: str, name: str, expected: str
) -> None:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    result = cli(["audit", "--stdin", "--policy", str(path)], input=CANARY + "\n")
    assert result.exit_code == 3
    assert expected in result.stderr
    assert "S3cr3tValue" not in everything(result)


def test_policy_file_errors_are_reported_before_the_password_is_read(
    cli: Cli, tmp_path: Path
) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{oops", encoding="utf-8")
    result = cli(["audit", "--policy", str(path)], input="", tty=True)  # would block on a prompt
    assert result.exit_code == 3


def test_missing_policy_file(cli: Cli, tmp_path: Path) -> None:
    result = cli(["audit", "--stdin", "--policy", str(tmp_path / "none.json")], input="x\n")
    assert result.exit_code == 3
    assert "not found" in result.stderr


def test_policy_path_that_is_a_directory(cli: Cli, tmp_path: Path) -> None:
    result = cli(["audit", "--stdin", "--policy", str(tmp_path)], input="x\n")
    assert result.exit_code == 3


@pytest.mark.parametrize(
    ("fail_on", "exit_code"),
    [("none", 0), ("moderate", 1), ("high", 1), ("critical", 1)],
)
def test_fail_on_gate_with_a_critical_password(
    cli: Cli, permissive_policy: Path, fail_on: str, exit_code: int
) -> None:
    result = cli(
        ["audit", "--stdin", "--policy", str(permissive_policy), "--fail-on", fail_on],
        input="letmein\n",
    )
    assert result.exit_code == exit_code


@pytest.mark.parametrize("fail_on", ["none", "moderate", "high", "critical"])
def test_fail_on_gate_never_trips_for_a_low_risk_password(
    cli: Cli, permissive_policy: Path, fail_on: str
) -> None:
    result = cli(
        ["audit", "--stdin", "--policy", str(permissive_policy), "--fail-on", fail_on],
        input=CANARY + "\n",
    )
    assert result.exit_code == 0


def test_policy_violation_fails_even_with_fail_on_none(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--fail-on", "none", "-f", "json"], input="short\n")
    assert result.exit_code == 1
    assert parse(result)["verdict"]["reasons"] == ["policy_violations"]


# ----------------------------------------------------------------------------- context


def test_personal_info_file_detects_without_echoing(cli: Cli, tmp_path: Path) -> None:
    info = tmp_path / "me.txt"
    info.write_text("# about me\nZebulon Quillfeather\n\nzq@example.org\n", encoding="utf-8")
    password = "zebulon-" + CANARY
    result = cli(["audit", "--stdin", "-f", "json", "--personal-info-file", str(info)],
                 input=password + "\n")  # fmt: skip
    data = parse(result)
    assert result.exit_code == 1
    kinds = {f["kind"] for f in data["analysis"]["findings"]}
    assert "personal_info" in kinds
    assert data["settings"]["personal_info_entries"] == 2
    blob = everything(result).lower()
    assert "zebulon" not in blob
    assert "quillfeather" not in blob
    assert "example.org" not in blob


def test_personal_info_file_errors(cli: Cli, tmp_path: Path) -> None:
    missing = cli(
        ["audit", "--stdin", "--personal-info-file", str(tmp_path / "x.txt")], input="a\n"
    )
    assert missing.exit_code == 3
    many = tmp_path / "many.txt"
    many.write_text("\n".join(f"name{i:03d}" for i in range(51)), encoding="utf-8")
    result = cli(["audit", "--stdin", "--personal-info-file", str(many)], input="a\n")
    assert result.exit_code == 3
    assert "more than 50" in result.stderr
    long_line = tmp_path / "long.txt"
    long_line.write_text("x" * 300, encoding="utf-8")
    assert (
        cli(["audit", "--stdin", "--personal-info-file", str(long_line)], input="a\n").exit_code
        == 3
    )


def test_usage_changes_the_target(cli: Cli) -> None:
    online = parse(cli(["audit", "--stdin", "-f", "json", "--usage", "online_account"],
                       input="Tr0ub4dor&3\n"))  # fmt: skip
    key = parse(cli(["audit", "--stdin", "-f", "json", "--usage", "encryption_key"],
                    input="Tr0ub4dor&3\n"))  # fmt: skip
    assert online["analysis"]["meets_usage_target"] is True
    assert key["analysis"]["meets_usage_target"] is False
    assert key["settings"]["usage"] == "encryption_key"


def test_reused_flag_adds_advice(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "-f", "json", "--reused"], input=CANARY + "\n")
    codes = [r["code"] for r in parse(result)["analysis"]["recommendations"]]
    assert "unique_per_service" in codes


def test_custom_wordlist(cli: Cli, tmp_path: Path) -> None:
    words = tmp_path / "block.txt"
    words.write_text("acme-corp-2024\n", encoding="utf-8")
    hit = parse(cli(["audit", "--stdin", "-f", "json", "--wordlist", str(words)],
                    input="Acme-Corp-2024\n"))  # fmt: skip
    assert any(f["kind"] == "common_password" for f in hit["analysis"]["findings"])
    assert hit["settings"]["custom_wordlist"] is True
    assert "block.txt" not in json.dumps(hit)


def test_missing_wordlist(cli: Cli, tmp_path: Path) -> None:
    result = cli(["audit", "--stdin", "--wordlist", str(tmp_path / "none.txt")], input="x\n")
    assert result.exit_code == 3


def test_risk_levels_in_report_are_valid(cli: Cli) -> None:
    data = parse(cli(["audit", "--stdin", "-f", "json"], input="letmein\n"))
    assert data["analysis"]["risk"]["level"] in {lvl.value for lvl in RiskLevel}


def test_wordlist_and_personal_info_encoding_errors(cli: Cli, tmp_path: Path) -> None:
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff\xfe\xfa\n")
    assert cli(["audit", "--stdin", "--wordlist", str(bad)], input="x\n").exit_code == 3
    assert cli(["audit", "--stdin", "--personal-info-file", str(bad)], input="x\n").exit_code == 3
    assert cli(["audit", "--stdin", "--wordlist", str(tmp_path)], input="x\n").exit_code == 3
    assert (
        cli(["audit", "--stdin", "--personal-info-file", str(tmp_path)], input="x\n").exit_code == 3
    )


def test_wordlist_too_large(cli: Cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    words = tmp_path / "w.txt"
    words.write_text("abc\n" * 10, encoding="utf-8")
    monkeypatch.setattr("passaudit.analysis.wordlist.MAX_LIST_FILE_BYTES", 5)
    result = cli(["audit", "--stdin", "--wordlist", str(words)], input="x\n")
    assert result.exit_code == 3
    assert "byte limit" in result.stderr


def test_subcommand_without_root_callback_still_works(cli: Cli) -> None:
    # `version` after a bare invocation uses default consoles; also checks --no-color placement
    assert cli(["--no-color", "version"]).exit_code == 0
