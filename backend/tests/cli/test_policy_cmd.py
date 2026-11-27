"""`passaudit policy check` and `passaudit policy show`."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from passaudit.cli.reports import POLICY_CSV_COLUMNS

from .conftest import CANARY, Cli, everything, parse, write_policy


def _rule_status(result_stdout: str) -> dict[str, str]:
    return {r["rule"]: r["status"] for r in json.loads(result_stdout)["rules"]}


# ------------------------------------------------------------------------------ check


def test_compliant_password_passes(cli: Cli) -> None:
    result = cli(["policy", "check"], input=CANARY + "\n", tty=True)
    assert result.exit_code == 0
    assert "PASS" in result.stdout
    assert "all 4 rules satisfied" in result.stdout
    assert CANARY not in everything(result)


def test_weak_password_fails_with_details(cli: Cli) -> None:
    result = cli(["policy", "check", "--stdin"], input="letmein\n")
    assert result.exit_code == 1
    assert "FAIL" in result.stdout
    assert "At least 12 characters" in result.stdout
    assert "3 of 4 rules violated" in result.stdout
    assert "letmein" not in everything(result)


def test_check_needs_a_terminal_or_stdin(cli: Cli) -> None:
    result = cli(["policy", "check"], input="x\n", tty=False)
    assert result.exit_code == 3
    assert "--stdin" in result.stderr


@pytest.mark.parametrize(
    ("flags", "exit_code"),
    [
        (["--min-digits", "3"], 0),  # CANARY has exactly 3 digits
        (["--min-digits", "4"], 1),
        (["--min-uppercase", "5"], 0),  # Z K W L R
        (["--min-uppercase", "6"], 1),
        (["--min-lowercase", "7"], 0),
        (["--min-lowercase", "8"], 1),
        (["--min-symbols", "3"], 0),  # ! # $
        (["--min-symbols", "4"], 1),
        (["--min-length", "18"], 0),  # exactly the length
        (["--min-length", "19"], 1),
    ],
)
def test_rule_boundaries_through_flags(cli: Cli, flags: list[str], exit_code: int) -> None:
    result = cli(["policy", "check", "--stdin", *flags], input=CANARY + "\n")
    assert result.exit_code == exit_code


def test_max_repeat_run_flag(cli: Cli) -> None:
    ok = cli(["policy", "check", "--stdin", "--max-repeat-run", "3", "-f", "json"],
             input="aaa-Zq7!xKp#9mWv\n")  # fmt: skip
    bad = cli(["policy", "check", "--stdin", "--max-repeat-run", "3", "-f", "json"],
              input="aaaa-Zq7!xKp#9mWv\n")  # fmt: skip
    assert _rule_status(ok.stdout)["max_repeat_run"] == "pass"
    assert _rule_status(bad.stdout)["max_repeat_run"] == "fail"
    assert bad.exit_code == 1


def test_no_whitespace_flag(cli: Cli) -> None:
    bad = cli(["policy", "check", "--stdin", "--no-whitespace", "-f", "json"],
              input="Zq7!xKp #9mWv$L2nRb\n")  # fmt: skip
    ok = cli(["policy", "check", "--stdin", "--no-whitespace", "-f", "json"], input=CANARY + "\n")
    assert _rule_status(bad.stdout)["forbid_whitespace"] == "fail"
    assert _rule_status(ok.stdout)["forbid_whitespace"] == "pass"


def test_only_enabled_rules_are_listed(cli: Cli) -> None:
    default = _rule_status(
        cli(["policy", "check", "--stdin", "-f", "json"], input=CANARY + "\n").stdout
    )
    assert set(default) == {
        "min_length",
        "block_common_passwords",
        "forbid_personal_info",
        "min_strength_score",
    }
    extended = _rule_status(
        cli(
            ["policy", "check", "--stdin", "-f", "json", "--min-digits", "1"], input=CANARY + "\n"
        ).stdout
    )
    assert "min_digits" in extended


def test_json_report(cli: Cli) -> None:
    result = cli(["policy", "check", "--stdin", "-f", "json"], input="letmein\n")
    assert result.exit_code == 1
    data = parse(result)
    assert set(data) == {
        "report", "settings", "policy", "verdict", "length", "rules", "external_checks",
        "integrity",
    }  # fmt: skip
    assert data["report"]["type"] == "policy_check"
    assert data["length"] == 7
    assert data["verdict"] == {"failed": True, "reasons": ["policy_violations"]}
    failing = {r["rule"]: r for r in data["rules"] if r["status"] == "fail"}
    assert failing["min_length"]["required"] == 12
    assert failing["min_length"]["actual"] == 7
    assert "letmein" not in result.stdout


def test_csv_report(cli: Cli) -> None:
    result = cli(["policy", "check", "--stdin", "-f", "csv"], input="letmein\n")
    rows = list(csv.DictReader(io.StringIO(result.stdout)))
    assert tuple(rows[0]) == POLICY_CSV_COLUMNS
    assert {r["rule"]: r["status"] for r in rows}["min_length"] == "fail"
    assert "letmein" not in result.stdout


def test_report_file(cli: Cli, tmp_path: Path) -> None:
    target = tmp_path / "check.json"
    result = cli(
        ["policy", "check", "--stdin", "-f", "json", "-o", str(target)], input=CANARY + "\n"
    )
    assert result.exit_code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["verdict"]["failed"] is False
    assert cli(["policy", "check", "--stdin", "-f", "json", "-o", str(target)],
               input=CANARY + "\n").exit_code == 4  # fmt: skip


def test_policy_file_with_overrides(cli: Cli, tmp_path: Path) -> None:
    policy = write_policy(tmp_path / "p.json", {"min_length": 30, "min_digits": 1})
    result = cli(["policy", "check", "--stdin", "--policy", str(policy), "-f", "json"],
                 input=CANARY + "\n")  # fmt: skip
    data = parse(result)
    assert result.exit_code == 1
    assert data["policy"]["min_length"] == 30
    args = [
        "policy",
        "check",
        "--stdin",
        "--policy",
        str(policy),
        "--min-length",
        "10",
        "-f",
        "json",
    ]
    override = cli(args, input=CANARY + "\n")
    assert override.exit_code == 0
    assert parse(override)["policy"]["min_length"] == 10


def test_invalid_policy_is_an_input_error(cli: Cli, tmp_path: Path) -> None:
    policy = write_policy(tmp_path / "p.json", {"min_length": 50, "max_length": 5})
    result = cli(["policy", "check", "--stdin", "--policy", str(policy)], input="x\n")
    assert result.exit_code == 3
    assert "max_length" in result.stderr


def test_personal_info_rule(cli: Cli, tmp_path: Path) -> None:
    info = tmp_path / "me.txt"
    info.write_text("Zebulon\n", encoding="utf-8")
    result = cli(["policy", "check", "--stdin", "--personal-info-file", str(info), "-f", "json"],
                 input="zebulon-" + CANARY + "\n")  # fmt: skip
    assert _rule_status(result.stdout)["forbid_personal_info"] == "fail"
    assert "zebulon" not in everything(result).lower()


def test_custom_wordlist_rule(cli: Cli, tmp_path: Path) -> None:
    words = tmp_path / "w.txt"
    words.write_text("acme-corp-2024\n", encoding="utf-8")
    result = cli(["policy", "check", "--stdin", "--wordlist", str(words), "-f", "json"],
                 input="Acme-Corp-2024\n")  # fmt: skip
    assert _rule_status(result.stdout)["block_common_passwords"] == "fail"


def test_empty_input_is_an_input_error(cli: Cli) -> None:
    assert cli(["policy", "check", "--stdin"], input="").exit_code == 3


def test_check_quiet(cli: Cli) -> None:
    result = cli(["policy", "check", "--stdin", "-q"], input="letmein\n")
    assert result.exit_code == 1
    assert result.stdout == ""


# ------------------------------------------------------------------------------- show


def test_show_prints_the_default_policy_as_json(cli: Cli) -> None:
    result = cli(["policy", "show"])
    assert result.exit_code == 0
    data = parse(result)
    assert data["min_length"] == 12
    assert data["block_common_passwords"] is True
    assert set(data) >= {"min_length", "max_length", "min_digits", "min_strength_score"}


def test_show_applies_file_and_overrides(cli: Cli, tmp_path: Path) -> None:
    policy = write_policy(tmp_path / "p.json", {"min_length": 20, "min_symbols": 2})
    data = parse(cli(["policy", "show", "--policy", str(policy), "--min-strength-score", "4"]))
    assert (data["min_length"], data["min_symbols"], data["min_strength_score"]) == (20, 2, 4)


def test_show_output_is_a_valid_policy_file(cli: Cli, tmp_path: Path) -> None:
    template = tmp_path / "template.json"
    template.write_text(cli(["policy", "show"]).stdout, encoding="utf-8")
    result = cli(["policy", "check", "--stdin", "--policy", str(template)], input=CANARY + "\n")
    assert result.exit_code == 0


def test_show_with_a_bad_policy_file(cli: Cli, tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert cli(["policy", "show", "--policy", str(bad)]).exit_code == 3


def test_requirement_wording_is_singular_for_one(cli: Cli) -> None:
    one = cli(["policy", "check", "--stdin", "--min-uppercase", "1", "--min-digits", "1"],
              input=CANARY + "\n")  # fmt: skip
    assert "At least 1 uppercase letter " in one.stdout + " "
    assert "At least 1 digit " in one.stdout + " "
    assert "1 digits" not in one.stdout
    many = cli(["policy", "check", "--stdin", "--min-digits", "2"], input=CANARY + "\n")
    assert "At least 2 digits" in many.stdout
