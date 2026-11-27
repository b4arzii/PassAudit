"""--help, version, and how the CLI rejects bad command lines."""

from __future__ import annotations

from pathlib import Path

import pytest

from passaudit import __version__

from .conftest import Cli, everything

SUBCOMMAND_HELP = [
    ["audit", "--help"],
    ["batch", "--help"],
    ["policy", "--help"],
    ["policy", "check", "--help"],
    ["policy", "show", "--help"],
    ["version", "--help"],
]


def test_help_lists_every_command(cli: Cli) -> None:
    result = cli(["--help"])
    assert result.exit_code == 0
    for name in ("audit", "batch", "policy", "version"):
        assert name in result.stdout
    assert "Usage" in result.stdout


def test_short_help_flag(cli: Cli) -> None:
    result = cli(["-h"])
    assert result.exit_code == 0
    assert "audit" in result.stdout


def test_help_states_the_password_rules(cli: Cli) -> None:
    text = " ".join(cli(["--help"]).stdout.split())
    assert "never from command-line arguments" in text
    assert "Exit codes" in text


def test_no_arguments_prints_help_and_succeeds(cli: Cli) -> None:
    result = cli([])
    assert result.exit_code == 0
    assert "Usage" in result.stdout
    assert "audit" in result.stdout


@pytest.mark.parametrize("args", SUBCOMMAND_HELP, ids=[" ".join(a[:-1]) for a in SUBCOMMAND_HELP])
def test_every_subcommand_has_help(cli: Cli, args: list[str]) -> None:
    result = cli(args)
    assert result.exit_code == 0
    assert "Usage" in result.stdout
    assert "--help" in result.stdout


def test_audit_help_documents_input_and_exit_codes(cli: Cli) -> None:
    text = " ".join(cli(["audit", "--help"]).stdout.split())
    assert "--stdin" in text
    assert "hidden prompt" in text
    assert "Exit codes" in text


def test_policy_group_without_subcommand_prints_help(cli: Cli) -> None:
    result = cli(["policy"])
    assert result.exit_code == 0
    assert "check" in result.stdout
    assert "show" in result.stdout


# --------------------------------------------------------------------------- version


def test_version_command(cli: Cli) -> None:
    result = cli(["version"])
    assert result.exit_code == 0
    assert f"PassAudit {__version__}" in result.stdout


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_version_flag(cli: Cli, flag: str) -> None:
    result = cli([flag])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_version_verbose(cli: Cli) -> None:
    result = cli(["version", "--verbose"])
    assert result.exit_code == 0
    for label in ("Analysis engine", "Python", "zxcvbn", "typer", "rich", "pydantic"):
        assert label in result.stdout


# ------------------------------------------------------------- usage errors (exit 2)


def test_unknown_command_is_a_usage_error_without_echo(cli: Cli) -> None:
    result = cli(["hunter2-secret"])
    assert result.exit_code == 2
    assert "hunter2-secret" not in everything(result)
    assert "Unknown command" in result.stderr


def test_a_password_as_extra_argument_is_rejected_and_not_echoed(cli: Cli) -> None:
    result = cli(["audit", "hunter2-secret"])
    assert result.exit_code == 2
    assert "hunter2-secret" not in everything(result)
    assert "never accepts a password" in " ".join(result.stderr.split())


def test_a_password_as_batch_extra_argument_is_not_echoed(cli: Cli) -> None:
    result = cli(["batch", "somefile.txt", "hunter2-secret"])
    assert result.exit_code == 2
    assert "hunter2-secret" not in everything(result)


def test_a_password_as_policy_check_argument_is_not_echoed(cli: Cli) -> None:
    result = cli(["policy", "check", "hunter2-secret"])
    assert result.exit_code == 2
    assert "hunter2-secret" not in everything(result)


@pytest.mark.parametrize(
    "args",
    [
        ["audit", "--password", "hunter2-secret"],
        ["audit", "--password=hunter2-secret"],
        ["audit", "-p", "hunter2-secret"],
        ["policy", "check", "--password=hunter2-secret"],
    ],
)
def test_there_is_no_password_option(cli: Cli, args: list[str]) -> None:
    result = cli(args)
    assert result.exit_code == 2
    assert "hunter2-secret" not in everything(result)
    assert "No such option" in result.stderr


def test_invalid_choice_value_is_not_echoed(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--usage", "hunter2-secret"])
    assert result.exit_code == 2
    assert "hunter2-secret" not in everything(result)
    assert "--usage" in result.stderr


def test_invalid_format_value_is_not_echoed(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--format", "hunter2-secret"])
    assert result.exit_code == 2
    assert "hunter2-secret" not in everything(result)


def test_invalid_number_is_not_echoed(cli: Cli) -> None:
    result = cli(["audit", "--stdin", "--max-length", "hunter2-secret"])
    assert result.exit_code == 2
    assert "hunter2-secret" not in everything(result)


@pytest.mark.parametrize("value", ["0", "65537", "-1"])
def test_number_out_of_range_is_a_usage_error(cli: Cli, value: str) -> None:
    assert cli(["audit", "--stdin", "--max-length", value]).exit_code == 2


def test_missing_batch_file_argument_is_a_usage_error(cli: Cli) -> None:
    result = cli(["batch"])
    assert result.exit_code == 2
    assert "FILE" in result.stderr


def test_usage_error_points_to_help(cli: Cli) -> None:
    result = cli(["audit", "--bogus"])
    assert result.exit_code == 2
    assert "--help" in result.stderr


def test_output_requires_a_machine_format(cli: Cli, tmp_path: Path) -> None:
    result = cli(["audit", "--stdin", "-o", str(tmp_path / "x.txt")], input="abc\n")
    assert result.exit_code == 2
    assert "--format" in result.stderr


def test_rejected_choice_lists_the_valid_values(cli: Cli) -> None:
    result = " ".join(cli(["audit", "--stdin", "--usage", "hunter2-secret"]).stderr.split())
    assert "choose one of general, online_account" in result
    assert "hunter2-secret" not in result
    fmt = " ".join(cli(["audit", "--stdin", "-f", "hunter2-secret"]).stderr.split())
    assert "choose one of text, json, csv" in fmt
    fail_on = " ".join(cli(["audit", "--stdin", "--fail-on", "x"]).stderr.split())
    assert "none, moderate, high, critical" in fail_on
    batch_fmt = " ".join(cli(["batch", "f.txt", "--input-format", "x"]).stderr.split())
    assert "lines, csv" in batch_fmt


def test_rejected_number_states_the_allowed_range(cli: Cli) -> None:
    result = " ".join(cli(["audit", "--stdin", "--max-length", "0"]).stderr.split())
    assert "whole number from 1 to 65536" in result
    assert "whole number from 0 to 1024" in " ".join(
        cli(["audit", "--stdin", "--min-length", "hunter2-secret"]).stderr.split()
    )
