"""The CLI must never expose passwords: argv, output, reports, logs, tracebacks, source."""

from __future__ import annotations

import ast
import json
import logging
from pathlib import Path

import pytest
import typer
import typer.main

import passaudit.cli as cli_pkg
from passaudit.cli import app, inputs

from .conftest import CANARY, OTHER_STRONG, Cli, everything

PERSONAL = "Zebulon-Quillfeather"
PACKAGE_DIR = Path(cli_pkg.__file__).parent
SOURCE_FILES = sorted(PACKAGE_DIR.glob("*.py"))


@pytest.fixture
def fixtures(tmp_path: Path) -> dict[str, Path]:
    info = tmp_path / "me.txt"
    info.write_text(PERSONAL + "\n", encoding="utf-8")
    batch = tmp_path / "batch.txt"
    batch.write_text(f"{CANARY}\nletmein\n{OTHER_STRONG}\n{CANARY}\n", encoding="utf-8")
    batch_csv = tmp_path / "batch.csv"
    batch_csv.write_text(
        f"label,password\nuser1,{CANARY}\nuser2,{OTHER_STRONG}\n", encoding="utf-8"
    )
    return {"info": info, "batch": batch, "batch_csv": batch_csv, "dir": tmp_path}


def _matrix(fx: dict[str, Path]) -> list[tuple[list[str], str | None]]:
    """Every command in every output mode; (args, stdin)."""
    info = ["--personal-info-file", str(fx["info"])]
    pw = CANARY + "\n"
    return [
        (["audit", "--stdin", *info], pw),
        (["audit", "--stdin", "-d", *info], pw),
        (["audit", "--stdin", "-f", "json", *info], pw),
        (["audit", "--stdin", "-f", "csv", *info], pw),
        (["audit", "--stdin", "-f", "json", "-o", str(fx["dir"] / "a.json"), *info], pw),
        (["audit", "--stdin", "--min-length", "99"], f"{PERSONAL}-{CANARY}\n"),
        (["policy", "check", "--stdin", *info], pw),
        (["policy", "check", "--stdin", "-f", "json", *info], pw),
        (["policy", "check", "--stdin", "-f", "csv"], pw),
        (["batch", str(fx["batch"]), *info], None),
        (["batch", str(fx["batch"]), "-f", "json", "--detailed", *info], None),
        (["batch", str(fx["batch"]), "-f", "csv"], None),
        (["batch", str(fx["batch_csv"]), "--input-format", "csv", "-f", "json"], None),
        (["batch", "-", "-f", "json"], f"{CANARY}\n{OTHER_STRONG}\n"),
        (["batch", str(fx["batch"]), "-f", "json", "-o", str(fx["dir"] / "b.json")], None),
        (["batch", str(fx["batch"]), "-f", "csv", "-o", str(fx["dir"] / "b.csv")], None),
    ]


def test_no_secret_reaches_any_output_or_report_file(cli: Cli, fixtures: dict[str, Path]) -> None:
    secrets = [CANARY, OTHER_STRONG, "letmein", PERSONAL, "Quillfeather"]
    for args, stdin in _matrix(fixtures):
        result = cli(args, input=stdin)
        assert result.exit_code in (0, 1), (args, result.stderr)
        blob = everything(result).lower()
        for secret in secrets:
            assert secret.lower() not in blob, (args, secret)
    for report in fixtures["dir"].glob("[ab].*"):
        text = report.read_text(encoding="utf-8").lower()
        for secret in secrets:
            assert secret.lower() not in text, (report.name, secret)


def test_no_fragment_of_a_random_password_appears_anywhere(
    cli: Cli, fixtures: dict[str, Path]
) -> None:
    for args, stdin in _matrix(fixtures)[:4]:
        blob = everything(cli(args, input=stdin))
        for i in range(len(CANARY) - 5):
            assert CANARY[i : i + 6] not in blob, (args, i)


def test_hidden_prompt_never_echoes_even_on_failure_paths(cli: Cli) -> None:
    for args in (["audit"], ["policy", "check"], ["audit", "--max-length", "5"]):
        result = cli(args, input=CANARY + "\n", tty=True)
        assert CANARY not in everything(result)


def test_nothing_is_logged(
    cli: Cli, fixtures: dict[str, Path], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    for args, stdin in _matrix(fixtures):
        cli(args, input=stdin)
    assert caplog.records == []


# ------------------------------------------------------------ failure paths stay safe


def test_unexpected_exception_shows_only_its_class(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        secret = CANARY  # a local that a "pretty exception" would print
        raise RuntimeError(f"internal failure with {secret}")

    monkeypatch.setattr("passaudit.cli.commands.analyze_one", boom)
    result = cli(["audit", "--stdin"], input=CANARY + "\n")
    assert result.exit_code == 70
    assert "RuntimeError" in result.stderr
    assert "Traceback" not in everything(result)
    assert "locals" not in everything(result).lower()
    assert CANARY not in everything(result)


def test_keyboard_interrupt_at_the_prompt(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*_a: object, **_k: object) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(inputs.typer, "prompt", interrupt)
    result = cli(["audit"], tty=True)
    assert result.exit_code == 130
    assert "Interrupted" in result.stderr


def test_abort_at_the_prompt(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    def abort(*_a: object, **_k: object) -> str:
        raise typer.Abort

    monkeypatch.setattr(inputs.typer, "prompt", abort)
    result = cli(["policy", "check"], tty=True)
    assert result.exit_code == 130
    assert "Aborted" in result.stderr


def test_broken_pipe_is_quiet(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    def pipe(*_a: object, **_k: object) -> None:
        raise BrokenPipeError

    monkeypatch.setattr("passaudit.cli.commands.analyze_one", pipe)
    result = cli(["audit", "--stdin"], input="abc\n")
    assert result.stderr == ""


def test_other_oserror_is_an_internal_error_without_details(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_a: object, **_k: object) -> None:
        raise OSError(5, f"disk exploded near {CANARY}")

    monkeypatch.setattr("passaudit.cli.commands.analyze_one", fail)
    result = cli(["audit", "--stdin"], input="abc\n")
    assert result.exit_code == 70
    assert CANARY not in everything(result)


# ------------------------------------------------------------------ static guarantees


def test_no_command_accepts_a_password_argument_or_option() -> None:
    root = typer.main.get_command(app)
    banned = {"--password", "--pass", "--passwd", "--pw", "--secret", "-p", "-P"}
    arguments: list[str] = []

    def walk(cmd: object, path: str) -> None:
        for param in getattr(cmd, "params", []):
            if getattr(param, "param_type_name", "") == "argument":
                arguments.append(f"{path}:{param.name}")
            for opt in getattr(param, "opts", []):
                assert opt not in banned, f"{path} has {opt}"
        for name, sub in getattr(cmd, "commands", {}).items():
            walk(sub, f"{path} {name}")

    walk(root, "passaudit")
    assert arguments == ["passaudit batch:source"]  # the only positional is a file path


def test_cli_source_has_no_logging_printing_or_dynamic_execution() -> None:
    banned_imports = {
        "logging", "pickle", "shelve", "marshal", "sqlite3", "socket", "ssl", "subprocess",
        "urllib", "http", "requests", "httpx", "tempfile", "shutil", "os", "traceback",
        "fastapi", "starlette", "uvicorn",
    }  # fmt: skip
    banned_calls = {"print", "eval", "exec", "compile", "__import__", "breakpoint", "input"}
    assert SOURCE_FILES
    for path in SOURCE_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = {node.module.split(".")[0]}
            else:
                names = set()
            assert not names & banned_imports, f"{path.name} imports {names & banned_imports}"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in banned_calls, f"{path.name} calls {node.func.id}()"


def test_cli_does_not_depend_on_the_web_app() -> None:
    forbidden = {"passaudit.main", "passaudit.config"}
    for path in SOURCE_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in forbidden, f"{path.name} imports {node.module}"


def test_typer_pretty_exceptions_are_disabled() -> None:
    # Typer's pretty exceptions print local variables - which could hold a password.
    assert app._add_completion is False
    assert app.pretty_exceptions_enable is False
    assert app.pretty_exceptions_show_locals is False


def test_report_json_keys_never_include_a_password_field(
    cli: Cli, fixtures: dict[str, Path]
) -> None:
    def keys(node: object) -> set[str]:
        if isinstance(node, dict):
            return set(node) | {k for v in node.values() for k in keys(v)}
        if isinstance(node, list):
            return {k for v in node for k in keys(v)}
        return set()

    for args, stdin in _matrix(fixtures):
        if "json" not in args or "-o" in args:
            continue
        found = keys(json.loads(cli(args, input=stdin).stdout))
        assert "password" not in found
        assert not {k for k in found if k in {"hash", "digest", "token", "secret", "preview"}}
