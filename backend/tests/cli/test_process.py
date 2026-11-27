"""Run the CLI as a real subprocess (`python -m passaudit`), as a user or script would."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from passaudit import __version__

from .conftest import CANARY


def run(
    *args: str, stdin: bytes | None = None, cwd: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "COLUMNS": "120", "NO_COLOR": "1"}
    return subprocess.run(  # noqa: S603 - fixed argv; the interpreter is our own
        [sys.executable, "-m", "passaudit", *args],
        input=stdin if stdin is not None else b"",
        capture_output=True,
        timeout=120,
        check=False,
        env=env,
        cwd=cwd,
    )


def test_module_help_and_version() -> None:
    help_run = run("--help")
    assert help_run.returncode == 0
    assert b"audit" in help_run.stdout
    assert b"Traceback" not in help_run.stderr
    version = run("version")
    assert version.returncode == 0
    assert f"PassAudit {__version__}".encode() in version.stdout


def test_audit_stdin_end_to_end() -> None:
    ok = run("audit", "--stdin", stdin=CANARY.encode() + b"\n")
    assert ok.returncode == 0
    weak = run("audit", "--stdin", stdin=b"letmein\n")
    assert weak.returncode == 1
    assert b"CRITICAL" in weak.stdout
    for process in (ok, weak):
        assert CANARY.encode() not in process.stdout + process.stderr
        assert b"letmein" not in process.stdout + process.stderr


def test_json_report_end_to_end() -> None:
    process = run("audit", "--stdin", "-f", "json", stdin=CANARY.encode() + b"\n")
    assert process.returncode == 0
    data = json.loads(process.stdout)
    assert data["report"]["type"] == "audit"
    assert CANARY.encode() not in process.stdout + process.stderr


def test_hidden_prompt_refuses_to_run_without_a_terminal() -> None:
    process = run("audit", stdin=b"letmein\n")
    assert process.returncode == 3
    assert b"--stdin" in process.stderr
    assert b"letmein" not in process.stdout + process.stderr


def test_password_argument_is_rejected_without_echo() -> None:
    process = run("audit", "hunter2-secret")
    assert process.returncode == 2
    assert b"hunter2-secret" not in process.stdout + process.stderr


def test_batch_end_to_end(tmp_path: Path) -> None:
    source = tmp_path / "pw.txt"
    source.write_text(f"{CANARY}\nletmein\n", encoding="utf-8")
    report = tmp_path / "out.csv"
    process = run("batch", str(source), "-f", "csv", "-o", str(report), "-q")
    assert process.returncode == 1
    assert process.stdout == b""
    text = report.read_text(encoding="utf-8")
    assert "letmein" not in text
    assert CANARY not in text
    assert text.count("\n") == 3  # header + two rows


def test_policy_check_end_to_end() -> None:
    process = run("policy", "check", "--stdin", "--min-digits", "3", stdin=CANARY.encode() + b"\n")
    assert process.returncode == 0
    assert b"PASS" in process.stdout


def test_unicode_password_over_a_pipe() -> None:
    process = run("audit", "--stdin", "-f", "json", stdin="пароль密码🔑\n".encode())
    assert json.loads(process.stdout)["analysis"]["length"] == 9
