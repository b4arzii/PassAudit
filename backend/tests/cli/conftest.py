"""Shared fixtures for the CLI tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner, Result

from passaudit.cli import app
from passaudit.cli import inputs as inputs_module

# Random-looking, in no dictionary: if it appears in any output, a password leaked.
CANARY = "Zq7!xKp#9mWv$L2nRb"
OTHER_STRONG = "Qw8$yL3!pN6#zT1vHd"
# A permissive policy so only the risk gate decides pass/fail in --fail-on tests.
PERMISSIVE_POLICY = {
    "min_length": 0,
    "min_strength_score": 0,
    "block_common_passwords": False,
    "forbid_personal_info": False,
}

Cli = Callable[..., Result]


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch) -> Cli:
    """Invoke the app. ``tty=True`` makes the hidden prompt available (stdin looks interactive)."""
    runner = CliRunner(env={"COLUMNS": "140", "NO_COLOR": "1", "TERM": "dumb"})

    def run(args: list[str], *, input: str | bytes | None = None, tty: bool = False) -> Result:  # noqa: A002
        monkeypatch.setattr(inputs_module, "stdin_is_tty", lambda: tty)
        return runner.invoke(app, args, input=input)

    return run


def everything(result: Result) -> str:
    """All text a user (or log scraper) could see from a run."""
    return result.stdout + result.stderr + repr(result.exception)


def parse(result: Result) -> Any:
    return json.loads(result.stdout)


def write_policy(path: Path, data: dict[str, Any]) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def permissive_policy(tmp_path: Path) -> Path:
    return write_policy(tmp_path / "permissive.json", PERMISSIVE_POLICY)
