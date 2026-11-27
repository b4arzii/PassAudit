"""Phase 9: the error paths of the reuse commands (previously untested) and their exit codes."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import Result

from .conftest import CANARY, Cli, everything


def _build(cli: Cli, tmp_path: Path, *sources: str) -> tuple[Path, Path, Result]:
    index, key = tmp_path / "reuse.idx", tmp_path / "reuse.key"
    args = ["reuse", "build", "--index-out", str(index), "--key-file", str(key)]
    for spec in sources:
        args += ["--source", spec]
    result = cli([*args, "--confirm-authorized", "--authorization-ref", "TICKET-9"])
    return index, key, result


@pytest.mark.parametrize("spec", ["nodelimiter", "=file.txt", "name=", ""])
def test_a_malformed_source_is_a_usage_error(cli: Cli, tmp_path: Path, spec: str) -> None:
    _, _, result = _build(cli, tmp_path, spec)
    assert result.exit_code == 2
    assert "NAME=FILE" in result.stderr


def test_a_missing_source_file_is_an_input_error_that_does_not_name_the_path(
    cli: Cli, tmp_path: Path
) -> None:
    secret_dir = tmp_path / "jane-doe-private"
    _, _, result = _build(cli, tmp_path, f"hr={secret_dir / 'missing.txt'}")
    assert result.exit_code == 3
    assert "not found" in result.stderr
    assert "jane-doe-private" not in everything(result)


def test_a_dataset_that_is_not_utf8_is_rejected_without_echoing_it(
    cli: Cli, tmp_path: Path
) -> None:
    data = tmp_path / "bad.txt"
    data.write_bytes(b"ok-password\n" + CANARY.encode() + b"\xff\xfe\n")
    index, _, result = _build(cli, tmp_path, f"hr={data}")
    assert result.exit_code == 3
    assert "UTF-8" in result.stderr
    assert CANARY not in everything(result)
    assert not index.exists()  # a failed build leaves no half-written index


def test_an_oversized_dataset_is_refused(
    cli: Cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("passaudit.cli.advanced.MAX_SOURCE_BYTES", 10)
    data = tmp_path / "big.txt"
    data.write_text("a-long-password-list\n" * 3)
    index, _, result = _build(cli, tmp_path, f"hr={data}")
    assert result.exit_code == 3
    assert "larger than" in result.stderr
    assert not index.exists()


def test_reuse_info_prints_a_readable_summary_without_digests(cli: Cli, tmp_path: Path) -> None:
    data = tmp_path / "d.txt"
    data.write_text(f"{CANARY}\nsecond-password-1\n")
    index, key, built = _build(cli, tmp_path, f"hr={data}")
    assert built.exit_code == 0
    result = cli(["reuse", "info", "--index", str(index), "--key-file", str(key)])
    assert result.exit_code == 0
    assert "TICKET-9" in result.stdout
    assert "hr: 2 passwords" in result.stdout
    assert CANARY not in everything(result)


def test_reuse_info_refuses_the_wrong_key_a_missing_index_and_garbage(
    cli: Cli, tmp_path: Path
) -> None:
    data = tmp_path / "d.txt"
    data.write_text("only-password-1\n")
    index, key, _ = _build(cli, tmp_path, f"hr={data}")
    other_key = tmp_path / "other.key"
    other_key.write_text("ab" * 32 + "\n")
    garbage = tmp_path / "garbage.idx"
    garbage.write_text("this is not an index\n")
    for args in (
        ["--index", str(index), "--key-file", str(other_key)],  # key does not match the index
        ["--index", str(tmp_path / "nope.idx"), "--key-file", str(key)],
        ["--index", str(garbage), "--key-file", str(key)],
        ["--index", str(index), "--key-file", str(tmp_path / "nokey")],
    ):
        result = cli(["reuse", "info", *args])
        assert result.exit_code == 3, args
        assert "Traceback" not in everything(result)
