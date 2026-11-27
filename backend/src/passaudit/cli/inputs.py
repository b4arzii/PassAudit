"""Everything that reads input: the password, policy files, word lists, batch files.

The password is **never** accepted as a command-line argument (argv is visible to other
processes and lands in shell history). It comes from a hidden terminal prompt, from standard
input, or - for batch - from a file.
"""

from __future__ import annotations

import csv
import io
import json
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from pydantic import SecretStr, ValidationError

from passaudit.analysis import PasswordPolicy, WordList, safe_label
from passaudit.analysis.models import MAX_PERSONAL_ITEM_LENGTH, MAX_PERSONAL_ITEMS
from passaudit.cli.errors import CliError

if TYPE_CHECKING:
    from collections.abc import Iterator

MAX_SMALL_FILE_BYTES = 1_000_000  # policy / personal-info files
STDIN_NAME = "-"
_NEWLINES = ("\r\n", "\n", "\r")


# --------------------------------------------------------------------------- password


def stdin_is_tty() -> bool:
    """Whether standard input is an interactive terminal (a seam tests can replace)."""
    return sys.stdin.isatty()


def _strip_newline(text: str) -> str:
    for newline in _NEWLINES:
        if text.endswith(newline):
            return text[: -len(newline)]
    return text


def read_password(*, from_stdin: bool, max_length: int) -> str:
    """Obtain one password without ever touching argv.

    * ``from_stdin=False``: a hidden prompt (nothing is echoed). The prompt text goes to
      stderr so redirecting stdout to a report file cannot capture it.
    * ``from_stdin=True``: the first line of standard input, decoded as UTF-8.
    """
    if from_stdin:
        raw = sys.stdin.buffer.readline(max_length * 4 + 8)
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise CliError("Standard input is not valid UTF-8.") from exc
        password = _strip_newline(text)
    else:
        if not stdin_is_tty():
            raise CliError(
                "No interactive terminal is available for the hidden prompt. "
                "Pipe the password in with --stdin instead."
            )
        password = typer.prompt("Password", hide_input=True, err=True)
    if not password:
        raise CliError("No password was provided.")
    if len(password) > max_length:
        raise CliError(
            f"The password is too long: {len(password)} characters (maximum {max_length}). "
            "Raise the limit with --max-length if this is intended."
        )
    return password


# ---------------------------------------------------------------------- small files


def _read_small_file(path: Path, what: str) -> bytes:
    try:
        if path.stat().st_size > MAX_SMALL_FILE_BYTES:
            raise CliError(f"The {what} file is larger than {MAX_SMALL_FILE_BYTES} bytes.")
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise CliError(f"The {what} file was not found: {path}") from exc
    except IsADirectoryError as exc:
        raise CliError(f"The {what} path is a directory, not a file: {path}") from exc
    except OSError as exc:
        raise CliError(f"The {what} file could not be read: {path}") from exc


def _read_policy_mapping(path: Path) -> dict[str, Any]:
    raw = _read_small_file(path, "policy")
    suffix = path.suffix.lower()
    try:
        if suffix == ".toml":
            data: Any = tomllib.loads(raw.decode("utf-8"))
        elif suffix == ".json":
            data = json.loads(raw.decode("utf-8-sig"))
        else:
            raise CliError("The policy file must end in .json or .toml.")
    except UnicodeDecodeError as exc:
        raise CliError("The policy file is not valid UTF-8.") from exc
    except json.JSONDecodeError as exc:
        raise CliError(
            f"The policy file is not valid JSON (line {exc.lineno}, column {exc.colno})."
        ) from exc
    except tomllib.TOMLDecodeError as exc:
        raise CliError(f"The policy file is not valid TOML: {exc}") from exc
    if not isinstance(data, dict):
        raise CliError("The policy file must contain an object/table of policy fields.")
    if set(data) == {"policy"} and isinstance(data["policy"], dict):
        data = data["policy"]
    mapping: dict[str, Any] = data
    return mapping


def _format_validation_error(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors(include_input=False, include_url=False, include_context=False):
        field_name = ".".join(str(part) for part in err["loc"]) or "policy"
        message = (
            "unknown policy field"
            if err["type"] == "extra_forbidden"
            else str(err["msg"]).removeprefix("Value error, ")
        )
        lines.append(f"  - {field_name}: {message}")
    return "The policy is invalid:\n" + "\n".join(lines)


def load_policy(path: Path | None, overrides: dict[str, Any]) -> PasswordPolicy:
    """Build the effective policy: defaults, then the file, then command-line overrides."""
    data: dict[str, Any] = _read_policy_mapping(path) if path else {}
    data.update({key: value for key, value in overrides.items() if value is not None})
    try:
        return PasswordPolicy.model_validate(data)
    except ValidationError as exc:
        raise CliError(_format_validation_error(exc)) from None


def load_wordlist(path: Path | None) -> WordList | None:
    """Load a custom blocklist, or return ``None`` to use the bundled one."""
    if path is None:
        return None
    try:
        return WordList.from_file(path)
    except FileNotFoundError as exc:
        raise CliError(f"The word list was not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise CliError("The word list is not valid UTF-8.") from exc
    except ValueError as exc:
        raise CliError(f"The word list cannot be used: {exc}") from exc
    except OSError as exc:
        raise CliError(f"The word list could not be read: {path}") from exc


def load_personal_info(path: Path | None) -> tuple[SecretStr, ...]:
    """Read one personal string per line (blank lines and ``#`` comments are skipped)."""
    if path is None:
        return ()
    try:
        text = _read_small_file(path, "personal-info").decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CliError("The personal-info file is not valid UTF-8.") from exc
    items: list[SecretStr] = []
    for number, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if len(value) > MAX_PERSONAL_ITEM_LENGTH:
            raise CliError(
                f"personal-info line {number} is longer than {MAX_PERSONAL_ITEM_LENGTH} characters."
            )
        items.append(SecretStr(value))
    if len(items) > MAX_PERSONAL_ITEMS:
        raise CliError(f"The personal-info file has more than {MAX_PERSONAL_ITEMS} entries.")
    return tuple(items)


# --------------------------------------------------------------------------- batch


@dataclass(slots=True)
class BatchEntry:
    """One password from a batch file. The password is excluded from ``repr``."""

    index: int  # 1-based position among non-blank entries
    line: int  # 1-based line (or CSV record) number in the source
    password: str = field(repr=False)
    length: int = 0
    label: str | None = None
    too_long: bool = False


@dataclass(slots=True)
class BatchInput:
    entries: list[BatchEntry]
    skipped_blank: int


def _open_source(source: Path, *, newline: str | None) -> tuple[io.TextIOWrapper, bool]:
    """Return ``(text handle, owns_handle)`` for a file path or ``-`` (stdin, UTF-8)."""
    if str(source) == STDIN_NAME:
        wrapper = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8-sig", newline=newline)
        return wrapper, False
    try:
        return source.open(encoding="utf-8-sig", newline=newline), True
    except FileNotFoundError as exc:
        raise CliError(f"The input file was not found: {source}") from exc
    except IsADirectoryError as exc:
        raise CliError(f"The input path is a directory, not a file: {source}") from exc
    except OSError as exc:
        raise CliError(f"The input file could not be read: {source}") from exc


def _iter_lines(handle: io.TextIOWrapper, max_length: int) -> Iterator[tuple[int, str, int, bool]]:
    """Yield ``(line_number, text, length, too_long)`` reading at most a bounded amount."""
    limit = max_length + 2
    line_no = 0
    while True:
        raw = handle.readline(limit)
        if raw == "":
            return
        line_no += 1
        if len(raw) >= limit and not raw.endswith("\n"):
            total = len(raw)
            while True:  # discard the remainder of an over-long line, counting it
                rest = handle.readline(65536)
                total += len(rest.removesuffix("\n"))
                if rest == "" or rest.endswith("\n"):
                    break
            yield line_no, "", total, True
        else:
            text = _strip_newline(raw)
            yield line_no, text, len(text), len(text) > max_length


def read_batch(
    source: Path,
    *,
    input_format: str,
    password_column: str,
    label_column: str,
    max_entries: int,
    max_length: int,
) -> BatchInput:
    """Read a batch file of passwords (``lines`` or ``csv``). Never echoes password text."""
    entries: list[BatchEntry] = []
    skipped = 0
    handle, owned = _open_source(source, newline="" if input_format == "csv" else None)
    line_no = 0
    try:
        if input_format == "csv":
            reader = csv.DictReader(handle)
            names = reader.fieldnames
            if not names:
                raise CliError("The CSV input is empty or has no header row.")
            if password_column not in names:
                raise CliError(
                    f"The CSV input has no column named '{password_column}'. "
                    "Use --password-column to choose the right one."
                )
            has_label = label_column in names
            for row in reader:
                line_no = reader.line_num
                password = row.get(password_column) or ""
                if not password:
                    skipped += 1
                    continue
                label = row.get(label_column) if has_label else None
                _add_entry(entries, line_no, password, label, max_entries, max_length)
        else:
            for line_no, text, length, too_long in _iter_lines(handle, max_length):
                if length == 0:
                    skipped += 1
                    continue
                _add_entry(entries, line_no, text, None, max_entries, max_length, length, too_long)
    except UnicodeDecodeError as exc:
        raise CliError(f"The input is not valid UTF-8 (near line {line_no + 1}).") from exc
    except csv.Error as exc:
        raise CliError(f"The CSV input could not be parsed (near line {line_no + 1}).") from exc
    finally:
        if owned:
            handle.close()
        else:
            handle.detach()  # leave the real stdin open
    if not entries:
        raise CliError("The input contains no passwords.")
    return BatchInput(entries=entries, skipped_blank=skipped)


def _add_entry(
    entries: list[BatchEntry],
    line_no: int,
    password: str,
    label: str | None,
    max_entries: int,
    max_length: int,
    length: int | None = None,
    too_long: bool | None = None,
) -> None:
    actual = len(password) if length is None else length
    if len(entries) >= max_entries:
        raise CliError(
            f"The input has more than {max_entries} passwords. Raise the limit with --max-entries."
        )
    over = (actual > max_length) if too_long is None else too_long
    entries.append(
        BatchEntry(
            index=len(entries) + 1,
            line=line_no,
            password="" if over else password,
            length=actual,
            label=safe_label(label, password),
            too_long=over,
        )
    )
