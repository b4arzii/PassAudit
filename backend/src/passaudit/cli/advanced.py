"""Commands added in Phase 8: ``policy profiles`` and ``reuse build`` / ``reuse info``."""

from __future__ import annotations

import json
from pathlib import Path  # runtime import: Typer resolves option annotations
from typing import TYPE_CHECKING, Annotated

import typer
from rich import box
from rich.table import Table

from passaudit.cli import reports
from passaudit.cli.common import get_state
from passaudit.cli.errors import CliError, ExitCode
from passaudit.cli.extras import ProfilesFileOption
from passaudit.profiles import ProfileFileError, load_profiles
from passaudit.reuse import (
    ReuseIndex,
    ReuseIndexBuilder,
    ReuseIndexError,
    generate_key,
    read_key_file,
    require_authorization,
    write_key_file,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024  # refuse absurd dataset files


# ------------------------------------------------------------------------ policy profiles


def policy_profiles(
    ctx: typer.Context,
    profiles_file: ProfilesFileOption = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Print the full profiles as JSON instead of a table.")
    ] = False,
) -> None:
    """List the policy profiles (built-in plus any from --profiles-file).

    Use one with --profile NAME on audit, batch and policy check. The built-in profiles are
    *inspired by* public guidance; they are starting points, not compliance certifications.

    Exit codes: 0 success, 3 the profiles file is unusable.
    """
    state = get_state(ctx)
    try:
        registry = load_profiles(profiles_file)
    except ProfileFileError as exc:
        raise CliError(str(exc)) from None
    if as_json:
        data = {"profiles": [p.model_dump(mode="json") for p in registry.all()]}
        typer.echo(reports.dumps(data), nl=False)
        return
    table = Table(title="Policy profiles", box=box.SIMPLE_HEAD, title_justify="left")
    for column in ("Name", "Usage", "Source", "Description"):
        table.add_column(column, overflow="fold")
    for profile in registry.all():
        table.add_row(
            profile.name,
            profile.usage.value.replace("_", " "),
            "built-in" if profile.builtin else "custom",
            profile.description or profile.title,
        )
    state.console.print(table)


# ------------------------------------------------------------------------------- reuse


def _parse_source(spec: str) -> tuple[str, Path]:
    name, separator, location = spec.partition("=")
    if not separator or not name or not location:
        raise CliError(
            "--source must look like NAME=FILE (for example hr-export=hr.txt).", ExitCode.USAGE
        )
    return name.strip(), Path(location)


def _passwords(path: Path) -> Iterator[str]:
    """One password per line of a dataset file (UTF-8); streamed, never fully loaded."""
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            raise CliError("A --source file is larger than the supported size.")
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for line in handle:
                yield line.rstrip("\r\n")
    except FileNotFoundError:
        raise CliError("A --source file was not found.") from None
    except UnicodeDecodeError:
        raise CliError("A --source file is not valid UTF-8.") from None
    except OSError:
        raise CliError("A --source file could not be read.") from None


def reuse_build(
    ctx: typer.Context,
    source: Annotated[
        list[str],
        typer.Option(
            "--source",
            metavar="NAME=FILE",
            help="A dataset: a lower-case name and a file with one password per line. "
            "Repeat for several datasets (at most 20).",
        ),
    ],
    index_out: Annotated[
        Path, typer.Option("--index-out", metavar="FILE", help="Where to write the index.")
    ],
    key_file: Annotated[
        Path,
        typer.Option(
            "--key-file",
            metavar="FILE",
            help="Key file. Created (random 32 bytes) if it does not exist; an existing key is "
            "reused. Keep it apart from the index and protect it like the datasets.",
        ),
    ],
    confirm_authorized: Annotated[
        bool,
        typer.Option(
            "--confirm-authorized",
            help="State that you are authorised to hold and compare these datasets.",
        ),
    ] = False,
    authorization_ref: Annotated[
        str | None,
        typer.Option("--authorization-ref", metavar="TEXT", help="Ticket / engagement reference."),
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing index.")] = False,
) -> None:
    """Build a keyed reuse index from local password datasets.

    The index stores HMAC-SHA-256 digests (under the key file) and the dataset names - never
    the passwords, never an unkeyed hash. PassAudit cannot verify authorisation: it makes you
    state it, and records the reference in the index and in every report that uses it.

    Exit codes: 0 success, 2 usage error (including a missing authorisation statement),
    3 input error, 4 the index or key could not be written.
    """
    state = get_state(ctx)
    try:
        reference = require_authorization(confirm_authorized, authorization_ref)
    except ReuseIndexError as exc:
        raise CliError(str(exc), ExitCode.USAGE) from None
    sources = [_parse_source(spec) for spec in source]
    try:
        created_key = not key_file.exists()
        if created_key:
            write_key_file(key_file, generate_key())
        key = read_key_file(key_file)
        builder = ReuseIndexBuilder(key, authorization_reference=reference)
        counts = {name: builder.add_source(name, _passwords(path)) for name, path in sources}
        index_id = builder.write(index_out, force=force)
    except ReuseIndexError as exc:
        raise CliError(
            str(exc), ExitCode.OUTPUT_ERROR if exc.reason == "exists" else ExitCode.INPUT_ERROR
        ) from None
    state.console.print(
        f"Indexed {sum(counts.values())} distinct passwords from {len(counts)} dataset(s): "
        + ", ".join(f"{name} ({count})" for name, count in counts.items())
    )
    state.console.print(f"Index id {index_id}. Key file {'created' if created_key else 'reused'}.")
    state.console.print(
        "Protect the key file like the datasets themselves: with it, the index can be brute-forced."
    )


def reuse_info(
    ctx: typer.Context,
    index: Annotated[Path, typer.Option("--index", metavar="FILE", help="The reuse index.")],
    key_file: Annotated[Path, typer.Option("--key-file", metavar="FILE", help="Its key file.")],
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    """Show an index's dataset names, sizes and authorisation reference (no digests).

    Exit codes: 0 success, 3 the index or key is unreadable, malformed or does not match.
    """
    state = get_state(ctx)
    try:
        loaded = ReuseIndex.load(index, read_key_file(key_file))
    except ReuseIndexError as exc:
        raise CliError(str(exc)) from None
    info = {
        "index_id": loaded.index_id,
        "created_at": loaded.created_at,
        "authorization_reference": loaded.authorization_reference,
        "datasets": [{"name": s.id, "passwords": s.count} for s in loaded.sources],
        "entries": len(loaded),
    }
    if as_json:
        typer.echo(json.dumps(info, indent=2, ensure_ascii=True))
        return
    state.console.print(f"Index {loaded.index_id}, created {loaded.created_at}")
    state.console.print(f"Authorisation reference: {loaded.authorization_reference}")
    for dataset in loaded.sources:
        state.console.print(f"  {dataset.id}: {dataset.count} passwords")
