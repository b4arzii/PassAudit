"""Shared building blocks for the commands: state, option types, analysis and delivery."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path  # runtime import: Typer resolves option annotations
from typing import TYPE_CHECKING, Annotated

import typer
from pydantic import SecretStr
from rich.console import Console
from rich.markup import escape

from passaudit.analysis import (
    AnalysisContext,
    AnalysisRequest,
    AnalyzerConfig,
    DictionarySet,
    ExposureSignals,
    PasswordAnalysis,
    PasswordAnalyzer,
    PasswordPolicy,
    PasswordTooLongError,
    PasswordUsage,
)
from passaudit.cli.errors import CliError, ExitCode
from passaudit.cli.inputs import load_wordlist
from passaudit.cli.reports import write_report

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

DEFAULT_MAX_LENGTH = 1024


class OutputFormat(StrEnum):
    TEXT = "text"
    JSON = "json"
    CSV = "csv"


class InputFormat(StrEnum):
    LINES = "lines"
    CSV = "csv"


@dataclass(slots=True)
class CliState:
    """Per-invocation consoles. ``console`` is stdout; ``err`` is stderr."""

    console: Console
    err: Console


def make_state(*, no_color: bool) -> CliState:
    return CliState(
        console=Console(highlight=False, no_color=no_color or None),
        err=Console(stderr=True, highlight=False, no_color=no_color or None),
    )


def get_state(ctx: typer.Context) -> CliState:
    state = ctx.obj
    if isinstance(state, CliState):
        return state
    return make_state(no_color=False)  # e.g. a subcommand invoked without the root callback


# ------------------------------------------------------------------ option aliases

PolicyFileOption = Annotated[
    Path | None,
    typer.Option(
        "--policy",
        metavar="FILE",
        help="Policy file (.json or .toml). Defaults to the built-in policy; see 'policy show'.",
        rich_help_panel="Policy",
    ),
]
MinLengthOption = Annotated[
    int | None,
    typer.Option(
        "--min-length",
        min=0,
        max=1024,
        help="Override the policy's minimum length.",
        rich_help_panel="Policy",
    ),
]
MinStrengthOption = Annotated[
    int | None,
    typer.Option(
        "--min-strength-score",
        min=0,
        max=4,
        help="Override the minimum strength score (0 disables the rule).",
        rich_help_panel="Policy",
    ),
]
UsageOption = Annotated[
    PasswordUsage,
    typer.Option(
        "--usage",
        case_sensitive=False,
        help=(
            "What the password protects. Sets the strength target and the advice given "
            "(general, online_account, privileged_account, master_password, encryption_key)."
        ),
        rich_help_panel="Context",
    ),
]
PersonalInfoOption = Annotated[
    Path | None,
    typer.Option(
        "--personal-info-file",
        metavar="FILE",
        help="Text file, one personal string per line (name, username, e-mail...) to check for.",
        rich_help_panel="Context",
    ),
]
WordlistOption = Annotated[
    Path | None,
    typer.Option(
        "--wordlist",
        metavar="FILE",
        help="Custom blocklist, one password per line. Replaces the bundled common-password list.",
        rich_help_panel="Context",
    ),
]
MaxLengthOption = Annotated[
    int,
    typer.Option(
        "--max-length",
        min=1,
        max=65536,
        help="Longest password accepted (longer input is rejected, not truncated).",
        rich_help_panel="Limits",
    ),
]
FormatOption = Annotated[
    OutputFormat,
    typer.Option(
        "--format",
        "-f",
        help="text = terminal view; json / csv = sanitized machine-readable report.",
        rich_help_panel="Output",
    ),
]
OutputOption = Annotated[
    Path | None,
    typer.Option(
        "--output",
        "-o",
        metavar="FILE",
        help="Write the json/csv report to FILE instead of standard output.",
        rich_help_panel="Output",
    ),
]
ForceOption = Annotated[
    bool,
    typer.Option(
        "--force", help="Overwrite the --output file if it exists.", rich_help_panel="Output"
    ),
]
QuietOption = Annotated[
    bool,
    typer.Option(
        "--quiet", "-q", help="Print nothing except a requested report.", rich_help_panel="Output"
    ),
]


# -------------------------------------------------------------------------- helpers


def make_analyzer(
    max_length: int,
    wordlist_path: Path | None,
    dictionaries: DictionarySet | None = None,
) -> PasswordAnalyzer:
    return PasswordAnalyzer(
        AnalyzerConfig(max_input_length=max_length),
        wordlist=load_wordlist(wordlist_path),
        dictionaries=dictionaries,
    )


def analyze_one(
    analyzer: PasswordAnalyzer,
    password: str,
    policy: PasswordPolicy,
    context: AnalysisContext,
    exposure: ExposureSignals | None = None,
) -> PasswordAnalysis:
    try:
        return analyzer.analyze(
            AnalysisRequest(password=SecretStr(password), policy=policy, context=context),
            exposure=exposure,
        )
    except PasswordTooLongError as exc:
        raise CliError(
            f"The password is too long: {exc.length} characters (maximum {exc.maximum})."
        ) from None


def check_output_options(fmt: OutputFormat, output: Path | None) -> None:
    if output is not None and fmt is OutputFormat.TEXT:
        raise CliError("--output needs --format json or --format csv.", ExitCode.USAGE)


def deliver(
    state: CliState,
    *,
    fmt: OutputFormat,
    output: Path | None,
    force: bool,
    quiet: bool,
    render_text: Callable[[], None],
    build_machine: Callable[[OutputFormat], str],
    input_paths: Sequence[Path] = (),
) -> None:
    """Send the result where the user asked: terminal, stdout report, or report file."""
    if fmt is OutputFormat.TEXT:
        if not quiet:
            render_text()
        return
    report = build_machine(fmt)
    if output is None:
        stream = sys.stdout.buffer
        stream.write(report.encode("utf-8"))
        stream.flush()
        return
    write_report(output, report, force=force, input_paths=input_paths)
    if not quiet:
        render_text()
        state.err.print(
            f"Sanitized {fmt.value} report written to {escape(str(output))}", highlight=False
        )
