"""The CLI commands: audit, batch, policy check, policy show, version."""

from __future__ import annotations

import importlib.metadata
import platform
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

from passaudit import __version__
from passaudit.analysis import ANALYSIS_VERSION, AnalysisContext, PasswordUsage, ReuseTracker
from passaudit.breach import DEFAULT_RANGE_URL
from passaudit.cli import render, reports
from passaudit.cli.common import (
    DEFAULT_MAX_LENGTH,
    ForceOption,
    FormatOption,
    InputFormat,
    MaxLengthOption,
    MinLengthOption,
    MinStrengthOption,
    OutputFormat,
    OutputOption,
    PersonalInfoOption,
    PolicyFileOption,
    QuietOption,
    UsageOption,
    WordlistOption,
    analyze_one,
    check_output_options,
    deliver,
    get_state,
    make_analyzer,
)
from passaudit.cli.errors import ExitCode
from passaudit.cli.extras import (
    AllowExternalOption,
    AuthorizationRefOption,
    BreachFileOption,
    BreachMode,
    BreachOption,
    BreachUrlOption,
    ConfirmAuthorizedOption,
    DictionaryOption,
    ProfileOption,
    ProfilesFileOption,
    ReuseIndexOption,
    ReuseKeyOption,
    effective_policy,
    effective_usage,
    load_dictionaries,
    resolve_exposure,
    resolve_profile,
)
from passaudit.cli.inputs import load_personal_info, read_batch, read_password
from passaudit.cli.policy_view import rule_rows
from passaudit.cli.results import (
    FailOn,
    PasswordResult,
    Verdict,
    error_result,
    judge,
    summarize,
)

StdinOption = Annotated[
    bool,
    typer.Option(
        "--stdin",
        help="Read the password from the first line of standard input (UTF-8) instead of "
        "the hidden prompt. For scripts; never put the password on the command line.",
        rich_help_panel="Input",
    ),
]
FailOnOption = Annotated[
    FailOn,
    typer.Option(
        "--fail-on",
        case_sensitive=False,
        help="Exit with code 1 when the risk level reaches this level (policy violations "
        "always fail). 'none' checks policy only.",
        rich_help_panel="Output",
    ),
]
ReusedOption = Annotated[
    bool,
    typer.Option(
        "--reused",
        help="Tell the audit this password is used on more than one service.",
        rich_help_panel="Context",
    ),
]


def _policy_overrides(min_length: int | None, min_strength_score: int | None) -> dict[str, Any]:
    return {"min_length": min_length, "min_strength_score": min_strength_score}


def _settings(
    *,
    usage: PasswordUsage,
    fail_on: FailOn | None,
    max_length: int,
    wordlist: Path | None,
    personal: int,
    **extra: Any,
) -> dict[str, Any]:
    """Non-sensitive run settings recorded in reports (no file names, no personal data)."""
    settings: dict[str, Any] = {
        "usage": usage.value,
        "max_length": max_length,
        "custom_wordlist": wordlist is not None,
        "personal_info_entries": personal,
    }
    if fail_on is not None:
        settings["fail_on"] = fail_on.value
    return settings | extra


# ------------------------------------------------------------------------------ audit


def audit(
    ctx: typer.Context,
    stdin: StdinOption = False,
    policy_file: PolicyFileOption = None,
    min_length: MinLengthOption = None,
    min_strength_score: MinStrengthOption = None,
    usage: UsageOption = PasswordUsage.GENERAL,
    reused: ReusedOption = False,
    personal_info_file: PersonalInfoOption = None,
    wordlist: WordlistOption = None,
    profile: ProfileOption = None,
    profiles_file: ProfilesFileOption = None,
    dictionary: DictionaryOption = None,
    breach: BreachOption = BreachMode.OFF,
    breach_file: BreachFileOption = None,
    allow_external: AllowExternalOption = False,
    breach_url: BreachUrlOption = DEFAULT_RANGE_URL,
    reuse_index: ReuseIndexOption = None,
    reuse_key_file: ReuseKeyOption = None,
    confirm_authorized: ConfirmAuthorizedOption = False,
    authorization_ref: AuthorizationRefOption = None,
    max_length: MaxLengthOption = DEFAULT_MAX_LENGTH,
    fmt: FormatOption = OutputFormat.TEXT,
    output: OutputOption = None,
    force: ForceOption = False,
    fail_on: FailOnOption = FailOn.HIGH,
    details: Annotated[
        bool,
        typer.Option(
            "--details",
            "-d",
            help="Also show crack-time estimates and the full risk-score breakdown.",
            rich_help_panel="Output",
        ),
    ] = False,
    quiet: QuietOption = False,
) -> None:
    """Audit one password: strength, weaknesses, policy compliance, risk and advice.

    The password is read from a hidden prompt (nothing is echoed) or from --stdin. It is
    analysed in memory only and never printed, logged or written to a report.

    Exit codes: 0 passed, 1 failed policy or risk gate, 2 usage error, 3 input error,
    4 report could not be written.
    """
    state = get_state(ctx)
    check_output_options(fmt, output)
    chosen = resolve_profile(profile, profiles_file, policy_file)
    policy = effective_policy(
        chosen, policy_file, _policy_overrides(min_length, min_strength_score)
    )
    usage = effective_usage(chosen, usage)
    analyzer = make_analyzer(max_length, wordlist, load_dictionaries(dictionary))
    exposure = resolve_exposure(
        breach=breach,
        breach_file=breach_file,
        allow_external=allow_external,
        breach_url=breach_url,
        reuse_index=reuse_index,
        reuse_key_file=reuse_key_file,
        confirm_authorized=confirm_authorized,
        authorization_ref=authorization_ref,
        notify=lambda message: None if quiet else state.err.print(message),
    )
    personal = load_personal_info(personal_info_file)
    password = read_password(from_stdin=stdin, max_length=max_length)
    context = AnalysisContext(usage=usage, personal_info=personal, reused_elsewhere=reused)
    signals = exposure.signals([password])[0]
    analysis = analyze_one(analyzer, password, policy, context, signals)
    # Held only until the report is built: the final guard refuses a report containing them.
    secrets = [password, *(p.get_secret_value() for p in personal)]
    del password

    verdict = judge(analysis, fail_on)
    result = PasswordResult(index=1, length=analysis.length, verdict=verdict, analysis=analysis)
    settings = _settings(
        usage=usage,
        fail_on=fail_on,
        max_length=max_length,
        wordlist=wordlist,
        personal=len(personal),
        reused=reused,
        profile=chosen.name if chosen else None,
        extra_dictionaries=len(dictionary or []),
    )

    def machine(fmt_: OutputFormat) -> str:
        if fmt_ is OutputFormat.JSON:
            return reports.audit_json(
                result,
                analysis,
                policy,
                settings,
                now=reports.now_utc(),
                external=exposure.external_block(),
                secrets=secrets,
            )
        return reports.results_csv([result])

    deliver(
        state,
        fmt=fmt,
        output=output,
        force=force,
        quiet=quiet,
        render_text=lambda: render.render_audit(
            state.console, analysis, policy, verdict, usage=usage.value, details=details
        ),
        build_machine=machine,
    )
    secrets.clear()
    if verdict.failed:
        raise typer.Exit(ExitCode.CHECK_FAILED)


# ------------------------------------------------------------------------------ batch


def batch(
    ctx: typer.Context,
    source: Annotated[
        Path,
        typer.Argument(
            metavar="FILE",
            help="File with the passwords to audit, or - to read standard input.",
        ),
    ],
    input_format: Annotated[
        InputFormat,
        typer.Option(
            "--input-format",
            case_sensitive=False,
            help="lines = one password per line; csv = a header row and a password column.",
            rich_help_panel="Input",
        ),
    ] = InputFormat.LINES,
    password_column: Annotated[
        str,
        typer.Option(
            "--password-column",
            help="CSV column holding the password.",
            rich_help_panel="Input",
        ),
    ] = "password",  # noqa: S107  # a CSV column *name*, not a secret  # nosec B107
    label_column: Annotated[
        str,
        typer.Option(
            "--label-column",
            help="Optional CSV column with a label shown in reports (never the password).",
            rich_help_panel="Input",
        ),
    ] = "label",
    max_entries: Annotated[
        int,
        typer.Option(
            "--max-entries",
            min=1,
            max=1_000_000,
            help="Refuse files with more passwords than this.",
            rich_help_panel="Limits",
        ),
    ] = 10_000,
    policy_file: PolicyFileOption = None,
    min_length: MinLengthOption = None,
    min_strength_score: MinStrengthOption = None,
    usage: UsageOption = PasswordUsage.GENERAL,
    personal_info_file: PersonalInfoOption = None,
    wordlist: WordlistOption = None,
    profile: ProfileOption = None,
    profiles_file: ProfilesFileOption = None,
    dictionary: DictionaryOption = None,
    breach: BreachOption = BreachMode.OFF,
    breach_file: BreachFileOption = None,
    allow_external: AllowExternalOption = False,
    breach_url: BreachUrlOption = DEFAULT_RANGE_URL,
    reuse_index: ReuseIndexOption = None,
    reuse_key_file: ReuseKeyOption = None,
    confirm_authorized: ConfirmAuthorizedOption = False,
    authorization_ref: AuthorizationRefOption = None,
    max_length: MaxLengthOption = DEFAULT_MAX_LENGTH,
    fmt: FormatOption = OutputFormat.TEXT,
    output: OutputOption = None,
    force: ForceOption = False,
    fail_on: FailOnOption = FailOn.HIGH,
    detailed: Annotated[
        bool,
        typer.Option(
            "--detailed",
            help="json: include the full analysis for every password (larger report).",
            rich_help_panel="Output",
        ),
    ] = False,
    show: Annotated[
        int,
        typer.Option(
            "--show",
            min=1,
            max=1000,
            help="text: how many of the highest-risk entries to list.",
            rich_help_panel="Output",
        ),
    ] = 15,
    quiet: QuietOption = False,
) -> None:
    """Audit many passwords from a file and summarise the results.

    Passwords are identified in output by their position and optional label only. Identical
    passwords within the file are detected and flagged as reused. Exit code 1 if any
    password fails (policy violation, risk gate, or too long to analyse).
    """
    state = get_state(ctx)
    check_output_options(fmt, output)
    chosen = resolve_profile(profile, profiles_file, policy_file)
    policy = effective_policy(
        chosen, policy_file, _policy_overrides(min_length, min_strength_score)
    )
    usage = effective_usage(chosen, usage)
    analyzer = make_analyzer(max_length, wordlist, load_dictionaries(dictionary))
    exposure = resolve_exposure(
        breach=breach,
        breach_file=breach_file,
        allow_external=allow_external,
        breach_url=breach_url,
        reuse_index=reuse_index,
        reuse_key_file=reuse_key_file,
        confirm_authorized=confirm_authorized,
        authorization_ref=authorization_ref,
        notify=lambda message: None if quiet else state.err.print(message),
    )
    personal = load_personal_info(personal_info_file)
    batch_input = read_batch(
        source,
        input_format=input_format.value,
        password_column=password_column,
        label_column=label_column,
        max_entries=max_entries,
        max_length=max_length,
    )
    # Distinct prefixes are asked for once each, in random order (see passaudit.breach).
    analysable = [e.password for e in batch_input.entries if not e.too_long]
    signals = iter(exposure.signals(analysable))
    secrets = [*analysable, *(p.get_secret_value() for p in personal)]
    reused = ReuseTracker(e.password for e in batch_input.entries if not e.too_long)

    results: list[PasswordResult] = []
    progress = Progress(
        TextColumn("Analysing"),
        BarColumn(),
        TaskProgressColumn(),
        console=state.err,
        transient=True,
        disable=quiet or not state.err.is_terminal,
    )
    with progress:
        task = progress.add_task("audit", total=len(batch_input.entries))
        for entry in batch_input.entries:
            if entry.too_long:
                results.append(
                    error_result(entry.index, entry.line, entry.label, entry.length, "too_long")
                )
            else:
                reused_here = reused.is_reused(entry.password)
                entry_context = AnalysisContext(
                    usage=usage, personal_info=personal, reused_elsewhere=reused_here
                )
                analysis = analyze_one(
                    analyzer, entry.password, policy, entry_context, next(signals)
                )
                results.append(
                    PasswordResult(
                        index=entry.index,
                        line=entry.line,
                        label=entry.label,
                        length=analysis.length,
                        verdict=judge(analysis, fail_on),
                        analysis=analysis,
                        reused_in_batch=reused_here,
                    )
                )
            entry.password = ""  # clears the secret; drops our reference  # nosec B105
            progress.advance(task)
    reused.clear()

    summary = summarize(results, skipped_blank=batch_input.skipped_blank)
    settings = _settings(
        usage=usage,
        fail_on=fail_on,
        max_length=max_length,
        wordlist=wordlist,
        personal=len(personal),
        input_format=input_format.value,
        max_entries=max_entries,
        profile=chosen.name if chosen else None,
        extra_dictionaries=len(dictionary or []),
    )

    def machine(fmt_: OutputFormat) -> str:
        if fmt_ is OutputFormat.JSON:
            return reports.batch_json(
                results,
                summary,
                policy,
                settings,
                detailed=detailed,
                now=reports.now_utc(),
                external=exposure.external_block(),
                secrets=secrets,
            )
        return reports.results_csv(results)

    deliver(
        state,
        fmt=fmt,
        output=output,
        force=force,
        quiet=quiet,
        render_text=lambda: render.render_batch(
            state.console,
            results,
            summary,
            source="standard input" if str(source) == "-" else str(source),
            fail_on=fail_on,
            show=show,
        ),
        build_machine=machine,
        input_paths=[source],
    )
    secrets.clear()
    analysable.clear()
    if summary["failed"]:
        raise typer.Exit(ExitCode.CHECK_FAILED)


# ------------------------------------------------------------------------ policy check


def policy_check(
    ctx: typer.Context,
    stdin: StdinOption = False,
    policy_file: PolicyFileOption = None,
    min_length: MinLengthOption = None,
    min_strength_score: MinStrengthOption = None,
    min_lowercase: Annotated[
        int | None,
        typer.Option(
            "--min-lowercase",
            min=0,
            max=1024,
            help="Minimum lowercase letters.",
            rich_help_panel="Policy",
        ),
    ] = None,
    min_uppercase: Annotated[
        int | None,
        typer.Option(
            "--min-uppercase",
            min=0,
            max=1024,
            help="Minimum uppercase letters.",
            rich_help_panel="Policy",
        ),
    ] = None,
    min_digits: Annotated[
        int | None,
        typer.Option(
            "--min-digits", min=0, max=1024, help="Minimum digits.", rich_help_panel="Policy"
        ),
    ] = None,
    min_symbols: Annotated[
        int | None,
        typer.Option(
            "--min-symbols", min=0, max=1024, help="Minimum symbols.", rich_help_panel="Policy"
        ),
    ] = None,
    max_repeat_run: Annotated[
        int | None,
        typer.Option(
            "--max-repeat-run",
            min=1,
            max=1024,
            help="Longest allowed run of one repeated character.",
            rich_help_panel="Policy",
        ),
    ] = None,
    no_whitespace: Annotated[
        bool,
        typer.Option(
            "--no-whitespace", help="Forbid whitespace characters.", rich_help_panel="Policy"
        ),
    ] = False,
    personal_info_file: PersonalInfoOption = None,
    wordlist: WordlistOption = None,
    profile: ProfileOption = None,
    profiles_file: ProfilesFileOption = None,
    dictionary: DictionaryOption = None,
    breach: BreachOption = BreachMode.OFF,
    breach_file: BreachFileOption = None,
    allow_external: AllowExternalOption = False,
    breach_url: BreachUrlOption = DEFAULT_RANGE_URL,
    max_length: MaxLengthOption = DEFAULT_MAX_LENGTH,
    fmt: FormatOption = OutputFormat.TEXT,
    output: OutputOption = None,
    force: ForceOption = False,
    quiet: QuietOption = False,
) -> None:
    """Check one password against a password policy, rule by rule.

    The policy comes from --policy FILE, the built-in defaults, and any option overrides
    given here. The password is read from a hidden prompt or --stdin and is never shown.

    Exit codes: 0 compliant, 1 at least one rule violated, 2 usage error, 3 input error,
    4 report could not be written.
    """
    state = get_state(ctx)
    check_output_options(fmt, output)
    overrides = _policy_overrides(min_length, min_strength_score) | {
        "min_lowercase": min_lowercase,
        "min_uppercase": min_uppercase,
        "min_digits": min_digits,
        "min_symbols": min_symbols,
        "max_repeat_run": max_repeat_run,
        "allow_whitespace": False if no_whitespace else None,
    }
    chosen = resolve_profile(profile, profiles_file, policy_file)
    policy = effective_policy(chosen, policy_file, overrides)
    analyzer = make_analyzer(max_length, wordlist, load_dictionaries(dictionary))
    exposure = resolve_exposure(
        breach=breach,
        breach_file=breach_file,
        allow_external=allow_external,
        breach_url=breach_url,
        reuse_index=None,
        reuse_key_file=None,
        confirm_authorized=False,
        authorization_ref=None,
        notify=lambda message: None if quiet else state.err.print(message),
    )
    personal = load_personal_info(personal_info_file)
    password = read_password(from_stdin=stdin, max_length=max_length)
    context = AnalysisContext(
        usage=effective_usage(chosen, PasswordUsage.GENERAL), personal_info=personal
    )
    signals = exposure.signals([password])[0]
    analysis = analyze_one(analyzer, password, policy, context, signals)
    secrets = [password, *(p.get_secret_value() for p in personal)]
    del password

    verdict = Verdict(
        failed=not analysis.policy.compliant,
        reasons=("policy_violations",) if not analysis.policy.compliant else (),
    )
    result = PasswordResult(index=1, length=analysis.length, verdict=verdict, analysis=analysis)
    rows = rule_rows(policy, analysis)
    settings = _settings(
        usage=context.usage,
        fail_on=None,
        max_length=max_length,
        wordlist=wordlist,
        personal=len(personal),
        profile=chosen.name if chosen else None,
        extra_dictionaries=len(dictionary or []),
    )

    def machine(fmt_: OutputFormat) -> str:
        if fmt_ is OutputFormat.JSON:
            return reports.policy_json(
                rows,
                result,
                policy,
                settings,
                now=reports.now_utc(),
                external=exposure.external_block(),
                secrets=secrets,
            )
        return reports.policy_csv(rows)

    deliver(
        state,
        fmt=fmt,
        output=output,
        force=force,
        quiet=quiet,
        render_text=lambda: render.render_policy_check(
            state.console, rows, verdict.failed, analysis.length
        ),
        build_machine=machine,
    )
    secrets.clear()
    if verdict.failed:
        raise typer.Exit(ExitCode.CHECK_FAILED)


def policy_show(
    policy_file: PolicyFileOption = None,
    profile: ProfileOption = None,
    profiles_file: ProfilesFileOption = None,
    min_length: MinLengthOption = None,
    min_strength_score: MinStrengthOption = None,
) -> None:
    """Print the effective policy as JSON (a template for a --policy file).

    Exit codes: 0 success, 3 the policy file is missing or invalid.
    """
    chosen = resolve_profile(profile, profiles_file, policy_file)
    policy = effective_policy(
        chosen, policy_file, _policy_overrides(min_length, min_strength_score)
    )
    typer.echo(reports.dumps(policy.model_dump(mode="json")), nl=False)


# ----------------------------------------------------------------------------- version


def version(
    ctx: typer.Context,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Also show engine, Python and dependency versions."),
    ] = False,
) -> None:
    """Show the PassAudit version."""
    state = get_state(ctx)
    state.console.print(f"PassAudit {__version__}")
    if verbose:
        state.console.print(f"Analysis engine   {ANALYSIS_VERSION}")
        state.console.print(f"Python            {platform.python_version()} ({platform.system()})")
        for package in ("zxcvbn", "typer", "rich", "pydantic"):
            try:
                installed = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:  # pragma: no cover
                installed = "not installed"
            state.console.print(f"{package:<17} {installed}")
