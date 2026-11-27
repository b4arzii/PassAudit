"""The Typer application and the hardened command group.

``SafeGroup`` is the single place where every failure is turned into a terminal message and
an exit code. It exists because the stock behaviour is unsafe for a password tool:

* Typer's "pretty exceptions" print **local variables** - which could include the password.
* Click-style parsing errors echo offending argv values ("unexpected extra argument
  (hunter2)"), so a password typed by mistake would be echoed back.

Here, unexpected exceptions are reported by class name only, and argv-echoing messages are
replaced by fixed text.

Typer 0.29+ bundles a private copy of Click (``typer._click``) while older Typer releases use
the real ``click`` package. To work with both without importing either, click-style errors
are recognised by class name and attributes instead of ``isinstance``.
"""

from __future__ import annotations

import enum
import errno
import sys
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape
from typer.core import TyperGroup

from passaudit import __version__
from passaudit.analysis import PasswordUsage
from passaudit.cli import advanced, commands
from passaudit.cli.common import InputFormat, OutputFormat, make_state
from passaudit.cli.errors import CliError, ExitCode
from passaudit.cli.results import FailOn

if TYPE_CHECKING:
    from collections.abc import Sequence

PROG_NAME = "passaudit"

# Enumerated options, by parameter name, so a rejected value can be answered with the valid ones.
_ENUM_PARAMS: dict[str, type[enum.Enum]] = {
    "usage": PasswordUsage,
    "fmt": OutputFormat,
    "fail_on": FailOn,
    "input_format": InputFormat,
}

_ARGV_ECHO_HELP = (
    "PassAudit never accepts a password on the command line. Enter it at the hidden prompt, "
    "or pipe it in with --stdin (batch: pass a file path)."
)


def _class_names(exc: BaseException) -> set[str]:
    return {cls.__name__ for cls in type(exc).__mro__}


def _error_hint(exc: Any) -> str:
    """The option/argument name an error refers to (never the value that was supplied)."""
    param = getattr(exc, "param", None)
    if param is None:
        return "this option"
    try:
        return str(param.get_error_hint(getattr(exc, "ctx", None)))
    except TypeError:  # newer Click/Typer: no ctx argument
        return str(param.get_error_hint())


def _usage_message(exc: Any) -> str:  # noqa: PLR0911 - one return per message shape
    """The error text for a usage error, with any user-typed value removed."""
    text = str(exc.format_message())
    lowered = text.lower()
    if "unexpected extra argument" in lowered:
        return f"Unexpected extra argument. {_ARGV_ECHO_HELP}"
    if "no such command" in lowered:
        return "Unknown command. Run 'passaudit --help' to list the commands."
    if type(exc).__name__ == "BadParameter":  # a value was rejected: describe the rule only
        hint = _error_hint(exc)
        param: Any = getattr(exc, "param", None)
        old_style_type: Any = getattr(param, "type", None)  # Typer/Click versions with .type
        choices = getattr(old_style_type, "choices", None)
        enum_type = _ENUM_PARAMS.get(str(getattr(param, "name", "")))  # Typer 0.29+: no .type
        if not choices and enum_type is not None:
            choices = [member.value for member in enum_type]
        if choices:
            options = ", ".join(str(getattr(c, "value", c)) for c in choices)
            return f"Invalid value for {hint}: choose one of {options}."
        low = getattr(param, "min", getattr(old_style_type, "min", None))
        high = getattr(param, "max", getattr(old_style_type, "max", None))
        if low is not None and high is not None:
            return f"Invalid value for {hint}: expected a whole number from {low} to {high}."
        if low is not None:
            return f"Invalid value for {hint}: expected a whole number of at least {low}."
        return f"Invalid value for {hint}."
    return text


class SafeGroup(TyperGroup):
    """A command group whose ``main`` never leaks tracebacks, locals or argv values."""

    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        windows_expand_args: bool = True,
        **extra: Any,
    ) -> Any:
        code = self._run(
            args=args,
            prog_name=prog_name,
            complete_var=complete_var,
            windows_expand_args=windows_expand_args,
            **extra,
        )
        if standalone_mode:
            sys.exit(code)
        return code

    def _run(self, **kwargs: Any) -> int:
        err = Console(stderr=True, highlight=False)
        try:
            result = super().main(standalone_mode=False, **kwargs)
        except CliError as exc:
            err.print(f"[bold red]Error:[/] {escape(exc.message)}")
            return int(exc.code)
        except KeyboardInterrupt:
            err.print("Interrupted.")
            return int(ExitCode.INTERRUPTED)
        except BrokenPipeError:
            return int(ExitCode.CHECK_FAILED)
        except Exception as exc:  # the last line of defence, by design
            return self._handle(err, exc)
        if result == ExitCode.INTERRUPTED:  # Typer turns Ctrl-C into Exit(130)
            err.print("Interrupted.")
        return result if isinstance(result, int) else int(ExitCode.OK)

    def _handle(self, err: Console, exc: Exception) -> int:
        names = _class_names(exc)
        if "NoArgsIsHelpError" in names:
            # Running a group with no arguments is a request for help, not an error. Typer has
            # already printed the help while building the exception.
            message = str(getattr(exc, "message", ""))
            if message:
                typer.echo(message)
            return int(ExitCode.OK)
        if "Abort" in names:
            err.print("Aborted.")
            return int(ExitCode.INTERRUPTED)
        if "UsageError" in names:
            err.print(f"[bold red]Error:[/] {escape(_usage_message(exc))}")
            ctx = getattr(exc, "ctx", None)
            if ctx is not None:
                err.print(f"Try '{ctx.command_path} --help' for help.")
            return int(ExitCode.USAGE)
        if "ClickException" in names:
            err.print(f"[bold red]Error:[/] {escape(str(exc.format_message()))}")  # type: ignore[attr-defined]
            return int(getattr(exc, "exit_code", ExitCode.USAGE))
        if isinstance(exc, OSError) and exc.errno == errno.EPIPE:
            return int(ExitCode.CHECK_FAILED)
        # Only the exception *class* is shown: its message or traceback could contain input.
        err.print(
            f"[bold red]Error:[/] unexpected internal error ({type(exc).__name__}). "
            "No details are shown because they could contain sensitive input."
        )
        return int(ExitCode.INTERNAL_ERROR)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{PROG_NAME} {__version__}")
        raise typer.Exit


app = typer.Typer(
    name=PROG_NAME,
    cls=SafeGroup,
    help=(
        "PassAudit - audit password strength and policy compliance, locally.\n\n"
        "Passwords are read from a hidden prompt, standard input or a file - never from "
        "command-line arguments - and are never printed, logged or written to reports."
    ),
    epilog="Exit codes: 0 ok, 1 check failed, 2 usage error, 3 input error, 4 report error.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
    pretty_exceptions_show_locals=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["--help", "-h"]},
)

policy_app = typer.Typer(
    help="Work with password policies.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    pretty_exceptions_show_locals=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["--help", "-h"]},
)


@app.callback()
def root(
    ctx: typer.Context,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable coloured output (NO_COLOR is also honoured)."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """PassAudit command-line interface."""
    del version  # handled by the eager callback
    ctx.obj = make_state(no_color=no_color)


reuse_app = typer.Typer(
    help="Authorised password-reuse auditing against local datasets (opt-in).",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    pretty_exceptions_show_locals=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["--help", "-h"]},
)

app.command("audit")(commands.audit)
app.command("batch")(commands.batch)
app.command("version")(commands.version)
policy_app.command("check")(commands.policy_check)
policy_app.command("show")(commands.policy_show)
policy_app.command("profiles")(advanced.policy_profiles)
reuse_app.command("build")(advanced.reuse_build)
reuse_app.command("info")(advanced.reuse_info)
app.add_typer(policy_app, name="policy")
app.add_typer(reuse_app, name="reuse")


def main() -> None:
    """Console-script entry point."""
    app(prog_name=PROG_NAME)
