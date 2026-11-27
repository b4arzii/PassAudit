"""Exit codes and the CLI's own exception type.

Messages carried by ``CliError`` are written to the terminal verbatim, so they must be
password-free by construction: only fixed text, option names, file paths and counts.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process exit codes, documented in docs/cli.md."""

    OK = 0  # success; every check passed
    CHECK_FAILED = 1  # the audit/check ran but the password(s) failed policy or the risk gate
    USAGE = 2  # bad command line (Click's own convention)
    INPUT_ERROR = 3  # unreadable/invalid input: password, policy, word list, batch file...
    OUTPUT_ERROR = 4  # a report could not be written
    INTERNAL_ERROR = 70  # unexpected failure (sysexits EX_SOFTWARE)
    INTERRUPTED = 130  # Ctrl-C / end of input at the prompt (128 + SIGINT)


class CliError(Exception):
    """A user-facing failure with a safe message and a specific exit code."""

    def __init__(self, message: str, code: ExitCode = ExitCode.INPUT_ERROR) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
