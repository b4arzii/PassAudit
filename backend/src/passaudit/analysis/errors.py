"""Exceptions raised by the analysis engine.

Messages contain only numbers and fixed text - never password content.
"""

from __future__ import annotations


class AnalysisError(Exception):
    """Base class for engine errors."""


class PasswordTooLongError(AnalysisError, ValueError):
    """The password is longer than the analyzer's configured input limit."""

    def __init__(self, length: int, maximum: int) -> None:
        super().__init__(f"Password length {length} exceeds the maximum of {maximum} characters.")
        self.length = length
        self.maximum = maximum
