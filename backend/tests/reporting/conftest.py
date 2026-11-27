"""Fixtures for the reporting tests."""

from __future__ import annotations

import pytest

from passaudit.analysis import PasswordAnalyzer


@pytest.fixture(scope="session")
def analyzer() -> PasswordAnalyzer:
    return PasswordAnalyzer()
