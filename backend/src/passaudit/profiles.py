"""Loading policy profiles from a file (JSON or TOML).

The profile model, the built-in profiles and the registry live in ``passaudit.analysis`` (pure,
no I/O). This module reads an operator's custom profiles from disk and validates them. Error
messages name the profile's position and the offending field - never a value from the file.

File shape (JSON shown)::

    {"profiles": [
        {"name": "payroll", "title": "Payroll system", "description": "...",
         "usage": "privileged_account",
         "policy": {"min_length": 16, "block_breached_passwords": true}}
    ]}

A bare list of profiles, or a single profile object, is accepted too.
"""

from __future__ import annotations

import json
import tomllib
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from passaudit.analysis import (
    BUILTIN_PROFILES,
    PasswordPolicy,
    PolicyProfile,
    PolicyProfileError,
    ProfileRegistry,
)

if TYPE_CHECKING:
    from pathlib import Path

MAX_PROFILE_FILE_BYTES = 256 * 1024


class ProfileFileError(Exception):
    """The profiles file is unusable. The message never quotes the file's content."""


_KNOWN_FIELDS = frozenset(PolicyProfile.model_fields) | frozenset(PasswordPolicy.model_fields)
UNKNOWN_FIELD = "<unknown field>"


def _describe(error: ValidationError) -> str:
    """Where the first problem is and what kind it is. Field names that are not part of the
    profile format are redacted: a secret mistakenly used as a key must not come back."""
    first = error.errors(include_input=False, include_url=False)[0]
    parts = [str(p) if str(p) in _KNOWN_FIELDS else UNKNOWN_FIELD for p in first["loc"]]
    return f"{'.'.join(parts) or 'profile'}: {first['msg']}"


def parse_profiles(data: Any) -> list[PolicyProfile]:
    """Validate already-parsed profile data into profile objects."""
    if isinstance(data, dict) and "profiles" in data and set(data) == {"profiles"}:
        items = data["profiles"]
    elif isinstance(data, dict):
        items = [data]
    else:
        items = data
    if not isinstance(items, list):
        raise ProfileFileError("The profiles file must contain a list of profiles.")
    profiles: list[PolicyProfile] = []
    for number, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise ProfileFileError(f"Profile {number} must be an object.")
        try:
            profiles.append(PolicyProfile.model_validate(item))
        except ValidationError as exc:
            raise ProfileFileError(f"Profile {number} is invalid ({_describe(exc)}).") from None
    return profiles


def load_profiles(path: Path | None) -> ProfileRegistry:
    """The built-in profiles plus those in ``path`` (if given)."""
    if path is None:
        return BUILTIN_PROFILES
    try:
        if path.stat().st_size > MAX_PROFILE_FILE_BYTES:
            raise ProfileFileError("The profiles file is too large.")
        raw = path.read_bytes()
    except ProfileFileError:
        raise
    except OSError:
        raise ProfileFileError("The profiles file could not be read.") from None
    try:
        text = raw.decode("utf-8-sig")
        data = tomllib.loads(text) if path.suffix.lower() == ".toml" else json.loads(text)
    except (UnicodeDecodeError, ValueError):  # JSONDecodeError and TOMLDecodeError are ValueErrors
        raise ProfileFileError("The profiles file is not valid JSON or TOML.") from None
    try:
        return BUILTIN_PROFILES.with_custom(parse_profiles(data))
    except PolicyProfileError as exc:
        raise ProfileFileError(str(exc)) from None
