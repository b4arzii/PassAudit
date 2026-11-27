"""Custom policy profiles loaded from a file."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from passaudit.analysis import BUILTIN_PROFILES
from passaudit.profiles import (
    MAX_PROFILE_FILE_BYTES,
    ProfileFileError,
    load_profiles,
    parse_profiles,
)

CANARY = "Zq7!xKp#9mWv$L2nRb"
GOOD = {
    "name": "payroll",
    "title": "Payroll",
    "description": "Payroll system",
    "usage": "privileged_account",
    "policy": {"min_length": 18, "block_breached_passwords": True},
}


def _write(tmp_path: Path, name: str, content: str | bytes) -> Path:
    path = tmp_path / name
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    return path


def test_no_file_means_the_builtin_profiles_only() -> None:
    assert load_profiles(None) is BUILTIN_PROFILES


@pytest.mark.parametrize(
    "document",
    [{"profiles": [GOOD]}, [GOOD], GOOD],
    ids=["wrapped", "bare-list", "single"],
)
def test_json_shapes(tmp_path: Path, document: object) -> None:
    registry = load_profiles(_write(tmp_path, "p.json", json.dumps(document)))
    assert registry.get("payroll").policy.min_length == 18
    assert registry.get("payroll").builtin is False
    assert registry.get("strict" if "strict" in registry else "default").builtin is True


def test_toml_is_supported(tmp_path: Path) -> None:
    toml = (
        '[[profiles]]\nname = "lab"\ntitle = "Lab"\nusage = "general"\n'
        "[profiles.policy]\nmin_length = 10\n"
    )
    registry = load_profiles(_write(tmp_path, "p.toml", toml))
    assert registry.get("lab").policy.min_length == 10


def test_a_byte_order_mark_is_tolerated(tmp_path: Path) -> None:
    raw = b"\xef\xbb\xbf" + json.dumps([GOOD]).encode()
    assert "payroll" in load_profiles(_write(tmp_path, "p.json", raw))


@pytest.mark.parametrize(
    ("content", "expect"),
    [
        ("{not json", "not valid JSON or TOML"),
        (b"\xff\xfe\x00bad", "not valid JSON or TOML"),
        ("42", "list of profiles"),
        ('{"profiles": [5]}', "Profile 1 must be an object"),
        (json.dumps([{**GOOD, "name": "Bad Name"}]), "Profile 1 is invalid (name"),
        (json.dumps([{**GOOD, "extra": 1}]), "Profile 1 is invalid"),
        (json.dumps([{**GOOD, "policy": {"min_lenght": 9}}]), "Profile 1 is invalid (policy"),
        (json.dumps([{**GOOD, "policy": {"min_length": -1}}]), "Profile 1 is invalid"),
        (json.dumps([GOOD, GOOD]), "share the same name"),
        (json.dumps([{**GOOD, "name": "default"}]), "built-in name"),
        (json.dumps([{**GOOD, "builtin": True}]), "built-in"),
    ],
)
def test_bad_files_are_rejected_with_a_message_that_quotes_no_content(
    tmp_path: Path, content: str | bytes, expect: str
) -> None:
    with pytest.raises(ProfileFileError, match=re.escape(expect)):
        load_profiles(_write(tmp_path, "p.json", content))


def test_error_messages_never_echo_values_from_the_file(tmp_path: Path) -> None:
    secrets = {"name": f"BAD {CANARY}", "title": "t", "policy": {"min_length": CANARY}}
    with pytest.raises(ProfileFileError) as caught:
        load_profiles(_write(tmp_path, "p.json", json.dumps([secrets])))
    assert CANARY not in str(caught.value)
    with pytest.raises(ProfileFileError) as unknown:
        load_profiles(_write(tmp_path, "q.json", json.dumps([{**GOOD, CANARY: 1}])))
    assert CANARY not in str(unknown.value)
    assert "<unknown field>" in str(unknown.value)


def test_missing_and_oversized_files(tmp_path: Path) -> None:
    with pytest.raises(ProfileFileError, match="could not be read"):
        load_profiles(tmp_path / "nope.json")
    big = _write(tmp_path, "big.json", " " * (MAX_PROFILE_FILE_BYTES + 1))
    with pytest.raises(ProfileFileError, match="too large"):
        load_profiles(big)


def test_parse_profiles_limits_the_number(tmp_path: Path) -> None:
    many = [{"name": f"p{i}", "title": "t"} for i in range(101)]
    with pytest.raises(ProfileFileError, match="At most 100"):
        load_profiles(_write(tmp_path, "many.json", json.dumps(many)))
    assert len(parse_profiles(many)) == 101  # parsing alone does not cap; the registry does
