"""The reuse index: nothing plaintext on disk, keyed digests, authorization, strict loading."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from passaudit.reuse import (
    ReuseIndex,
    ReuseIndexBuilder,
    ReuseIndexError,
    generate_key,
    read_key_file,
    require_authorization,
    write_key_file,
)
from passaudit.reuse import index as index_module

CANARY = "Zq7!xKp#9mWv$L2nRb"
OTHER = "Qw8$yL3!pN6#zT1vHd"
SHARED = "Shared-Zq9!pw-44"


@pytest.fixture
def key() -> bytes:
    return generate_key()


@pytest.fixture
def built(tmp_path: Path, key: bytes) -> tuple[Path, bytes]:
    builder = ReuseIndexBuilder(key, authorization_reference="TICKET-42")
    builder.add_source("hr-export", [CANARY, SHARED, "", SHARED])
    builder.add_source("vpn", [OTHER, SHARED])
    path = tmp_path / "reuse.idx"
    builder.write(path)
    return path, key


# --------------------------------------------------------------------------- no plaintext


def test_the_index_file_contains_no_plaintext_and_no_unkeyed_hash(
    built: tuple[Path, bytes],
) -> None:
    path, key = built
    text = path.read_text(encoding="utf-8")
    for password in (CANARY, OTHER, SHARED):
        raw = password.encode()
        assert password not in text
        for algorithm in ("md5", "sha1", "sha256", "sha512"):
            assert hashlib.new(algorithm, raw).hexdigest() not in text.lower()
        assert key.hex() not in text


def test_the_header_holds_names_counts_and_the_attestation_only(built: tuple[Path, bytes]) -> None:
    header = json.loads(built[0].read_text(encoding="utf-8").splitlines()[0])
    assert set(header) == {
        "format", "version", "index_id", "created_at", "authorization_reference", "key_check",
        "sources",
    }  # fmt: skip
    assert header["sources"] == [{"id": "hr-export", "count": 2}, {"id": "vpn", "count": 2}]
    assert header["authorization_reference"] == "TICKET-42"


def test_digests_are_keyed_so_the_same_dataset_indexes_differently_under_another_key(
    tmp_path: Path,
) -> None:
    files = []
    for name in ("a.idx", "b.idx"):
        builder = ReuseIndexBuilder(generate_key(), authorization_reference="T")
        builder.add_source("src", [CANARY])
        builder.write(tmp_path / name)
        files.append((tmp_path / name).read_text().splitlines()[1:])
    assert files[0] != files[1]


# ---------------------------------------------------------------------------- round trip


def test_lookup_reports_which_datasets_contain_a_password(built: tuple[Path, bytes]) -> None:
    index = ReuseIndex.load(*built)
    assert index.lookup(CANARY) == ("hr-export",)
    assert index.lookup(OTHER) == ("vpn",)
    assert index.lookup(SHARED) == ("hr-export", "vpn")
    assert index.lookup("never-seen") == ()
    assert index.lookup("") == ()
    assert len(index) == 3
    assert [(s.id, s.count) for s in index.sources] == [("hr-export", 2), ("vpn", 2)]
    assert index.authorization_reference == "TICKET-42"


def test_lookup_is_case_sensitive_but_unicode_normalised(tmp_path: Path, key: bytes) -> None:
    builder = ReuseIndexBuilder(key, authorization_reference="T")
    builder.add_source("src", ["Pässword-Zq7", "Secret-Zq8"])
    builder.write(tmp_path / "i.idx")
    index = ReuseIndex.load(tmp_path / "i.idx", key)
    assert index.lookup("Pässword-Zq7") == ("src",)  # decomposed form of the same text
    assert index.lookup("secret-zq8") == ()


def test_reprs_and_errors_never_leak(built: tuple[Path, bytes]) -> None:
    index = ReuseIndex.load(*built)
    assert CANARY not in repr(index)
    assert str(built[0]) not in repr(index)
    with pytest.raises(ReuseIndexError) as caught:
        ReuseIndex.load(built[0], generate_key())
    assert caught.value.reason == "wrong_key"
    assert str(built[0]) not in str(caught.value)
    assert built[1].hex() not in str(caught.value)


# ------------------------------------------------------------------------- authorization


def test_an_explicit_authorization_claim_is_required() -> None:
    assert require_authorization(True, "  TICKET-7\n") == "TICKET-7"
    for confirmed, reference in ((False, "TICKET-7"), (True, None), (True, ""), (True, "  \t")):
        with pytest.raises(ReuseIndexError) as caught:
            require_authorization(confirmed, reference)
        assert caught.value.reason == "authorization_required"


def test_the_authorization_reference_is_sanitised_and_bounded() -> None:
    cleaned = require_authorization(True, "ref\x00with\x1bcontrols" + "x" * 500)
    assert cleaned.isprintable()
    assert len(cleaned) <= 120


# ----------------------------------------------------------------------------- key file


def test_key_files_are_exclusive_hex_and_owner_only(tmp_path: Path, key: bytes) -> None:
    path = tmp_path / "reuse.key"
    write_key_file(path, key)
    assert read_key_file(path) == key
    with pytest.raises(ReuseIndexError) as exists:
        write_key_file(path, generate_key())
    assert exists.value.reason == "exists"
    assert read_key_file(path) == key  # the first key survived
    other = generate_key()
    write_key_file(path, other, force=True)
    assert read_key_file(path) == other
    if sys.platform != "win32":
        assert (os.stat(path).st_mode & 0o077) == 0


@pytest.mark.parametrize("content", [b"", b"zz" * 32, b"ab" * 31, b"ab" * 33, b"ab" * 600])
def test_malformed_key_files_are_rejected(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "bad.key"
    path.write_bytes(content)
    with pytest.raises(ReuseIndexError) as caught:
        read_key_file(path)
    assert caught.value.reason == "bad_key"


def test_a_missing_key_or_index_is_unreadable(tmp_path: Path, key: bytes) -> None:
    with pytest.raises(ReuseIndexError) as no_key:
        read_key_file(tmp_path / "missing.key")
    assert no_key.value.reason == "unreadable"
    with pytest.raises(ReuseIndexError) as no_index:
        ReuseIndex.load(tmp_path / "missing.idx", key)
    assert no_index.value.reason == "unreadable"
    with pytest.raises(ReuseIndexError):
        ReuseIndex.load(tmp_path / "missing.idx", b"short")


# ----------------------------------------------------------------------- builder rules


def test_builder_enforces_dataset_names_and_limits(tmp_path: Path, key: bytes) -> None:
    builder = ReuseIndexBuilder(key, authorization_reference="T")
    for bad in ("", "UPPER", "has space", "../x", "-lead", "x" * 65):
        with pytest.raises(ReuseIndexError) as caught:
            builder.add_source(bad, [CANARY])
        assert caught.value.reason == "bad_source"
    builder.add_source("ok", [CANARY])
    with pytest.raises(ReuseIndexError):
        builder.add_source("ok", [OTHER])  # duplicate name
    for number in range(19):
        builder.add_source(f"s{number}", [f"pw{number}"])
    with pytest.raises(ReuseIndexError) as many:
        builder.add_source("one-too-many", [CANARY])
    assert many.value.reason == "too_many_sources"
    with pytest.raises(ReuseIndexError):
        ReuseIndexBuilder(b"short", authorization_reference="T")


def test_builder_never_overwrites_without_force(tmp_path: Path, key: bytes) -> None:
    builder = ReuseIndexBuilder(key, authorization_reference="T")
    builder.add_source("src", [CANARY])
    path = tmp_path / "i.idx"
    builder.write(path)
    before = path.read_text()
    with pytest.raises(ReuseIndexError) as caught:
        builder.write(path)
    assert caught.value.reason == "exists"
    assert path.read_text() == before
    builder.write(path, force=True)
    assert path.read_text() != before  # a new random index id


def test_builder_caps_the_number_of_entries(
    tmp_path: Path, key: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(index_module, "MAX_ENTRIES", 3)
    builder = ReuseIndexBuilder(key, authorization_reference="T")
    with pytest.raises(ReuseIndexError) as caught:
        builder.add_source("big", [f"pw{i}" for i in range(10)])
    assert caught.value.reason == "too_large"


# ------------------------------------------------------------------------ strict loading


def _rewrite(path: Path, edit: object) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(edit(lines)) + "\n", encoding="utf-8")  # type: ignore[operator]


def _header(lines: list[str]) -> dict[str, object]:
    return json.loads(lines[0])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda h: {**h, "format": "other"},
        lambda h: {**h, "version": 99},
        lambda h: {**h, "sources": []},
        lambda h: {**h, "sources": [{"id": "BAD ID", "count": 1}]},
        lambda h: {**h, "sources": [{"id": "ok", "count": -1}]},
        lambda h: {**h, "sources": [{"id": "ok", "count": True}]},
        lambda h: {**h, "sources": "nope"},
        lambda h: {**h, "key_check": 5},
        lambda h: {k: v for k, v in h.items() if k != "index_id"},
    ],
)
def test_a_tampered_header_is_rejected(built: tuple[Path, bytes], mutate: object) -> None:
    path, key = built
    _rewrite(path, lambda lines: [json.dumps(mutate(_header(lines))), *lines[1:]])  # type: ignore[operator]
    with pytest.raises(ReuseIndexError) as caught:
        ReuseIndex.load(path, key)
    assert caught.value.reason == "bad_index"


@pytest.mark.parametrize(
    "bad_line",
    [
        "nothex 0",
        "ab" * 32 + " 9",
        "ab" * 32,
        "ab" * 32 + " 0,",
        "AB" * 32 + " 0",
        "ab" * 32 + " 0 0",
    ],
)
def test_a_malformed_entry_is_rejected(built: tuple[Path, bytes], bad_line: str) -> None:
    path, key = built
    _rewrite(path, lambda lines: [*lines, bad_line])
    with pytest.raises(ReuseIndexError) as caught:
        ReuseIndex.load(path, key)
    assert caught.value.reason == "bad_index"


def test_garbage_and_truncated_files_are_rejected(tmp_path: Path, key: bytes) -> None:
    for name, content in (
        ("a", b"not json\n"),
        ("b", b'{"format":"passaudit-reuse-index"'),
        ("c", b""),
    ):
        path = tmp_path / name
        path.write_bytes(content)
        with pytest.raises(ReuseIndexError) as caught:
            ReuseIndex.load(path, key)
        assert caught.value.reason == "bad_index"
    binary = tmp_path / "d"
    binary.write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(ReuseIndexError):
        ReuseIndex.load(binary, key)


def test_size_limits_are_enforced_before_reading(
    built: tuple[Path, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(index_module, "MAX_INDEX_BYTES", 10)
    with pytest.raises(ReuseIndexError) as caught:
        ReuseIndex.load(*built)
    assert caught.value.reason == "too_large"
    monkeypatch.undo()
    monkeypatch.setattr(index_module, "MAX_ENTRIES", 1)
    with pytest.raises(ReuseIndexError) as entries:
        ReuseIndex.load(*built)
    assert entries.value.reason == "too_large"
