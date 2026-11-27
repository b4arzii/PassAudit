"""The reuse index: keyed digests of dataset passwords, plus dataset names.

File format (UTF-8 text, ``\\n`` line endings):

* line 1: a JSON header ``{"format": "passaudit-reuse-index", "version": 1, "index_id": ...,
  "created_at": ..., "authorization_reference": ..., "key_check": ..., "sources": [{"id":
  "hr-export", "count": 120}, ...]}``;
* every further line: ``<64 hex digest> <comma-separated source numbers>``, sorted by digest.

``key_check`` is an HMAC of a constant under the key: it lets a load detect a wrong key (and a
tampered header) without revealing anything about the key.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from passaudit.analysis.batch import sanitize_label

if TYPE_CHECKING:
    from collections.abc import Iterable

FORMAT = "passaudit-reuse-index"
VERSION = 1
KEY_BYTES = 32
MAX_SOURCES = 20
MAX_SOURCE_ID_LENGTH = 64
MAX_ENTRIES = 5_000_000
MAX_INDEX_BYTES = 512 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_REFERENCE_LENGTH = 120
_KEY_CHECK_MESSAGE = b"passaudit-reuse-index/key-check/v1"
_SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_ENTRY = re.compile(r"^([0-9a-f]{64}) (\d{1,2}(?:,\d{1,2})*)$")

_MESSAGES = {
    "authorization_required": "Building or using a reuse index requires an explicit "
    "authorization confirmation and reference.",
    "bad_key": "The key file is not a 64-character hexadecimal key.",
    "wrong_key": "The key does not match this index.",
    "bad_index": "The reuse index file is malformed or has an unsupported version.",
    "too_large": "The reuse index exceeds the supported size.",
    "bad_source": "Dataset names must be lower-case slugs (letters, digits, '.', '_' or '-').",
    "too_many_sources": f"At most {MAX_SOURCES} datasets are supported per index.",
    "unreadable": "The file could not be read or written.",
    "exists": "The file already exists (use force to overwrite).",
}


class ReuseIndexError(Exception):
    """A reuse-index problem. The message is fixed text: it never includes a password, a key,
    a digest or a path."""

    def __init__(self, reason: str) -> None:
        super().__init__(_MESSAGES[reason])
        self.reason = reason


@dataclass(frozen=True, slots=True)
class _Header:
    key_check: str
    index_id: str
    created_at: str
    authorization_reference: str
    sources: tuple[SourceInfo, ...]


@dataclass(frozen=True, slots=True)
class SourceInfo:
    """A dataset in the index: its name and how many (distinct) passwords it contributed."""

    id: str
    count: int


# ------------------------------------------------------------------- key and attestation


def generate_key() -> bytes:
    """A fresh random 32-byte key."""
    return secrets.token_bytes(KEY_BYTES)


def write_key_file(path: Path, key: bytes, *, force: bool = False) -> None:
    """Write the key as 64 hex characters. Never overwrites unless ``force``; owner-only
    permissions are requested (effective on POSIX; on Windows rely on the folder's ACL)."""
    try:
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise ReuseIndexError("exists") from None
    except OSError:
        raise ReuseIndexError("unreadable") from None
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(key.hex() + "\n")


def read_key_file(path: Path) -> bytes:
    """Read a key written by :func:`write_key_file`."""
    try:
        raw = path.read_bytes()
    except OSError:
        raise ReuseIndexError("unreadable") from None
    text = raw.decode("ascii", "replace").strip()
    if len(raw) > 1024 or not re.fullmatch(r"[0-9a-fA-F]{64}", text):
        raise ReuseIndexError("bad_key")
    return bytes.fromhex(text)


def require_authorization(confirmed: bool, reference: str | None) -> str:
    """Insist on an explicit authorisation claim and return the sanitised reference text.

    PassAudit cannot verify authorisation; it makes the user state it, and records the
    reference (a ticket number, an engagement id...) so a report shows who vouched for what.
    """
    cleaned = sanitize_label(reference)
    if not confirmed or not cleaned:
        raise ReuseIndexError("authorization_required")
    return cleaned[:MAX_REFERENCE_LENGTH]


# ----------------------------------------------------------------------------- digests


def _digest(key: bytes, password: str) -> str:
    normalised = unicodedata.normalize("NFC", password)
    return hmac.new(key, normalised.encode("utf-8", "surrogatepass"), "sha256").hexdigest()


def _key_check(key: bytes) -> str:
    return hmac.new(key, _KEY_CHECK_MESSAGE, "sha256").hexdigest()


def _check_source_id(source_id: str) -> str:
    if not _SOURCE_ID.fullmatch(source_id):
        raise ReuseIndexError("bad_source")
    return source_id


# ------------------------------------------------------------------------------ builder


class ReuseIndexBuilder:
    """Accumulates datasets and writes an index. Holds digests only, never the passwords."""

    def __init__(self, key: bytes, *, authorization_reference: str) -> None:
        if len(key) != KEY_BYTES:
            raise ReuseIndexError("bad_key")
        self._key = key
        self._reference = authorization_reference
        self._sources: list[str] = []
        self._counts: list[int] = []
        self._entries: dict[str, set[int]] = {}

    def add_source(self, source_id: str, passwords: Iterable[str]) -> int:
        """Add a dataset (``passwords`` is consumed once). Returns the distinct count added."""
        source_id = _check_source_id(source_id)
        if source_id in self._sources:
            raise ReuseIndexError("bad_source")
        if len(self._sources) >= MAX_SOURCES:
            raise ReuseIndexError("too_many_sources")
        number = len(self._sources)
        distinct: set[str] = set()
        for password in passwords:
            if not password:
                continue
            distinct.add(_digest(self._key, password))
            if len(self._entries) + len(distinct) > MAX_ENTRIES:
                raise ReuseIndexError("too_large")
        for digest in distinct:
            self._entries.setdefault(digest, set()).add(number)
        self._sources.append(source_id)
        self._counts.append(len(distinct))
        return len(distinct)

    def write(self, path: Path, *, force: bool = False) -> str:
        """Write the index and return its random id. Refuses to overwrite unless ``force``."""
        index_id = uuid.uuid4().hex
        header = {
            "format": FORMAT,
            "version": VERSION,
            "index_id": index_id,
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "authorization_reference": self._reference,
            "key_check": _key_check(self._key),
            "sources": [
                {"id": source, "count": count}
                for source, count in zip(self._sources, self._counts, strict=True)
            ],
        }
        lines = [json.dumps(header, ensure_ascii=True, separators=(",", ":"))]
        lines.extend(
            f"{digest} {','.join(str(n) for n in sorted(numbers))}"
            for digest, numbers in sorted(self._entries.items())
        )
        try:
            with path.open("w" if force else "x", encoding="utf-8", newline="\n") as handle:
                handle.write("\n".join(lines) + "\n")
        except FileExistsError:
            raise ReuseIndexError("exists") from None
        except OSError:
            raise ReuseIndexError("unreadable") from None
        return index_id


# -------------------------------------------------------------------------------- index


class ReuseIndex:
    """A loaded reuse index. ``lookup`` needs the key; the index alone reveals nothing."""

    def __init__(  # noqa: PLR0913 - one value per header field
        self,
        key: bytes,
        *,
        entries: dict[str, tuple[int, ...]],
        sources: tuple[SourceInfo, ...],
        index_id: str,
        created_at: str,
        authorization_reference: str,
    ) -> None:
        self._key = key
        self._entries = entries
        self.sources = sources
        self.index_id = index_id
        self.created_at = created_at
        self.authorization_reference = authorization_reference

    @classmethod
    def load(cls, path: Path, key: bytes) -> ReuseIndex:
        """Load and fully validate an index; raises ``ReuseIndexError`` (fixed text) if wrong."""
        if len(key) != KEY_BYTES:
            raise ReuseIndexError("bad_key")
        try:
            if path.stat().st_size > MAX_INDEX_BYTES:
                raise ReuseIndexError("too_large")
            with path.open("r", encoding="utf-8", newline="") as handle:
                first = handle.readline(MAX_HEADER_BYTES + 1)
                header = _parse_header(first)
                if not hmac.compare_digest(header.key_check, _key_check(key)):
                    raise ReuseIndexError("wrong_key")
                sources = header.sources
                entries = _parse_entries(handle, len(sources))
        except ReuseIndexError:
            raise
        except (OSError, UnicodeDecodeError):
            raise ReuseIndexError("unreadable") from None
        return cls(
            key,
            entries=entries,
            sources=sources,
            index_id=header.index_id,
            created_at=header.created_at,
            authorization_reference=header.authorization_reference,
        )

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:  # sizes only
        return f"ReuseIndex(sources={[s.id for s in self.sources]}, entries={len(self)})"

    def lookup(self, password: str) -> tuple[str, ...]:
        """Names of the datasets that contain ``password`` (empty if none)."""
        numbers = self._entries.get(_digest(self._key, password), ())
        return tuple(self.sources[n].id for n in numbers)


def _parse_header(line: str) -> _Header:
    if not line.endswith("\n") or len(line) > MAX_HEADER_BYTES:
        raise ReuseIndexError("bad_index")
    try:
        header = json.loads(line)
    except ValueError:
        raise ReuseIndexError("bad_index") from None
    if (
        not isinstance(header, dict)
        or header.get("format") != FORMAT
        or header.get("version") != VERSION
        or not isinstance(header.get("key_check"), str)
        or not isinstance(header.get("index_id"), str)
        or not isinstance(header.get("created_at"), str)
        or not isinstance(header.get("authorization_reference"), str)
    ):
        raise ReuseIndexError("bad_index")
    sources = header.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise ReuseIndexError("bad_index")
    for source in sources:
        if (
            not isinstance(source, dict)
            or not isinstance(source.get("id"), str)
            or not _SOURCE_ID.fullmatch(source["id"])
            or not isinstance(source.get("count"), int)
            or isinstance(source.get("count"), bool)
            or source["count"] < 0
        ):
            raise ReuseIndexError("bad_index")
    return _Header(
        key_check=header["key_check"],
        index_id=header["index_id"],
        created_at=header["created_at"],
        authorization_reference=header["authorization_reference"],
        sources=tuple(SourceInfo(s["id"], s["count"]) for s in sources),
    )


def _parse_entries(handle: Iterable[str], source_count: int) -> dict[str, tuple[int, ...]]:
    entries: dict[str, tuple[int, ...]] = {}
    for raw in handle:
        match = _ENTRY.fullmatch(raw.rstrip("\n"))
        if match is None:
            raise ReuseIndexError("bad_index")
        numbers = tuple(int(n) for n in match.group(2).split(","))
        if any(n >= source_count for n in numbers):
            raise ReuseIndexError("bad_index")
        entries[match.group(1)] = numbers
        if len(entries) > MAX_ENTRIES:
            raise ReuseIndexError("too_large")
    return entries
