"""Sources of breach data, all behind one tiny interface: ``fetch_range(prefix)``.

* :class:`HibpRangeProvider` - the online Pwned Passwords range API (network, opt-in).
* :class:`SortedHashFile` - a local file of ``SHA1[:count]`` lines sorted by hash (the format
  of the Pwned Passwords offline download), searched with binary search without loading it.
* :class:`MemoryRangeProvider` - an in-memory set of hashes (small corpora, tests).

Every provider receives only a 5-character upper-case hex *prefix* and returns
``{suffix: count}`` for that bucket. None of them ever sees a password.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import BinaryIO, Literal, Protocol
from urllib.parse import urlsplit

from passaudit.breach.errors import BreachLookupError
from passaudit.breach.hashing import HASH_LENGTH, PREFIX_LENGTH

DEFAULT_RANGE_URL = "https://api.pwnedpasswords.com/range"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # a padded bucket is ~40 KiB; this is a hard cap
USER_AGENT = "PassAudit"  # generic on purpose: no version, host, user or project details

_PREFIX = re.compile(rf"[0-9A-F]{{{PREFIX_LENGTH}}}")
_RANGE_LINE = re.compile(rf"([0-9A-F]{{{HASH_LENGTH - PREFIX_LENGTH}}}):(\d{{1,12}})")
_FILE_LINE = re.compile(rf"([0-9A-F]{{{HASH_LENGTH}}})(?::(\d{{1,12}}))?")

MAX_FILE_LINE_BYTES = 128
MAX_BUCKET_LINES = 20_000  # the real data set has ~1,000 per prefix; refuse absurd buckets

# (url, headers, timeout_seconds, max_bytes) -> response body bytes. Injectable for tests.
Transport = Callable[[str, Mapping[str, str], float, int], bytes]


class RangeProvider(Protocol):
    """Anything that can answer "which hash suffixes start with this prefix?"."""

    source: Literal["local", "online"]

    def fetch_range(self, prefix: str) -> dict[str, int]: ...


def _read_line(handle: BinaryIO) -> bytes:
    """One line of a local corpus; a line longer than any real entry means a corrupt file."""
    raw = handle.readline(MAX_FILE_LINE_BYTES + 1)
    if len(raw) > MAX_FILE_LINE_BYTES:
        raise BreachLookupError("unreadable")
    return raw


def check_prefix(prefix: str) -> str:
    """Validate a range prefix: exactly five upper-case hex characters."""
    if not _PREFIX.fullmatch(prefix):
        raise ValueError("a range prefix is exactly five upper-case hexadecimal characters")
    return prefix


def parse_range_response(text: str) -> dict[str, int]:
    """Parse a range response (``SUFFIX:COUNT`` per line) strictly.

    Padding entries (count 0, added by ``Add-Padding``) are dropped. Anything that is not a
    well-formed line is an error: a service that sends something else is not trusted.
    """
    result: dict[str, int] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _RANGE_LINE.fullmatch(line.upper())
        if match is None:
            raise BreachLookupError("bad_response")
        count = int(match.group(2))
        if count > 0:
            result[match.group(1)] = count
    return result


# ------------------------------------------------------------------------------- online


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect could send the request (and the prefix) somewhere else: never follow one."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def urllib_transport(url: str, headers: Mapping[str, str], timeout: float, max_bytes: int) -> bytes:
    """HTTPS GET with certificate verification, no redirects, no cookies, a size cap.

    The opener contains *only* HTTPS (plus environment proxy settings, which the operator may
    rely on): no plain HTTP, no ``file:`` or ``ftp:`` handlers, so a malformed URL or a
    hostile redirect cannot reach them.
    """
    if urlsplit(url).scheme != "https":  # defence in depth: the provider validated this already
        raise BreachLookupError("bad_response")
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        _RefuseRedirects(),
    ):
        opener.add_handler(handler)
    request = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
    try:
        with opener.open(request, timeout=timeout) as response:  # https only  # nosec B310
            if response.status != 200:
                raise BreachLookupError("bad_response")
            data: bytes = response.read(max_bytes + 1)
    except BreachLookupError:
        raise
    except urllib.error.HTTPError:
        raise BreachLookupError("bad_response") from None
    except TimeoutError:
        raise BreachLookupError("timeout") from None
    except (urllib.error.URLError, OSError, ssl.SSLError):
        raise BreachLookupError("network") from None
    if len(data) > max_bytes:
        raise BreachLookupError("too_large")
    return data


class HibpRangeProvider:
    """The Pwned Passwords range API: ``GET <base>/<5-hex-prefix>``.

    The base URL must be ``https`` with no credentials, query or fragment; a self-hosted mirror
    is fine. Requests carry a generic ``User-Agent`` and ``Add-Padding: true`` (so the response
    length does not reveal how many real hashes share the prefix).
    """

    source: Literal["local", "online"] = "online"

    def __init__(
        self,
        base_url: str = DEFAULT_RANGE_URL,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        transport: Transport = urllib_transport,
    ) -> None:
        self.base_url = validate_https_base(base_url)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._transport = transport

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    def __repr__(self) -> str:
        return f"HibpRangeProvider(host={self.host!r})"

    def fetch_range(self, prefix: str) -> dict[str, int]:
        check_prefix(prefix)
        headers = {"User-Agent": USER_AGENT, "Accept": "text/plain", "Add-Padding": "true"}
        body = self._transport(f"{self.base_url}/{prefix}", headers, self.timeout, self.max_bytes)
        if len(body) > self.max_bytes:  # a custom transport might not enforce the cap
            raise BreachLookupError("too_large")
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            raise BreachLookupError("bad_response") from None
        return parse_range_response(text)


def validate_https_base(url: str) -> str:
    """Return ``url`` without a trailing slash, or raise ``ValueError`` if it is unsafe."""
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise ValueError("the breach API URL must be https, with no credentials, query or fragment")
    return url.rstrip("/")


# -------------------------------------------------------------------------------- local


class MemoryRangeProvider:
    """An in-memory corpus of full SHA-1 hashes (``{hash: count}``)."""

    source: Literal["local", "online"] = "local"

    def __init__(self, hashes: Mapping[str, int] | Iterable[str]) -> None:
        counts: Mapping[str, int] = hashes if isinstance(hashes, dict) else dict.fromkeys(hashes, 1)
        self._buckets: dict[str, dict[str, int]] = {}
        for digest, count in counts.items():
            clean = digest.strip().upper()
            if len(clean) != HASH_LENGTH or count < 1:
                raise ValueError("corpus entries must be 40-character SHA-1 hex digests")
            self._buckets.setdefault(clean[:PREFIX_LENGTH], {})[clean[PREFIX_LENGTH:]] = count

    def __len__(self) -> int:
        return sum(len(bucket) for bucket in self._buckets.values())

    def fetch_range(self, prefix: str) -> dict[str, int]:
        return dict(self._buckets.get(check_prefix(prefix), {}))


class SortedHashFile:
    """A local file of ``SHA1HEX[:count]`` lines sorted ascending by hash.

    This is the format of the Pwned Passwords offline download (tens of gigabytes), so the file
    is **searched in place** (binary search on byte offsets), never loaded. A line without a
    count counts as 1. The file must really be sorted; use :meth:`verify_sorted` to check a
    sample. Only hashes are stored - there are no plaintext passwords in this format.
    """

    source: Literal["local", "online"] = "local"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        try:
            self._size = self.path.stat().st_size
        except OSError:
            raise BreachLookupError("unreadable") from None

    def __repr__(self) -> str:  # no path: it can reveal a user name
        return f"SortedHashFile(bytes={self._size})"

    def fetch_range(self, prefix: str) -> dict[str, int]:
        key = check_prefix(prefix).encode("ascii")
        found: dict[str, int] = {}
        try:
            with self.path.open("rb") as handle:
                handle.seek(self._first_line_at_or_after(handle, key))
                lines = 0
                while raw := _read_line(handle):
                    if raw[:PREFIX_LENGTH].upper() != key:
                        break
                    lines += 1
                    if lines > MAX_BUCKET_LINES:  # far larger than any real bucket
                        raise BreachLookupError("unreadable")
                    match = _FILE_LINE.fullmatch(raw.decode("ascii", "replace").strip().upper())
                    if match is None:
                        raise BreachLookupError("unreadable")
                    found[match.group(1)[PREFIX_LENGTH:]] = int(match.group(2) or 1)
        except OSError:
            raise BreachLookupError("unreadable") from None
        return found

    def _first_line_at_or_after(self, handle: BinaryIO, key: bytes) -> int:
        """Byte offset of the first line whose hash prefix is >= ``key`` (binary search).

        Invariant: every line starting before ``lo`` sorts below ``key``; every line starting
        at or after ``hi`` sorts at or above it.
        """
        lo, hi = 0, self._size
        while lo < hi:
            mid = (lo + hi) // 2
            # The first line start at or after ``mid``. Reading from ``mid - 1`` means a line
            # that begins exactly at ``mid`` is kept (only the newline before it is consumed).
            handle.seek(max(mid - 1, 0))
            if mid:
                _read_line(handle)
            start = handle.tell()
            if start >= hi:  # no line starts in [mid, hi)
                hi = mid
                continue
            line = _read_line(handle)
            if line[: len(key)].upper() < key:
                lo = start + len(line)
            else:
                hi = start
        return lo

    def verify_sorted(self, samples: int = 64) -> bool:
        """Spot-check that the file is sorted (cheap; not a full proof)."""
        try:
            with self.path.open("rb") as handle:
                previous = b""
                step = max(1, self._size // samples)
                for offset in range(0, self._size, step):
                    handle.seek(offset)
                    if offset:
                        handle.readline(MAX_FILE_LINE_BYTES + 1)
                    line = handle.readline(MAX_FILE_LINE_BYTES + 1).strip().upper()
                    if line and line[:HASH_LENGTH] < previous:
                        return False
                    previous = line[:HASH_LENGTH] or previous
        except OSError:
            return False
        return True
