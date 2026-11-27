"""Breach providers: what leaves the process, transport hardening, local corpus search."""

from __future__ import annotations

import hashlib
import random
import re
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from passaudit.breach import (
    DEFAULT_RANGE_URL,
    BreachLookupError,
    HibpRangeProvider,
    MemoryRangeProvider,
    SortedHashFile,
    parse_range_response,
    sha1_hex,
    split_hash,
)
from passaudit.breach import providers as providers_module

CANARY = "Zq7!xKp#9mWv$L2nRb"
KNOWN_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"  # sha1("password")


def _suffix(prefix: str, n: int) -> str:
    return f"{n:035X}"


# --------------------------------------------------------------------------- hashing


def test_sha1_matches_the_published_value_and_splits_at_five() -> None:
    assert sha1_hex("password") == KNOWN_SHA1
    assert split_hash(KNOWN_SHA1) == ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
    with pytest.raises(ValueError, match="40-character"):
        split_hash("ABC")


def test_hashing_is_utf8_and_tolerates_lone_surrogates() -> None:
    assert sha1_hex("é") == hashlib.sha1("é".encode(), usedforsecurity=False).hexdigest().upper()
    assert len(sha1_hex("\ud800")) == 40


# ------------------------------------------------------------------- response parsing


def test_parse_range_response_drops_padding_and_accepts_any_case() -> None:
    text = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\n\n" + (
        "abcdefabcdefabcdefabcdefabcdefabcde:12\n"
    )
    assert parse_range_response(text) == {
        "0018A45C4D1DEF81644B54AB7F969B88D65": 3,
        "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDE": 12,
    }


@pytest.mark.parametrize(
    "bad",
    [
        "<html>blocked</html>",
        "0018A45C4D1DEF81644B54AB7F969B88D65",  # no count
        "0018A45C4D1DEF81644B54AB7F969B88D65:x",
        "0018A45C4D1DEF81644B54AB7F969B88D6:3",  # 34 characters
        "0018A45C4D1DEF81644B54AB7F969B88D65:3 extra",
        "G018A45C4D1DEF81644B54AB7F969B88D65:3",  # not hex
        "0018A45C4D1DEF81644B54AB7F969B88D65:1234567890123",  # absurd count
    ],
)
def test_malformed_range_responses_are_rejected_not_guessed_at(bad: str) -> None:
    with pytest.raises(BreachLookupError) as caught:
        parse_range_response(bad)
    assert caught.value.reason == "bad_response"


# ------------------------------------------------------------- online provider (fake)


class FakeTransport:
    def __init__(self, body: bytes = b"") -> None:
        self.body = body
        self.calls: list[dict[str, Any]] = []

    def __call__(self, url: str, headers: Any, timeout: float, max_bytes: int) -> bytes:
        self.calls.append(
            {"url": url, "headers": dict(headers), "timeout": timeout, "max_bytes": max_bytes}
        )
        return self.body


def test_only_the_five_character_prefix_is_sent() -> None:
    transport = FakeTransport(b"1E4C9B93F3F0682250B6CF8331B7EE68FD8:9\n")
    provider = HibpRangeProvider(transport=transport)
    prefix, suffix = split_hash(sha1_hex("password"))
    assert provider.fetch_range(prefix) == {suffix: 9}
    (call,) = transport.calls
    assert call["url"] == f"{DEFAULT_RANGE_URL}/5BAA6"
    assert re.fullmatch(r"https://[^/]+/range/[0-9A-F]{5}", call["url"])

    # What the *service* could see for a real secret: the prefix and nothing else.
    secret_prefix, secret_suffix = split_hash(sha1_hex(CANARY))
    transport.calls.clear()
    provider.fetch_range(secret_prefix)
    sent = transport.calls[0]["url"] + repr(transport.calls[0]["headers"])
    assert CANARY not in sent
    assert secret_suffix not in sent
    assert sha1_hex(CANARY) not in sent
    assert sent.count(secret_prefix) == 1


def test_requests_are_padded_generic_and_carry_nothing_identifying() -> None:
    transport = FakeTransport()
    HibpRangeProvider(transport=transport).fetch_range("ABCDE")
    headers = transport.calls[0]["headers"]
    assert headers == {"User-Agent": "PassAudit", "Accept": "text/plain", "Add-Padding": "true"}
    assert not {"cookie", "authorization", "referer", "x-forwarded-for"} & {
        h.lower() for h in headers
    }


@pytest.mark.parametrize(
    "prefix", ["", "abcde", "ABCD", "ABCDEF", "ABCD!", "5BAA61E4C9B9", "../..."]
)
def test_a_provider_refuses_anything_but_a_five_character_upper_hex_prefix(prefix: str) -> None:
    transport = FakeTransport()
    for provider in (HibpRangeProvider(transport=transport), MemoryRangeProvider({})):
        with pytest.raises(ValueError, match="five upper-case"):
            provider.fetch_range(prefix)
    assert transport.calls == []  # nothing was sent for an invalid prefix


@pytest.mark.parametrize(
    "url",
    [
        "http://api.pwnedpasswords.com/range",
        "ftp://api.pwnedpasswords.com/range",
        "file:///etc/passwd",
        "https://user:pass@api.pwnedpasswords.com/range",
        "https://api.pwnedpasswords.com/range?x=1",
        "https://api.pwnedpasswords.com/range#frag",
        "https:///range",
        "api.pwnedpasswords.com/range",
    ],
)
def test_the_service_url_must_be_plain_https(url: str) -> None:
    with pytest.raises(ValueError, match="https"):
        HibpRangeProvider(url)


def test_a_self_hosted_https_mirror_is_allowed_and_normalised() -> None:
    provider = HibpRangeProvider("https://hibp.internal.example:8443/pwned/range/")
    assert provider.base_url == "https://hibp.internal.example:8443/pwned/range"
    assert provider.host == "hibp.internal.example"
    assert "5BAA6" not in repr(provider)


def test_oversized_and_undecodable_bodies_are_rejected() -> None:
    big = HibpRangeProvider(transport=FakeTransport(b"A" * 64), max_bytes=32)
    with pytest.raises(BreachLookupError) as too_large:
        big.fetch_range("ABCDE")
    assert too_large.value.reason == "too_large"
    bad = HibpRangeProvider(transport=FakeTransport(b"\xff\xfe\x00"))
    with pytest.raises(BreachLookupError) as undecodable:
        bad.fetch_range("ABCDE")
    assert undecodable.value.reason == "bad_response"


def test_error_messages_are_fixed_text() -> None:
    for reason in (
        "network",
        "timeout",
        "bad_response",
        "too_large",
        "not_configured",
        "unreadable",
    ):
        error = BreachLookupError(reason)  # type: ignore[arg-type]
        assert error.reason == reason
        assert "http" not in str(error).lower()
        assert "/" not in str(error)


# --------------------------------------------------------------- real transport (mocked)


class _Response:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self, n: int = -1) -> bytes:
        return self._body[:n] if n >= 0 else self._body


def _patch_open(monkeypatch: pytest.MonkeyPatch, outcome: Any) -> list[urllib.request.Request]:
    seen: list[urllib.request.Request] = []

    def fake_open(self: Any, request: Any, *a: Any, **k: Any) -> Any:
        seen.append(request)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", fake_open)
    return seen


def test_the_transport_refuses_plain_http_before_any_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_network(*_a: object, **_k: object) -> None:
        raise AssertionError("a connection was attempted")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    with pytest.raises(BreachLookupError) as caught:
        providers_module.urllib_transport("http://example.test/range/ABCDE", {}, 1.0, 100)
    assert caught.value.reason == "bad_response"


def test_the_transport_returns_the_body_on_200_and_sends_a_get(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _patch_open(monkeypatch, _Response(200, b"hello"))
    body = providers_module.urllib_transport(
        "https://example.test/range/ABCDE", {"User-Agent": "PassAudit"}, 1.0, 100
    )
    assert body == b"hello"
    assert seen[0].get_method() == "GET"
    assert seen[0].data is None  # nothing in a body either
    assert seen[0].full_url == "https://example.test/range/ABCDE"


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (_Response(500, b"x"), "bad_response"),
        (_Response(302, b"x"), "bad_response"),
        (urllib.error.HTTPError("u", 429, "slow", {}, None), "bad_response"),  # type: ignore[arg-type]
        (urllib.error.URLError("dns"), "network"),
        (TimeoutError(), "timeout"),
        (ssl.SSLCertVerificationError(), "network"),
        (ConnectionResetError(), "network"),
        (_Response(200, b"A" * 500), "too_large"),
    ],
)
def test_every_transport_failure_maps_to_a_fixed_reason(
    monkeypatch: pytest.MonkeyPatch, outcome: Any, reason: str
) -> None:
    _patch_open(monkeypatch, outcome)
    with pytest.raises(BreachLookupError) as caught:
        providers_module.urllib_transport("https://example.test/range/ABCDE", {}, 1.0, 100)
    assert caught.value.reason == reason
    assert "example.test" not in str(caught.value)


def test_the_opener_has_only_https_handlers_and_never_follows_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    added: list[type] = []
    original = urllib.request.OpenerDirector.add_handler

    def spy(self: Any, handler: Any) -> None:
        added.append(type(handler))
        original(self, handler)

    monkeypatch.setattr(urllib.request.OpenerDirector, "add_handler", spy)
    _patch_open(monkeypatch, _Response(200, b""))
    providers_module.urllib_transport("https://example.test/range/ABCDE", {}, 1.0, 100)

    names = {t.__name__ for t in added}
    assert names == {
        "ProxyHandler", "HTTPSHandler", "HTTPDefaultErrorHandler", "HTTPErrorProcessor",
        "_RefuseRedirects",
    }  # fmt: skip
    assert not names & {
        "HTTPHandler",
        "FileHandler",
        "FTPHandler",
        "HTTPCookieProcessor",
        "DataHandler",
    }
    redirect = providers_module._RefuseRedirects()
    assert redirect.redirect_request() is None


# --------------------------------------------------------------- memory / local corpora


def _corpus(passwords: dict[str, int]) -> dict[str, int]:
    return {sha1_hex(pw): count for pw, count in passwords.items()}


def test_memory_provider_buckets_by_prefix() -> None:
    provider = MemoryRangeProvider(_corpus({"password": 9_000, "letmein": 3}))
    prefix, suffix = split_hash(sha1_hex("password"))
    assert provider.fetch_range(prefix) == {suffix: 9_000}
    assert provider.fetch_range("00000") == {}
    assert len(provider) == 2
    assert provider.source == "local"


def test_memory_provider_accepts_a_plain_iterable_and_validates() -> None:
    assert len(MemoryRangeProvider([KNOWN_SHA1.lower(), KNOWN_SHA1])) == 1
    with pytest.raises(ValueError, match="40-character"):
        MemoryRangeProvider(["short"])
    with pytest.raises(ValueError, match="40-character"):
        MemoryRangeProvider({KNOWN_SHA1: 0})


def _write_sorted(
    path: Path, hashes: dict[str, int], *, counts: bool = True, eol: str = "\n"
) -> None:
    lines = [f"{h}:{c}" if counts else h for h, c in sorted(hashes.items())]
    path.write_bytes((eol.join(lines) + eol).encode("ascii"))


def test_sorted_file_finds_buckets_with_binary_search(tmp_path: Path) -> None:
    corpus = _corpus({"password": 9_000, "letmein": 3, "qwerty": 77, "dragon": 5, "monkey": 1})
    file = tmp_path / "pwned.txt"
    _write_sorted(file, corpus)
    provider = SortedHashFile(file)
    for pw, count in {
        "password": 9_000,
        "letmein": 3,
        "qwerty": 77,
        "dragon": 5,
        "monkey": 1,
    }.items():
        prefix, suffix = split_hash(sha1_hex(pw))
        assert provider.fetch_range(prefix)[suffix] == count
    assert provider.fetch_range("00000") == {}
    assert provider.fetch_range("FFFFF") == {}
    assert provider.verify_sorted()
    assert str(file) not in repr(provider)


def test_sorted_file_agrees_with_the_in_memory_provider_on_random_data(tmp_path: Path) -> None:
    rng = random.Random(3)  # noqa: S311 - deterministic test data
    hashes = {f"{rng.getrandbits(160):040X}": rng.randint(1, 500) for _ in range(800)}
    file = tmp_path / "big.txt"
    _write_sorted(file, hashes)
    sorted_file, memory = SortedHashFile(file), MemoryRangeProvider(hashes)
    prefixes = {h[:5] for h in hashes} | {f"{rng.getrandbits(20):05X}" for _ in range(200)}
    for prefix in sorted(prefixes):
        assert sorted_file.fetch_range(prefix) == memory.fetch_range(prefix)


@pytest.mark.parametrize(("counts", "eol"), [(False, "\n"), (True, "\r\n"), (False, "\r\n")])
def test_sorted_file_accepts_missing_counts_and_crlf(
    tmp_path: Path, counts: bool, eol: str
) -> None:
    file = tmp_path / "f.txt"
    _write_sorted(file, {KNOWN_SHA1: 4}, counts=counts, eol=eol)
    prefix, suffix = split_hash(KNOWN_SHA1)
    assert SortedHashFile(file).fetch_range(prefix) == {suffix: 4 if counts else 1}


def test_sorted_file_edge_cases(tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    assert SortedHashFile(empty).fetch_range("ABCDE") == {}
    single = tmp_path / "one.txt"
    single.write_bytes(f"{KNOWN_SHA1}:2".encode("ascii"))  # no trailing newline
    assert SortedHashFile(single).fetch_range("5BAA6") == {split_hash(KNOWN_SHA1)[1]: 2}
    lower = tmp_path / "lower.txt"
    lower.write_bytes(f"{KNOWN_SHA1.lower()}:2\n".encode("ascii"))
    assert SortedHashFile(lower).fetch_range("5BAA6")


@pytest.mark.parametrize(
    "content",
    [
        b"5BAA6not-a-hash:1\n",
        b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:x\n",
        b"5BAA6" + b"Z" * 40 + b"\n",
        b"5BAA6" + b"1" * 400 + b"\n",
    ],
)
def test_a_corrupt_corpus_is_reported_as_unreadable(tmp_path: Path, content: bytes) -> None:
    file = tmp_path / "bad.txt"
    file.write_bytes(content)
    with pytest.raises(BreachLookupError) as caught:
        SortedHashFile(file).fetch_range("5BAA6")
    assert caught.value.reason == "unreadable"


def test_a_missing_corpus_and_an_absurd_bucket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(BreachLookupError) as missing:
        SortedHashFile(tmp_path / "nope.txt")
    assert missing.value.reason == "unreadable"
    assert str(tmp_path) not in str(missing.value)

    monkeypatch.setattr(providers_module, "MAX_BUCKET_LINES", 3)
    file = tmp_path / "bucket.txt"
    _write_sorted(file, {f"5BAA6{i:035X}": 1 for i in range(10)})
    with pytest.raises(BreachLookupError):
        SortedHashFile(file).fetch_range("5BAA6")


def test_verify_sorted_detects_an_unsorted_file(tmp_path: Path) -> None:
    file = tmp_path / "unsorted.txt"
    file.write_bytes(b"\n".join(f"{n:040X}:1".encode("ascii") for n in range(200, 0, -1)) + b"\n")
    assert not SortedHashFile(file).verify_sorted()
