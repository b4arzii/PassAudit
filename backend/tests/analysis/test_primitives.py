"""Tests for text helpers, spans and character profiling."""

from __future__ import annotations

import time

import pytest

from passaudit.analysis.charsets import (
    POOL_NON_ASCII,
    CharacterProfile,
    profile_of,
)
from passaudit.analysis.text import MAX_LEET_VARIANTS, Span, deleet_variants, fold, merge_spans

# ------------------------------------------------------------------------------- fold


def test_fold_lowercases() -> None:
    assert fold("PaSsWoRd") == "password"


@pytest.mark.parametrize("text", ["", "abc", "ÄÖÜ", "ǅ", "İstanbul", "ß", "日本語", "\U0001f511A"])
def test_fold_never_changes_length(text: str) -> None:
    assert len(fold(text)) == len(text)


# ----------------------------------------------------------------------- deleet_variants


def test_deleet_returns_nothing_without_leet_characters() -> None:
    assert deleet_variants("plain") == []
    assert deleet_variants("") == []


def test_deleet_simple_substitution() -> None:
    assert deleet_variants("p@ssw0rd") == ["password"]


def test_deleet_ambiguous_characters_yield_all_readings() -> None:
    variants = deleet_variants("l1ght")
    assert set(variants) == {"light", "llght"}


def test_deleet_preserves_length() -> None:
    for variant in deleet_variants("!1|$@+"):
        assert len(variant) == 6


def test_deleet_variant_count_is_bounded() -> None:
    start = time.perf_counter()
    variants = deleet_variants("1" * 200)
    assert len(variants) <= MAX_LEET_VARIANTS
    assert time.perf_counter() - start < 1.0


def test_deleet_limit_parameter() -> None:
    assert len(deleet_variants("1111", limit=3)) == 3


# ------------------------------------------------------------------------------ spans


def test_span_end_and_overlap() -> None:
    a = Span(2, 4)  # [2, 6)
    assert a.end == 6
    assert a.overlap(Span(5, 3)) == 1
    assert a.overlap(Span(6, 3)) == 0  # touching is not overlapping
    assert a.overlap(Span(0, 2)) == 0
    assert a.overlap(Span(3, 1)) == 1
    assert a.overlap(a) == 4


def test_merge_spans() -> None:
    assert merge_spans([]) == []
    assert merge_spans([Span(5, 2), Span(0, 3)]) == [Span(0, 3), Span(5, 2)]
    assert merge_spans([Span(0, 3), Span(2, 3)]) == [Span(0, 5)]
    assert merge_spans([Span(0, 3), Span(3, 2)]) == [Span(0, 5)]  # touching merges
    assert merge_spans([Span(0, 10), Span(2, 2)]) == [Span(0, 10)]  # contained


# ---------------------------------------------------------------------------- charsets


def test_profile_of_empty_password() -> None:
    p = profile_of("")
    assert p.length == 0
    assert p.unique == 0
    assert p.pool_size == 0
    assert p.class_count == 0


def test_profile_counts_each_class() -> None:
    p = profile_of("aB3! x")
    assert (p.lowercase, p.uppercase, p.digits, p.symbols, p.whitespace) == (2, 1, 1, 1, 1)
    assert p.length == 6
    assert p.unique == 6
    assert p.class_count == 4
    assert p.pool_size == 26 + 26 + 10 + 32 + 1


def test_profile_unique_counts_distinct_characters() -> None:
    assert profile_of("aabbcc").unique == 3


def test_profile_non_ascii_letters_and_scripts() -> None:
    p = profile_of("éÉ日٣")  # lowercase, uppercase, caseless letter, non-ASCII digit
    assert p.non_ascii == 4
    assert (p.lowercase, p.uppercase, p.other, p.digits) == (1, 1, 1, 1)
    # No ASCII classes present: the pool is exactly the flat non-ASCII allowance.
    assert p.pool_size == POOL_NON_ASCII


def test_profile_non_ascii_symbol_and_whitespace() -> None:
    p = profile_of("\U0001f511\u00a0")  # emoji (symbol) + no-break space
    assert p.symbols == 1
    assert p.whitespace == 1
    assert p.non_ascii == 2


def test_profile_tabs_and_newlines_are_whitespace() -> None:
    assert profile_of("a\tb\nc").whitespace == 2


def test_profile_ascii_control_character_is_symbol() -> None:
    assert profile_of("\x00").symbols == 1


@pytest.mark.parametrize(
    ("password", "pool"),
    [
        ("abc", 26),
        ("ABC", 26),
        ("123", 10),
        ("!!!", 32),
        ("aA", 52),
        ("a1", 36),
        ("aA1", 62),
        ("aA1!", 94),
        (" ", 1),
    ],
)
def test_pool_size(password: str, pool: int) -> None:
    assert profile_of(password).pool_size == pool


def test_profile_is_immutable() -> None:
    p = profile_of("abc")
    assert isinstance(p, CharacterProfile)
    with pytest.raises(AttributeError):
        p.length = 5  # type: ignore[misc]
