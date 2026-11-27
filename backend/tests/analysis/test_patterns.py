"""Repeat, sequence and keyboard-pattern detectors, including boundaries."""

from __future__ import annotations

import secrets
import string
import time
from itertools import pairwise

import pytest

from passaudit.analysis.keyboard import find_keyboard_runs
from passaudit.analysis.patterns import find_repeats, find_sequences, is_simple_sequence


def _spans(matches: list) -> list[tuple[int, int]]:  # type: ignore[type-arg]
    return [(m.span.start, m.span.length) for m in matches]


# ------------------------------------------------------------------------------ repeats


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("", []),
        ("a", []),
        ("aa", []),  # boundary: one below the default minimum run of 3
        ("aaa", [(0, 3)]),  # boundary: exactly the minimum
        ("aaaa", [(0, 4)]),
        ("xaaay", [(1, 3)]),
        ("aaabbb", [(0, 3), (3, 3)]),
        ("AaA", [(0, 3)]),  # case-insensitive
        ("abab", [(0, 4)]),  # smallest repeated block
        ("aba", []),
        ("abcabc", [(0, 6)]),
        ("ababab", [(0, 6)]),
        ("aabaab", [(0, 6)]),
        ("xxabcabcyy", [(2, 6)]),
        ("abcabd", []),
        ("a1b2c3", []),
        ("!!!!", [(0, 4)]),
    ],
)
def test_find_repeats(password: str, expected: list[tuple[int, int]]) -> None:
    assert _spans(find_repeats(password)) == expected


def test_repeat_metadata() -> None:
    (run,) = find_repeats("zzzzz")
    assert (run.block_length, run.count) == (1, 5)
    (block,) = find_repeats("abcabcabc")
    assert (block.block_length, block.count) == (3, 3)


def test_repeat_min_run_is_configurable() -> None:
    assert find_repeats("aaa", min_run=4) == []
    assert _spans(find_repeats("aaaa", min_run=4)) == [(0, 4)]
    assert _spans(find_repeats("aa", min_run=2)) == [(0, 2)]


def test_repeat_min_run_below_two_is_rejected() -> None:
    with pytest.raises(ValueError, match="min_run"):
        find_repeats("aaa", min_run=1)


def test_repeats_never_overlap() -> None:
    matches = find_repeats("aaaabababab" + "cccc")
    spans = _spans(matches)
    for (s1, l1), (s2, _l2) in pairwise(spans):
        assert s1 + l1 <= s2


# --------------------------------------------------------------------------- sequences


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("", []),
        ("a", []),
        ("ab", []),  # boundary: one below the minimum length of 3
        ("abc", [(0, 3, 1)]),  # boundary: exactly the minimum
        ("abcd", [(0, 4, 1)]),
        ("cba", [(0, 3, -1)]),
        ("ABC", [(0, 3, 1)]),
        ("AbC", [(0, 3, 1)]),
        ("123", [(0, 3, 1)]),
        ("321", [(0, 3, -1)]),
        ("0123456789", [(0, 10, 1)]),
        ("9012", [(1, 3, 1)]),  # 9 -> 0 is not a step of one
        ("xyz", [(0, 3, 1)]),
        ("yza", []),  # no wrap-around
        ("a1b2", []),
        ("abdc", []),
        ("ab1", []),  # letters and digits never mix
        ("89:", []),  # ':' follows '9' in ASCII but is not a digit
        ("z{|", []),
        ("abcba", [(0, 3, 1), (2, 3, -1)]),
        ("xabcx", [(1, 3, 1)]),
        ("αβγ", []),  # non-ASCII is out of scope
    ],
)
def test_find_sequences(password: str, expected: list[tuple[int, int, int]]) -> None:
    got = [(m.span.start, m.span.length, m.step) for m in find_sequences(password)]
    assert got == expected


def test_sequence_min_length_is_configurable() -> None:
    assert [(m.span.start, m.span.length) for m in find_sequences("ab", min_length=2)] == [(0, 2)]
    assert find_sequences("abc", min_length=4) == []


def test_sequence_min_length_below_two_is_rejected() -> None:
    with pytest.raises(ValueError, match="min_length"):
        find_sequences("abc", min_length=1)


@pytest.mark.parametrize(
    ("text", "expected"),
    [("abc", True), ("4321", True), ("ab", True), ("a", False), ("", False), ("abd", False)],
)
def test_is_simple_sequence(text: str, expected: bool) -> None:
    assert is_simple_sequence(text) is expected


# ---------------------------------------------------------------------------- keyboard


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("", []),
        ("q", []),
        ("qwe", []),  # boundary: one below the default minimum of 4
        ("qwer", [(0, 4, "qwerty")]),  # boundary: exactly the minimum
        ("qwerty", [(0, 6, "qwerty")]),
        ("ytrewq", [(0, 6, "qwerty")]),  # reversed
        ("QWERTY", [(0, 6, "qwerty")]),
        ("asdf", [(0, 4, "qwerty")]),
        ("zxcv", [(0, 4, "qwerty")]),
        ("1qaz", [(0, 4, "qwerty")]),  # down a diagonal
        ("zaq1", [(0, 4, "qwerty")]),
        ("2wsx", [(0, 4, "qwerty")]),
        ("!QAZ", [(0, 4, "qwerty")]),  # shifted keys count as their base key
        ("1qaz2wsx", [(0, 4, "qwerty"), (4, 4, "qwerty")]),
        ("qwrt", []),  # a gap breaks the run
        ("qaws", []),  # direction change
        ("xxqwerxx", [(2, 4, "qwerty")]),
        ("azerty", [(0, 6, "azerty")]),
        ("aoeu", [(0, 4, "dvorak")]),
        ("7410", [(0, 4, "keypad")]),
    ],
)
def test_find_keyboard_runs(password: str, expected: list[tuple[int, int, str]]) -> None:
    got = [(m.span.start, m.span.length, m.layout) for m in find_keyboard_runs(password)]
    assert got == expected


def test_keyboard_plain_sequences_are_left_to_the_sequence_detector() -> None:
    assert find_keyboard_runs("1234") == []
    assert find_keyboard_runs("123456789") == []
    assert [(m.span.length) for m in find_sequences("1234")] == [4]


def test_keyboard_run_min_length_is_configurable() -> None:
    assert [(m.span.start, m.span.length) for m in find_keyboard_runs("qwe", min_length=3)] == [
        (0, 3)
    ]
    assert find_keyboard_runs("qwer", min_length=5) == []
    assert [(m.span.length) for m in find_keyboard_runs("159", min_length=3)] == [3]


def test_keyboard_min_length_below_two_is_rejected() -> None:
    with pytest.raises(ValueError, match="min_length"):
        find_keyboard_runs("qwer", min_length=1)


def test_keyboard_only_reports_one_layout_per_span() -> None:
    # "asdf" is a valid walk on QWERTY, QWERTZ and AZERTY-derived rows; report it once.
    assert len(find_keyboard_runs("asdf")) == 1


def test_keyboard_unknown_characters_break_runs() -> None:
    assert find_keyboard_runs("qwe€rty") == []


# ------------------------------------------------------------------------- performance


@pytest.mark.parametrize(
    "password",
    [
        "a" * 1024,
        "ab" * 512,
        "abc123" * 170,
        "".join(secrets.choice("ab") for _ in range(1024)),
        "".join(secrets.choice(string.printable) for _ in range(1024)),
    ],
    ids=["one-char", "two-char-period", "period-six", "binary-random", "printable-random"],
)
def test_detectors_stay_fast_on_adversarial_input(password: str) -> None:
    start = time.perf_counter()
    find_repeats(password)
    find_sequences(password)
    find_keyboard_runs(password)
    assert time.perf_counter() - start < 3.0
