"""Repeated-character and sequence detectors.

Both detectors work on case-folded text (``"aAaA"`` is a repeat, ``"AbC"`` is a sequence) and
return positions only - never the matched text.
"""

from __future__ import annotations

from dataclasses import dataclass

from passaudit.analysis.text import Span, fold


@dataclass(frozen=True, slots=True)
class RepeatMatch:
    """A run of one character (``block_length == 1``) or a repeated block."""

    span: Span
    block_length: int
    count: int


@dataclass(frozen=True, slots=True)
class SequenceMatch:
    """A run of letters or digits that advances by a constant step (``+-1`` for ``abc``)."""

    span: Span
    step: int  # signed: +1 ascending, -1 descending; +-2 and +-3 for stepped runs


def find_repeats(password: str, *, min_run: int = 3) -> list[RepeatMatch]:
    """Find runs of identical characters and repeated multi-character blocks.

    * A single character repeated at least ``min_run`` times (``"aaa"``) is reported.
    * A block of two or more characters repeated at least twice (``"abab"``, ``"abcabc"``)
      is reported.

    Matches never overlap. At each position the candidate covering the most characters wins;
    ties go to the shorter block. Worst case ``O(n^2)``, bounded by the input length cap.
    """
    if min_run < 2:
        raise ValueError("min_run must be at least 2")
    text = fold(password)
    n = len(text)
    matches: list[RepeatMatch] = []
    i = 0
    while i < n:
        best: RepeatMatch | None = None
        best_cover = 0
        for block in range(1, (n - i) // 2 + 1):
            # Cheap pre-filter: a repeat requires the block's first character to recur.
            if text[i + block] != text[i]:
                continue
            unit = text[i : i + block]
            count = 1
            pos = i + block
            while text.startswith(unit, pos):
                count += 1
                pos += block
            needed = min_run if block == 1 else 2
            cover = count * block
            if count >= needed and cover > best_cover:
                best_cover = cover
                best = RepeatMatch(Span(i, cover), block, count)
        if best is None:
            i += 1
        else:
            matches.append(best)
            i += best.span.length
    return matches


def _sequence_class(ch: str) -> str | None:
    if "a" <= ch <= "z":
        return "lower"
    if "0" <= ch <= "9":
        return "digit"
    return None


def find_sequences(password: str, *, min_length: int = 3) -> list[SequenceMatch]:
    """Find maximal runs of ASCII letters or digits that step by exactly +1 or -1.

    ``"abc"``, ``"CBA"``, ``"1234"`` and ``"9876"`` are sequences. Runs never mix letters with
    digits and do not wrap (``"xyz"`` is a sequence, ``"yza"`` is not). Steps other than +-1
    (``"246"``) are out of scope - see the documented limitations.
    """
    if min_length < 2:
        raise ValueError("min_length must be at least 2")
    text = fold(password)
    n = len(text)
    matches: list[SequenceMatch] = []
    i = 0
    while i < n - 1:
        cls = _sequence_class(text[i])
        step = ord(text[i + 1]) - ord(text[i])
        if cls is None or step not in (1, -1) or _sequence_class(text[i + 1]) != cls:
            i += 1
            continue
        j = i + 1
        while (
            j + 1 < n
            and _sequence_class(text[j + 1]) == cls
            and ord(text[j + 1]) - ord(text[j]) == step
        ):
            j += 1
        length = j - i + 1
        if length >= min_length:
            matches.append(SequenceMatch(Span(i, length), step))
        # Resume at the last character: "abcba" yields both "abc" and "cba".
        i = j
    return matches


def find_stepped_sequences(
    password: str, *, min_length: int = 4, steps: tuple[int, ...] = (2, 3)
) -> list[SequenceMatch]:
    """Find runs that advance by a constant step of 2 or 3 (``"2468"``, ``"acegi"``, ``"9630"``).

    Like :func:`find_sequences` but for the larger steps that people use to make a pattern
    "look random". The default minimum is 4 because three characters stepping by two happen by
    chance far more often than three consecutive ones.
    """
    if min_length < 3:
        raise ValueError("min_length must be at least 3")
    text = fold(password)
    n = len(text)
    matches: list[SequenceMatch] = []
    i = 0
    while i < n - 1:
        cls = _sequence_class(text[i])
        step = ord(text[i + 1]) - ord(text[i])
        if cls is None or abs(step) not in steps or _sequence_class(text[i + 1]) != cls:
            i += 1
            continue
        j = i + 1
        while (
            j + 1 < n
            and _sequence_class(text[j + 1]) == cls
            and ord(text[j + 1]) - ord(text[j]) == step
        ):
            j += 1
        length = j - i + 1
        if length >= min_length:
            matches.append(SequenceMatch(Span(i, length), step))
        i = j
    return matches


def is_simple_sequence(text: str) -> bool:
    """True when ``text`` is entirely one +-1 sequence of letters or digits.

    Used to stop the keyboard detector double-reporting runs such as ``"1234"``.
    """
    folded = fold(text)
    if len(folded) < 2:
        return False
    found = find_sequences(folded, min_length=len(folded))
    return len(found) == 1 and found[0].span.length == len(folded)
