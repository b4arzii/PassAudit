"""Text normalisation helpers shared by the detectors.

Every transformation here is **length-preserving** (one input character maps to exactly one
output character) so that match positions found on normalised text are valid positions in the
original password.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

# Common "leetspeak" substitutions. Ambiguous characters list every plausible letter.
LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "il",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "il",
    "|": "il",
    "+": "t",
}

# Upper bound on de-leet variants generated for one string; keeps worst-case work bounded
# (a password made only of ambiguous characters would otherwise explode combinatorially).
MAX_LEET_VARIANTS = 64


def fold(text: str) -> str:
    """Lower-case ``text`` one character at a time, never changing its length.

    ``str.lower`` can expand a character (e.g. ``"İ"`` becomes two code points), which would
    desynchronise positions, so expanding results are left unchanged.
    """
    return "".join(lowered if len(lowered := ch.lower()) == 1 else ch for ch in text)


def deleet_variants(text: str, limit: int = MAX_LEET_VARIANTS) -> list[str]:
    """Return up to ``limit`` distinct de-leeted readings of ``text`` (excluding ``text``).

    ``text`` should already be folded. The result is empty when ``text`` contains no leet
    characters.
    """
    options: list[str] = []
    changed = False
    for ch in text:
        mapped = LEET_MAP.get(ch)
        if mapped is None:
            options.append(ch)
        else:
            options.append(mapped)
            changed = True
    if not changed:
        return []
    variants: list[str] = []
    for combo in itertools.islice(itertools.product(*options), limit + 1):
        candidate = "".join(combo)
        if candidate != text and candidate not in variants:
            variants.append(candidate)
        if len(variants) >= limit:
            break
    return variants


@dataclass(frozen=True, slots=True)
class Span:
    """A half-open character range ``[start, start + length)`` inside a password."""

    start: int
    length: int

    @property
    def end(self) -> int:
        return self.start + self.length

    def overlap(self, other: Span) -> int:
        """Number of characters shared with ``other``."""
        return max(0, min(self.end, other.end) - max(self.start, other.start))


def merge_spans(spans: list[Span]) -> list[Span]:
    """Merge overlapping or touching spans into a minimal sorted list."""
    merged: list[Span] = []
    for span in sorted(spans, key=lambda s: (s.start, s.length)):
        if merged and span.start <= merged[-1].end:
            last = merged[-1]
            merged[-1] = Span(last.start, max(last.end, span.end) - last.start)
        else:
            merged.append(span)
    return merged
