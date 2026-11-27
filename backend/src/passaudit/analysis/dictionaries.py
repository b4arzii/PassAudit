"""Advanced dictionary analysis: several word lists, and words joined together.

``wordlist.WordList`` answers "is this password a known *password*?". This module adds the
broader question "what is this password *made of*?":

* **Kinds of dictionary.** Beyond the common-password list, the bundled ``words`` (everyday
  English words) and ``names`` (common first names) lists, plus any operator-supplied
  dictionaries (company terms, product names, local-language words, merged into ``words``).
* **Match types** are those of ``WordList`` (exact, reversed, leet, decorated, embedded) plus
  ``SEGMENTED``: the password is two or more listed words joined together, possibly decorated
  (``"CorrectHorseBattery!1"``, ``"planet-basket_desert"``).
* **Segmentation** is a bounded dynamic programme over the letters (see ``_segment``), run on
  the plain text and on its two canonical leet readings, so ``"c0rr3cth0rse"`` is found.

Matches carry kinds and positions only - never the matched word.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from passaudit.analysis.models import WordMatchType
from passaudit.analysis.text import Span, fold
from passaudit.analysis.wordlist import WordList, _primary_reading

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

WORDS_FILE = "common_words.txt"
NAMES_FILE = "first_names.txt"

SEGMENT_MIN_WORD = 3  # shortest word that counts as a segment (avoids "a"+"to"+"be"...)
SEGMENT_MAX_INPUT = 128  # longest core the segmenter will try (cost is linear in this)


class DictionaryKind(StrEnum):
    WORDS = "words"
    NAMES = "names"


@dataclass(frozen=True, slots=True)
class DictionaryMatch:
    kind: DictionaryKind
    match_type: WordMatchType
    span: Span


class DictionarySet:
    """The non-password dictionaries used for word and name detection (immutable)."""

    def __init__(self, words: WordList | None = None, names: WordList | None = None) -> None:
        self.words = words if words is not None else WordList((), name="words")
        self.names = names if names is not None else WordList((), name="names")
        self._lexicon = self.words.union(self.names, name="lexicon")

    @classmethod
    def bundled(cls) -> DictionarySet:
        return cls(
            WordList.bundled_resource(WORDS_FILE, name="words"),
            WordList.bundled_resource(NAMES_FILE, name="names"),
        )

    @classmethod
    def empty(cls) -> DictionarySet:
        return cls()

    def with_extra_files(self, paths: Iterable[str | Path]) -> DictionarySet:
        """Like :meth:`with_extra_words`, loading one word list per file (UTF-8, one word per
        line). ``OSError``, ``UnicodeDecodeError`` and ``ValueError`` (file too large) propagate
        unchanged and never include file content."""
        return self.with_extra_words([WordList.from_file(path, name="extra") for path in paths])

    def with_extra_words(self, extra: Iterable[WordList]) -> DictionarySet:
        """A copy whose ``words`` dictionary also contains ``extra`` (operator dictionaries)."""
        return DictionarySet(self.words.union(*extra, name="words"), self.names)

    def __repr__(self) -> str:  # sizes only, never contents
        return f"DictionarySet(words={len(self.words)}, names={len(self.names)})"

    # -- matching -------------------------------------------------------------------

    def find_matches(self, password: str, *, min_embedded_length: int = 5) -> list[DictionaryMatch]:
        """Every word/name match in ``password``; segmented runs replace their parts."""
        if not password:
            return []
        matches: list[DictionaryMatch] = []
        for kind, wordlist in (
            (DictionaryKind.WORDS, self.words),
            (DictionaryKind.NAMES, self.names),
        ):
            matches.extend(
                DictionaryMatch(kind, m.match_type, m.span)
                for m in wordlist.find_matches(password, min_embedded_length=min_embedded_length)
            )
        whole = any(m.match_type is not WordMatchType.EMBEDDED for m in matches)
        if not whole:
            segmented = self._segmented(password)
            if segmented is not None:
                matches = [m for m in matches if segmented.span.overlap(m.span) == 0]
                matches.append(segmented)
        matches.sort(key=lambda m: (m.span.start, -m.span.length))
        return matches

    def _segmented(self, password: str) -> DictionaryMatch | None:
        text = fold(password)
        for keep in (str.isalpha, str.isalnum):
            start, end = 0, len(text)
            while start < end and not keep(text[start]):
                start += 1
            while end > start and not keep(text[end - 1]):
                end -= 1
            core = text[start:end]
            if not 2 * SEGMENT_MIN_WORD <= len(core) <= SEGMENT_MAX_INPUT:
                continue
            if self._spells_words(core):
                return DictionaryMatch(
                    DictionaryKind.WORDS, WordMatchType.SEGMENTED, Span(start, len(core))
                )
        return None

    def _spells_words(self, core: str) -> bool:
        """Is ``core`` two or more listed words, joined directly or by separators?

        ``"correcthorse"`` and ``"planet-basket_desert"`` both qualify. Each separator-free
        token is read as plain text and through the two canonical leet readings.
        """
        tokens = [t for t in re.split(r"[\W_]+", core) if t]
        total = 0
        for token in tokens:
            counts = [
                n
                for reading in dict.fromkeys(
                    (token, _primary_reading(token, "i"), _primary_reading(token, "l"))
                )
                if (n := self._words_in(reading)) is not None
            ]
            if not counts:
                return False
            total += min(counts)
        return total >= 2

    def _words_in(self, token: str) -> int | None:
        """Fewest listed words that spell ``token`` exactly (a single word counts as 1)."""
        if len(token) >= SEGMENT_MIN_WORD and self._lexicon.has(token):
            return 1
        return self._segment(token)

    def _segment(self, text: str) -> int | None:
        """Fewest listed words (at least two) that exactly spell ``text``, or ``None``.

        ``best[i]`` is the fewest words covering ``text[:i]``; the inner loop only tries word
        lengths the lexicon can contain, so the cost is ``O(len(text) * longest word)``.
        """
        if not text.isalpha():
            return None
        n = len(text)
        longest = min(self._lexicon.max_word_length, n)
        infinity = n + 1
        best = [infinity] * (n + 1)
        best[0] = 0
        for end in range(SEGMENT_MIN_WORD, n + 1):
            for size in range(SEGMENT_MIN_WORD, min(longest, end) + 1):
                prior = best[end - size]
                if (
                    prior < infinity
                    and best[end] > prior + 1
                    and self._lexicon.has(text[end - size : end])
                ):
                    best[end] = prior + 1
        return best[n] if best[n] >= 2 and best[n] < infinity else None
