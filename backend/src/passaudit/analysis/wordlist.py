"""Local dictionary-based weak-password detection.

Everything here is offline: the bundled list ships inside the package and custom lists are read
from a path the caller supplies. The password is only ever compared against in-memory sets.

Match types, in the order they are tried (the first that hits wins, except ``EMBEDDED`` which
may report several spans):

``EXACT``      the whole password, case-insensitively, is a listed word
``REVERSED``   the whole password reversed is a listed word (``"drowssap"``)
``LEET``       the whole password is a listed word after undoing leetspeak (``"p@ssw0rd"``)
``DECORATED``  a listed word (optionally leet-substituted) with digits/symbols stuck on the
               front or back (``"Password123!"``)
``EMBEDDED``   a listed word of at least ``min_embedded_length`` characters appears inside
               the password (``"xxdragonxx"``)
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

from passaudit.analysis.models import WordMatchType
from passaudit.analysis.text import LEET_MAP, Span, deleet_variants, fold

if TYPE_CHECKING:
    from collections.abc import Iterable

BUNDLED_NAME = "common_passwords.txt"
MAX_LIST_FILE_BYTES = 64 * 1024 * 1024  # refuse absurdly large custom lists
MAX_WORD_LENGTH = 128  # longer entries are not realistic passwords-list words
MIN_DECORATED_CORE = 4  # shortest stripped core accepted as a DECORATED match
MAX_EMBEDDED_MATCHES = 8  # bounds output for pathological inputs (e.g. 1000 x 'x')


@dataclass(frozen=True, slots=True)
class WordMatch:
    """Where in the password a listed word was found. Never contains the word itself."""

    match_type: WordMatchType
    span: Span


class WordList:
    """An immutable set of known-weak passwords with matching logic."""

    def __init__(self, words: Iterable[str], *, name: str = "custom") -> None:
        cleaned = {w for raw in words if (w := fold(raw.strip())) and len(w) <= MAX_WORD_LENGTH}
        self._words: frozenset[str] = frozenset(cleaned)
        self._max_len = max((len(w) for w in cleaned), default=0)
        self.name = name

    # -- construction -----------------------------------------------------------------

    @classmethod
    def from_lines(cls, lines: Iterable[str], *, name: str = "custom") -> WordList:
        """Build a list from text lines, skipping blanks and ``#`` comments."""
        return cls(
            (line for line in lines if (stripped := line.strip()) and not stripped.startswith("#")),
            name=name,
        )

    @classmethod
    def from_file(cls, path: str | Path, *, name: str | None = None) -> WordList:
        """Load a UTF-8 word list (one word per line) from ``path``.

        Raises ``ValueError`` (with no file content in the message) if the file is larger than
        ``MAX_LIST_FILE_BYTES``; ``OSError``/``UnicodeDecodeError`` propagate unchanged.
        """
        file = Path(path)
        if file.stat().st_size > MAX_LIST_FILE_BYTES:
            raise ValueError(f"Word list exceeds the {MAX_LIST_FILE_BYTES} byte limit.")
        with file.open(encoding="utf-8") as handle:
            return cls.from_lines(handle, name=name or file.name)

    @classmethod
    def bundled(cls) -> WordList:
        """The list shipped with PassAudit (cached)."""
        return _load_bundled()

    @classmethod
    def bundled_resource(cls, filename: str, *, name: str) -> WordList:
        """Another list shipped with PassAudit (``data/<filename>``), cached by name."""
        return _load_resource(filename, name)

    def union(self, *others: WordList, name: str = "merged") -> WordList:
        """A new list holding the words of this list and ``others``."""
        merged = WordList((), name=name)
        merged._words = frozenset(self._words.union(*(o._words for o in others)))
        merged._max_len = max([self._max_len, *(o._max_len for o in others)])
        return merged

    @property
    def max_word_length(self) -> int:
        return self._max_len

    def has(self, folded_word: str) -> bool:
        """Exact membership of an already case-folded word (no leet, no decoration)."""
        return folded_word in self._words

    # -- container protocol -----------------------------------------------------------

    def __len__(self) -> int:
        return len(self._words)

    def __contains__(self, word: object) -> bool:
        return isinstance(word, str) and fold(word) in self._words

    def __repr__(self) -> str:  # never list contents
        return f"WordList(name={self.name!r}, size={len(self)})"

    # -- matching ---------------------------------------------------------------------

    def _contains_reading(self, text: str) -> bool:
        """True if ``text`` or any de-leeted reading of it is listed."""
        if text in self._words:
            return True
        return any(v in self._words for v in deleet_variants(text))

    def find_matches(self, password: str, *, min_embedded_length: int = 5) -> list[WordMatch]:
        """Return every weak-word match found in ``password`` (empty if none)."""
        if not password or not self._words:
            return []
        text = fold(password)
        n = len(text)
        whole = Span(0, n)

        if text in self._words:
            return [WordMatch(WordMatchType.EXACT, whole)]
        if text[::-1] in self._words:
            return [WordMatch(WordMatchType.REVERSED, whole)]
        if any(v in self._words for v in deleet_variants(text)):
            return [WordMatch(WordMatchType.LEET, whole)]

        decorated = self._match_decorated(text)
        if decorated is not None:
            return [decorated]
        return self._match_embedded(text, min_embedded_length)

    def _match_decorated(self, text: str) -> WordMatch | None:
        """A listed word with decoration stuck on one or both ends.

        Two strippings are tried because some decoration characters double as leetspeak:
        stripping every non-letter finds ``"password"`` in ``"password123!"``; stripping only
        non-alphanumerics finds ``"passw0rd"`` (then de-leeted) in ``"passw0rd!"``.
        """
        for keep in (str.isalpha, str.isalnum):
            start = 0
            end = len(text)
            while start < end and not keep(text[start]):
                start += 1
            while end > start and not keep(text[end - 1]):
                end -= 1
            core = text[start:end]
            if MIN_DECORATED_CORE <= len(core) < len(text) and self._contains_reading(core):
                return WordMatch(WordMatchType.DECORATED, Span(start, len(core)))
        return None

    def _match_embedded(self, text: str, min_length: int) -> list[WordMatch]:
        n = len(text)
        if n < min_length or self._max_len < min_length:
            return []
        # Two canonical readings cover the common ambiguity of ``1``/``!`` (i or l).
        readings = [text, _primary_reading(text, "i"), _primary_reading(text, "l")]
        hits: list[Span] = []
        longest = min(self._max_len, n)
        for reading in dict.fromkeys(readings):
            for i in range(n - min_length + 1):
                for length in range(min_length, min(longest, n - i) + 1):
                    if reading[i : i + length] in self._words:
                        hits.append(Span(i, length))
        # Keep the longest hits that do not overlap one another.
        chosen: list[Span] = []
        for span in sorted(hits, key=lambda s: (-s.length, s.start)):
            if all(span.overlap(c) == 0 for c in chosen):
                chosen.append(span)
                if len(chosen) == MAX_EMBEDDED_MATCHES:
                    break
        chosen.sort(key=lambda s: s.start)
        return [WordMatch(WordMatchType.EMBEDDED, s) for s in chosen]


def _primary_reading(text: str, ambiguous: str) -> str:
    """Length-preserving de-leet using ``ambiguous`` ('i' or 'l') for ``1``/``!``/``|``."""
    out: list[str] = []
    for ch in text:
        mapped = LEET_MAP.get(ch)
        if mapped is None:
            out.append(ch)
        else:
            out.append(ambiguous if len(mapped) > 1 else mapped)
    return "".join(out)


@lru_cache(maxsize=8)
def _load_resource(filename: str, name: str) -> WordList:
    resource = resources.files("passaudit.analysis").joinpath("data", filename)
    text = resource.read_text(encoding="utf-8")
    return WordList.from_lines(text.splitlines(), name=name)


def _load_bundled() -> WordList:
    return _load_resource(BUNDLED_NAME, "bundled")
