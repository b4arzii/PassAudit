"""Character classification and the character profile of a password."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

# Pool sizes used by the naive charset entropy estimate (see ``entropy.py``).
POOL_LOWERCASE = 26
POOL_UPPERCASE = 26
POOL_DIGITS = 10
POOL_ASCII_SYMBOLS = 32  # printable ASCII punctuation
POOL_SPACE = 1
# Rough, deliberately flat allowance for any non-ASCII character (accents, other scripts,
# emoji). It is a heuristic, not a measured alphabet size.
POOL_NON_ASCII = 100


@dataclass(frozen=True, slots=True)
class CharacterProfile:
    """Counts of each character class in a password. Contains no password text."""

    length: int
    lowercase: int
    uppercase: int
    digits: int
    symbols: int
    whitespace: int
    other: int  # caseless letters from non-ASCII scripts (e.g. CJK)
    unique: int
    non_ascii: int
    ascii_lowercase: int
    ascii_uppercase: int
    ascii_digits: int
    ascii_symbols: int

    @property
    def pool_size(self) -> int:
        """Size of the character pool a uniformly random generator would need to produce
        every character class seen in the password."""
        pool = 0
        if self.ascii_lowercase:
            pool += POOL_LOWERCASE
        if self.ascii_uppercase:
            pool += POOL_UPPERCASE
        if self.ascii_digits:
            pool += POOL_DIGITS
        if self.ascii_symbols:
            pool += POOL_ASCII_SYMBOLS
        if self.whitespace:
            pool += POOL_SPACE
        if self.non_ascii:
            pool += POOL_NON_ASCII
        return pool

    @property
    def class_count(self) -> int:
        """Number of distinct character classes present (0-5)."""
        return sum(
            1 for n in (self.lowercase, self.uppercase, self.digits, self.symbols, self.other) if n
        )


def _classify(ch: str) -> str:  # noqa: PLR0911 - a flat early-return classifier is clearest
    """Return one of ``lower upper digit symbol space other`` for a single character."""
    if ch.isspace():
        return "space"
    if ch.isascii():
        if "a" <= ch <= "z":
            return "lower"
        if "A" <= ch <= "Z":
            return "upper"
        if "0" <= ch <= "9":
            return "digit"
        return "symbol"
    if ch.islower():
        return "lower"
    if ch.isupper():
        return "upper"
    if ch.isdecimal():
        return "digit"
    return "other" if ch.isalpha() else "symbol"


def profile_of(password: str) -> CharacterProfile:
    """Classify every character of ``password``."""
    counts: Counter[str] = Counter()
    ascii_counts: Counter[str] = Counter()
    non_ascii = 0
    for ch in password:
        category = _classify(ch)
        counts[category] += 1
        if ch.isascii():
            ascii_counts[category] += 1
        else:
            non_ascii += 1
    return CharacterProfile(
        length=len(password),
        lowercase=counts["lower"],
        uppercase=counts["upper"],
        digits=counts["digit"],
        symbols=counts["symbol"],
        whitespace=counts["space"],
        other=counts["other"],
        unique=len(set(password)),
        non_ascii=non_ascii,
        ascii_lowercase=ascii_counts["lower"],
        ascii_uppercase=ascii_counts["upper"],
        ascii_digits=ascii_counts["digit"],
        ascii_symbols=ascii_counts["symbol"],
    )
