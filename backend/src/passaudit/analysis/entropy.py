"""Entropy estimation - and an honest account of what it can and cannot tell you.

Three numbers are produced:

``charset_bits``
    ``length * log2(pool)`` where *pool* is the number of symbols a uniformly random generator
    would need to cover the character classes present. It is an **upper bound that is only
    valid for passwords generated uniformly at random**. For human-chosen passwords it grossly
    overstates strength (``"Password1!"`` scores ~65 bits and is cracked instantly).

``shannon_bits``
    The Shannon entropy of the password's *own* character frequencies times its length. It
    measures how evenly characters are used inside this one string, not how an attacker would
    guess it, and for short strings it is capped at ``length * log2(length)``.

``guess_bits``
    ``log2`` of zxcvbn's estimated number of guesses. This models real attacker behaviour
    (dictionaries, leetspeak, keyboard walks, dates, repeats) and is the figure to prefer.

``estimated_bits = min(charset_bits, guess_bits)`` - never more optimistic than either.
"""

from __future__ import annotations

import math
from collections import Counter

from passaudit.analysis.charsets import CharacterProfile
from passaudit.analysis.models import EntropyEstimate

LOG2_10 = math.log2(10)

LIMITATIONS: tuple[str, ...] = (
    "Charset entropy assumes every character was drawn independently and uniformly at "
    "random; human-chosen passwords are far more predictable, so it overstates their strength.",
    "Shannon entropy only describes character frequency inside this one string; it says "
    "nothing about how likely the string is to be guessed.",
    "Guess-based bits come from zxcvbn's statistical model of common attacks and are an "
    "estimate, not a guarantee; unknown personal patterns or a leaked password can make a "
    "high estimate irrelevant.",
    "Non-ASCII characters are credited with a flat, rough alphabet allowance.",
    "Only the first part of very long passwords is passed to zxcvbn (see 'truncated'); "
    "estimates for such inputs are lower bounds.",
    "Entropy is a property of how a password was generated, not of the password string; "
    "a string that merely looks random can still be known to attackers.",
)


def charset_bits(profile: CharacterProfile) -> float:
    """Naive uniform-random entropy in bits; ``0.0`` for an empty password."""
    if profile.length == 0 or profile.pool_size < 2:
        return 0.0
    return profile.length * math.log2(profile.pool_size)


def shannon_bits_per_char(password: str) -> float:
    """Shannon entropy (bits per character) of the password's character distribution."""
    n = len(password)
    if n == 0:
        return 0.0
    counts = Counter(password)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return max(0.0, entropy)  # guard against -0.0


def guess_bits_from_log10(guesses_log10: float) -> float:
    """Convert zxcvbn's ``log10(guesses)`` to bits."""
    return max(0.0, guesses_log10 * LOG2_10)


def estimate_entropy(
    password: str, profile: CharacterProfile, guesses_log10: float
) -> EntropyEstimate:
    """Combine the three estimates into one model. ``password`` is not retained."""
    charset = charset_bits(profile)
    per_char = shannon_bits_per_char(password)
    guess = guess_bits_from_log10(guesses_log10)
    return EntropyEstimate(
        pool_size=profile.pool_size,
        charset_bits=charset,
        shannon_bits_per_char=per_char,
        shannon_bits=per_char * profile.length,
        guess_bits=guess,
        estimated_bits=min(charset, guess),
        limitations=LIMITATIONS,
    )
