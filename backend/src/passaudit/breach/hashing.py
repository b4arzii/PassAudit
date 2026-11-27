"""SHA-1 hashing for the k-anonymity range protocol.

SHA-1 is used here **only as the lookup key of the Pwned Passwords data set**, which is indexed
by SHA-1. It is not used to protect anything (the hash never leaves the machine except for its
first five characters), so its collision weaknesses are irrelevant; ``usedforsecurity=False``
says so explicitly.
"""

from __future__ import annotations

import hashlib

PREFIX_LENGTH = 5
HASH_LENGTH = 40  # hex characters of a SHA-1 digest


def sha1_hex(password: str) -> str:
    """Upper-case hex SHA-1 of the UTF-8 password (the data set's key format)."""
    # SHA-1 is the lookup key of the Pwned Passwords data set, not a security hash.
    digest = hashlib.sha1(password.encode("utf-8", "surrogatepass"), usedforsecurity=False)
    return digest.hexdigest().upper()


def split_hash(digest: str) -> tuple[str, str]:
    """Split a full upper-case hash into the 5-character prefix and the 35-character suffix."""
    if len(digest) != HASH_LENGTH:
        raise ValueError("expected a 40-character SHA-1 hex digest")
    return digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]
