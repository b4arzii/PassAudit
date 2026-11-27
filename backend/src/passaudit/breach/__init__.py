"""Privacy-preserving breach checking (opt-in).

This is the **only** package in PassAudit that may open a network connection, and it does so
only through :class:`HibpRangeProvider`, which the application constructs only when the operator
has set ``PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED=true``. The analysis engine never imports it.

The protocol is k-anonymity over a hash prefix (the "range" API of Pwned Passwords):

1. hash the password locally with SHA-1,
2. send **only the first five hex characters** of the hash (20 bits) to the service,
3. receive every hash suffix in that bucket (padded with fake entries, so the response size
   does not reveal the bucket's real size) and compare locally.

The password, its full hash and the matched suffix never leave the machine. Read
``docs/security.md`` ("Breach checking") for what the service *can* still learn.
"""

from passaudit.breach.checker import BreachChecker
from passaudit.breach.errors import BreachLookupError, BreachReason
from passaudit.breach.hashing import PREFIX_LENGTH, sha1_hex, split_hash
from passaudit.breach.providers import (
    DEFAULT_RANGE_URL,
    HibpRangeProvider,
    MemoryRangeProvider,
    RangeProvider,
    SortedHashFile,
    parse_range_response,
)

__all__ = [
    "DEFAULT_RANGE_URL",
    "PREFIX_LENGTH",
    "BreachChecker",
    "BreachLookupError",
    "BreachReason",
    "HibpRangeProvider",
    "MemoryRangeProvider",
    "RangeProvider",
    "SortedHashFile",
    "parse_range_response",
    "sha1_hex",
    "split_hash",
]
