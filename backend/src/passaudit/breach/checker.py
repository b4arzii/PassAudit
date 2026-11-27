"""Check passwords against a breach corpus without sending anything identifying.

``BreachChecker`` hashes locally, asks a :class:`RangeProvider` only for 5-character prefixes,
and compares the returned suffixes locally. Privacy measures beyond the protocol itself:

* **one request per distinct prefix**, however many passwords share it;
* prefixes are queried in **random order**, so the order of requests does not reveal the order
  of the batch;
* a small **cache of public bucket data** (prefix -> suffixes) avoids repeating a prefix
  disclosure; it holds no password, no full hash of a checked password and no result;
* a **time budget** and a **distinct-prefix cap** bound how much a single call can send;
* failures are reported per password as ``unavailable`` (unchecked - never "clean") and carry
  no detail that could reveal input.

The checker never logs and keeps no reference to a password or its hash after the call.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Literal

from passaudit.analysis import BreachExposure
from passaudit.breach.errors import BreachLookupError
from passaudit.breach.hashing import sha1_hex, split_hash

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from passaudit.breach.providers import RangeProvider

Mode = Literal["local", "online"]

DEFAULT_CACHE_SIZE = 512
DEFAULT_CACHE_TTL_SECONDS = 3600.0
DEFAULT_MAX_PREFIXES = 100


class _BucketCache:
    """A tiny thread-safe LRU of ``prefix -> {suffix: count}`` with a time-to-live."""

    def __init__(self, size: int, ttl: float, clock: Callable[[], float]) -> None:
        self._size = size
        self._ttl = ttl
        self._clock = clock
        self._items: OrderedDict[str, tuple[float, dict[str, int]]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, prefix: str) -> dict[str, int] | None:
        with self._lock:
            entry = self._items.get(prefix)
            if entry is None:
                return None
            expires, bucket = entry
            if expires <= self._clock():
                del self._items[prefix]
                return None
            self._items.move_to_end(prefix)
            return bucket

    def put(self, prefix: str, bucket: dict[str, int]) -> None:
        if self._size <= 0:
            return
        with self._lock:
            self._items[prefix] = (self._clock() + self._ttl, bucket)
            self._items.move_to_end(prefix)
            while len(self._items) > self._size:
                self._items.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class BreachChecker:
    """Looks passwords up in the configured sources (``local`` and/or ``online``)."""

    def __init__(
        self,
        *,
        online: RangeProvider | None = None,
        local: RangeProvider | None = None,
        cache_size: int = DEFAULT_CACHE_SIZE,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._providers: dict[str, RangeProvider] = {}
        if local is not None:
            self._providers["local"] = local
        if online is not None:
            self._providers["online"] = online
        self._cache = _BucketCache(cache_size, cache_ttl_seconds, clock)
        self._clock = clock
        self._shuffle = secrets.SystemRandom().shuffle

    def available(self, mode: Mode) -> bool:
        return mode in self._providers

    def __repr__(self) -> str:
        return f"BreachChecker(sources={sorted(self._providers)})"

    # ----------------------------------------------------------------------- lookups

    def check(self, password: str, mode: Mode) -> BreachExposure:
        """Check one password. Raises ``not_configured`` if ``mode`` has no provider."""
        return self.check_many([password], mode)[0]

    def check_many(
        self,
        passwords: Sequence[str],
        mode: Mode,
        *,
        deadline_seconds: float | None = None,
        max_prefixes: int = DEFAULT_MAX_PREFIXES,
    ) -> list[BreachExposure]:
        """Check each password; the result list is parallel to ``passwords``.

        Raises ``BreachLookupError('not_configured')`` if ``mode`` has no provider. Any other
        failure marks the affected passwords ``unavailable`` instead of raising, so one bad
        bucket does not hide the rest.
        """
        provider = self._providers.get(mode)
        if provider is None:
            raise BreachLookupError("not_configured")
        started = self._clock()

        by_prefix: dict[str, list[tuple[int, str]]] = {}
        for position, password in enumerate(passwords):
            prefix, suffix = split_hash(sha1_hex(password))
            by_prefix.setdefault(prefix, []).append((position, suffix))

        results: list[BreachExposure | None] = [None] * len(passwords)
        order = list(by_prefix)
        self._shuffle(order)  # never reveal the batch order through the request order

        for index, prefix in enumerate(order):
            over_budget = (
                deadline_seconds is not None and self._clock() - started > deadline_seconds
            )
            bucket: dict[str, int] | None = None
            if not over_budget and index < max_prefixes:
                bucket = self._bucket(provider, prefix)
            for position, suffix in by_prefix[prefix]:
                results[position] = self._outcome(mode, bucket, suffix)

        by_prefix.clear()
        return [
            r if r is not None else BreachExposure(status="unavailable", source=mode)
            for r in results
        ]

    def _bucket(self, provider: RangeProvider, prefix: str) -> dict[str, int] | None:
        cached = self._cache.get(prefix) if provider.source == "online" else None
        if cached is not None:
            return cached
        try:
            bucket = provider.fetch_range(prefix)
        except BreachLookupError:
            return None
        if provider.source == "online":
            self._cache.put(prefix, bucket)
        return bucket

    @staticmethod
    def _outcome(mode: Mode, bucket: dict[str, int] | None, suffix: str) -> BreachExposure:
        if bucket is None:
            return BreachExposure(status="unavailable", source=mode)
        count = bucket.get(suffix)
        if count is None:
            return BreachExposure(status="clean", source=mode, count=0)
        return BreachExposure(status="breached", source=mode, count=count)
