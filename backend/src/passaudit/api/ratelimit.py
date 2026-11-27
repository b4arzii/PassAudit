"""Rate limiting.

Design (also documented in docs/api.md):

* **Algorithm: token bucket.** Each client has a bucket of ``capacity`` tokens that refills at
  ``refill_per_second``. A request spends its *cost* in tokens; if the bucket cannot pay, the
  request is rejected with ``429`` and ``Retry-After``. Bursts are allowed up to the capacity;
  the sustained rate is the refill rate.
* **Cost units, not request counts.** A single-password request costs 1; a batch request costs
  one unit per password. This ties the limit to CPU use, which is what an attacker could
  exhaust (password analysis is CPU-bound).
* **Client key: the socket peer address.** ``X-Forwarded-For`` is *not* trusted, because the
  service is local-only and a client could forge it. If it is ever placed behind a reverse
  proxy, the key function must be changed deliberately (see docs/api.md).
* **Pluggable.** ``RateLimiter`` is a protocol; the in-memory implementation is per process.
  A multi-worker or multi-host deployment needs a shared store (e.g. Redis) behind the same
  interface.
* **Bounded memory.** At most ``max_keys`` buckets are tracked; idle (fully refilled) buckets
  are dropped first, then the least recently used.
* **Denied requests are free.** A rejected request does not consume tokens.
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int  # bucket capacity, in cost units
    remaining: int  # whole tokens left after this decision
    retry_after: int  # seconds until the request could succeed (0 when allowed)
    reset_after: int  # seconds until the bucket is full again


class RateLimiter(Protocol):
    """What the middleware and routes need from a limiter."""

    async def acquire(self, key: str, cost: int = 1) -> RateLimitDecision: ...


class TokenBucketLimiter:
    """In-memory token bucket limiter for a single process / event loop."""

    def __init__(
        self,
        *,
        capacity: int,
        refill_per_second: float,
        max_keys: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity < 1 or refill_per_second <= 0 or max_keys < 1:
            raise ValueError("capacity, refill rate and max_keys must be positive")
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.max_keys = max_keys
        self._clock = clock
        # key -> (tokens, last_update); ordered by recency of use
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._buckets)

    def _refilled(self, key: str, now: float) -> float:
        tokens, updated = self._buckets.get(key, (float(self.capacity), now))
        return min(float(self.capacity), tokens + (now - updated) * self.refill_per_second)

    def _evict(self, now: float) -> None:
        if len(self._buckets) <= self.max_keys:
            return
        full_after = self.capacity / self.refill_per_second
        for key in [k for k, (_, updated) in self._buckets.items() if now - updated >= full_after]:
            del self._buckets[key]
        while len(self._buckets) > self.max_keys:
            self._buckets.popitem(last=False)  # least recently used

    async def acquire(self, key: str, cost: int = 1) -> RateLimitDecision:
        # No ``await`` inside: the read-modify-write below is atomic on the event loop.
        now = self._clock()
        tokens = self._refilled(key, now)
        allowed = tokens >= cost
        if allowed:
            tokens -= cost
        self._buckets[key] = (tokens, now)
        self._buckets.move_to_end(key)
        self._evict(now)
        missing = 0.0 if allowed else cost - tokens
        return RateLimitDecision(
            allowed=allowed,
            limit=self.capacity,
            remaining=int(tokens),
            retry_after=0 if allowed else max(1, math.ceil(missing / self.refill_per_second)),
            reset_after=math.ceil((self.capacity - tokens) / self.refill_per_second),
        )
