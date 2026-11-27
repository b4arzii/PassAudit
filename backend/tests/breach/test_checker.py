"""BreachChecker: grouping, ordering, caching, budgets, failure handling and privacy."""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

import pytest

from passaudit.breach import (
    BreachChecker,
    BreachLookupError,
    MemoryRangeProvider,
    sha1_hex,
    split_hash,
)

CANARY = "Zq7!xKp#9mWv$L2nRb"
OTHER = "Qw8$yL3!pN6#zT1vHd"
THIRD = "Mn4&tR7@kB2%xC9sFj"
PREFIX = re.compile(r"[0-9A-F]{5}")


class RecordingProvider:
    """Wraps a corpus, recording every prefix asked for (what an online service would see)."""

    def __init__(
        self,
        corpus: dict[str, int],
        *,
        source: Literal["local", "online"] = "online",
        fail_on: set[str] | None = None,
    ) -> None:
        self.source: Literal["local", "online"] = source
        self._inner = MemoryRangeProvider(corpus)
        self.requests: list[str] = []
        self.fail_on = fail_on or set()

    def fetch_range(self, prefix: str) -> dict[str, int]:
        self.requests.append(prefix)
        if prefix in self.fail_on:
            raise BreachLookupError("network")
        return self._inner.fetch_range(prefix)


def _corpus(*passwords: str) -> dict[str, int]:
    return {sha1_hex(pw): 100 + i for i, pw in enumerate(passwords)}


def test_known_and_unknown_passwords_get_breached_and_clean() -> None:
    provider = RecordingProvider(_corpus(CANARY))
    checker = BreachChecker(online=provider)
    breached, clean = checker.check_many([CANARY, OTHER], "online")
    assert (breached.status, breached.count, breached.source) == ("breached", 100, "online")
    assert (clean.status, clean.count) == ("clean", 0)


def test_only_distinct_five_character_prefixes_are_requested() -> None:
    provider = RecordingProvider(_corpus(CANARY))
    BreachChecker(online=provider).check_many([CANARY, OTHER, CANARY, THIRD, OTHER], "online")
    assert sorted(provider.requests) == sorted(
        {split_hash(sha1_hex(p))[0] for p in (CANARY, OTHER, THIRD)}
    )
    assert all(PREFIX.fullmatch(p) for p in provider.requests)
    assert len(provider.requests) == len(set(provider.requests))


def test_nothing_but_prefixes_ever_reaches_a_provider() -> None:
    provider = RecordingProvider(_corpus(CANARY))
    checker = BreachChecker(online=provider)
    checker.check_many([CANARY, OTHER, THIRD], "online")
    seen = " ".join(provider.requests)
    for password in (CANARY, OTHER, THIRD):
        assert password not in seen
        assert sha1_hex(password) not in seen
        assert split_hash(sha1_hex(password))[1] not in seen


def test_results_and_reprs_do_not_contain_the_password_hash_or_prefix() -> None:
    checker = BreachChecker(online=RecordingProvider(_corpus(CANARY)))
    results = checker.check_many([CANARY], "online")
    blob = results[0].model_dump_json() + repr(results) + repr(checker)
    digest = sha1_hex(CANARY)
    for needle in (CANARY, digest, digest[:5], digest[5:], digest[:8]):
        assert needle not in blob


def test_requests_are_sent_in_random_order_not_in_batch_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = RecordingProvider({})
    checker = BreachChecker(online=provider)
    passwords = [f"pw-{i}-Zq7!" for i in range(12)]
    orders = set()
    for _ in range(6):
        provider.requests.clear()
        checker.check_many(passwords, "online")
        orders.add(tuple(provider.requests))
    assert len(orders) > 1  # a fixed order would make the request order reveal the batch order

    # ...and the shuffle really is what decides the order.
    provider.requests.clear()
    checker._shuffle = lambda seq: seq.reverse()  # type: ignore[method-assign,assignment]
    checker._cache = type(checker._cache)(0, 1.0, lambda: 0.0)
    checker.check_many(passwords, "online")
    expected = [split_hash(sha1_hex(p))[0] for p in passwords]
    assert provider.requests == list(dict.fromkeys(expected))[::-1]


def test_a_failing_bucket_makes_only_its_passwords_unavailable() -> None:
    bad_prefix = split_hash(sha1_hex(OTHER))[0]
    provider = RecordingProvider(_corpus(CANARY), fail_on={bad_prefix})
    good, bad = BreachChecker(online=provider).check_many([CANARY, OTHER], "online")
    assert good.status == "breached"
    assert bad.status == "unavailable"
    assert bad.count is None  # unchecked is never reported as a count of zero


def test_unavailable_is_never_reported_as_clean() -> None:
    checker = BreachChecker(online=RecordingProvider({}, fail_on={split_hash(sha1_hex(CANARY))[0]}))
    assert checker.check(CANARY, "online").status == "unavailable"


def test_an_unconfigured_source_raises_a_fixed_error() -> None:
    checker = BreachChecker(local=MemoryRangeProvider({}))
    assert checker.available("local")
    assert not checker.available("online")
    with pytest.raises(BreachLookupError) as caught:
        checker.check(CANARY, "online")
    assert caught.value.reason == "not_configured"
    assert CANARY not in str(caught.value)


def test_online_buckets_are_cached_but_local_files_are_always_read() -> None:
    online = RecordingProvider(_corpus(CANARY))
    checker = BreachChecker(online=online)
    for _ in range(3):
        assert checker.check(CANARY, "online").status == "breached"
    assert len(online.requests) == 1

    local = RecordingProvider(_corpus(CANARY), source="local")
    local_checker = BreachChecker(local=local)
    for _ in range(3):
        local_checker.check(CANARY, "local")
    assert len(local.requests) == 3


def test_cache_entries_expire_and_the_cache_is_bounded() -> None:
    now = [0.0]
    online = RecordingProvider(_corpus(CANARY))
    checker = BreachChecker(online=online, cache_ttl_seconds=60, cache_size=2, clock=lambda: now[0])
    checker.check(CANARY, "online")
    now[0] = 30
    checker.check(CANARY, "online")
    assert len(online.requests) == 1
    now[0] = 61
    checker.check(CANARY, "online")
    assert len(online.requests) == 2

    for pw in (OTHER, THIRD, "fourth-Zq7!"):
        checker.check(pw, "online")
    assert len(checker._cache) <= 2


def test_the_cache_stores_public_buckets_only() -> None:
    checker = BreachChecker(online=RecordingProvider(_corpus(CANARY)))
    checker.check(CANARY, "online")
    stored = repr(checker._cache._items)
    assert CANARY not in stored
    assert sha1_hex(CANARY) not in stored  # the suffix alone is stored, never the whole hash


def test_a_time_budget_and_a_prefix_cap_bound_what_one_call_can_send() -> None:
    now = [0.0]

    class SlowProvider(RecordingProvider):
        def fetch_range(self, prefix: str) -> dict[str, int]:
            now[0] += 10
            return super().fetch_range(prefix)

    passwords = [f"pw-{i}-Zq7!" for i in range(8)]
    slow = SlowProvider({})
    results = BreachChecker(online=slow, clock=lambda: now[0]).check_many(
        passwords, "online", deadline_seconds=25
    )
    assert len(slow.requests) == 3  # clock reads 0, 10, 20 (within 25); at 30 the budget is spent
    assert sum(r.status == "unavailable" for r in results) == 5

    capped = RecordingProvider({})
    results = BreachChecker(online=capped).check_many(passwords, "online", max_prefixes=3)
    assert len(capped.requests) == 3
    assert sum(r.status == "unavailable" for r in results) == 5


def test_concurrent_checks_share_the_cache_safely() -> None:
    checker = BreachChecker(online=RecordingProvider(_corpus(CANARY, OTHER)))
    passwords = [CANARY, OTHER, THIRD] * 10

    def run(_: int) -> list[str]:
        return [r.status for r in checker.check_many(passwords, "online")]

    with ThreadPoolExecutor(8) as pool:
        outcomes = list(pool.map(run, range(16)))
    assert all(o == outcomes[0] for o in outcomes)
    assert outcomes[0][:3] == ["breached", "breached", "clean"]


def test_local_and_memory_lookups_open_no_network_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    checker = BreachChecker(local=MemoryRangeProvider(_corpus(CANARY)))
    assert checker.check(CANARY, "local").status == "breached"
    assert checker.check(OTHER, "local").status == "clean"
    assert checker.check_many([], "local") == []
