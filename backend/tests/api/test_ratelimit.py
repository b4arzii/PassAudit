"""Rate limiting: the token bucket, the middleware, per-password cost, concurrency limits."""

from __future__ import annotations

import asyncio
import json
import threading
import time

import anyio
import pytest
from fastapi.testclient import TestClient

from passaudit.api.errors import ApiError
from passaudit.api.ratelimit import TokenBucketLimiter
from passaudit.api.service import AnalysisService

from .conftest import CANARY, MakeApp, MakeClient, asgi_call, asgi_call_async, make_settings

AUDIT = "/api/v1/audit"
BATCH = "/api/v1/audit/batch"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def acquire(limiter: TokenBucketLimiter, key: str = "a", cost: int = 1):  # type: ignore[no-untyped-def]
    return asyncio.run(limiter.acquire(key, cost))


# ------------------------------------------------------------------------- token bucket


def test_bucket_allows_a_burst_up_to_capacity_then_denies() -> None:
    clock = FakeClock()
    limiter = TokenBucketLimiter(capacity=3, refill_per_second=1, clock=clock)
    decisions = [acquire(limiter) for _ in range(4)]
    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert [d.remaining for d in decisions] == [2, 1, 0, 0]
    assert decisions[0].limit == 3


def test_bucket_refills_over_time() -> None:
    clock = FakeClock()
    limiter = TokenBucketLimiter(capacity=2, refill_per_second=1, clock=clock)
    assert acquire(limiter).allowed
    assert acquire(limiter).allowed
    assert not acquire(limiter).allowed
    clock.now += 1
    assert acquire(limiter).allowed
    assert not acquire(limiter).allowed
    clock.now += 100  # never exceeds capacity
    assert acquire(limiter).remaining == 1


def test_retry_after_and_reset_after() -> None:
    clock = FakeClock()
    limiter = TokenBucketLimiter(capacity=5, refill_per_second=0.5, clock=clock)
    acquire(limiter, cost=5)
    denied = acquire(limiter, cost=1)
    assert denied.allowed is False
    assert denied.retry_after == 2  # one token at 0.5/s
    assert denied.reset_after == 10  # five tokens at 0.5/s
    clock.now += denied.retry_after
    assert acquire(limiter).allowed


def test_denied_requests_do_not_consume_tokens() -> None:
    clock = FakeClock()
    limiter = TokenBucketLimiter(capacity=2, refill_per_second=1, clock=clock)
    acquire(limiter, cost=2)
    for _ in range(50):
        assert not acquire(limiter).allowed
    clock.now += 1
    assert acquire(limiter).allowed  # exactly one second of refill was enough


def test_cost_is_charged_in_units() -> None:
    limiter = TokenBucketLimiter(capacity=10, refill_per_second=1, clock=FakeClock())
    assert acquire(limiter, cost=7).remaining == 3
    assert not acquire(limiter, cost=4).allowed  # 3 left, 4 needed
    assert acquire(limiter, cost=3).allowed


def test_cost_above_capacity_can_never_succeed() -> None:
    decision = acquire(
        TokenBucketLimiter(capacity=5, refill_per_second=1, clock=FakeClock()), cost=6
    )
    assert decision.allowed is False
    assert decision.retry_after >= 1


def test_keys_are_independent() -> None:
    limiter = TokenBucketLimiter(capacity=1, refill_per_second=0.001, clock=FakeClock())
    assert acquire(limiter, "alice").allowed
    assert not acquire(limiter, "alice").allowed
    assert acquire(limiter, "bob").allowed


def test_memory_is_bounded() -> None:
    clock = FakeClock()
    limiter = TokenBucketLimiter(capacity=2, refill_per_second=1, max_keys=100, clock=clock)
    for i in range(1000):
        acquire(limiter, f"client-{i}")
    assert len(limiter) <= 100


def test_idle_buckets_are_evicted_before_active_ones() -> None:
    clock = FakeClock()
    limiter = TokenBucketLimiter(capacity=2, refill_per_second=1, max_keys=3, clock=clock)
    for key in ("idle1", "idle2", "idle3"):
        acquire(limiter, key)
    clock.now += 60  # they are all fully refilled (idle) now
    acquire(limiter, "active", cost=2)  # drains
    acquire(limiter, "new")  # pushes over max_keys: idle ones go first
    assert not acquire(limiter, "active").allowed  # the drained bucket survived


@pytest.mark.parametrize(
    "kwargs",
    [{"capacity": 0, "refill_per_second": 1}, {"capacity": 1, "refill_per_second": 0},
     {"capacity": 1, "refill_per_second": 1, "max_keys": 0}],
)  # fmt: skip
def test_invalid_limiter_parameters(kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        TokenBucketLimiter(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- middleware


def test_requests_beyond_the_burst_get_429_with_retry_after(make_client: MakeClient) -> None:
    client = make_client(rate_limit_burst=3, rate_limit_per_minute=60, batch_max_items=3)
    statuses = [client.post(AUDIT, json={"password": CANARY}).status_code for _ in range(5)]
    assert statuses == [200, 200, 200, 429, 429]
    denied = client.post(AUDIT, json={"password": CANARY})
    assert denied.status_code == 429
    error = denied.json()["error"]
    assert error["code"] == "rate_limited"
    assert error["request_id"] == denied.headers["x-request-id"]
    assert int(denied.headers["retry-after"]) >= 1
    assert f"{denied.headers['retry-after']} seconds" in error["message"]
    assert denied.headers["x-ratelimit-limit"] == "3"
    assert denied.headers["x-ratelimit-remaining"] == "0"
    assert CANARY not in denied.text


def test_rate_limit_headers_on_successful_responses(make_client: MakeClient) -> None:
    client = make_client(rate_limit_burst=10, rate_limit_per_minute=60, batch_max_items=5)
    first = client.post(AUDIT, json={"password": CANARY})
    second = client.post(AUDIT, json={"password": CANARY})
    assert first.headers["x-ratelimit-limit"] == "10"
    assert (first.headers["x-ratelimit-remaining"], second.headers["x-ratelimit-remaining"]) == (
        "9",
        "8",
    )
    assert int(first.headers["x-ratelimit-reset"]) >= 1


def test_invalid_requests_are_charged_too(make_client: MakeClient) -> None:
    client = make_client(rate_limit_burst=2, rate_limit_per_minute=60, batch_max_items=2)
    assert client.post(AUDIT, json={}).status_code == 422
    assert client.post(AUDIT, content="x").status_code == 415
    assert client.post(AUDIT, json={"password": CANARY}).status_code == 429


def test_health_docs_and_preflight_are_exempt(make_client: MakeClient) -> None:
    client = make_client(rate_limit_burst=1, rate_limit_per_minute=1, batch_max_items=1)
    client.post(AUDIT, json={"password": CANARY})
    assert client.post(AUDIT, json={"password": CANARY}).status_code == 429
    for _ in range(5):
        assert client.get("/api/v1/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    preflight = client.options(
        AUDIT, headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"}
    )
    assert preflight.status_code == 200
    assert "x-ratelimit-limit" not in client.get("/api/v1/health").headers


def test_limits_endpoint_is_rate_limited_but_policy_default_too(make_client: MakeClient) -> None:
    client = make_client(rate_limit_burst=1, rate_limit_per_minute=1, batch_max_items=1)
    assert client.get("/api/v1/limits").status_code == 200
    assert client.get("/api/v1/policy/default").status_code == 429


def test_rate_limiting_can_be_disabled(make_client: MakeClient) -> None:
    client = make_client(
        rate_limit_enabled=False, rate_limit_burst=1, rate_limit_per_minute=1, batch_max_items=1
    )
    for _ in range(20):
        response = client.post(AUDIT, json={"password": CANARY})
        assert response.status_code == 200
    assert "x-ratelimit-limit" not in response.headers


def test_each_client_address_has_its_own_bucket(make_app: MakeApp) -> None:
    app = make_app(rate_limit_burst=1, rate_limit_per_minute=1, batch_max_items=1)
    body = json.dumps({"password": CANARY}).encode()
    call = lambda addr: asgi_call(app, chunks=[body], client_addr=addr)[0]  # noqa: E731
    assert call(("198.51.100.1", 1)) == 200
    assert call(("198.51.100.1", 2)) == 429  # same host, different port: same bucket
    assert call(("198.51.100.2", 1)) == 200  # another host: fresh bucket
    assert asgi_call(app, chunks=[body], client_addr=None)[0] == 200  # unknown peer: own bucket


def test_x_forwarded_for_cannot_be_used_to_dodge_the_limit(make_app: MakeApp) -> None:
    app = make_app(rate_limit_burst=1, rate_limit_per_minute=1, batch_max_items=1)
    body = json.dumps({"password": CANARY}).encode()
    codes = [
        asgi_call(
            app,
            chunks=[body],
            headers=[("content-type", "application/json"), ("x-forwarded-for", f"10.9.9.{i}")],
        )[0]
        for i in range(3)
    ]
    assert codes == [200, 429, 429]


# ------------------------------------------------------------------------ batch cost


def test_batch_costs_one_unit_per_password(make_client: MakeClient) -> None:
    client = make_client(rate_limit_burst=10, rate_limit_per_minute=60, batch_max_items=10)
    payload = {"items": [{"password": f"{CANARY}{i}"} for i in range(5)]}
    first = client.post(BATCH, json=payload)
    assert first.status_code == 200
    assert first.headers["x-ratelimit-remaining"] == "5"  # 10 - 5, not 10 - 1
    second = client.post(BATCH, json=payload)
    assert second.status_code == 200
    assert second.headers["x-ratelimit-remaining"] == "0"
    third = client.post(BATCH, json={"items": [{"password": CANARY}]})
    assert third.status_code == 429


def test_batch_that_cannot_be_paid_for_is_refused_before_analysis(
    make_client: MakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = make_client(rate_limit_burst=10, rate_limit_per_minute=60, batch_max_items=10)
    analysed: list[int] = []
    original = AnalysisService.audit_batch

    async def spy(self: AnalysisService, request):  # type: ignore[no-untyped-def]
        analysed.append(len(request.items))
        return await original(self, request)

    monkeypatch.setattr(AnalysisService, "audit_batch", spy)
    assert client.post(AUDIT, json={"password": CANARY}).status_code == 200  # 9 tokens left
    big = {"items": [{"password": f"{CANARY}{i}"} for i in range(10)]}
    response = client.post(BATCH, json=big)  # needs 10, has 9 after the middleware's unit
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert int(response.headers["retry-after"]) >= 1
    assert analysed == []


def test_oversized_batch_is_refused_before_it_is_charged(make_client: MakeClient) -> None:
    client = make_client(rate_limit_burst=10, rate_limit_per_minute=60, batch_max_items=3)
    too_big = {"items": [{"password": f"{CANARY}{i}"} for i in range(4)]}
    response = client.post(BATCH, json=too_big)
    assert response.status_code == 422
    assert response.headers["x-ratelimit-remaining"] == "9"  # only the middleware's unit


# --------------------------------------------------------------- concurrency limit


def test_busy_server_returns_503_after_the_queue_timeout() -> None:
    settings = make_settings(max_concurrent_analyses=1, analysis_queue_timeout_seconds=0.05)
    service = AnalysisService(settings)
    release = threading.Event()

    def slow() -> str:
        release.wait(5)
        return "done"

    async def scenario() -> None:
        async with anyio.create_task_group() as tg:
            results: list[str] = []

            async def hold() -> None:
                results.append(await service._run(slow))

            tg.start_soon(hold)
            await anyio.sleep(0.05)  # let the first job take the only slot
            with pytest.raises(ApiError) as busy:
                await service._run(lambda: "never")
            assert busy.value.status_code == 503
            assert busy.value.code == "server_busy"
            assert busy.value.headers == {"Retry-After": "2"}
            release.set()
        assert results == ["done"]

    anyio.run(scenario)


def test_slots_are_released_after_use_and_after_errors() -> None:
    service = AnalysisService(
        make_settings(max_concurrent_analyses=1, analysis_queue_timeout_seconds=0.2)
    )

    def fail() -> None:
        raise RuntimeError("boom")

    async def scenario() -> None:
        with pytest.raises(RuntimeError):
            await service._run(fail)
        assert await service._run(lambda: 42) == 42  # the slot came back
        assert await service._run(lambda: 43) == 43

    anyio.run(scenario)


def test_concurrent_requests_share_the_analysis_slots_without_deadlock(make_app: MakeApp) -> None:
    app = make_app(max_concurrent_analyses=2, rate_limit_enabled=False)

    async def scenario() -> list[int]:
        results: list[int] = []

        async def one(i: int) -> None:
            body = json.dumps({"password": f"{CANARY}{i}"}).encode()
            status, _, _ = await asgi_call_async(app, chunks=[body])
            results.append(status)

        async with anyio.create_task_group() as tg:
            for i in range(8):
                tg.start_soon(one, i)
        return results

    started = time.perf_counter()
    assert anyio.run(scenario) == [200] * 8
    assert time.perf_counter() - started < 30


def test_unused_client_fixture_is_still_valid(client: TestClient) -> None:
    assert client.get("/api/v1/health").status_code == 200
