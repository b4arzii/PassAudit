"""Phase 9: seeded mutation fuzzing of every POST route.

Valid request bodies are mutated (types swapped, values replaced by extreme or hostile ones,
keys dropped or added, JSON truncated). Whatever is sent, the server must answer with a
documented client error or success - never a 5xx - and must never echo the password or a
personal detail. The seed is fixed so a failure is reproducible.
"""

from __future__ import annotations

import copy
import json
import os
import random
from typing import Any

import pytest
from fastapi.testclient import TestClient

from passaudit.main import create_app

from .conftest import CANARY, JSON, PERSONAL, MakeClient, make_settings

ROUTES = {
    "/api/v1/audit": {
        "password": CANARY,
        "policy": {"min_length": 12, "min_strength_score": 2, "block_common_passwords": True},
        "context": {
            "usage": "online_account",
            "personal_info": [PERSONAL],
            "reused_elsewhere": False,
        },
        "exposure": {"breach": "off", "reuse": False},
    },
    "/api/v1/policy/validate": {
        "password": CANARY,
        "profile": "default",
        "context": {"personal_info": [PERSONAL]},
    },
    "/api/v1/audit/batch": {
        "items": [{"id": "a", "password": CANARY}, {"id": "b", "password": "second-pass-1"}],
        "policy": {"min_length": 10},
        "context": {"personal_info": [PERSONAL]},
        "detail": "summary",
    },
    "/api/v1/audit/report": {
        "items": [{"id": "a", "password": CANARY}],
        "profile": "enterprise",
        "context": {"personal_info": [PERSONAL]},
    },
}

HOSTILE: list[Any] = [
    None,
    True,
    False,
    0,
    -1,
    2**70,
    -(2**70),
    1e308,
    -0.0,
    "",
    " ",
    "\x00",
    "\ud800",  # a lone surrogate
    chr(0x202E) + chr(0x200B),  # right-to-left override + zero-width space
    "x" * 5000,
    "../../etc/passwd",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "${jndi:ldap://x}",
    [],
    [None],
    [[[[[]]]]],
    {},
    {"a": 1},
    {"__proto__": {"x": 1}},
    {"password": "nested-not-the-field-1"},
    [{"password": "q"}] * 60,
    "off",
    "online",
]
# Raise for a deep one-off run: PASSAUDIT_FUZZ_ITERATIONS=5000 pytest backend/tests/api/test_fuzz.py
SEEDS = int(os.environ.get("PASSAUDIT_FUZZ_ITERATIONS", "150"))


def _paths(node: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    out: list[tuple[Any, ...]] = [prefix] if prefix else []
    if isinstance(node, dict):
        for key, value in node.items():
            out += _paths(value, (*prefix, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            out += _paths(value, (*prefix, index))
    return out


def _set(root: Any, path: tuple[Any, ...], value: Any) -> None:
    node = root
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value


def _drop(root: Any, path: tuple[Any, ...]) -> None:
    node = root
    for part in path[:-1]:
        node = node[part]
    if isinstance(node, dict):
        node.pop(path[-1], None)
    else:
        node.pop(path[-1])


def mutate(rng: random.Random, template: dict[str, Any]) -> Any:
    body = json.loads(json.dumps(template))
    for _ in range(rng.randint(1, 3)):
        paths = _paths(body)
        if not paths:
            break
        path = rng.choice(paths)
        action = rng.choice(["replace", "replace", "drop", "extra", "swap_root"])
        if action == "replace":
            _set(body, path, copy.deepcopy(rng.choice(HOSTILE)))
        elif action == "drop":
            _drop(body, path)
        elif action == "extra":
            key = rng.choice(["x", "password2", "__class__", "$where"])
            body[key] = copy.deepcopy(rng.choice(HOSTILE))
        else:
            return copy.deepcopy(rng.choice(HOSTILE))  # the whole body is the wrong type
    return body


def _send(client: TestClient, route: str, rng: random.Random, template: dict[str, Any]) -> Any:
    body = mutate(rng, template)
    raw = json.dumps(body, allow_nan=True, ensure_ascii=rng.random() < 0.5).encode(
        "utf-8", "surrogatepass"
    )
    if rng.random() < 0.15:
        raw = raw[: rng.randint(0, max(0, len(raw) - 1))]  # truncated JSON
    return client.post(route, content=raw, headers=JSON)


@pytest.fixture(scope="module")
def fuzz_client(make_client_module: MakeClient) -> TestClient:
    return make_client_module(rate_limit_enabled=False, rate_limit_burst=1000)


@pytest.fixture(scope="module")
def make_client_module() -> MakeClient:
    def _make(**overrides: Any) -> TestClient:
        return TestClient(create_app(make_settings(**overrides)), raise_server_exceptions=False)

    return _make


@pytest.mark.parametrize("route", list(ROUTES))
def test_mutated_requests_never_cause_a_server_error_or_leak(
    fuzz_client: TestClient, route: str
) -> None:
    rng = random.Random(f"passaudit-phase9-{route}")  # noqa: S311 - reproducible test data
    seen: dict[int, int] = {}
    for _ in range(SEEDS):
        response = _send(fuzz_client, route, rng, ROUTES[route])
        seen[response.status_code] = seen.get(response.status_code, 0) + 1
        assert response.status_code < 500, (route, response.status_code, response.text[:200])
        assert CANARY not in response.text
        assert PERSONAL not in response.text
        if response.status_code >= 400:
            assert set(response.json()) == {"error"}, response.text[:200]
    # The fuzzer must exercise both outcomes, or it is not testing anything.
    assert 200 in seen, seen
    assert any(code in seen for code in (400, 422)), seen
