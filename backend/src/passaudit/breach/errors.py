"""Errors of the breach package. Messages are fixed text: they never include a password, a hash,
a prefix or a URL."""

from __future__ import annotations

from typing import Literal

BreachReason = Literal[
    "network",  # could not connect / TLS failure / DNS
    "timeout",
    "bad_response",  # non-200 status, redirect, malformed body
    "too_large",  # response exceeded the size cap
    "not_configured",  # the requested source does not exist on this server
    "unreadable",  # a local corpus could not be read
]

_MESSAGES: dict[str, str] = {
    "network": "The breach service could not be reached.",
    "timeout": "The breach service did not answer in time.",
    "bad_response": "The breach service sent an unexpected response.",
    "too_large": "The breach service response was larger than the allowed size.",
    "not_configured": "That breach-check source is not configured.",
    "unreadable": "The local breach corpus could not be read.",
}


class BreachLookupError(Exception):
    """A breach lookup failed. ``reason`` is machine-readable; the message is fixed text."""

    def __init__(self, reason: BreachReason) -> None:
        super().__init__(_MESSAGES[reason])
        self.reason: BreachReason = reason
