"""Detection of personal information (name, username, e-mail, ...) inside a password."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from passaudit.analysis.text import Span, deleet_variants, fold, merge_spans

if TYPE_CHECKING:
    from collections.abc import Iterable

MIN_TOKEN_LENGTH = 3
_SPLIT = re.compile(r"[\W_]+")
# Fragments of e-mail addresses / URLs that are not personal and would only add noise.
_STOP_TOKENS = frozenset({"com", "net", "org", "edu", "gov", "www", "http", "https", "mail"})


def extract_tokens(values: Iterable[str]) -> tuple[str, ...]:
    """Turn raw personal strings into distinct, case-folded search tokens.

    For each value the whole value (spaces and punctuation removed) and each alphanumeric
    fragment of at least ``MIN_TOKEN_LENGTH`` characters become tokens, so
    ``"jane.doe@example.com"`` yields ``janedoeexamplecom``, ``jane``, ``doe`` and ``example``.
    """
    tokens: dict[str, None] = {}
    for value in values:
        folded = fold(value.strip())
        if not folded:
            continue
        joined = _SPLIT.sub("", folded)
        candidates = [joined, *(part for part in _SPLIT.split(folded) if part)]
        for token in candidates:
            if len(token) >= MIN_TOKEN_LENGTH and token not in _STOP_TOKENS:
                tokens[token] = None
    return tuple(tokens)


def _occurrences(haystack: str, needle: str) -> list[Span]:
    spans: list[Span] = []
    start = haystack.find(needle)
    while start != -1:
        spans.append(Span(start, len(needle)))
        start = haystack.find(needle, start + 1)
    return spans


def find_personal_info(password: str, tokens: Iterable[str]) -> list[Span]:
    """Return merged spans of ``password`` that contain any token.

    Tokens are searched forwards, reversed, and through de-leeted readings of the password
    (``"j4n3"`` finds ``jane``). Spans only - the token text is never returned.
    """
    text = fold(password)
    readings = [text, *deleet_variants(text, limit=8)]
    spans: list[Span] = []
    for token in tokens:
        for needle in dict.fromkeys((token, token[::-1])):
            for reading in readings:
                spans.extend(_occurrences(reading, needle))
    return merge_spans(spans)
