"""Helpers for auditing many passwords at once, shared by every front end.

* label sanitising and redaction (a label must never reveal the password it describes),
* detection of passwords that occur more than once in the batch, **without keeping them**:
  :class:`ReuseTracker` stores only HMAC digests under a random per-run key, so a crash dump
  or a stray reference to the tracker does not hold a list of plaintext passwords,
* :func:`analyze_batch`, which analyses a list with the right "reused" context per entry.
"""

from __future__ import annotations

import hmac
import secrets
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from passaudit.analysis.models import AnalysisContext, AnalysisRequest, PasswordPolicy

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from pydantic import SecretStr

    from passaudit.analysis.analyzer import PasswordAnalyzer
    from passaudit.analysis.models import ExposureSignals, PasswordAnalysis

MAX_LABEL_LENGTH = 64
REDACTED_LABEL = "[redacted]"


def sanitize_label(raw: str | None) -> str | None:
    """Make a caller-supplied label safe to print and store: printable, short, single line."""
    if raw is None:
        return None
    cleaned = "".join(ch if ch.isprintable() else " " for ch in raw).strip()
    if not cleaned:
        return None
    return cleaned[:MAX_LABEL_LENGTH]


def safe_label(label: str | None, password: str) -> str | None:
    """Sanitise ``label`` and replace it if it would reveal ``password``."""
    cleaned = sanitize_label(label)
    if cleaned is None:
        return None
    if password and (cleaned == password or (len(password) >= 3 and password in cleaned)):
        return REDACTED_LABEL
    return cleaned


class ReuseTracker:
    """Counts how often each password occurs, storing only keyed digests.

    The key is random, lives only in this object, and is never written anywhere, so the digests
    are useless outside the process: they cannot be compared with another run's, looked up in
    a rainbow table, or brute-forced without the key. ``repr`` shows nothing.
    """

    __slots__ = ("_counts", "_key")

    def __init__(self, passwords: Iterable[str] = ()) -> None:
        self._key = secrets.token_bytes(32)
        self._counts: Counter[bytes] = Counter()
        for password in passwords:
            self.add(password)

    def _digest(self, password: str) -> bytes:
        return hmac.new(self._key, password.encode("utf-8", "surrogatepass"), "sha256").digest()

    def add(self, password: str) -> None:
        self._counts[self._digest(password)] += 1

    def is_reused(self, password: str) -> bool:
        """True if ``password`` was added more than once."""
        return self._counts.get(self._digest(password), 0) > 1

    def reused_count(self) -> int:
        """How many distinct passwords occur more than once."""
        return sum(1 for n in self._counts.values() if n > 1)

    def clear(self) -> None:
        self._counts.clear()

    def __repr__(self) -> str:
        return f"ReuseTracker(distinct={len(self._counts)})"


@dataclass(frozen=True, slots=True)
class BatchItemResult:
    """One analysed entry. Holds the (password-free) analysis, never the password."""

    index: int  # 1-based position in the request
    label: str | None
    reused_in_batch: bool
    analysis: PasswordAnalysis


def analyze_batch(
    analyzer: PasswordAnalyzer,
    entries: Sequence[tuple[str | None, SecretStr]],
    policy: PasswordPolicy,
    context: AnalysisContext,
    exposures: Sequence[ExposureSignals | None] | None = None,
) -> list[BatchItemResult]:
    """Analyse ``(label, password)`` pairs in order.

    Identical passwords within the batch are flagged and analysed with
    ``reused_elsewhere=True``. ``exposures`` (same length as ``entries``) carries the results of
    opt-in breach/reuse lookups the caller already ran. Raises ``PasswordTooLongError``
    (content-free) if any password exceeds the analyzer's input limit.
    """
    if exposures is not None and len(exposures) != len(entries):
        raise ValueError("exposures must have one item per entry")
    tracker = ReuseTracker(password.get_secret_value() for _, password in entries)
    results: list[BatchItemResult] = []
    for position, (label, password) in enumerate(entries, 1):
        plain = password.get_secret_value()
        is_reused = tracker.is_reused(plain)
        entry_context = context.model_copy(
            update={"reused_elsewhere": context.reused_elsewhere or is_reused}
        )
        analysis = analyzer.analyze(
            AnalysisRequest(password=password, policy=policy, context=entry_context),
            exposure=exposures[position - 1] if exposures is not None else None,
        )
        results.append(
            BatchItemResult(
                index=position,
                label=safe_label(label, plain),
                reused_in_batch=is_reused,
                analysis=analysis,
            )
        )
    tracker.clear()
    return results
