"""Guessability estimation via zxcvbn.

zxcvbn (the Python port, ``zxcvbn`` 4.5.x) has three behaviours that matter for a tool that
handles secrets, and this adapter neutralises each of them:

1. **Global state.** ``zxcvbn()`` stores the caller's ``user_inputs`` in the module-level dict
   ``zxcvbn.matching.RANKED_DICTIONARIES['user_inputs']`` and never clears it. That would keep
   personal data in memory after the call and leak it into concurrent calls. Calls are
   serialised with a lock and the entry is removed in a ``finally`` block.
2. **Unbounded cost.** Run time grows super-linearly with length (over 6 s at 256 characters)
   and, through its leetspeak matcher, with the number of leet symbols (about 2.5 s at 100
   characters of ``4@({[<69!|1$5+7``). Only the first ``max_chars`` characters are analysed,
   fewer for symbol-dense input; the result is flagged ``truncated`` and is then a lower bound.
3. **Empty input.** zxcvbn raises ``IndexError`` on ``""``; empty passwords are scored here.
"""

from __future__ import annotations

import math
import threading
from typing import TYPE_CHECKING, Any

from zxcvbn import matching, zxcvbn

from passaudit.analysis.models import (
    CrackTimeEstimates,
    StrengthEstimate,
    StrengthLabel,
    StrengthSegment,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

_LOCK = threading.Lock()
_MAX_LOG10 = 1000.0  # clamp so absurdly long inputs can never yield inf/nan
# Work budget for the leet search: (readings of the leet symbols) x (characters). Ordinary text
# has one reading, so it keeps the full ``max_chars``; at ~50 microseconds per unit the budget
# is about 0.4 s. The floor keeps short passwords fully analysed whatever their symbols.
_WORK_BUDGET = 8_000
_MIN_ANALYSED_CHARS = 32

_LABELS = (
    StrengthLabel.VERY_WEAK,
    StrengthLabel.WEAK,
    StrengthLabel.FAIR,
    StrengthLabel.STRONG,
    StrengthLabel.VERY_STRONG,
)

_INSTANT = "less than a second"
_EMPTY = StrengthEstimate(
    score=0,
    label=StrengthLabel.VERY_WEAK,
    guesses_log10=0.0,
    crack_times=CrackTimeEstimates(
        online_throttled=_INSTANT,
        online_unthrottled=_INSTANT,
        offline_slow_hash=_INSTANT,
        offline_fast_hash=_INSTANT,
    ),
    segments=(),
    warning="",
    suggestions=(),
    truncated=False,
    analyzed_length=0,
)


def _segment(raw: dict[str, Any]) -> StrengthSegment:
    start = int(raw["i"])
    end = int(raw["j"])
    log10 = float(raw.get("guesses_log10", 0.0))
    return StrengthSegment(
        pattern=str(raw["pattern"]),
        start=start,
        length=end - start + 1,
        guesses_log10=min(max(log10, 0.0), _MAX_LOG10) if math.isfinite(log10) else _MAX_LOG10,
        dictionary=str(raw["dictionary_name"]) if raw.get("dictionary_name") else None,
        l33t=bool(raw.get("l33t", False)),
        reversed=bool(raw.get("reversed", False)),
    )


def _affordable_chars(password: str, max_chars: int) -> int:
    """How many leading characters can be analysed within the work budget.

    zxcvbn's l33t matcher re-runs its dictionary search once per way of reading the leet
    symbols in the password, so symbol-dense input is far costlier than plain text of the
    same length (measured: about 2.5 s for 100 characters built from ``4@({[<69!|1$5+7``,
    against well under 0.1 s for ordinary text). The number of readings is bounded by the
    product of the candidate symbols per letter; the work is roughly that times the length.
    """
    readings = 1
    for symbols in matching.relevant_l33t_subtable(
        password[:max_chars], matching.L33T_TABLE
    ).values():
        readings *= len(symbols)
    return min(max_chars, max(_MIN_ANALYSED_CHARS, _WORK_BUDGET // readings))


def estimate_strength(
    password: str, personal_tokens: Sequence[str] = (), *, max_chars: int = 100
) -> StrengthEstimate:
    """Estimate guessability of ``password``.

    At most ``max_chars`` characters are analysed, fewer when the password is so full of leet
    symbols that the search would be expensive (see ``_affordable_chars``). Either way the
    result is flagged ``truncated`` and is a lower bound.
    """
    if not password:
        return _EMPTY
    sample = password[: _affordable_chars(password, max_chars)]
    with _LOCK:
        try:
            raw = zxcvbn(sample, user_inputs=list(personal_tokens), max_length=len(sample))
        finally:
            matching.RANKED_DICTIONARIES.pop("user_inputs", None)

    log10 = float(raw["guesses_log10"])
    if not math.isfinite(log10):
        log10 = _MAX_LOG10
    score = int(raw["score"])
    times = raw["crack_times_display"]
    feedback = raw["feedback"]
    return StrengthEstimate(
        score=score,
        label=_LABELS[score],
        guesses_log10=min(max(log10, 0.0), _MAX_LOG10),
        crack_times=CrackTimeEstimates(
            online_throttled=str(times["online_throttling_100_per_hour"]),
            online_unthrottled=str(times["online_no_throttling_10_per_second"]),
            offline_slow_hash=str(times["offline_slow_hashing_1e4_per_second"]),
            offline_fast_hash=str(times["offline_fast_hashing_1e10_per_second"]),
        ),
        segments=tuple(_segment(m) for m in raw["sequence"]),
        warning=str(feedback.get("warning") or ""),
        suggestions=tuple(str(s) for s in feedback.get("suggestions", [])),
        truncated=len(sample) < len(password),
        analyzed_length=len(sample),
    )
