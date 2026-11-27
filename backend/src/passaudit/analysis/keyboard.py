"""Keyboard-walk detection.

Keys are placed on a coordinate grid that mimics the physical stagger of each layout. A
*run* is a straight line of physically adjacent keys: along a row, or down/up the same
diagonal (``"asdf"``, ``"zxcv"``, ``"1qaz"``, ``"zaq1"``). Shifted characters count as their
base key, so ``"!QAZ"`` matches ``"1qaz"``.

Limitations (see docs/analysis-engine.md): walks that change direction (``"qazwsx"``) are not
reported here, although zxcvbn's own spatial matcher accounts for them in the guessability
estimate; only the layouts listed in ``LAYOUTS`` are known.
"""

from __future__ import annotations

from dataclasses import dataclass

from passaudit.analysis.patterns import is_simple_sequence
from passaudit.analysis.text import Span, fold

# US-layout shifted characters -> base key.
_SHIFTED = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8",
    "(": "9", ")": "0", "_": "-", "+": "=", "{": "[", "}": "]", "|": "\\", ":": ";",
    '"': "'", "<": ",", ">": ".", "?": "/", "~": "`",
}  # fmt: skip


@dataclass(frozen=True, slots=True)
class Layout:
    """A keyboard geometry: rows of base keys plus each row's x offset (in key widths)."""

    name: str
    rows: tuple[str, ...]
    offsets: tuple[float, ...]
    staggered: bool  # True: rows offset like a typewriter; False: a square grid (keypad)

    def positions(self) -> dict[str, tuple[float, int]]:
        table: dict[str, tuple[float, int]] = {}
        for y, (row, offset) in enumerate(zip(self.rows, self.offsets, strict=True)):
            for x, key in enumerate(row):
                table.setdefault(key, (offset + x, y))
        return table


_STAGGER = (0.0, 1.5, 1.75, 2.25)

LAYOUTS: tuple[Layout, ...] = (
    Layout(
        "qwerty",
        ("`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"),
        _STAGGER,
        staggered=True,
    ),
    Layout(
        "qwertz",
        ("`1234567890-=", "qwertzuiop[]\\", "asdfghjkl;'", "yxcvbnm,./"),
        _STAGGER,
        staggered=True,
    ),
    Layout(
        "azerty",
        ("`1234567890-=", "azertyuiop[]\\", "qsdfghjklm'", "wxcvbn,;:/"),
        _STAGGER,
        staggered=True,
    ),
    Layout(
        "dvorak",
        ("`1234567890[]", "',.pyfgcrl/=\\", "aoeuidhtns-", ";qjkxbmwvz"),
        _STAGGER,
        staggered=True,
    ),
    Layout("keypad", ("789", "456", "123", "0"), (0.0, 0.0, 0.0, 0.0), staggered=False),
)


@dataclass(frozen=True, slots=True)
class KeyboardMatch:
    span: Span
    layout: str


def _base_key(ch: str) -> str:
    folded = fold(ch)
    return _SHIFTED.get(folded, folded)


def _direction(
    a: tuple[float, int], b: tuple[float, int], *, staggered: bool
) -> tuple[int, int] | None:
    """Direction from key ``a`` to adjacent key ``b``, or ``None`` if not adjacent."""
    dx = b[0] - a[0]
    dy = b[1] - a[1]
    if dy == 0:
        return (0, 1 if dx > 0 else -1) if abs(dx) == 1 else None
    if abs(dy) != 1:
        return None
    reach = abs(dx) < 1 if staggered else abs(dx) <= 1
    if not reach:
        return None
    sign = 0 if dx == 0 else (1 if dx > 0 else -1)
    return (dy, sign)


def _runs_for_layout(password: str, layout: Layout, min_length: int) -> list[KeyboardMatch]:
    table = layout.positions()
    keys = [table.get(_base_key(ch)) for ch in password]
    n = len(keys)
    found: list[KeyboardMatch] = []
    i = 0
    while i < n - 1:
        a, b = keys[i], keys[i + 1]
        direction = _direction(a, b, staggered=layout.staggered) if a and b else None
        if direction is None:
            i += 1
            continue
        j = i + 1
        while j + 1 < n:
            c, d = keys[j], keys[j + 1]
            if not (c and d) or _direction(c, d, staggered=layout.staggered) != direction:
                break
            j += 1
        length = j - i + 1
        if length >= min_length and not is_simple_sequence(password[i : j + 1]):
            found.append(KeyboardMatch(Span(i, length), layout.name))
        i = j
    return found


def _adjacent(a: tuple[float, int], b: tuple[float, int], *, staggered: bool) -> bool:
    """True if two distinct keys touch (same row neighbours, or neighbours one row up/down)."""
    dy = b[1] - a[1]
    dx = abs(b[0] - a[0])
    if dy == 0:
        return dx == 1
    if abs(dy) != 1:
        return False
    return dx < 1 if staggered else dx <= 1


def _walks_for_layout(password: str, layout: Layout, min_length: int) -> list[KeyboardMatch]:
    table = layout.positions()
    keys = [table.get(_base_key(ch)) for ch in password]
    n = len(keys)
    found: list[KeyboardMatch] = []
    i = 0
    while i < n - 1:
        a, b = keys[i], keys[i + 1]
        if not (a and b and _adjacent(a, b, staggered=layout.staggered)):
            i += 1
            continue
        j = i + 1
        while j + 1 < n:
            c, d = keys[j], keys[j + 1]
            if not (c and d and _adjacent(c, d, staggered=layout.staggered)):
                break
            j += 1
        if j - i + 1 >= min_length:
            found.append(KeyboardMatch(Span(i, j - i + 1), layout.name))
        i = j
    return found


def find_keyboard_walks(password: str, *, min_length: int = 5) -> list[KeyboardMatch]:
    """Find paths of physically adjacent keys, including ones that change direction.

    ``find_keyboard_runs`` only reports straight lines (``"asdf"``). Real keyboard patterns
    often bend (``"zaq12wsx"``, ``"qweasd"`` is two lines, ``"poiuytrew"`` is one): every pair
    of neighbours in the chain is adjacent, but the direction may change. The default minimum
    is 5 keys because bends make chance matches in random text more likely than for lines;
    the numeric keypad is excluded for the same reason (only straight lines count there).
    """
    if min_length < 3:
        raise ValueError("min_length must be at least 3")
    candidates: list[tuple[int, KeyboardMatch]] = []
    for order, layout in enumerate(LAYOUTS):
        if not layout.staggered:
            continue  # on a keypad most digit strings are "adjacent": only straight lines count
        candidates.extend((order, m) for m in _walks_for_layout(password, layout, min_length))
    candidates.sort(key=lambda c: (-c[1].span.length, c[0], c[1].span.start))
    accepted: list[KeyboardMatch] = []
    for _, match in candidates:
        if all(match.span.overlap(a.span) < 2 for a in accepted):
            accepted.append(match)
    accepted.sort(key=lambda m: m.span.start)
    return accepted


def find_keyboard_runs(password: str, *, min_length: int = 4) -> list[KeyboardMatch]:
    """Find straight-line keyboard walks of at least ``min_length`` keys.

    When several layouts match the same characters (``"asdf"`` is valid on QWERTY and
    QWERTZ) only the first layout is reported. Runs that are plain letter/digit sequences
    (``"1234"``) are left to the sequence detector.
    """
    if min_length < 2:
        raise ValueError("min_length must be at least 2")
    candidates: list[tuple[int, KeyboardMatch]] = []
    for order, layout in enumerate(LAYOUTS):
        candidates.extend((order, m) for m in _runs_for_layout(password, layout, min_length))
    candidates.sort(key=lambda c: (-c[1].span.length, c[0], c[1].span.start))
    accepted: list[KeyboardMatch] = []
    for _, match in candidates:
        # Adjacent runs may share one pivot key; any larger overlap is a duplicate.
        if all(match.span.overlap(a.span) < 2 for a in accepted):
            accepted.append(match)
    accepted.sort(key=lambda m: m.span.start)
    return accepted
