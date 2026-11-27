"""Detection of dates and years inside a password.

Birthdays, anniversaries and "this year" are among the first things an attacker appends to a
guessed word, so a plausible date is a weakness even though it looks like random digits.
Detection is positional only (spans); the matched digits are never returned.

Recognised, with the year range 1900-2099 for four-digit years:

* a four-digit year at the start or end of a digit run (``"Summer2024"``),
* a six- or eight-digit run that is a valid calendar date in ``ddmmyy``, ``mmddyy``,
  ``yymmdd``, ``ddmmyyyy``, ``mmddyyyy`` or ``yyyymmdd`` order,
* separated dates such as ``24/12/2005``, ``1.2.99`` and ``12-24-05``.

False positives are expected (random digits can look like a date) and accepted: a date finding
adds only a small amount of risk and no default policy rule depends on it.
"""

from __future__ import annotations

import re

from passaudit.analysis.text import Span, merge_spans

MIN_YEAR = 1900
MAX_YEAR = 2099

_DIGIT_RUN = re.compile(r"\d{4,}")
_SEPARATED = re.compile(r"(?<!\d)(\d{1,2})([/.\-])(\d{1,2})\2(\d{4}|\d{2})(?!\d)")
_DAYS = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)  # February: leap-year maximum


def _valid_day_month(day: int, month: int) -> bool:
    return 1 <= month <= 12 and 1 <= day <= _DAYS[month - 1]


def _valid_full_date(day: int, month: int, year: int) -> bool:
    if not _valid_day_month(day, month):
        return False
    if month == 2 and day == 29:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return leap
    return True


def _is_year(text: str) -> bool:
    return len(text) == 4 and MIN_YEAR <= int(text) <= MAX_YEAR


def _six_digit_date(d: str) -> bool:
    a, b, c = int(d[:2]), int(d[2:4]), int(d[4:])
    return (
        _valid_day_month(a, b)  # ddmmyy
        or _valid_day_month(b, a)  # mmddyy
        or _valid_day_month(c, b)  # yymmdd
    )


def _eight_digit_date(d: str) -> bool:
    first4, last4 = d[:4], d[4:]
    if _is_year(first4):  # yyyymmdd
        return _valid_full_date(int(d[6:]), int(d[4:6]), int(first4))
    if _is_year(last4):  # ddmmyyyy or mmddyyyy
        year = int(last4)
        a, b = int(d[:2]), int(d[2:4])
        return _valid_full_date(a, b, year) or _valid_full_date(b, a, year)
    return False


def _windows(run: str, offset: int) -> list[Span]:
    """Date-like windows at the start and end of a digit run (where decoration sits)."""
    spans: list[Span] = []
    length = len(run)
    for size, check in ((8, _eight_digit_date), (6, _six_digit_date), (4, _is_year)):
        if length < size:
            continue
        head, tail = run[:size], run[-size:]
        hit = False
        if check(head):
            spans.append(Span(offset, size))
            hit = True
        if length > size and check(tail):
            spans.append(Span(offset + length - size, size))
            hit = True
        if hit:
            break
    return spans


def find_dates(password: str) -> list[Span]:
    """Return merged spans of ``password`` that look like a date or a year."""
    spans: list[Span] = []
    for match in _DIGIT_RUN.finditer(password):
        spans.extend(_windows(match.group(), match.start()))
    for match in _SEPARATED.finditer(password):
        day_or_month_a, _, day_or_month_b, year_text = match.groups()
        a, b = int(day_or_month_a), int(day_or_month_b)
        if len(year_text) == 4:
            ok = _is_year(year_text) and (
                _valid_full_date(a, b, int(year_text)) or _valid_full_date(b, a, int(year_text))
            )
        else:
            ok = _valid_day_month(a, b) or _valid_day_month(b, a)
        if ok:
            spans.append(Span(match.start(), match.end() - match.start()))
    return merge_spans(spans)
