"""Phase 8 detection: dates, stepped sequences, keyboard walks, advanced dictionary analysis."""

from __future__ import annotations

import random
import string

import pytest

from passaudit.analysis import (
    AnalysisContext,
    DictionaryKind,
    DictionarySet,
    FindingKind,
    PasswordAnalyzer,
    PasswordPolicy,
    PasswordUsage,
    WordList,
    WordMatchType,
)
from passaudit.analysis.dates import find_dates
from passaudit.analysis.keyboard import find_keyboard_walks
from passaudit.analysis.patterns import find_stepped_sequences

from .conftest import CANARY

# --------------------------------------------------------------------------------- dates


@pytest.mark.parametrize(
    ("text", "start", "length"),
    [
        ("Summer2024", 6, 4),  # a year at the end
        ("1987purple", 0, 4),  # a year at the start
        ("24/12/2005xx", 0, 10),  # separated, four-digit year
        ("x1.2.99y", 1, 6),  # separated, short
        ("pw20240131", 2, 8),  # yyyymmdd
        ("31122005", 0, 8),  # ddmmyyyy
        ("pw311299", 2, 6),  # ddmmyy
        ("x19871234", 1, 4),  # not a date, but its first four digits are a year
    ],
)
def test_dates_and_years_are_found_with_their_position(text: str, start: int, length: int) -> None:
    spans = find_dates(text)
    assert (spans[0].start, spans[0].length) == (start, length)


@pytest.mark.parametrize(
    "text",
    ["", "abc", "123", "1850", "2150", "99999", "32/13/1850", "99991345", "x31x12x"],
)
def test_non_dates_are_not_reported(text: str) -> None:
    assert find_dates(text) == []


def test_leap_day_is_valid_only_in_leap_years() -> None:
    def whole(text: str) -> bool:  # the trailing year is always found; the full date only if valid
        return any(span.length == len(text) for span in find_dates(text))

    assert whole("29/02/2024")
    assert not whole("29/02/2023")
    assert whole("29/02/2000")
    assert not whole("29/02/1900")


def test_the_date_finding_is_reported_and_carries_no_digits(analyzer: PasswordAnalyzer) -> None:
    result = analyzer.analyze_password("Zq7!kP#24/12/2005")
    dates = [f for f in result.findings if f.kind is FindingKind.DATE]
    assert len(dates) == 1
    assert "2005" not in dates[0].description
    assert "2005" not in result.model_dump_json()


# ------------------------------------------------------------------- stepped sequences


@pytest.mark.parametrize(
    ("text", "start", "length", "step"),
    [("a2468b", 1, 4, 2), ("acegik", 0, 6, 2), ("9630", 0, 4, -3), ("x0369y", 1, 4, 3)],
)
def test_stepped_sequences(text: str, start: int, length: int, step: int) -> None:
    (match,) = find_stepped_sequences(text)
    assert (match.span.start, match.span.length, match.step) == (start, length, step)


def test_stepped_sequences_need_four_and_never_mix_classes() -> None:
    assert find_stepped_sequences("246") == []  # three is within chance
    assert find_stepped_sequences("a2c4e6") == []  # letters and digits are not one run
    assert find_stepped_sequences("1234") == []  # step 1 belongs to find_sequences
    with pytest.raises(ValueError, match="min_length"):
        find_stepped_sequences("abc", min_length=2)


def test_stepped_sequence_is_a_sequence_finding_with_its_step(analyzer: PasswordAnalyzer) -> None:
    result = analyzer.analyze_password("Zq7!2468xk")
    (found,) = [f for f in result.findings if f.kind is FindingKind.SEQUENCE]
    assert (found.step, found.direction) == (2, "ascending")
    assert "skipping by 2" in found.description


# -------------------------------------------------------------------------- keyboard walks


def test_walks_follow_adjacent_keys_through_a_change_of_direction() -> None:
    (walk,) = find_keyboard_walks("zaq12wsx")
    assert (walk.span.start, walk.span.length, walk.layout) == (0, 8, "qwerty")


def test_walks_need_five_adjacent_keys_and_skip_the_keypad() -> None:
    assert find_keyboard_walks("zaq1") == []
    assert find_keyboard_walks("2024!") == []  # adjacent only on the numeric keypad
    assert find_keyboard_walks("q9r2k8") == []
    with pytest.raises(ValueError, match="min_length"):
        find_keyboard_walks("abc", min_length=2)


def test_a_walk_replaces_the_straight_runs_it_contains(analyzer: PasswordAnalyzer) -> None:
    result = analyzer.analyze_password("Zq7!zaq12wsx")
    keyboard = [f for f in result.findings if f.kind is FindingKind.KEYBOARD_PATTERN]
    assert [(f.start, f.length) for f in keyboard] == [(4, 8)]
    assert "connected path" in keyboard[0].description


def test_a_walk_that_is_just_one_straight_run_is_not_reported_twice(
    analyzer: PasswordAnalyzer,
) -> None:
    keyboard = [
        f
        for f in analyzer.analyze_password("Zq7!asdfgh").findings
        if f.kind is FindingKind.KEYBOARD_PATTERN
    ]
    assert len(keyboard) == 1
    assert "in a line" in keyboard[0].description


# ------------------------------------------------------------------------- dictionaries


def _words(password: str) -> list[tuple[str, WordMatchType | None, str | None]]:
    result = PasswordAnalyzer().analyze_password(password)
    return [
        (f.kind.value, f.match_type, f.dictionary)
        for f in result.findings
        if f.kind is FindingKind.DICTIONARY_WORD
    ]


def test_joined_words_are_one_segmented_finding() -> None:
    result = PasswordAnalyzer().analyze_password("CorrectHorseBattery!1")
    (found,) = [f for f in result.findings if f.kind is FindingKind.DICTIONARY_WORD]
    assert found.match_type is WordMatchType.SEGMENTED
    assert (found.start, found.length) == (0, 19)  # the decoration is outside the span
    assert found.dictionary == "words"


def test_segmentation_sees_through_leetspeak() -> None:
    (kind, match_type, _) = _words("c0rr3ctH0rs3b4tt3ry")[0]
    assert (kind, match_type) == ("dictionary_word", WordMatchType.SEGMENTED)


def test_a_first_name_is_reported_with_its_dictionary() -> None:
    found = _words("Zq7!Zachary-xk")
    assert ("dictionary_word", WordMatchType.EMBEDDED, "names") in found


def test_separated_words_are_segmented_too() -> None:
    result = PasswordAnalyzer().analyze_password("planet-basket_desert7")
    (found,) = [f for f in result.findings if f.kind is FindingKind.DICTIONARY_WORD]
    assert found.match_type is WordMatchType.SEGMENTED
    assert (found.start, found.length) == (0, 20)


def test_a_single_word_with_decoration() -> None:
    assert ("dictionary_word", WordMatchType.DECORATED, "words") in _words("Basket7")


def test_a_known_password_is_not_double_reported_as_a_word() -> None:
    result = PasswordAnalyzer().analyze_password("password123")
    assert not [f for f in result.findings if f.kind is FindingKind.DICTIONARY_WORD]
    assert [f for f in result.findings if f.kind is FindingKind.COMMON_PASSWORD]


def test_short_chance_words_do_not_match_inside_random_text() -> None:
    assert _words("Zq7!xKp#9mWv$L2nRb") == []
    assert _words("qxzvk-bbb-jjj") == []


def test_dictionary_findings_never_contain_the_word() -> None:
    result = PasswordAnalyzer().analyze_password("xxCorrectHorseBatteryxx")
    blob = result.model_dump_json().lower()
    for word in ("correct", "horse", "battery"):
        assert word not in blob


def test_custom_dictionaries_extend_the_words_list() -> None:
    plain = PasswordAnalyzer()
    custom = PasswordAnalyzer(
        dictionaries=DictionarySet.bundled().with_extra_words(
            [WordList(["quillfeather", "zebulon"], name="company")]
        )
    )
    password = "Zq7!Quillfeather-Zebulon!9"
    assert not [f for f in plain.analyze_password(password).findings if f.dictionary]
    assert [f for f in custom.analyze_password(password).findings if f.dictionary == "words"]


def test_an_empty_dictionary_set_disables_the_feature() -> None:
    quiet = PasswordAnalyzer(dictionaries=DictionarySet.empty())
    assert not [
        f
        for f in quiet.analyze_password("CorrectHorseBattery!1").findings
        if f.kind is FindingKind.DICTIONARY_WORD
    ]


def test_dictionary_set_repr_shows_sizes_not_contents() -> None:
    text = repr(DictionarySet.bundled())
    assert "words=" in text
    assert "horse" not in text
    assert DictionaryKind.NAMES.value == "names"


def test_segmentation_is_bounded_for_long_input() -> None:
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze_password("horse" * 200)  # 1000 characters; over the segment cap
    assert result.length == 1000
    assert PasswordAnalyzer().dictionaries.find_matches("") == []


def test_random_passwords_rarely_trigger_any_phase8_finding() -> None:
    """False-positive guard: random 12-20 character passwords almost never look like dates,
    words, names or keyboard paths."""
    rng = random.Random(8)  # noqa: S311 - deterministic test data, not security
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    analyzer = PasswordAnalyzer()
    phase8 = {FindingKind.DATE, FindingKind.DICTIONARY_WORD}
    noisy = 0
    total = 1500
    for _ in range(total):
        password = "".join(rng.choice(alphabet) for _ in range(rng.choice([12, 16, 20])))
        if any(f.kind in phase8 for f in analyzer.analyze_password(password).findings):
            noisy += 1
    assert noisy / total < 0.02


# ----------------------------------------------------------------------------- policy


def test_block_dictionary_words_rule() -> None:
    policy = PasswordPolicy(
        min_length=0,
        min_strength_score=0,
        block_common_passwords=False,
        block_dictionary_words=True,
    )
    analyzer = PasswordAnalyzer()
    mostly = analyzer.analyze_password("CorrectHorseBattery", policy=policy)
    (violation,) = mostly.policy.violations
    assert violation.rule.value == "block_dictionary_words"
    assert violation.actual is not None
    assert violation.actual >= 60
    assert analyzer.analyze_password(CANARY, policy=policy).policy.compliant


def test_new_policy_rules_are_off_by_default() -> None:
    policy = PasswordPolicy()
    assert policy.block_dictionary_words is False
    assert policy.block_breached_passwords is False


def test_dictionary_advice_only_when_the_password_is_not_strong_enough() -> None:
    analyzer = PasswordAnalyzer()
    weak = analyzer.analyze_password(
        "Basket7", context=AnalysisContext(usage=PasswordUsage.MASTER_PASSWORD)
    )
    strong = analyzer.analyze_password("CorrectHorseBatteryStaple-Wolf-Moon-Delta-91x")
    assert "avoid_dictionary_words" in {r.code.value for r in weak.recommendations}
    assert "avoid_dictionary_words" not in {r.code.value for r in strong.recommendations}
