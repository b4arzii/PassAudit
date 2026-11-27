"""Dictionary-based weak-password detection and personal-information matching."""

from __future__ import annotations

from pathlib import Path

import pytest

from passaudit.analysis import wordlist as wordlist_module
from passaudit.analysis.personal import extract_tokens, find_personal_info
from passaudit.analysis.wordlist import MAX_EMBEDDED_MATCHES, WordList

SMALL = WordList(["secret", "dragon", "light", "password", "cat"], name="small")


def _types(wl: WordList, password: str, **kw: int) -> list[tuple[str, int, int]]:
    return [
        (m.match_type.value, m.span.start, m.span.length) for m in wl.find_matches(password, **kw)
    ]


# ----------------------------------------------------------------------- bundled list


def test_bundled_list_loads_and_is_cached() -> None:
    bundled = WordList.bundled()
    assert len(bundled) >= 300
    assert bundled.name == "bundled"
    assert WordList.bundled() is bundled


@pytest.mark.parametrize("word", ["password", "PASSWORD", "123456", "qwerty", "letmein"])
def test_bundled_list_contains_the_classics(word: str) -> None:
    assert word in WordList.bundled()


def test_bundled_list_skips_comments() -> None:
    assert "# PassAudit bundled common-password list." not in WordList.bundled()
    assert not any(w.startswith("#") for w in WordList.bundled()._words)


def test_repr_does_not_list_contents() -> None:
    text = repr(WordList.bundled())
    assert "password" not in text
    assert "size=" in text


# ---------------------------------------------------------------------- matching types


def test_exact_match_is_case_insensitive() -> None:
    assert _types(SMALL, "secret") == [("exact", 0, 6)]
    assert _types(SMALL, "SeCrEt") == [("exact", 0, 6)]


def test_reversed_match() -> None:
    assert _types(SMALL, "terces") == [("reversed", 0, 6)]


def test_leet_match() -> None:
    assert _types(SMALL, "s3cr3t") == [("leet", 0, 6)]
    assert _types(SMALL, "dr@g0n") == [("leet", 0, 6)]
    assert _types(SMALL, "SECR3T") == [("leet", 0, 6)]


def test_leet_ambiguous_one_reads_as_l_or_i() -> None:
    assert _types(SMALL, "l1ght") == [("leet", 0, 5)]
    assert _types(SMALL, "l!ght") == [("leet", 0, 5)]


def test_decorated_match_reports_position_of_the_core() -> None:
    assert _types(SMALL, "secret123") == [("decorated", 0, 6)]
    assert _types(SMALL, "!!secret99") == [("decorated", 2, 6)]
    assert _types(SMALL, "123secret") == [("decorated", 3, 6)]
    assert _types(SMALL, "Secret1!") == [("decorated", 0, 6)]


def test_decorated_leet_core() -> None:
    assert _types(SMALL, "s3cr3t!") == [("decorated", 0, 6)]


def test_decoration_requires_a_core_of_at_least_four_characters() -> None:
    assert _types(SMALL, "cat123") == []  # "cat" is only three characters


def test_embedded_match_needs_minimum_word_length() -> None:
    assert _types(SMALL, "xxsecretxx") == [("embedded", 2, 6)]
    assert _types(SMALL, "xxcatxx") == []  # "cat" is below min_embedded_length (5)
    assert _types(SMALL, "xxcatxx", min_embedded_length=3) == [("embedded", 2, 3)]


def test_embedded_boundary_around_minimum_length() -> None:
    wl = WordList(["abcde"])
    assert _types(wl, "xxabcdexx", min_embedded_length=5) == [("embedded", 2, 5)]
    assert _types(wl, "xxabcdexx", min_embedded_length=6) == []


def test_embedded_leet() -> None:
    assert _types(SMALL, "xxdr@g0nxx") == [("embedded", 2, 6)]


def test_embedded_reports_multiple_non_overlapping_words() -> None:
    assert _types(SMALL, "secretXdragon") == [("embedded", 0, 6), ("embedded", 7, 6)]


def test_embedded_output_is_bounded() -> None:
    wl = WordList(["xxxxxx"])
    matches = wl.find_matches("x" * 5000)
    assert 0 < len(matches) <= MAX_EMBEDDED_MATCHES


def test_no_match_for_unrelated_text() -> None:
    assert _types(SMALL, "zq8vk2plmx") == []
    assert _types(SMALL, "correct horse battery staple") == []


def test_empty_inputs() -> None:
    assert SMALL.find_matches("") == []
    assert WordList([]).find_matches("secret") == []


def test_exact_takes_priority_and_returns_one_match() -> None:
    assert len(SMALL.find_matches("password")) == 1


def test_matches_never_expose_the_matched_text() -> None:
    (match,) = SMALL.find_matches("xxsecretxx")
    assert not hasattr(match, "text")
    assert "secret" not in repr(match)


# ----------------------------------------------------------------------- construction


def test_words_are_stripped_folded_and_deduplicated() -> None:
    wl = WordList(["  Alpha ", "alpha", "", "   ", "BETA"])
    assert len(wl) == 2
    assert "ALPHA" in wl
    assert "beta" in wl


def test_overlong_entries_are_ignored() -> None:
    wl = WordList(["a" * 500, "ok"])
    assert len(wl) == 1


def test_from_lines_skips_blanks_and_comments() -> None:
    wl = WordList.from_lines(["# comment", "", "  word  ", "#another", "second"])
    assert len(wl) == 2
    assert "word" in wl
    assert "second" in wl


def test_contains_rejects_non_strings() -> None:
    assert 5 not in SMALL
    assert None not in SMALL


def test_from_file_loads_utf8_list(tmp_path: Path) -> None:
    path = tmp_path / "list.txt"
    path.write_text("# header\nhunter2\npässwort\n\n", encoding="utf-8")
    wl = WordList.from_file(path)
    assert wl.name == "list.txt"
    assert len(wl) == 2
    assert "pässwort" in wl
    assert _types(wl, "HUNTER2") == [("exact", 0, 7)]


def test_from_file_custom_name(tmp_path: Path) -> None:
    path = tmp_path / "x.txt"
    path.write_text("word\n", encoding="utf-8")
    assert WordList.from_file(path, name="mine").name == "mine"


def test_from_file_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        WordList.from_file(tmp_path / "nope.txt")


def test_from_file_size_limit_message_has_no_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "big.txt"
    path.write_text("supersecretcontent\n" * 10, encoding="utf-8")
    monkeypatch.setattr(wordlist_module, "MAX_LIST_FILE_BYTES", 10)
    with pytest.raises(ValueError, match="byte limit") as info:
        WordList.from_file(path)
    assert "supersecretcontent" not in str(info.value)


def test_from_file_accepts_path_at_exact_size_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "edge.txt"
    path.write_bytes(b"abc\n")
    monkeypatch.setattr(wordlist_module, "MAX_LIST_FILE_BYTES", 4)
    assert "abc" in WordList.from_file(path)


# --------------------------------------------------------------------------- personal


def test_extract_tokens_from_name() -> None:
    assert set(extract_tokens(["Jane Doe"])) == {"janedoe", "jane", "doe"}


def test_extract_tokens_from_email_drops_noise() -> None:
    tokens = set(extract_tokens(["Jane.Doe@Example.com"]))
    assert {"jane", "doe", "example"} <= tokens
    assert "com" not in tokens


def test_extract_tokens_minimum_length_boundary() -> None:
    assert extract_tokens(["ab"]) == ()  # below 3
    assert extract_tokens(["abc"]) == ("abc",)  # exactly 3


def test_extract_tokens_ignores_blank_and_deduplicates() -> None:
    assert extract_tokens(["", "   ", "!!"]) == ()
    assert extract_tokens(["Bob1", "bob1"]) == ("bob1",)


def test_find_personal_info_basic_and_position() -> None:
    spans = find_personal_info("xxJaneyy", ["jane"])
    assert [(s.start, s.length) for s in spans] == [(2, 4)]


def test_find_personal_info_is_case_insensitive() -> None:
    assert find_personal_info("JANE", ["jane"])


def test_find_personal_info_sees_through_leetspeak() -> None:
    assert find_personal_info("j4n3!", ["jane"])


def test_find_personal_info_sees_reversed_tokens() -> None:
    assert find_personal_info("enaj", ["jane"])


def test_find_personal_info_none() -> None:
    assert find_personal_info("unrelated", ["jane"]) == []
    assert find_personal_info("", ["jane"]) == []
    assert find_personal_info("jane", []) == []


def test_find_personal_info_merges_overlaps() -> None:
    spans = find_personal_info("janedoe", ["jane", "anedo", "doe"])
    assert [(s.start, s.length) for s in spans] == [(0, 7)]
