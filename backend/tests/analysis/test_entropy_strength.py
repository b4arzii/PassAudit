"""Entropy estimation and the zxcvbn adapter (including its safety fixes)."""

from __future__ import annotations

import math
import secrets
import string
import threading
import time
from typing import Any

import pytest
from zxcvbn import matching

from passaudit.analysis import strength as strength_module
from passaudit.analysis.charsets import profile_of
from passaudit.analysis.entropy import (
    LIMITATIONS,
    charset_bits,
    estimate_entropy,
    guess_bits_from_log10,
    shannon_bits_per_char,
)
from passaudit.analysis.models import StrengthLabel, StrengthSegment
from passaudit.analysis.strength import estimate_strength

# ----------------------------------------------------------------------------- entropy


def test_charset_bits_known_values() -> None:
    assert charset_bits(profile_of("abcd")) == pytest.approx(4 * math.log2(26))
    assert charset_bits(profile_of("1234")) == pytest.approx(4 * math.log2(10))
    assert charset_bits(profile_of("aA1!")) == pytest.approx(4 * math.log2(94))


def test_charset_bits_empty_is_zero() -> None:
    assert charset_bits(profile_of("")) == 0.0


def test_charset_bits_single_symbol_pool_is_zero() -> None:
    assert charset_bits(profile_of(" ")) == 0.0  # pool of 1 carries no information


def test_charset_bits_grow_linearly_with_length() -> None:
    assert charset_bits(profile_of("a" * 20)) == pytest.approx(
        2 * charset_bits(profile_of("a" * 10))
    )


def test_shannon_known_values() -> None:
    assert shannon_bits_per_char("") == 0.0
    assert shannon_bits_per_char("aaaa") == 0.0
    assert shannon_bits_per_char("abcd") == pytest.approx(2.0)
    assert shannon_bits_per_char("aabb") == pytest.approx(1.0)
    assert shannon_bits_per_char("a") == 0.0


def test_shannon_zero_is_not_negative_zero() -> None:
    assert math.copysign(1.0, shannon_bits_per_char("aaaa")) == 1.0


def test_guess_bits_conversion() -> None:
    assert guess_bits_from_log10(0.0) == 0.0
    assert guess_bits_from_log10(3.0) == pytest.approx(9.9658, abs=1e-3)
    assert guess_bits_from_log10(-1.0) == 0.0


def test_estimated_bits_is_the_more_pessimistic_estimate() -> None:
    weak = estimate_entropy("Password1!", profile_of("Password1!"), guesses_log10=3.0)
    assert weak.charset_bits > 60  # naive estimate is wildly optimistic...
    assert weak.estimated_bits == pytest.approx(weak.guess_bits)  # ...the combined one is not
    assert weak.estimated_bits < 11

    huge = estimate_entropy("ab", profile_of("ab"), guesses_log10=50.0)
    assert huge.estimated_bits == pytest.approx(huge.charset_bits)  # charset caps it


def test_entropy_estimate_documents_its_limitations() -> None:
    est = estimate_entropy("abc", profile_of("abc"), guesses_log10=2.0)
    assert est.limitations == LIMITATIONS
    assert len(est.limitations) >= 4
    assert any("uniformly" in item for item in est.limitations)


def test_entropy_empty_password() -> None:
    est = estimate_entropy("", profile_of(""), guesses_log10=0.0)
    assert (est.charset_bits, est.shannon_bits, est.guess_bits, est.estimated_bits) == (0, 0, 0, 0)
    assert est.pool_size == 0


def test_entropy_shannon_total_scales_with_length() -> None:
    est = estimate_entropy("abcd", profile_of("abcd"), guesses_log10=5.0)
    assert est.shannon_bits == pytest.approx(8.0)


# ---------------------------------------------------------------------------- strength


def test_empty_password_does_not_crash_zxcvbn() -> None:
    est = estimate_strength("")
    assert est.score == 0
    assert est.label is StrengthLabel.VERY_WEAK
    assert est.guesses_log10 == 0.0
    assert est.segments == ()
    assert est.analyzed_length == 0
    assert est.truncated is False


@pytest.mark.parametrize("password", ["password", "123456", "qwerty"])
def test_common_passwords_score_zero(password: str) -> None:
    est = estimate_strength(password)
    assert est.score == 0
    assert est.label is StrengthLabel.VERY_WEAK
    assert est.warning  # zxcvbn explains why


def test_random_password_scores_four() -> None:
    pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
    est = estimate_strength(pw)
    assert est.score == 4
    assert est.label is StrengthLabel.VERY_STRONG
    assert est.guesses_log10 > 15


def test_score_labels_cover_the_scale() -> None:
    seen = {
        estimate_strength(p).label
        for p in ["123456", "tigger", "tigger1", "Tr0ub4dor&3", "Zq7!xKp#9mWv$L2nRb"]
    }
    assert StrengthLabel.VERY_WEAK in seen
    assert StrengthLabel.VERY_STRONG in seen


def test_crack_times_are_populated() -> None:
    times = estimate_strength("password").crack_times
    assert times.offline_fast_hash == "less than a second"
    assert times.online_throttled
    assert times.online_unthrottled
    assert times.offline_slow_hash


def test_segments_describe_shape_without_text() -> None:
    est = estimate_strength("correcthorse1999")
    assert est.segments
    assert sum(seg.length for seg in est.segments) == 16
    assert "token" not in StrengthSegment.model_fields
    assert "matched_word" not in StrengthSegment.model_fields
    assert est.segments[0].start == 0


def test_personal_tokens_lower_the_estimate() -> None:
    plain = estimate_strength("qzvxjw")
    informed = estimate_strength("qzvxjw", personal_tokens=["qzvxjw"])
    assert informed.guesses_log10 < plain.guesses_log10
    assert any(seg.dictionary == "user_inputs" for seg in informed.segments)
    assert not any(seg.dictionary == "user_inputs" for seg in plain.segments)


def test_truncation_boundary() -> None:
    at_limit = estimate_strength("a1" * 50, max_chars=100)
    assert (at_limit.truncated, at_limit.analyzed_length) == (False, 100)
    over_limit = estimate_strength("a1" * 50 + "z", max_chars=100)
    assert (over_limit.truncated, over_limit.analyzed_length) == (True, 100)


LEET_SYMBOLS = "4@({[<69!|1$5+7"  # every symbol zxcvbn can read as a letter, most ambiguous first


def test_ordinary_symbols_keep_the_full_analysis_length() -> None:
    est = estimate_strength("P@ssw0rd!" + "x" * 91, max_chars=100)
    assert (est.truncated, est.analyzed_length) == (False, 100)


def test_leet_dense_input_is_analysed_over_fewer_characters() -> None:
    """Phase 9: 100 leet symbols took ~2.5 s inside zxcvbn; the work is now bounded."""
    pw = (LEET_SYMBOLS * 7)[:100]
    est = estimate_strength(pw, max_chars=100)
    assert est.truncated
    assert est.analyzed_length == strength_module._MIN_ANALYSED_CHARS


def test_leet_dense_input_finishes_quickly() -> None:
    worst = "".join(("a", LEET_SYMBOLS[i % len(LEET_SYMBOLS)])[i % 2] for i in range(100))
    for pw in ((LEET_SYMBOLS * 7)[:100], worst, LEET_SYMBOLS * 60):
        start = time.perf_counter()
        est = estimate_strength(pw, max_chars=100)
        assert time.perf_counter() - start < 1.5, "leet expansion is no longer bounded"
        assert math.isfinite(est.guesses_log10)


def test_leet_budget_never_exceeds_the_configured_maximum() -> None:
    est = estimate_strength(LEET_SYMBOLS * 3, max_chars=8)
    assert est.analyzed_length == 8
    assert est.truncated


def test_a_short_leet_password_is_still_fully_analysed() -> None:
    est = estimate_strength(LEET_SYMBOLS, max_chars=100)  # 15 characters, under the floor
    assert (est.truncated, est.analyzed_length) == (False, len(LEET_SYMBOLS))


def test_long_input_is_bounded_in_time() -> None:
    pw = "".join(secrets.choice(string.printable) for _ in range(1024))
    start = time.perf_counter()
    est = estimate_strength(pw, max_chars=100)
    assert time.perf_counter() - start < 5.0
    assert est.truncated
    assert math.isfinite(est.guesses_log10)


def test_non_latin_input_is_handled() -> None:
    est = estimate_strength("пароль密码🔑abc")
    assert 0 <= est.score <= 4
    assert math.isfinite(est.guesses_log10)


def test_zxcvbn_global_state_is_scrubbed_after_use() -> None:
    estimate_strength("qzvxjw", personal_tokens=["super-private-name"])
    assert "user_inputs" not in matching.RANKED_DICTIONARIES


def test_zxcvbn_global_state_is_scrubbed_even_if_zxcvbn_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        matching.RANKED_DICTIONARIES["user_inputs"] = {"leaked": 1}
        raise RuntimeError("zxcvbn exploded")

    monkeypatch.setattr(strength_module, "zxcvbn", boom)
    with pytest.raises(RuntimeError):
        estimate_strength("whatever", personal_tokens=["x"])
    assert "user_inputs" not in matching.RANKED_DICTIONARIES


def test_personal_tokens_do_not_leak_between_concurrent_analyses() -> None:
    """Analysis A supplies a token; concurrent analysis B must never see it."""
    leaks: list[str] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def with_token() -> None:
        try:
            barrier.wait()
            for _ in range(25):
                estimate_strength("qzvxjw", personal_tokens=["qzvxjw"])
        except BaseException as exc:
            errors.append(exc)

    def without_token() -> None:
        try:
            barrier.wait()
            for _ in range(25):
                est = estimate_strength("qzvxjw")
                if any(seg.dictionary == "user_inputs" for seg in est.segments):
                    leaks.append("leak")
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=with_token), threading.Thread(target=without_token)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors
    assert not leaks


@pytest.mark.parametrize("bad", [float("inf"), float("nan")])
def test_non_finite_zxcvbn_output_is_clamped(monkeypatch: pytest.MonkeyPatch, bad: float) -> None:
    def fake(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {
            "guesses_log10": bad,
            "score": 4,
            "crack_times_display": {
                "online_throttling_100_per_hour": "centuries",
                "online_no_throttling_10_per_second": "centuries",
                "offline_slow_hashing_1e4_per_second": "centuries",
                "offline_fast_hashing_1e10_per_second": "centuries",
            },
            "sequence": [{"pattern": "bruteforce", "i": 0, "j": 2, "guesses_log10": bad}],
            "feedback": {"warning": "", "suggestions": []},
        }

    monkeypatch.setattr(strength_module, "zxcvbn", fake)
    est = estimate_strength("abc")
    assert math.isfinite(est.guesses_log10)
    assert all(math.isfinite(seg.guesses_log10) for seg in est.segments)
    assert est.guesses_log10 <= 1000.0
