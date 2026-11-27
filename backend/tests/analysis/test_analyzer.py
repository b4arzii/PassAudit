"""End-to-end analyzer behaviour, input limits, models and edge cases."""

from __future__ import annotations

import secrets
import string
import time
from collections.abc import Callable

import pytest
from pydantic import SecretStr, ValidationError

from passaudit.analysis import (
    ANALYSIS_VERSION,
    AnalysisContext,
    AnalysisRequest,
    AnalyzerConfig,
    FindingKind,
    PasswordAnalysis,
    PasswordAnalyzer,
    PasswordTooLongError,
    WordList,
    WordMatchType,
    analyze_password,
)

Analyze = Callable[..., PasswordAnalysis]
STRONG = "Zq7!xKp#9mWv$L2nRb"


# ------------------------------------------------------------------------ shape


def test_result_has_every_section(analyze: Analyze) -> None:
    result = analyze("Summer2024!")
    assert result.version == ANALYSIS_VERSION
    assert result.length == 11
    assert result.strength.score in range(5)
    assert result.entropy.limitations
    assert result.policy.violations is not None
    assert result.risk.components
    assert result.recommendations


def test_module_level_function_matches_analyzer(analyze: Analyze) -> None:
    assert analyze_password("Summer2024!") == analyze("Summer2024!")


def test_analysis_is_deterministic(analyze: Analyze) -> None:
    ctx = AnalysisContext(personal_info=(SecretStr("Jane"),))
    assert analyze("jane-2024", context=ctx) == analyze("jane-2024", context=ctx)


def test_result_is_frozen(analyze: Analyze) -> None:
    result = analyze("abc")
    with pytest.raises(ValidationError):
        result.length = 5  # type: ignore[misc]


def test_result_round_trips_through_json(analyze: Analyze) -> None:
    result = analyze("Summer2024!", context=AnalysisContext(personal_info=(SecretStr("Jane"),)))
    assert PasswordAnalysis.model_validate_json(result.model_dump_json()) == result


# ------------------------------------------------------------------ input limits


def test_default_limit_boundary() -> None:
    analyzer = PasswordAnalyzer()
    analyzer.analyze_password("a" * 1024)  # at the limit: accepted
    with pytest.raises(PasswordTooLongError):
        analyzer.analyze_password("a" * 1025)  # one over: rejected


def test_custom_limit_boundary() -> None:
    analyzer = PasswordAnalyzer(AnalyzerConfig(max_input_length=10))
    analyzer.analyze_password("a" * 10)
    with pytest.raises(PasswordTooLongError) as info:
        analyzer.analyze_password("a" * 11)
    assert (info.value.length, info.value.maximum) == (11, 10)


def test_too_long_error_message_is_content_free() -> None:
    analyzer = PasswordAnalyzer(AnalyzerConfig(max_input_length=5))
    with pytest.raises(PasswordTooLongError, match="12 exceeds the maximum of 5") as info:
        analyzer.analyze_password("S3cr3tValue!")
    assert "S3cr3t" not in str(info.value)
    assert isinstance(info.value, ValueError)


def test_limit_is_checked_before_any_expensive_work() -> None:
    analyzer = PasswordAnalyzer(AnalyzerConfig(max_input_length=64))
    start = time.perf_counter()
    with pytest.raises(PasswordTooLongError):
        analyzer.analyze_password("".join(secrets.choice(string.printable) for _ in range(50_000)))
    assert time.perf_counter() - start < 0.5


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_input_length": 0},
        {"max_input_length": 65537},
        {"zxcvbn_max_chars": 7},
        {"zxcvbn_max_chars": 257},
        {"min_repeat_run": 1},
        {"min_sequence_length": 1},
        {"min_keyboard_run": 1},
        {"min_embedded_word_length": 2},
        {"unknown": 1},
    ],
)
def test_config_validation(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        AnalyzerConfig(**kwargs)


def test_config_thresholds_change_detection() -> None:
    strict = PasswordAnalyzer(AnalyzerConfig(min_repeat_run=2, min_sequence_length=2))
    found = {f.kind for f in strict.analyze_password("aab12").findings}
    assert FindingKind.REPEATED_CHARACTERS in found
    assert FindingKind.SEQUENCE in found
    default = {f.kind for f in PasswordAnalyzer().analyze_password("aab12").findings}
    assert FindingKind.REPEATED_CHARACTERS not in default
    assert FindingKind.SEQUENCE not in default


# ----------------------------------------------------------------------- edge cases


def test_empty_password(analyze: Analyze) -> None:
    result = analyze("")
    assert result.length == 0
    assert result.risk.score == 100
    assert result.findings == ()
    assert result.entropy.estimated_bits == 0
    assert not result.policy.compliant


def test_single_character(analyze: Analyze) -> None:
    assert analyze("a").risk.score >= 40


def test_whitespace_only_password(analyze: Analyze) -> None:
    result = analyze("            ")  # 12 spaces
    assert result.length == 12
    assert result.risk.score > 30  # repeats, near-zero entropy


def test_unicode_passwords_count_code_points(analyze: Analyze) -> None:
    result = analyze("пароль密码🔑éÉ")
    assert result.length == 11
    assert 0 <= result.risk.score <= 100


def test_unicode_case_expansion_does_not_break_positions(analyze: Analyze) -> None:
    result = analyze("İİİİİ-Zq7!")  # "İ".lower() is two code points; fold must not shift offsets
    for f in result.findings:
        assert f.start + f.length <= result.length


def test_findings_always_lie_within_the_password(analyze: Analyze) -> None:
    for pw in ["aaaa", "abcabc", "qwerty123", "!!secret!!", "xxdragonxx", "0123456789", "1qaz2wsx"]:
        result = analyze(pw)
        assert result.findings
        for f in result.findings:
            assert 0 <= f.start < result.length
            assert f.start + f.length <= result.length


def test_findings_are_ordered_by_position(analyze: Analyze) -> None:
    starts = [f.start for f in analyze("aaa-abc-qwer-xxdragonxx").findings]
    assert starts == sorted(starts)


def test_finding_detail_fields(analyze: Analyze) -> None:
    findings = {f.kind: f for f in analyze("aaaXabcdXqwerXdr@g0nX").findings}
    assert findings[FindingKind.REPEATED_CHARACTERS].repeat_count == 3
    assert findings[FindingKind.SEQUENCE].direction == "ascending"
    assert findings[FindingKind.KEYBOARD_PATTERN].layout == "qwerty"
    assert findings[FindingKind.COMMON_PASSWORD].match_type in set(WordMatchType)
    assert analyze("dcba-Zq7!").findings[0].direction == "descending"


def test_repeated_block_finding(analyze: Analyze) -> None:
    (f,) = [x for x in analyze("Zq7!Zq7!Zq7!").findings if x.kind is FindingKind.REPEATED_BLOCK]
    assert (f.start, f.length, f.repeat_count) == (0, 12, 3)


# ------------------------------------------------------------- custom word list


def test_custom_wordlist_is_used_instead_of_the_bundled_one() -> None:
    analyzer = PasswordAnalyzer(wordlist=WordList(["acme-corp-2024"], name="mine"))
    hit = analyzer.analyze_password("Acme-Corp-2024")
    assert any(f.kind is FindingKind.COMMON_PASSWORD for f in hit.findings)
    miss = analyzer.analyze_password("letmein")  # bundled-only word
    assert all(f.kind is not FindingKind.COMMON_PASSWORD for f in miss.findings)


def test_empty_wordlist_disables_dictionary_findings() -> None:
    analyzer = PasswordAnalyzer(wordlist=WordList([]))
    assert all(
        f.kind is not FindingKind.COMMON_PASSWORD
        for f in analyzer.analyze_password("password").findings
    )


# ------------------------------------------------------------------ personal info


def test_personal_info_is_detected_and_lowers_strength(analyze: Analyze) -> None:
    ctx = AnalysisContext(personal_info=(SecretStr("Jane Doe"), SecretStr("jdoe@example.com")))
    result = analyze("jdoe-qzvxjw-77", context=ctx)
    assert any(f.kind is FindingKind.PERSONAL_INFO for f in result.findings)
    without = analyze("jdoe-qzvxjw-77")
    assert result.strength.guesses_log10 < without.strength.guesses_log10
    assert result.risk.score > without.risk.score


def test_context_without_personal_info_adds_no_findings(analyze: Analyze) -> None:
    result = analyze(STRONG, context=AnalysisContext())
    assert all(f.kind is not FindingKind.PERSONAL_INFO for f in result.findings)


# -------------------------------------------------------------------- models


def test_request_model_masks_password_everywhere() -> None:
    request = AnalysisRequest(password=SecretStr(STRONG))
    assert STRONG not in repr(request)
    assert STRONG not in str(request)
    assert STRONG not in request.model_dump_json()
    assert STRONG not in repr(request.model_dump())


def test_analyze_accepts_a_request_object(analyzer: PasswordAnalyzer) -> None:
    request = AnalysisRequest(password=SecretStr("letmein"))
    assert analyzer.analyze(request).risk.score >= 85


def test_request_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        AnalysisRequest(password=SecretStr("x"), extra=1)  # type: ignore[call-arg]


def test_context_personal_info_limits() -> None:
    AnalysisContext(personal_info=tuple(SecretStr("abc") for _ in range(50)))  # at limit
    with pytest.raises(ValidationError):
        AnalysisContext(personal_info=tuple(SecretStr("abc") for _ in range(51)))
    AnalysisContext(personal_info=(SecretStr("a" * 256),))  # at limit
    with pytest.raises(ValidationError):
        AnalysisContext(personal_info=(SecretStr("a" * 257),))


def test_context_coerces_plain_strings_to_secrets() -> None:
    ctx = AnalysisContext(personal_info=("Jane",))  # type: ignore[arg-type]
    assert isinstance(ctx.personal_info[0], SecretStr)
    assert "Jane" not in repr(ctx)


# ------------------------------------------------------------------- performance


@pytest.mark.parametrize(
    "password",
    [
        "".join(secrets.choice(string.printable) for _ in range(1024)),
        "a" * 1024,
        "ab" * 512,
        "password" * 128,
        "".join(secrets.choice("ab1!") for _ in range(1024)),
    ],
    ids=["random-1024", "single-char", "two-char", "common-word-x128", "small-alphabet"],
)
def test_maximum_length_input_finishes_quickly(analyze: Analyze, password: str) -> None:
    start = time.perf_counter()
    result = analyze(password)
    assert time.perf_counter() - start < 5.0
    assert result.strength.truncated
    assert len(result.findings) <= 400  # output size stays bounded
