"""The password analyzer: orchestrates every detector into one ``PasswordAnalysis``.

Security properties (verified by ``backend/tests/analysis/test_security.py``):

* No logging, printing, file writes, network access, or caching of passwords.
* The password is held in local variables only for the duration of ``analyze``.
* The result and every exception message are free of password text.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from passaudit.analysis.charsets import profile_of
from passaudit.analysis.dates import find_dates
from passaudit.analysis.dictionaries import DictionaryKind, DictionarySet
from passaudit.analysis.entropy import estimate_entropy
from passaudit.analysis.errors import PasswordTooLongError
from passaudit.analysis.keyboard import find_keyboard_runs, find_keyboard_walks
from passaudit.analysis.models import (
    AnalysisContext,
    AnalysisRequest,
    ExposureSignals,
    Finding,
    FindingKind,
    PasswordAnalysis,
    PasswordPolicy,
    WordMatchType,
)
from passaudit.analysis.patterns import find_repeats, find_sequences, find_stepped_sequences
from passaudit.analysis.personal import extract_tokens, find_personal_info
from passaudit.analysis.policy import validate_policy
from passaudit.analysis.recommendations import build_recommendations, meets_usage_target
from passaudit.analysis.scoring import assess_risk
from passaudit.analysis.strength import estimate_strength
from passaudit.analysis.text import Span
from passaudit.analysis.wordlist import WordList

ANALYSIS_VERSION = "1.1.0"

_WORD_DESCRIPTIONS: dict[WordMatchType, str] = {
    WordMatchType.EXACT: "Matches a commonly used password (ignoring letter case).",
    WordMatchType.REVERSED: "Is a commonly used password written backwards.",
    WordMatchType.LEET: "Is a commonly used password with look-alike symbol substitutions.",
    WordMatchType.DECORATED: (
        "Is a commonly used password with digits or symbols added to the start or end."
    ),
    WordMatchType.EMBEDDED: "Contains a commonly used password.",
    WordMatchType.SEGMENTED: "Is made of commonly used passwords joined together.",
}

_DICTIONARY_NOUN = {DictionaryKind.WORDS: "common word", DictionaryKind.NAMES: "common first name"}


def _dictionary_description(kind: DictionaryKind, match_type: WordMatchType) -> str:
    noun = _DICTIONARY_NOUN[kind]
    return {
        WordMatchType.EXACT: f"Is a {noun}.",
        WordMatchType.REVERSED: f"Is a {noun} written backwards.",
        WordMatchType.LEET: f"Is a {noun} with look-alike symbol substitutions.",
        WordMatchType.DECORATED: f"Is a {noun} with digits or symbols added.",
        WordMatchType.EMBEDDED: f"Contains a {noun}.",
        WordMatchType.SEGMENTED: "Is made of two or more common words joined together.",
    }[match_type]


class AnalyzerConfig(BaseModel):
    """Engine tuning knobs (not per-request policy). All have safe defaults."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Inputs longer than this are rejected with ``PasswordTooLongError`` before any work.
    max_input_length: Annotated[int, Field(ge=1, le=65536)] = 1024
    #: Characters passed to zxcvbn (its cost grows super-linearly; see ``strength.py``).
    zxcvbn_max_chars: Annotated[int, Field(ge=8, le=256)] = 100
    min_repeat_run: Annotated[int, Field(ge=2, le=64)] = 3
    min_sequence_length: Annotated[int, Field(ge=2, le=64)] = 3
    min_keyboard_run: Annotated[int, Field(ge=2, le=64)] = 4
    min_embedded_word_length: Annotated[int, Field(ge=3, le=64)] = 5
    min_stepped_sequence: Annotated[int, Field(ge=3, le=64)] = 4
    min_keyboard_walk: Annotated[int, Field(ge=3, le=64)] = 5
    #: Shortest word/name matched *inside* a longer password (shorter ones match by chance).
    min_dictionary_embedded: Annotated[int, Field(ge=3, le=64)] = 5


class PasswordAnalyzer:
    """Stateless (apart from its immutable word list) password analysis engine."""

    def __init__(
        self,
        config: AnalyzerConfig | None = None,
        wordlist: WordList | None = None,
        dictionaries: DictionarySet | None = None,
    ) -> None:
        self.config = config or AnalyzerConfig()
        self.wordlist = wordlist if wordlist is not None else WordList.bundled()
        self.dictionaries = dictionaries if dictionaries is not None else DictionarySet.bundled()

    def analyze_password(
        self,
        password: str,
        *,
        policy: PasswordPolicy | None = None,
        context: AnalysisContext | None = None,
        exposure: ExposureSignals | None = None,
    ) -> PasswordAnalysis:
        """Convenience wrapper around :meth:`analyze` for a plain ``str`` password."""
        request = AnalysisRequest(
            password=SecretStr(password),
            policy=policy or PasswordPolicy(),
            context=context or AnalysisContext(),
        )
        return self.analyze(request, exposure=exposure)

    def analyze(
        self, request: AnalysisRequest, *, exposure: ExposureSignals | None = None
    ) -> PasswordAnalysis:
        """Analyse the request's password. Raises ``PasswordTooLongError`` if over the limit.

        ``exposure`` carries the (password-free) results of opt-in breach / reuse lookups that
        the caller ran; it changes the risk score, policy result and advice, and is echoed in
        the result. The engine itself never performs a lookup.
        """
        cfg = self.config
        password = request.password.get_secret_value()
        if len(password) > cfg.max_input_length:
            raise PasswordTooLongError(len(password), cfg.max_input_length)

        profile = profile_of(password)
        personal_values = [item.get_secret_value() for item in request.context.personal_info]
        tokens = extract_tokens(personal_values)

        strength = estimate_strength(password, tokens, max_chars=cfg.zxcvbn_max_chars)
        entropy = estimate_entropy(password, profile, strength.guesses_log10)
        findings = self._find(password, tokens)
        policy_result = validate_policy(
            password,
            profile,
            request.policy,
            strength=strength,
            findings=findings,
            exposure=exposure,
        )
        risk = assess_risk(
            length=profile.length,
            strength=strength,
            findings=findings,
            policy=policy_result,
            exposure=exposure,
        )
        context = request.context
        if (
            exposure is not None
            and exposure.reuse is not None
            and exposure.reuse.status == "reused"
        ):
            context = context.model_copy(update={"reused_elsewhere": True})
        recommendations = build_recommendations(
            profile=profile,
            strength=strength,
            findings=findings,
            policy=request.policy,
            policy_result=policy_result,
            risk=risk,
            context=context,
            exposure=exposure,
        )
        return PasswordAnalysis(
            version=ANALYSIS_VERSION,
            length=profile.length,
            strength=strength,
            entropy=entropy,
            findings=findings,
            policy=policy_result,
            risk=risk,
            meets_usage_target=meets_usage_target(strength, request.context.usage),
            recommendations=recommendations,
            exposure=exposure,
        )

    # -- detectors -> findings --------------------------------------------------------

    def _find(self, password: str, tokens: tuple[str, ...]) -> tuple[Finding, ...]:
        cfg = self.config
        found: list[Finding] = []

        for rep in find_repeats(password, min_run=cfg.min_repeat_run):
            single = rep.block_length == 1
            found.append(
                Finding(
                    kind=FindingKind.REPEATED_CHARACTERS if single else FindingKind.REPEATED_BLOCK,
                    start=rep.span.start,
                    length=rep.span.length,
                    description=(
                        f"One character is repeated {rep.count} times in a row."
                        if single
                        else f"A {rep.block_length}-character block repeats {rep.count} times."
                    ),
                    repeat_count=rep.count,
                )
            )

        for seq in find_sequences(password, min_length=cfg.min_sequence_length):
            direction: Literal["ascending", "descending"] = (
                "ascending" if seq.step > 0 else "descending"
            )
            found.append(
                Finding(
                    kind=FindingKind.SEQUENCE,
                    start=seq.span.start,
                    length=seq.span.length,
                    description=f"{seq.span.length} consecutive letters or digits, {direction}.",
                    direction=direction,
                )
            )

        for stepped in find_stepped_sequences(password, min_length=cfg.min_stepped_sequence):
            skip = abs(stepped.step)
            way = "ascending" if stepped.step > 0 else "descending"
            found.append(
                Finding(
                    kind=FindingKind.SEQUENCE,
                    start=stepped.span.start,
                    length=stepped.span.length,
                    description=(
                        f"{stepped.span.length} letters or digits, {way}, skipping by {skip}."
                    ),
                    direction="ascending" if stepped.step > 0 else "descending",
                    step=skip,
                )
            )

        found.extend(self._keyboard_findings(password))

        for word in self.wordlist.find_matches(
            password, min_embedded_length=cfg.min_embedded_word_length
        ):
            found.append(
                Finding(
                    kind=FindingKind.COMMON_PASSWORD,
                    start=word.span.start,
                    length=word.span.length,
                    description=_WORD_DESCRIPTIONS[word.match_type],
                    match_type=word.match_type,
                )
            )

        found.extend(self._dictionary_findings(password, found))

        for span in find_dates(password):
            found.append(
                Finding(
                    kind=FindingKind.DATE,
                    start=span.start,
                    length=span.length,
                    description="Looks like a date or a year.",
                )
            )

        if tokens:
            for span in find_personal_info(password, tokens):
                found.append(
                    Finding(
                        kind=FindingKind.PERSONAL_INFO,
                        start=span.start,
                        length=span.length,
                        description="Contains personal information supplied as context.",
                    )
                )

        found.sort(key=lambda f: (f.start, f.kind.value))
        return tuple(found)

    def _keyboard_findings(self, password: str) -> list[Finding]:
        cfg = self.config
        runs = find_keyboard_runs(password, min_length=cfg.min_keyboard_run)
        walks = [
            w
            for w in find_keyboard_walks(password, min_length=cfg.min_keyboard_walk)
            # A walk that is just one straight run is already reported as that run.
            if not any(r.span.start <= w.span.start and w.span.end <= r.span.end for r in runs)
        ]
        runs = [
            r
            for r in runs
            if not any(w.span.start <= r.span.start and r.span.end <= w.span.end for w in walks)
        ]
        out = [
            Finding(
                kind=FindingKind.KEYBOARD_PATTERN,
                start=r.span.start,
                length=r.span.length,
                description=f"{r.span.length} adjacent keys typed in a line ({r.layout} layout).",
                layout=r.layout,
            )
            for r in runs
        ]
        out.extend(
            Finding(
                kind=FindingKind.KEYBOARD_PATTERN,
                start=w.span.start,
                length=w.span.length,
                description=(
                    f"{w.span.length} adjacent keys typed along a connected path "
                    f"({w.layout} layout)."
                ),
                layout=w.layout,
            )
            for w in walks
        )
        return out

    def _dictionary_findings(self, password: str, existing: list[Finding]) -> list[Finding]:
        """Word/name findings, skipping text already explained as a common password."""
        common = [f for f in existing if f.kind is FindingKind.COMMON_PASSWORD]
        if any(f.match_type is not WordMatchType.EMBEDDED for f in common):
            return []  # the whole password is a known password; word findings add nothing
        out: list[Finding] = []
        for match in self.dictionaries.find_matches(
            password, min_embedded_length=self.config.min_dictionary_embedded
        ):
            overlap = sum(match.span.overlap(Span(f.start, f.length)) for f in common)
            if overlap * 2 >= match.span.length:
                continue
            out.append(
                Finding(
                    kind=FindingKind.DICTIONARY_WORD,
                    start=match.span.start,
                    length=match.span.length,
                    description=_dictionary_description(match.kind, match.match_type),
                    match_type=match.match_type,
                    dictionary=match.kind.value,
                )
            )
        return out


@lru_cache(maxsize=1)
def _default_analyzer() -> PasswordAnalyzer:
    return PasswordAnalyzer()


def analyze_password(
    password: str,
    *,
    policy: PasswordPolicy | None = None,
    context: AnalysisContext | None = None,
    exposure: ExposureSignals | None = None,
) -> PasswordAnalysis:
    """Analyse ``password`` with a shared default analyzer (bundled word list, default config)."""
    return _default_analyzer().analyze_password(
        password, policy=policy, context=context, exposure=exposure
    )
