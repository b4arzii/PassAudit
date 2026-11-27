"""Typed input and output models of the analysis engine.

Design rules enforced here:

* **Inputs carry secrets in ``SecretStr``** so ``repr()``, ``str()`` and ``model_dump_json()``
  show ``**********`` instead of the value.
* **Outputs never contain password text.** Findings carry positions, lengths and kinds only;
  descriptions come from fixed templates.
* All models are frozen and reject unknown fields. ``hide_input_in_errors`` stops pydantic
  ``ValidationError`` messages from echoing rejected input values (which may be secrets).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

MAX_PERSONAL_ITEMS = 50
MAX_PERSONAL_ITEM_LENGTH = 256
MAX_REUSE_SOURCES = 20


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


# --------------------------------------------------------------------------- enums


class PasswordUsage(StrEnum):
    """What the password protects; drives the strength target and the advice given."""

    GENERAL = "general"
    ONLINE_ACCOUNT = "online_account"  # rate-limited login (attacker is throttled)
    PRIVILEGED_ACCOUNT = "privileged_account"  # admin / financial / email-recovery account
    MASTER_PASSWORD = (
        "master_password"  # password-manager or vault master password  # enum label, not a secret  # nosec B105
    )
    ENCRYPTION_KEY = "encryption_key"  # derives a key; attacker can guess offline


class FindingKind(StrEnum):
    REPEATED_CHARACTERS = "repeated_characters"
    REPEATED_BLOCK = "repeated_block"
    SEQUENCE = "sequence"
    KEYBOARD_PATTERN = "keyboard_pattern"
    COMMON_PASSWORD = "common_password"  # enum label, not a secret  # nosec B105
    PERSONAL_INFO = "personal_info"
    #: A plausible date or year (``1987``, ``24/12/2005``, ``20240131``).
    DATE = "date_pattern"
    #: A common word or first name from a non-password dictionary (see ``dictionaries``).
    DICTIONARY_WORD = "dictionary_word"


class WordMatchType(StrEnum):
    """How a dictionary word was recognised (see ``wordlist`` for the exact rules)."""

    EXACT = "exact"
    REVERSED = "reversed"
    LEET = "leet"
    DECORATED = "decorated"
    EMBEDDED = "embedded"
    #: Two or more listed words joined together (``"correcthorse"``).
    SEGMENTED = "segmented"


class PolicyRule(StrEnum):
    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"
    MIN_LOWERCASE = "min_lowercase"
    MIN_UPPERCASE = "min_uppercase"
    MIN_DIGITS = "min_digits"
    MIN_SYMBOLS = "min_symbols"
    MIN_UNIQUE_CHARACTERS = "min_unique_characters"
    MAX_REPEAT_RUN = "max_repeat_run"
    MAX_SEQUENCE_LENGTH = "max_sequence_length"
    MAX_KEYBOARD_RUN = "max_keyboard_run"
    FORBID_WHITESPACE = "forbid_whitespace"
    BLOCK_COMMON_PASSWORDS = "block_common_passwords"
    FORBID_PERSONAL_INFO = "forbid_personal_info"
    MIN_STRENGTH_SCORE = "min_strength_score"
    BLOCK_DICTIONARY_WORDS = "block_dictionary_words"
    BLOCK_BREACHED_PASSWORDS = "block_breached_passwords"


class StrengthLabel(StrEnum):
    VERY_WEAK = "very_weak"
    WEAK = "weak"
    FAIR = "fair"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


class RiskLevel(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: int) -> RiskLevel:
        """Map a 0-100 risk score to a level: <20 low, <40 moderate, <70 high, else critical."""
        if score < 20:
            return cls.LOW
        if score < 40:
            return cls.MODERATE
        if score < 70:
            return cls.HIGH
        return cls.CRITICAL


class RiskFactor(StrEnum):
    GUESSABILITY = "guessability"
    LENGTH = "length"
    COMMON_PASSWORD = "common_password"  # enum label, not a secret  # nosec B105
    PATTERNS = "patterns"
    PERSONAL_INFO = "personal_info"
    POLICY = "policy"
    KNOWN_WEAK_FLOOR = "known_weak_floor"


class Priority(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RecommendationCode(StrEnum):
    AVOID_COMMON_PASSWORD = "avoid_common_password"  # enum label, not a secret  # nosec B105
    AVOID_PERSONAL_INFO = "avoid_personal_info"
    LENGTHEN = "lengthen"
    AVOID_REPEATS = "avoid_repeats"
    AVOID_SEQUENCES = "avoid_sequences"
    AVOID_KEYBOARD_PATTERNS = "avoid_keyboard_patterns"
    MEET_POLICY = "meet_policy"
    BELOW_USAGE_TARGET = "below_usage_target"
    USE_PASSPHRASE = "use_passphrase"  # enum label, not a secret  # nosec B105
    USE_PASSWORD_MANAGER = "use_password_manager"  # enum label, not a secret  # nosec B105
    ENABLE_MFA = "enable_mfa"
    UNIQUE_PER_SERVICE = "unique_per_service"
    ADD_VARIETY = "add_variety"
    LOOKS_GOOD = "looks_good"
    AVOID_DATES = "avoid_dates"
    AVOID_DICTIONARY_WORDS = "avoid_dictionary_words"
    CHANGE_BREACHED_PASSWORD = "change_breached_password"  # rule id  # nosec B105


# --------------------------------------------------------------------------- input models


class PasswordPolicy(_Model):
    """A configurable password policy. ``None`` / ``0`` / ``False`` disables a rule.

    The defaults follow NIST SP 800-63B-style guidance: a sensible minimum length, a blocklist
    check, and *no* mandatory character-class mix. Enable the class minimums only if an
    external requirement forces it.
    """

    min_length: Annotated[int, Field(ge=0, le=1024)] = 12
    max_length: Annotated[int, Field(ge=1, le=65536)] | None = None
    min_lowercase: Annotated[int, Field(ge=0, le=1024)] = 0
    min_uppercase: Annotated[int, Field(ge=0, le=1024)] = 0
    min_digits: Annotated[int, Field(ge=0, le=1024)] = 0
    min_symbols: Annotated[int, Field(ge=0, le=1024)] = 0
    min_unique_characters: Annotated[int, Field(ge=0, le=1024)] = 0
    #: Longest allowed run of one repeated character (``3`` allows ``aaa`` but not ``aaaa``).
    max_repeat_run: Annotated[int, Field(ge=1, le=1024)] | None = None
    #: Longest allowed ascending/descending letter/digit run (``abc`` = 3).
    max_sequence_length: Annotated[int, Field(ge=2, le=1024)] | None = None
    #: Longest allowed straight keyboard run (``asdf`` = 4).
    max_keyboard_run: Annotated[int, Field(ge=2, le=1024)] | None = None
    allow_whitespace: bool = True
    block_common_passwords: bool = True
    forbid_personal_info: bool = True
    #: Minimum zxcvbn score (0-4). ``0`` disables the rule.
    min_strength_score: Annotated[int, Field(ge=0, le=4)] = 2
    #: Reject passwords made mostly (60%+) of common words and names. Off by default:
    #: long word-based passphrases are good passwords under NIST-style guidance.
    block_dictionary_words: bool = False
    #: Reject passwords found in breach data. Needs a breach check to be requested
    #: (opt-in); without one the rule is reported as "unchecked", never as a pass.
    block_breached_passwords: bool = False

    @model_validator(mode="after")
    def _check_bounds(self) -> Self:
        if self.max_length is not None and self.max_length < self.min_length:
            raise ValueError("max_length must be greater than or equal to min_length")
        return self


class AnalysisContext(_Model):
    """Facts about the password's situation. All optional; improves detection and advice."""

    usage: PasswordUsage = PasswordUsage.GENERAL
    #: Personal strings an attacker could guess (name, username, e-mail, employer, pet...).
    #: Treated as secret: masked in ``repr`` and never returned in results.
    personal_info: Annotated[tuple[SecretStr, ...], Field(max_length=MAX_PERSONAL_ITEMS)] = ()
    #: The caller knows this password is (or may be) used on more than one service.
    reused_elsewhere: bool = False

    @field_validator("personal_info")
    @classmethod
    def _bound_item_length(cls, items: tuple[SecretStr, ...]) -> tuple[SecretStr, ...]:
        for item in items:
            if len(item.get_secret_value()) > MAX_PERSONAL_ITEM_LENGTH:
                raise ValueError(
                    f"each personal_info item must be at most {MAX_PERSONAL_ITEM_LENGTH} characters"
                )
        return items


class AnalysisRequest(_Model):
    """Everything the analyzer needs. The password is a ``SecretStr``."""

    password: SecretStr
    policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    context: AnalysisContext = Field(default_factory=AnalysisContext)


# --------------------------------------------------------------------------- exposure


class BreachExposure(_Model):
    """The outcome of a breach-corpus lookup. Never contains the password or its hash.

    ``count`` is how often the corpus has seen the password (a lower bound: corpora dedupe
    imperfectly). ``unavailable`` means the lookup was requested but could not be completed
    (offline, timeout, not configured): the password is then *unchecked*, not *clean*.
    """

    status: Literal["clean", "breached", "unavailable"]
    source: Literal["local", "online"]
    count: Annotated[int, Field(ge=0)] | None = None


class ReuseExposure(_Model):
    """Which of the operator's local reuse datasets (by name) already contain this password."""

    status: Literal["clean", "reused"]
    sources: Annotated[tuple[str, ...], Field(max_length=MAX_REUSE_SOURCES)] = ()


class ExposureSignals(_Model):
    """Facts about a password learned from *outside* the engine (opt-in lookups).

    The engine itself stays offline and pure: callers run the lookups (see ``passaudit.breach``
    and ``passaudit.reuse``) and pass only these password-free results in. ``None`` means "not
    checked".
    """

    breach: BreachExposure | None = None
    reuse: ReuseExposure | None = None


# --------------------------------------------------------------------------- output models


class Finding(_Model):
    """One detected weakness. Locates it (``start``/``length``) without quoting it."""

    kind: FindingKind
    start: Annotated[int, Field(ge=0)]
    length: Annotated[int, Field(ge=1)]
    description: str
    match_type: WordMatchType | None = None  # COMMON_PASSWORD only
    repeat_count: int | None = None  # REPEATED_* only
    direction: Literal["ascending", "descending"] | None = None  # SEQUENCE only
    layout: str | None = None  # KEYBOARD_PATTERN only
    step: int | None = None  # SEQUENCE only: distance between neighbours (1, 2 or 3)
    dictionary: str | None = None  # DICTIONARY_WORD only: "words" or "names"


class StrengthSegment(_Model):
    """How zxcvbn explained one stretch of the password (no text, only the shape)."""

    pattern: str
    start: Annotated[int, Field(ge=0)]
    length: Annotated[int, Field(ge=1)]
    guesses_log10: float
    dictionary: str | None = None
    l33t: bool = False
    reversed: bool = False


class CrackTimeEstimates(_Model):
    """zxcvbn's human-readable crack times under four attacker models (see docs)."""

    online_throttled: str  # 100 guesses / hour
    online_unthrottled: str  # 10 guesses / second
    offline_slow_hash: str  # 10^4 guesses / second (e.g. bcrypt/argon2 class)
    offline_fast_hash: str  # 10^10 guesses / second (e.g. unsalted MD5/SHA-1, GPU)


class StrengthEstimate(_Model):
    """zxcvbn-based guessability."""

    score: Annotated[int, Field(ge=0, le=4)]
    label: StrengthLabel
    guesses_log10: Annotated[float, Field(ge=0)]
    crack_times: CrackTimeEstimates
    segments: tuple[StrengthSegment, ...]
    warning: str
    suggestions: tuple[str, ...]
    #: True when only the first ``analyzed_length`` characters were passed to zxcvbn.
    truncated: bool
    analyzed_length: Annotated[int, Field(ge=0)]


class EntropyEstimate(_Model):
    """Entropy figures. Read ``limitations`` before trusting any of them."""

    pool_size: Annotated[int, Field(ge=0)]
    charset_bits: Annotated[float, Field(ge=0)]
    shannon_bits_per_char: Annotated[float, Field(ge=0)]
    shannon_bits: Annotated[float, Field(ge=0)]
    guess_bits: Annotated[float, Field(ge=0)]
    #: ``min(charset_bits, guess_bits)``: the more pessimistic of the two usable estimates.
    estimated_bits: Annotated[float, Field(ge=0)]
    limitations: tuple[str, ...]


class PolicyViolation(_Model):
    rule: PolicyRule
    message: str
    required: int | None = None
    actual: int | None = None


class PolicyResult(_Model):
    compliant: bool
    violations: tuple[PolicyViolation, ...]


class RiskComponent(_Model):
    """One line of the risk score's bill of materials."""

    factor: RiskFactor
    points: Annotated[int, Field(ge=0, le=100)]
    max_points: Annotated[int, Field(ge=0, le=100)] | None
    explanation: str


class RiskAssessment(_Model):
    """``score`` is exactly the sum of ``components[*].points`` (0 = no risk, 100 = worst)."""

    score: Annotated[int, Field(ge=0, le=100)]
    level: RiskLevel
    components: tuple[RiskComponent, ...]


class Recommendation(_Model):
    code: RecommendationCode
    priority: Priority
    message: str


class PasswordAnalysis(_Model):
    """The complete, password-free result of analysing one password."""

    version: str
    length: Annotated[int, Field(ge=0)]
    strength: StrengthEstimate
    entropy: EntropyEstimate
    findings: tuple[Finding, ...]
    policy: PolicyResult
    risk: RiskAssessment
    meets_usage_target: bool
    recommendations: tuple[Recommendation, ...]
    #: Outcome of opt-in breach / reuse lookups; ``None`` when none were requested.
    exposure: ExposureSignals | None = None
