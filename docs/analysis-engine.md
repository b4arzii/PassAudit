# Password Analysis Engine

> Status: **implemented in Phase 2.** Package: `backend/src/passaudit/analysis/`.
> Not yet exposed over HTTP and not used by the frontend - that is later-phase work.

The engine takes one password (plus optional policy and context) and returns a fully typed,
**password-free** report: strength, entropy, detected weaknesses, policy compliance, a
transparent risk score and prioritised recommendations.

It is a plain Python library. It does not import FastAPI, Starlette, `passaudit.main` or
`passaudit.config`, and nothing in it knows about React. (Both properties are enforced by tests.)

## Quick start

```python
from pydantic import SecretStr
from passaudit.analysis import (
    AnalysisContext,
    PasswordPolicy,
    PasswordUsage,
    analyze_password,
)

result = analyze_password(
    "Summer2024!",
    policy=PasswordPolicy(min_length=14),
    context=AnalysisContext(
        usage=PasswordUsage.ONLINE_ACCOUNT,
        personal_info=(SecretStr("Jane Doe"), SecretStr("jdoe@example.com")),
    ),
)

result.risk.score  # 0 (no risk) .. 100 (compromised)
result.risk.level  # RiskLevel.LOW / MODERATE / HIGH / CRITICAL
result.strength.score  # zxcvbn 0..4
result.policy.violations  # which rules failed
result.recommendations  # ordered, context-aware advice
```

For repeated use, or to inject a custom word list or limits, build an analyzer once:

```python
from passaudit.analysis import AnalyzerConfig, PasswordAnalyzer, WordList

analyzer = PasswordAnalyzer(
    AnalyzerConfig(max_input_length=settings.max_password_length),  # wire to Settings later
    wordlist=WordList.from_file("my-blocklist.txt"),
)
analyzer.analyze_password("hunter2")
```

`analyzer.analyze(AnalysisRequest(...))` is the fully typed entry point (the password is a
`SecretStr`); `analyze_password(str, ...)` is a convenience wrapper over it.

## What it does

| Capability | Module | Notes |
| --- | --- | --- |
| Strength / guessability | `strength.py` | zxcvbn score 0-4, `log10(guesses)`, crack-time estimates, per-segment explanation, zxcvbn's own warning/suggestions |
| Entropy estimation | `entropy.py` | charset, Shannon and guess-based bits; **read the limitations below** |
| Repeats | `patterns.py` | `aaa` (3+), repeated blocks `abab`, `abcabc`; case-insensitive |
| Sequences | `patterns.py` | `abc`, `4321`; +-1 steps, letters or digits, no wrap-around |
| Keyboard patterns | `keyboard.py` | straight runs of 4+ adjacent keys on QWERTY, QWERTZ, AZERTY, Dvorak and keypad layouts; shifted keys map to their base key |
| Dictionary weak passwords | `wordlist.py` | exact, reversed, leetspeak, decorated (`Password123!`), embedded; local list only |
| Personal information | `personal.py` | caller-supplied strings found forwards, reversed or via leetspeak |
| Policy validation | `policy.py` | 14 configurable rules (below) |
| Risk scoring | `scoring.py` | transparent, fixed-weight, sums to the reported score |
| Recommendations | `recommendations.py` | driven by findings, policy, usage and reuse flag |
| Typed I/O | `models.py` | frozen, `extra="forbid"` pydantic models |

### Models at a glance

```
AnalysisRequest(password: SecretStr, policy: PasswordPolicy, context: AnalysisContext)
        |
        v   PasswordAnalyzer.analyze()
PasswordAnalysis
 |- version, length, meets_usage_target
 |- strength: StrengthEstimate     score, label, guesses_log10, crack_times, segments, warning, suggestions, truncated
 |- entropy:  EntropyEstimate      pool_size, charset_bits, shannon_bits, guess_bits, estimated_bits, limitations
 |- findings: tuple[Finding]       kind, start, length, description (+ match_type | repeat_count | direction | layout)
 |- policy:   PolicyResult         compliant, violations[rule, message, required, actual]
 |- risk:     RiskAssessment       score, level, components[factor, points, max_points, explanation]
 `- recommendations: tuple[Recommendation]   code, priority, message
```

`AnalysisContext` carries `usage` (`general`, `online_account`, `privileged_account`,
`master_password`, `encryption_key`), `personal_info` (up to 50 strings of at most 256 characters,
held as `SecretStr`) and `reused_elsewhere`.

## Password policy

`PasswordPolicy` defaults follow NIST SP 800-63B-style guidance: a length minimum, a blocklist
check and **no** mandatory character-class mix. `None`, `0` or `False` disables a rule.

| Field | Default | Rule enforced |
| --- | --- | --- |
| `min_length` | 12 | at least N characters |
| `max_length` | none | at most N characters (must be >= `min_length`) |
| `min_lowercase` / `min_uppercase` / `min_digits` / `min_symbols` | 0 | at least N of that class |
| `min_unique_characters` | 0 | at least N distinct characters |
| `max_repeat_run` | none | longest run of one character (case-insensitive) |
| `max_sequence_length` | none | longest ascending/descending letter or digit run |
| `max_keyboard_run` | none | longest straight keyboard run |
| `allow_whitespace` | `True` | `False` rejects any whitespace |
| `block_common_passwords` | `True` | no dictionary finding of any kind |
| `forbid_personal_info` | `True` | no personal-information finding |
| `min_strength_score` | 2 | zxcvbn score at least N (0 disables) |

Boundaries are inclusive: with `min_length=12`, 11 characters fail and 12 pass; with
`max_repeat_run=3`, `aaa` passes and `aaaa` fails.

## Risk scoring (fully transparent)

`risk.score` is an integer from 0 (no detected risk) to 100 (certainly compromised) and is
**exactly the sum of `risk.components[*].points`**. Component caps add up to 100.

| Factor | Max | How points are earned |
| --- | --- | --- |
| `guessability` | 50 | `50 * (1 - min(guesses_log10, 12) / 12)` from zxcvbn |
| `length` | 10 | under 8 chars: 10; under 12: 6; under 16: 3; otherwise 0 |
| `common_password` | 15 | exact 15, reversed 12, leetspeak 12, decorated 10, embedded 5 (summed, capped) |
| `patterns` | 10 | repeat 3, sequence 3, keyboard 4 per finding (summed, capped) |
| `personal_info` | 10 | 10 if the password contains supplied personal information |
| `policy` | 5 | 1 per violated rule (capped) |
| `known_weak_floor` | - | added only when it changes the score (see below) |

**Floor.** A password that *is* (exact/reversed/leetspeak) or is *decorated from* a listed word
covering at least 60% of its length can never score below 85, however many points the other
factors give it; an empty password is fixed at 100. The extra points appear as their own
`known_weak_floor` component so the sum rule still holds. Merely *containing* a listed word
(`embedded`) never triggers the floor.

**Levels:** 0-19 `low`, 20-39 `moderate`, 40-69 `high`, 70-100 `critical`.

The score is deliberately about the *password*: `usage` does not change it. Usage changes the
recommendations and `meets_usage_target` instead (below).

## Context-aware recommendations

| Usage | Strength target (`log10 guesses`) | Recommended minimum length | Extra advice |
| --- | --- | --- | --- |
| `general` | 8 | 12 | password manager if risk is not low |
| `online_account` | 8 | 12 | + enable MFA (low priority) |
| `privileged_account` | 10 | 16 | + enable MFA (medium priority) |
| `master_password` | 12 | 16 | passphrase of 5+ random words if under target or under 20 chars |
| `encryption_key` | 14 | 20 | as above |

The length target is the larger of this column and `PasswordPolicy.min_length`. Throttled online
targets need fewer guesses to resist than secrets an attacker can test offline, hence the ladder.
`reused_elsewhere=True` always yields a top-priority "never reuse" recommendation. Advice is
sorted high -> medium -> low; a result with nothing to flag contains a single `looks_good` item.
All messages are fixed templates.

## Entropy: what the numbers mean and where they mislead

`EntropyEstimate.limitations` carries these caveats in every result.

* **`charset_bits`** = `length * log2(pool)`. Valid only for a password generated by drawing
  characters uniformly at random. For human-chosen passwords it wildly overstates strength:
  `Password1!` scores about 65 bits yet is guessed almost instantly.
* **`shannon_bits`** measures how evenly characters are used *within this one string*. It is
  capped at `length * log2(length)` for short strings and says nothing about attacker effort.
* **`guess_bits`** = `log2` of zxcvbn's guess estimate. It models real attacker behaviour and is
  the figure to trust, but it is still a statistical estimate, not a guarantee.
* **`estimated_bits`** = `min(charset_bits, guess_bits)`: never more optimistic than either.
* Non-ASCII characters are credited with a flat, rough 100-symbol allowance.
* Entropy describes how a password was *generated*. A string that merely looks random but is
  already in a leak is weak regardless of any number here.

## Detection details and known limitations

* **Case-insensitive, length-preserving.** Matching lower-cases one character at a time so
  positions in findings always map back onto the original password.
* **Sequences** only step by +-1 within ASCII letters or digits. `246`, `acegi` and non-Latin
  alphabets are not flagged as sequences (zxcvbn may still price them in `guess_bits`).
* **Keyboard runs** must be straight lines. Walks that change direction (`qazwsx`) are not
  reported as findings, although zxcvbn's spatial matcher still lowers their strength. Only the
  five listed layouts are known; runs that are plain sequences (`1234`) are reported as
  sequences, not keyboard patterns.
* **Dictionary** is a sample, not the world. The bundled list
  (`analysis/data/common_passwords.txt`, ~540 entries) is small by design; zxcvbn adds its own
  ~30,000-entry frequency lists to the *strength* estimate. For serious blocklisting load a
  larger list with `WordList.from_file()`. Embedded matches need `min_embedded_word_length`
  (default 5) characters to limit false positives, and at most 8 are reported.
* **Leetspeak** covers `0 1 3 4 5 7 8 9 @ $ ! | +`; ambiguous characters (`1`, `!`, `|`) are tried
  as both `i` and `l`. At most 64 readings are tried per string.
* **Personal information** is matched only against strings the caller supplies, for tokens of at
  least 3 characters (so `ab` is never searched for). Common URL/e-mail fragments (`com`, `www`...)
  are ignored.
* **Unicode:** length is counted in code points, not grapheme clusters or bytes. No NFC/NFKC
  normalisation is applied, so visually identical strings can differ.
* **Truncation:** only the first `zxcvbn_max_chars` (default 100) characters go to zxcvbn
  because its cost grows steeply (about 0.25 s at 100 plain characters, over 6 s at 256).
  `strength.truncated` flags this; the estimate is then a lower bound.
* **Leetspeak work budget (Phase 9).** zxcvbn re-runs its dictionary search once per way of
  reading the leet symbols in the password (`4`/`@` as `a`, `1`/`!`/`|` as `i` or `l`, ...), so a
  100-character password made of such symbols took about 2.5 s - ten times plain text. The
  adapter bounds the number of readings (the product of candidate symbols per letter) times the
  length to a fixed budget, and analyses fewer characters (never fewer than 32) when it is
  exceeded; ordinary passwords have one reading and keep the full 100. The result is flagged
  `truncated` and is a lower bound, exactly as for a long password.
* **No breach lookup in the engine.** Whether the password appears in a real breach corpus is
  decided outside it (`passaudit.breach`, opt-in; see [security.md](security.md)) and passed in
  as `ExposureSignals`.

## Phase 8 additions (engine version 1.1.0)

* **New findings:** `date_pattern`; `dictionary_word` (`dictionary` = `words` / `names`; match types
  as before plus `segmented`); stepped sequences are `sequence` findings with `step` 2 or 3;
  keyboard *walks* are `keyboard_pattern` findings described as a "connected path".
* **Dictionaries** (`analysis/dictionaries.py`): a `DictionarySet` of bundled `common_words.txt` and
  `first_names.txt` plus operator lists. Segmentation (`CorrectHorseBattery!1`,
  `planet-basket_desert7`, `c0rr3cth0rs3b4tt3ry`) is a bounded dynamic programme over letters
  (cost linear in the input, capped at 128 characters). Whole-password matches of the common
  password list suppress word findings so nothing is reported twice.
* **Scoring:** dates and dictionary words add 2 points each to the *patterns* component (still
  capped at 10). A breach (from `ExposureSignals`) applies the known-weak floor of 85.
* **Policy:** `block_dictionary_words` (60%+ dictionary coverage; off by default) and
  `block_breached_passwords` (off by default; `unchecked` without a breach check).
* **Recommendations:** `avoid_dates`, `avoid_dictionary_words` (only when the password also misses its
  usage target - a long random-word passphrase is not nagged), `change_breached_password`.
* **Exposure signals:** `analyze(request, exposure=ExposureSignals(...))` takes the password-free
  results of opt-in lookups (see `passaudit.breach`, `passaudit.reuse`). The engine performs no
  lookup itself.
* **Profiles** (`analysis/profiles.py`): `PolicyProfile`, `ProfileRegistry`, `BUILTIN_PROFILES`.
* **Batch:** `ReuseTracker` replaces `reused_passwords`; `analyze_batch(..., exposures=...)`.

Detection limits are listed in [security.md](security.md#advanced-dictionary-and-pattern-analysis).

## Security guarantees (and the tests that enforce them)

| Guarantee | How | Test |
| --- | --- | --- |
| Result never contains the password, or any fragment of it | Findings hold positions/lengths/kinds only; free text comes from fixed templates; zxcvbn segments carry no tokens | `test_security.py::test_serialised_result_never_contains_the_password`, `..._no_fragment_...` |
| Personal information never echoed | stored as `SecretStr`, used only for matching | `test_personal_info_never_appears_in_the_result` |
| Secrets masked in `repr`/JSON | `SecretStr` fields | `test_context_masks_personal_info`, `test_request_model_masks_password_everywhere` |
| Validation errors don't echo values | `hide_input_in_errors=True` on every model | `test_validation_errors_do_not_echo_input_values` |
| Engine exceptions are content-free | `PasswordTooLongError` carries only two integers | `test_too_long_error_has_no_password_content` |
| Nothing printed or logged | no `print`/`logging`; verified at runtime and by AST scan | `test_analysis_does_not_print_or_log`, `test_source_has_no_logging_printing_or_dynamic_execution` |
| Nothing persisted | no file writes, no caches; analyzers hold only config + word list | `test_only_the_wordlist_module_touches_the_filesystem`, `test_no_result_caching_on_public_functions` |
| No state leaks between analyses | zxcvbn's global `user_inputs` is serialised under a lock and always scrubbed | `test_zxcvbn_global_state_is_scrubbed_*`, `test_personal_tokens_do_not_leak_between_concurrent_analyses` |
| Bounded work | input cap checked first; zxcvbn truncated; detector output capped | `test_limit_is_checked_before_any_expensive_work`, `test_maximum_length_input_finishes_quickly` |
| Independent of web/UI | no FastAPI/Starlette/app imports, even transitively | `test_engine_does_not_import_the_web_application`, `test_importing_the_engine_does_not_load_fastapi_or_the_app` |

**Python caveat.** Strings are immutable, so the engine cannot zero a password in memory; the
copy lives until the interpreter garbage-collects it. The engine keeps no reference beyond the
call, which is the strongest guarantee Python allows.

**zxcvbn's global state.** The `zxcvbn` package writes caller-supplied `user_inputs` into the
module-level dict `zxcvbn.matching.RANKED_DICTIONARIES` and never clears it, which would keep
personal data in memory and expose it to concurrent calls. `strength.py` therefore wraps every
call in a lock and removes that entry in a `finally` block. If you upgrade zxcvbn, re-run
`test_entropy_strength.py` - the pin is `zxcvbn>=4.5,<5`.

## Integrating later (guidance for the API phase)

* Create **one** `PasswordAnalyzer` at start-up with
  `AnalyzerConfig(max_input_length=settings.max_password_length)`.
* Take the password only from a POST body; build an `AnalysisRequest` and call `analyze`.
* Map `PasswordTooLongError` to HTTP 413/422 **without** echoing input, and return
  `PasswordAnalysis.model_dump()` directly - it is safe to serialise.
* Run the analysis in a worker thread: it is CPU-bound (about 2 ms for a typical password, at
  most roughly 0.25 s for the longest 1024-character inputs measured on a development laptop).
  Calls are thread-safe; the zxcvbn step is serialised by design.
* Do not add request-body logging or Pydantic validation-error logging that includes `input`.

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/analysis          # engine tests only
.\scripts\test.ps1 -Only backend                                      # with coverage
```

`backend/tests/analysis/` has one file per concern (primitives, patterns/keyboard, wordlist,
entropy+strength, policy, scoring, recommendations, analyzer, security). Every threshold has
tests at, one below and one above the boundary (e.g. length 7/8/11/12/15/16, repeat 2/3,
sequence 2/3, keyboard 3/4, policy minimums and maximums, the 1024/1025 input limit, the
100/101 zxcvbn truncation point, risk levels 19/20/39/40/69/70).
