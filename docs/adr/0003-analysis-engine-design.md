# ADR 0003: Analysis engine design

- Status: Accepted (Phase 2)
- Date: 2026-11-26

## Context

Phase 2 adds the password analysis engine. It handles the most sensitive data in the project, so
design choices are driven by three constraints: the password must never leak (logs, results,
errors, persistence); the engine must be reusable without FastAPI or the UI; and its scores must
be explainable rather than a black box.

## Decisions

1. **Plain library with typed pydantic models.** `passaudit.analysis` has no dependency on
   FastAPI, Starlette or the app modules; a test asserts this at the import level. Pydantic is
   already a dependency, so the models double as the future API schema.
2. **zxcvbn for guessability, not a home-grown estimator.** The `zxcvbn` Python port (pure
   Python, so it runs under Windows Application Control - see ADR 0002) models real attacker
   behaviour. Our own detectors (repeats, sequences, keyboard, dictionary, personal info) exist
   to *explain* weaknesses and to feed the risk score and policy, not to replace its estimate.
3. **Wrap zxcvbn defensively.** Measured behaviour that the adapter fixes:
   - it raises on `""` -> empty input is scored without calling it;
   - it caps input at 72 characters by default and its cost is super-linear (0.24 s at 100
     characters, 6.7 s at 256) -> only the first 100 characters are analysed, flagged as
     `truncated`. *(Phase 9 addendum: its leetspeak matcher makes symbol-dense input about ten
     times costlier - 2.5 s at 100 characters - so the number of characters analysed is also
     bounded by a work budget; see analysis-engine.md.)*;
   - it stores `user_inputs` in a module-global dict and never clears it -> calls are serialised
     with a lock and the entry is removed in a `finally` block.
4. **Results are redacted by construction.** Findings contain kind, start and length - never the
   matched text; descriptions, explanations and recommendations are fixed templates. Dictionary
   *rank* is deliberately omitted because rank plus a public list would reveal the word. Inputs
   use `SecretStr` and every model sets `hide_input_in_errors`.
5. **Transparent additive risk score.** Six capped components whose caps sum to 100, plus an
   explicit floor component for known-weak passwords, so `score == sum(points)` always holds and
   every point is explained. Thresholds live as named constants in `scoring.py`.
6. **Usage affects advice, not the score.** The score describes the password; the usage type
   (online account vs. encryption key) sets the strength target, length advice and extra
   recommendations (MFA, passphrase), reported via `meets_usage_target`.
7. **Entropy is reported with its caveats.** Three estimates are exposed, the combined figure is
   the minimum of the two usable ones, and every result carries the limitations text.
8. **NIST-style default policy.** Length minimum, blocklist and strength score on; composition
   rules (upper/lower/digit/symbol) are available but off by default.
9. **Small bundled dictionary + pluggable lists.** A ~540-entry curated list ships in the
   package; operators can load larger lists from a file. The engine performs no network I/O.
10. **Bounded work everywhere.** Input cap checked before any processing; de-leet variants capped
    at 64; embedded dictionary hits capped at 8; repeat detection prefilters on first character.

## Consequences

- One new runtime dependency (`zxcvbn`, pure Python).
- zxcvbn internals (`zxcvbn.matching.RANKED_DICTIONARIES`) are touched in one module; the
  dependency is pinned `>=4.5,<5` and tests fail if that behaviour changes.
- Keyboard detection finds straight runs only; direction-changing walks are priced by zxcvbn but
  not listed as findings. Sequences are +-1 steps only. Both are documented limitations.
- The API phase must keep the no-logging rule (no body logging, no validation `input` echo).
