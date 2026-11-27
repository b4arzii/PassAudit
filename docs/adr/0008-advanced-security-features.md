# ADR 0008: Advanced security features (breach checks, reuse auditing, profiles, sealed reports)

- Status: Accepted (Phase 8)
- Date: 2026-11-27

## Context

Phase 8 adds privacy-preserving breach checking (k-anonymity), authorised reuse auditing against
local datasets, advanced dictionary and pattern analysis, configurable policy profiles, secure
batch processing and sanitized reporting. The binding constraints: every external integration is
opt-in; no plaintext password is ever uploaded; limitations and threat models are documented.

## Decisions

1. **The engine stays offline and pure.** Lookups happen *outside* it (`passaudit.breach`,
   `passaudit.reuse`) and enter as a small password-free value, `ExposureSignals`, which changes
   the risk score (breached floor), policy result and advice and is echoed in the result. A test
   forbids the engine importing those packages and forbids network imports anywhere except
   `breach/providers.py`.
2. **k-anonymity with the Pwned Passwords range protocol**, SHA-1 only as the data set's lookup key
   (`usedforsecurity=False`, one call site, tested). Padding, random request order, per-prefix
   dedupe, a bucket cache, a time budget and extra rate-limit cost are layered on top. Chosen over
   sending hashes or using a vendor SDK: smallest disclosure, no new dependency (`urllib`
   with a hand-built HTTPS-only, redirect-refusing opener).
3. **Opt-in twice.** Server flag *and* per-request choice. The online provider is not even
   constructed unless enabled. A local sorted hash file gives the same answer with no network and
   needs no flag. The UI never remembers the choice; the CLI needs `--allow-external`.
4. **Unchecked is not clean.** Failed lookups are `unavailable`; policy rules needing a lookup
   are `unchecked`; the UI and reports word them so. A breach raises risk to the known-weak floor;
   absence never lowers it.
5. **Reuse index = keyed HMAC digests + names**, key in a separate file, explicit authorisation
   statement recorded and required (also to start the API feature). No work factor: it is an
   auditing index; the cost of that trade-off is in security.md. The API never takes a dataset
   path from a request.
6. **Dictionaries as data, matching as code.** Bundled word/name lists plus operator lists; a
   bounded DP segmenter finds joined words (with separators and leetspeak); a false-positive test
   guards against noise. `block_dictionary_words` is off by default (passphrases are good).
7. **Profiles are data**: a pure model/registry in the engine, file loading outside it, no shadowing
   of built-in names, unknown fields rejected, errors that redact field names. Presented as
   "inspired by", never as compliance.
8. **Reports: construct, inspect, seal.** Whitelisted entries; a final scan that refuses a report
   containing submitted secrets (fixed vocabulary and the engine's template fields exempt, or a
   weak password like `short` would trip over the engine's own words); a SHA-256 checksum that is
   explicitly not a signature (named `checksum` because the CLI security tests forbid
   hash/digest-like keys in reports).
9. **Batch duplicate detection without plaintext sets**: `ReuseTracker` replaces
   `reused_passwords` (removed), keeping only keyed digests under a per-run random key.

## Consequences

* A default deployment is unchanged: no network, no datasets, `exposure: null`.
* Operators who enable online checks accept the residual disclosure listed in the threat model.
* The guard's exemptions mean a bug that leaks input *into an engine template field* would not be
  caught by it; those fields are covered by the engine's canary tests.
* New API surface: `/capabilities`, `/policy/profiles[/{name}]`, `/audit/report`, and
  `profile` / `exposure` request fields; error codes `external_lookups_disabled`,
  `feature_unavailable`, `unknown_profile`.
