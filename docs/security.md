# PassAudit Security Model

PassAudit handles passwords, so its own security posture matters more than most tools.
This document states the rules the code must follow and what Phases 1-4 already enforce.

## Assets

| Asset                         | Sensitivity | Rule                                                      |
| ----------------------------- | ----------- | --------------------------------------------------------- |
| Password under analysis       | Critical    | Memory only, shortest possible lifetime, never logged/stored |
| Derived values (hashes, etc.) | High        | Treated like the password unless proven otherwise          |
| Audit results                 | Medium      | May reveal weakness patterns; do not include the password  |
| Configuration / `.env`        | Medium      | Never committed; no secrets in `VITE_*` variables          |

## Non-negotiable rules for future code

1. **Never log a password** or anything derived from it - not at debug level, not in exceptions.
   Exception messages and validation errors must not echo input values.
2. **Never persist plaintext passwords** (disk, DB, caches, temp files, crash dumps).
3. **POST bodies only.** Passwords never appear in URLs, query strings or headers. In the
   CLI the equivalent rule is: **never in argv** - input comes from a hidden prompt, stdin
   or a file.
4. **Bound all input.** Enforce `PASSAUDIT_MAX_PASSWORD_LENGTH` and request size limits before
   doing any work, to prevent resource exhaustion.
5. **No outbound network calls by default.** External lookups are opt-in
   (`PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED=false`) and must use k-anonymity-style protocols.
6. **No dynamic code execution** on user input (`eval`, `exec`, `pickle`, shell, unsafe YAML).
7. **Constant-time comparison** (`hmac.compare_digest`) whenever secrets are compared.
8. **Frontend:** never place the password in `localStorage`, `sessionStorage`, URLs, analytics
   or error reporters; clear it from component state after use. Since Phase 7 this is enforced
   end to end (see "Browser handling of passwords" below): the form is cleared after a
   successful request, the API client sends passwords only in a POST body and logs nothing, and
   the only `localStorage` keys are UI preferences and the policy *rules*.

## Controls in place (Phases 1-9)

| Control                         | Where                                    | Verified by                       |
| ------------------------------- | ---------------------------------------- | --------------------------------- |
| Loopback-only bind by default   | `config.py` (`host=127.0.0.1`)           | `test_default_settings_are_conservative` |
| Explicit CORS allow-list, no credentials | `main.py`                       | `test_cors_*`                     |
| Baseline security headers (`nosniff`, `DENY`, `no-referrer`, `no-store`, restrictive CSP) | `main.py` | `test_security_headers_are_applied` |
| API docs disabled in production | `main.py`                                | `test_docs_disabled_in_production` |
| Typed, validated configuration  | `config.py` (pydantic)                   | `test_invalid_port_is_rejected`   |
| Static security analysis        | ruff `S` rules + bandit                  | `scripts\audit.ps1`, `check.ps1`  |
| Dependency vulnerability audit  | pip-audit, `npm audit`                   | `scripts\audit.ps1`               |
| Secrets kept out of git         | `.gitignore` (`.env`, keys, `/data/`, DBs) | -                               |
| No stray `print` / `console.*`  | ruff `T20`, ESLint `no-console`          | lint                              |
| Analysis results never contain the password or personal info | `analysis/models.py` (positions + fixed templates only) | `analysis/test_security.py` |
| Secrets masked in `repr`/JSON; validation errors don't echo input | `SecretStr`, `hide_input_in_errors` | `analysis/test_security.py` |
| Engine never logs/prints/persists and never imports web code | AST + runtime tests | `analysis/test_security.py` |
| zxcvbn's global `user_inputs` scrubbed, calls serialised | `analysis/strength.py` | `analysis/test_entropy_strength.py` |
| Bounded analysis cost (input cap, zxcvbn truncation, a work budget for leetspeak-dense input, capped output) | `analysis/analyzer.py`, `strength.py` | `analysis/test_analyzer.py`, `analysis/test_entropy_strength.py` |
| API passwords only in JSON `POST` bodies; query strings, non-JSON bodies and oversized bodies rejected | `api/middleware.py` (`RequestGuardMiddleware`) | `api/test_guards.py` |
| API never logs bodies/URLs/headers; uvicorn access log disabled; unknown paths logged as `[unmatched]` | `api/middleware.py`, `main.py` | `api/test_privacy.py` |
| API errors never echo input (locations only; unknown field names redacted; 500s generic) | `api/errors.py` | `api/test_guards.py`, `api/test_privacy.py` |
| API local-only: loopback bind enforced, Host allow-list, exact-origin CORS without credentials | `config.py`, `api/middleware.py`, `main.py` | `api/test_config_and_openapi.py`, `api/test_guards.py` |
| API rate limiting (per client, cost per password) and bounded analysis concurrency | `api/ratelimit.py`, `api/service.py` | `api/test_ratelimit.py` |
| API layer reuses the engine and cannot duplicate or bypass it | architecture tests | `api/test_architecture.py` |
| Frontend: fonts/CSS/JS all same-origin (no CDN, no third-party requests); theme bootstrap is an external script so `script-src 'self'` stays possible; only UI preferences are persisted | `frontend/` (bundled `@fontsource-variable`, `public/theme-init.js`) | `App.test.tsx`, real-browser origin check |
| Frontend: passwords only in a `POST` body (never URL/headers); `no-store`, `credentials: omit`, `no-referrer`; the client logs nothing and error text is fixed or the server's sanitised message | `frontend/src/api/client.ts` | `api/client.test.ts`, `integration.test.tsx`, real-browser run |
| Frontend: password and personal details held in component state only, cleared after success (opt-out is memory-only), never in storage, URLs, console, session history or exports | `pages/*Page.tsx`, `state/` | `integration.test.tsx` leak scans, real-browser run (152 checks) |
| Frontend: reports built from results only (no password field exists to leak), CSV formula guard, safe file names, demo data marked synthetic in file and name | `lib/export.ts` | `lib/logic.test.tsx`, `integration.test.tsx` |
| Frontend: stale or duplicate requests cannot overwrite newer results; submit is ignored while loading | `lib/useAsyncAction.ts`, `Button` `loading` | `lib/logic.test.tsx`, `integration.test.tsx` |
| Network code exists in exactly one module; the engine, reuse and reporting packages cannot import it; no HTTP client is loaded by importing them | `breach/providers.py` | `test_phase8_architecture.py` |
| External lookups are opt-in twice (server flag + per-request / CLI confirmation); disabled requests fail with `403` before any work | `api/service.py`, `cli/extras.py` | `api/test_phase8.py`, `cli/test_phase8_cli.py` |
| Breach protocol sends only a 5-character prefix; https only, no redirects, size cap, strict parsing, fixed-text errors | `breach/providers.py`, `breach/checker.py` | `breach/test_providers.py`, `breach/test_checker.py`, `api/test_phase8.py` |
| Reuse index holds only HMAC digests + names; authorisation statement required and recorded; wrong key / malformed file rejected | `reuse/index.py` | `reuse/test_index.py` |
| Reports are whitelisted, leak-guarded and sealed | `reporting/sanitized.py` | `reporting/test_sanitized.py`, `cli/test_phase8_cli.py` |
| Batch duplicate detection keeps only keyed digests | `analysis/batch.py` | `analysis/test_phase8_exposure_profiles.py` |
| Frontend build ships a strict CSP (`default-src 'none'`, `script-src 'self'`, `connect-src 'self'`, no inline script or `eval`); `vite preview` serves the full header incl. `frame-ancestors 'none'` | `frontend/csp.ts`, `frontend/vite.config.ts` | `styles/csp.test.ts`, real-browser run (blocked cross-origin `fetch`, inline script, `eval`, foreign image; no violations from the app itself) |
| Every route that can trigger an online lookup (`/audit`, `/policy/validate`, `/audit/batch`, `/audit/report`) pays the extra rate-limit cost | `api/v1.py` | `api/test_phase8.py::test_online_checks_cost_extra_rate_limit_units` |
| Malformed `Content-Length` (including non-ASCII digits) is a `400`, never a crash | `api/middleware.py` | `api/test_guards.py` |
| Every POST route survives mutated, type-swapped and hostile bodies: no 5xx, no echo of the password, uniform error envelope | seeded fuzz | `api/test_fuzz.py` (`PASSAUDIT_FUZZ_ITERATIONS` for deep runs) |
| One definition of the report-safe analysis fields, shared by the API and CLI reports | `reporting/sanitized.py` (`analysis_summary`) | `reporting/test_sanitized.py` |
| Containers: API on an internal network (no published port, no internet route), web published on `127.0.0.1` only; non-root, read-only, no capabilities; nginx logs no request lines and never spools bodies to disk | `Dockerfile`, `docker-compose.yml`, `docker/nginx.conf` | `docker/smoke_test.py` (24 checks against a running stack; run in CI), [docker.md](docker.md) |
| Empty environment values mean "not set" (an empty path never becomes the current directory) | `config.py` | `api/test_config_and_openapi.py` |
| CLI accepts no password via argv; stray arguments rejected without echo | `cli/app.py` (`SafeGroup`), command signatures | `cli/test_basic.py`, `cli/test_security_cli.py` |
| CLI prompt hidden, on stderr, refuses non-terminals | `cli/inputs.py` | `cli/test_audit.py` |
| CLI shows no tracebacks/locals; unexpected errors print the class name only | `cli/app.py` | `cli/test_security_cli.py` |
| CLI reports are whitelisted and sanitized; labels redacted; CSV formula-injection guard; no overwrite of inputs | `cli/reports.py`, `cli/inputs.py` | `cli/test_security_cli.py`, `cli/test_batch.py` |

## Threat model (summary)

| Threat                                    | Mitigation / status                                               |
| ----------------------------------------- | ----------------------------------------------------------------- |
| Other machines reach the API              | Loopback bind. **If ever exposed, authentication is required first.** |
| Malicious website calls the local API (CSRF / DNS rebinding) | Exact-origin CORS (no credentials), JSON-only bodies (forces a preflight), **Host-header allow-list**, loopback bind |
| Password leaks via logs/telemetry         | Rules 1-2 above; engine redaction tests exist (Phase 2). **The API layer must not log request bodies or validation `input`.** |
| Password sent to third party              | Opt-in only, k-anonymity, documented per integration              |
| Password sent to the breach service in clear | Never: only a 5-character hash prefix leaves the machine; see "Breach checking" for what the prefix reveals |
| Resource exhaustion via huge inputs       | Engine enforces its own cap (`AnalyzerConfig.max_input_length`, default 1024) before any work and bounds zxcvbn cost; the API adds body-size limits, a rate limiter charged per password, and bounded concurrency |
| Vulnerable/compromised dependency         | Minimal runtime deps, version ranges, audit scripts, lockfile (npm) and snapshot (pip) |
| Secret committed by accident              | `.gitignore`, `.env.example` only                                 |

## Browser handling of passwords

What the web UI does with a password, step by step:

1. **Typing:** the field is `type="password"` with autocomplete, autocapitalize and autocorrect
   off and spell-check off; the value lives in the React state of the one page that owns it
   (`PasswordInput` itself keeps no value). The browser's own reveal button is hidden so the
   labelled show/hide toggle is the only one.
2. **Sending:** one `POST` with a JSON body to the same-origin `/api/v1/...` (the Vite dev proxy
   in development). No query string, no custom header, `Referrer-Policy: no-referrer`, no cookies.
3. **After success:** the password (and the pasted batch list / loaded file entries) is cleared
   from state. Personal details stay in their field so repeat audits are easy; they are never
   persisted. *Settings -> Privacy* has an opt-in to keep the password in the field as well
   (memory only; still never stored).
4. **After failure:** the input is kept in the form (memory only) so *Retry* works; nothing is
   written anywhere.
5. **Results:** the engine returns positions, scores and fixed advice. The in-memory *session*
   (used by the overview) keeps results only and is bounded to 25 runs; a reload or *Clear
   session results* drops it.
6. **Files and exports:** a password file is read in the browser, parsed, never displayed, and
   discarded after the audit. Reports are generated client-side from results; they contain no
   password, no personal details and no password-derived values, and are marked `sanitized`.
7. **Persisted:** theme, sidebar state, two privacy toggles, and the *policy rules*
   (`passaudit.policy`). A test fails if any other key appears.

Limits of this protection: browser extensions, a compromised machine, screen capture, and
JavaScript's inability to wipe strings from memory (the value is garbage-collected, not zeroed).
The batch box is a plain text area, so its content is visible on screen while typed; use
*Upload file* to keep a list off the screen.

## Phase 8: exposure checks, reuse auditing and sanitized reports

Everything here is **opt-in**. A default install makes no network connection, reads no dataset and
looks nothing up. Each feature needs the operator to configure it *and* the caller to ask for it.

### Breach checking (k-anonymity)

**Purpose:** tell a user that a password is already in public breach data - the strongest single
signal that it must not be used - without handing the password to anyone.

**Protocol** (`passaudit.breach`, the only package allowed to touch the network):

1. The server hashes the password with SHA-1 (the lookup key of the Pwned Passwords data set;
   it is not used to protect anything, so SHA-1's weaknesses are irrelevant here).
2. It asks the range service for **only the first 5 hex characters** (20 bits) of that hash:
   `GET https://<host>/range/5BAA6`, with `Add-Padding: true` and a generic `User-Agent: PassAudit`.
3. The service returns every hash *suffix* in that bucket (about a thousand real ones, plus
   padding entries with count 0 so the response size does not reveal the bucket's real size).
4. The server looks for the password's 35-character suffix **locally**.

The password, its full hash, its suffix and the verdict never leave the machine.

**Opt-in, twice, and visible:**

| Layer | What it does |
| --- | --- |
| Server setting | `PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED=true` must be set; otherwise the online provider is never even constructed, and a request for it is refused with `403 external_lookups_disabled` before any work |
| Per request | the caller must send `exposure.breach = "online"` (API), tick the option (web UI - not remembered), or pass `--breach online --allow-external` (CLI, which also prints what is sent) |
| Local alternative | `exposure.breach = "local"` searches a hash file on the server (binary search, no loading, no network) and needs no external flag |

**Transport hardening** (`HibpRangeProvider` / `urllib_transport`): the URL must be `https` with no
credentials, query or fragment; certificates are verified; the HTTP opener contains only HTTPS
(plus environment proxy settings) - no plain HTTP, `file:` or `ftp:` handlers; **redirects are
never followed** (a redirect could carry the prefix elsewhere); no cookies, no auth headers, no
referrer; responses are capped (2 MiB), timed out (5 s) and parsed strictly (any malformed line
rejects the whole response); every failure becomes a fixed-text error with no URL, host or prefix.

**Request shaping** (`BreachChecker`): one request per distinct prefix; prefixes queried in
**random order** (the order of requests does not reveal the order of a batch); a small cache of
public bucket data (prefix to suffixes; no password, no checked hash) limits repeat disclosure;
a per-batch time budget and prefix cap bound what one call can send; an online check costs
**extra rate-limit units**, so the local API cannot be used as a cheap proxy to the service.

**Failure semantics:** a lookup that cannot complete is reported `unavailable` - the password is
*unchecked*, never "clean" - and the audit itself still succeeds. A rule such as
`block_breached_passwords` is reported **`unchecked`**, not passed, when no check ran.

#### Threat model: what the range service (or someone watching it) can learn

| Observer | Learns | Mitigation | Residual risk |
| --- | --- | --- | --- |
| The range service operator | that a check happened, when, and from which address; the 5-character prefix (20 bits) | prefix only; padding; random order; dedupe; cache; generic client | the prefix is 20 bits of the hash: an operator who already has *candidate* passwords can test whether a candidate is consistent with it. Do not use the online check for secrets whose guessability matters more than their exposure |
| A batch: the service sees the *set* of prefixes | roughly how many distinct passwords were checked together, and when | random order; bounded batch size | the set of prefixes is a fingerprint of the batch |
| A network observer | the destination host and approximate timing/volume | TLS; response padding hides bucket size | the host is visible (and SNI); traffic analysis of timing |
| A malicious or compromised service | can send a crafted bucket to make a breached password look clean (or the reverse) | strict response parsing; the result only ever *raises* risk (breached floor) or is informational | a forged "clean" gives false comfort: **"not found" is never a guarantee** |
| A TLS-intercepting proxy, DNS provider | same as a network observer; the proxy can read the prefix | certificate verification | corporate interception defeats transport privacy; use the local dataset instead |
| Malware or an attacker on this machine | everything: it can read the password before PassAudit does | out of scope | - |

**Choose the local dataset when** the password is highly sensitive, the machine is offline, or
policy forbids any external lookup. Download the Pwned Passwords offline file (sorted by hash),
point `PASSAUDIT_BREACH_LOCAL_FILE` at it; start-up spot-checks that it is sorted.

#### Limitations of breach checking

* It finds passwords *in the consulted corpus*; absence proves nothing. Counts are lower bounds.
* The corpus holds leaked passwords, not "weak" ones: a never-leaked password can still be
  trivially guessable (that is what the strength and pattern analysis is for).
* The online service is a third party: you trust its availability and honesty (see above).
* A password that is breached **in one place** is flagged everywhere; the check cannot tell
  whether *this* account was exposed.
* The CLI keeps the checked passwords in memory until its report is built (for the final leak
  guard) and then clears the list; Python cannot wipe the underlying strings.

### Authorized reuse auditing (local datasets)

**Purpose:** an organisation that is *authorised* to hold password data from several systems
(an internal audit, with the data owners' agreement) can ask which audited passwords are already
present in those datasets - reuse across systems is a top cause of account takeover.

* `passaudit reuse build` turns datasets into a **reuse index**: every password becomes an
  **HMAC-SHA-256** digest under a random 32-byte key stored in a **separate key file**
  (exclusive create, owner-only mode requested). The index records dataset *names*, counts, a
  random id, the creation time, the authorisation reference and the digests - no plaintext, no
  unkeyed hash (a test searches the file for the MD5/SHA-1/SHA-256/SHA-512 of every password).
* Using it needs **`--confirm-authorized` and `--authorization-ref`** (API: the operator must set
  `PASSAUDIT_REUSE_AUTHORIZATION_REFERENCE` - start-up fails without it). PassAudit **cannot
  verify authorisation**; it makes the claim explicit and records it in the index header and in
  every report that used the index.
* The API never accepts a dataset path from a request: the index and key are operator-configured
  at start-up (no arbitrary file read), and a wrong key or malformed index stops the server.
* Results name datasets (`["hr-export", "vpn"]`) and nothing else.

| Scenario | Outcome |
| --- | --- |
| Index file stolen, key not | cannot be searched; brute-forcing needs the 256-bit key |
| Index **and** key stolen | an attacker can test guesses at full HMAC speed (this is an auditing index, not a password-storage scheme: there is deliberately no work factor, so building and checking stay fast). **Protect the key like the datasets** |
| Index holder (with the key) | learns set membership, per-dataset counts, and how many digests are shared between datasets |
| Source dataset files | still plaintext wherever you keep them: delete them when the index is built |

### Advanced dictionary and pattern analysis

New findings (engine version 1.1.0, all positional, none quoting text): `date_pattern`,
`dictionary_word` (kinds `words` / `names`, match types including `segmented` - words joined with or
without separators, also through leetspeak), stepped sequences (`2468`, `acegi`), and keyboard
**walks** that change direction (`zaq12wsx`). Operators can add dictionaries
(`--dictionary` / `PASSAUDIT_DICTIONARY_PATHS`).

Limitations: bundled lists are small hand-written samples (about 280 words, 180 first names);
a password built from words that are not listed is not detected; dates are recognised only in
the formats documented in `analysis/dates.py` and a random digit run can look like a date (a
small, accepted false-positive rate that adds two risk points and affects no default policy
rule); keyboard walks ignore the numeric keypad (its digits are mostly "adjacent") and
multi-row jumps such as `qweasdzxc`; a false-positive test keeps random 12-20 character
passwords below 2% for dates and words. `block_dictionary_words` is off by default because long
word passphrases are good passwords.

### Policy profiles

Named, documented policies: built-in `default`, `nist-inspired`, `enterprise`, `high-security`,
`passphrase`, `legacy-complexity`, `minimal`, plus operator profiles from a JSON/TOML file. They
are *inspired by* public guidance - **not compliance certifications**. A custom profile cannot
reuse a built-in name, unknown fields are rejected, error messages redact unknown field names
(a secret used as a key by mistake is not echoed), and an unknown profile name is never echoed.

### Secure batch processing

* Duplicate detection uses `ReuseTracker`: HMAC digests under a random per-run key held only in
  that object - no plaintext set, no digests that mean anything outside the process.
* Strict, existing limits (items, bytes, length) plus: distinct-prefix cap and time budget for
  online lookups, and extra rate-limit cost for them.
* One bad item cannot corrupt the rest (CLI isolates per-entry failures); labels are sanitised
  and redacted if they contain their own password; nothing is logged.
* Honest limits: Python strings are immutable and cannot be zeroed; the CLI holds the batch's
  passwords until its report is sealed, then drops the list; a crash dump during that window
  could contain them.

### Sanitized audit reporting

Three independent layers (`passaudit.reporting`, shared by API and CLI):

1. **By construction** - reports are whitelisted fields of password-free results (scores,
   finding kinds, rule ids, advice codes, dataset names, check modes).
2. **By inspection** - the finished report is scanned for every submitted password and personal
   detail (and the 8-character head/tail of long ones); if found, the report is **refused**
   (`422` / CLI exit 4). Fixed vocabulary (enum values, field names, the engine's template text)
   is exempt, so auditing the password `password` still works; the engine's template fields
   are proven free of input by their own canary tests.
3. **By integrity** - a SHA-256 `checksum` over the report body detects accidental change or
   truncation. **It is not a signature**: anyone can recompute it.

Every report states what external checks ran (modes, host, dataset names, authorisation
reference - never any data) and carries a fixed limitations list.

## CLI-specific notes

* A password **piped** to `--stdin` can end up in shell history if typed into the command
  (`echo secret | ...`); prefer the hidden prompt or a secret manager.
* Batch input files hold passwords in plaintext on disk; treat and delete them accordingly.
  Reports never contain them.
* Typer 0.29 bundles its own Click copy; the CLI avoids importing Click and recognises its
  errors by name. Re-run `backend/tests/cli` after upgrading Typer.

## Known gaps

- No authentication - acceptable only because the service is loopback-bound and holds no data.
- The rate limiter is in-memory and per process; it does not protect a multi-worker or
  multi-host deployment (see [api.md](api.md#rate-limiting-design)).
- Reverse-proxy deployment is unsupported: `X-Forwarded-For` is not trusted and no proxy
  trust configuration exists.
- The API cannot control what a proxy, packet capture or the client logs.
- Python cannot zero strings: a password stays in process memory until garbage-collected. The
  engine keeps no reference after the call; swap files and crash dumps are out of scope.
- The bundled common-password list is a small sample; larger blocklists must be supplied by the
  operator (see [analysis-engine.md](analysis-engine.md)). Breach-corpus lookups exist (Phase 8)
  but only against a hash file or service the operator configures.
- Entropy figures are estimates with documented limitations; never present them as guarantees.
- The batch paste box is not masked (browsers offer no portable masked textarea); *Upload file* avoids showing the list.
- Online breach checks trust a third-party service and reveal a 20-bit hash prefix, timing and the caller's address to it; there is no decoy-query or Tor/anonymising transport.
- The reuse index is brute-forceable by anyone holding both index and key (no work factor, by design).
- Report integrity checksums are not signatures; there is no report signing or key management.
- Authorisation for reuse auditing is a recorded statement, not an enforced control; the API has no user identity to attach it to.
- The frontend build carries its CSP as a `<meta>` tag, which cannot express `frame-ancestors`
  (clickjacking protection). The repository has no production web server: whoever serves
  `frontend/dist/` must also send the header from `frontend/csp.ts` (`vite preview` does, for testing).
- Analysis work is bounded (about 0.5 s worst case per password) but there is no per-request
  time budget: a 50-password batch of worst-case input holds one worker for roughly 25 s, and the
  worker is not cancelled when the client disconnects. Rate limiting and the concurrency cap
  (default 2) limit the damage; the service is loopback-only.
- The reuse key file's permissions are requested (`0600`) at creation but never checked when it
  is read, and `--force` on an existing file does not tighten them (POSIX; on Windows rely on the
  folder ACL).
- Only Windows has been exercised end to end. The Python code, tests and frontend avoid
  platform-specific behaviour (explicit encodings, `pathlib`, no shell calls) and the helper
  scripts now pick `bin/python` and `npm` outside Windows, but a Linux/macOS run has not been done.
- The Python snapshot (`backend/requirements.lock.txt`) is not hash-pinned, and the Docker base
  images are pinned to a minor tag, not a digest.
- In the Docker stack every request reaches the API from the nginx container, so the per-client
  rate limit sees one client; and anyone who can use the Docker socket on the host can read
  container memory (see [docker.md](docker.md)).

## Dependency policy

- Add a runtime dependency only with a clear need; prefer the standard library.
- Pin by compatible range in `pyproject.toml` / `package.json`; commit `frontend/package-lock.json`.
- Run `scripts\audit.ps1` before releases and after dependency changes.
- Dependencies must run under Windows Application Control (see
  [ADR 0002](adr/0002-application-control-compatible-dependencies.md)).

## Reporting a vulnerability

This is a private project. Report issues directly to the maintainer; do not open public issues
containing exploit details or real credentials.
