# Quality assurance report (Phase 9)

A full engineering and security audit of PassAudit 0.1.0, done by reading the code, running every
automated check, and attacking the running system. Every finding below was reproduced before it
was fixed, and every fix has a regression test unless stated otherwise.

## Summary

| Area | Result |
| --- | --- |
| Backend tests | **1169 passed**, 98% line+branch coverage (ruff, mypy `--strict`, bandit clean) |
| Frontend tests | **298 passed** in 12 files (ESLint, Prettier, `tsc` clean; production build succeeds) |
| Dependency vulnerabilities | `pip-audit`: none known; `npm audit`: 0 vulnerabilities |
| Fuzzing | 16,000 mutated requests across the 4 POST routes and 6,000 random Unicode passwords through the engine: no 5xx, no exception, no password echoed |
| Live-server attacks | CORS, Host spoofing, rate limiting, malformed framing, log canary: all behave as designed (details below) |
| Real-browser checks | CSP enforced; axe-core with **all** rules (incl. contrast) on every page in both themes: 0 violations after fixes |
| Fixed in this phase | 6 defects, 3 hardening gaps, 1 stale-documentation sweep |

The final gate (`scripts\check.ps1 -Audit`) passed on the finished code. These are the Phase 9
numbers; Phase 10 added 41 release-hygiene tests (1211 backend tests in total) - see
[release-checklist.md](release-checklist.md#verification-record) for the current results.

## Findings that were fixed

| # | Severity | Finding | How it was found | Fix and guard |
| --- | --- | --- | --- | --- |
| 1 | Medium | **CPU exhaustion through leetspeak-dense input.** zxcvbn re-runs its dictionary search once per reading of the leet symbols; a 100-character password of `4@({[<69!\|1$5+7` took about 2.5 s (ten times plain text), so a 50-password batch held a worker for about 2 minutes. The existing 100-character cap did not bound it. | Profiling a 1024-character random password (1.4 s) | `strength.py` bounds readings x length to a fixed budget and analyses fewer characters (never fewer than 32); the result is flagged `truncated`. Random 1024-character input: 1360 ms to 24 ms. `test_entropy_strength.py` (5 tests, incl. a wall-clock bound) |
| 2 | Low | **`POST /policy/validate` did not pay the extra rate-limit unit** for an online breach lookup, unlike `/audit`; a client could trigger lookups at half price. | Code review; confirmed by a failing assertion | `api/v1.py` charges it. `test_online_checks_cost_extra_rate_limit_units` now covers all four routes |
| 3 | Low | **A `Content-Length` of `"\xb2"` crashed the guard** (`str.isdigit()` accepts superscripts, `int()` does not) and returned a 500. uvicorn's parser rejects such headers first, so it was not reachable over a real socket. | Code review; reproduced at ASGI level | ASCII-only digit check. `test_guards.py` (4 cases). The test helper now encodes headers as latin-1, like a real server, which is how the hole was exposed |
| 4 | Medium | **The frontend shipped no Content-Security-Policy** (a documented gap). Nothing stopped a compromised script from sending a password to another origin. | Review of `docs/security.md` known gaps | `frontend/csp.ts` (`connect-src 'self'`, no inline script, no `eval`); injected as a meta tag in the build and as a header by `vite preview`. `csp.test.ts`; verified in Edge (see below) |
| 5 | Medium (a11y) | **WCAG 2.5.3 Label in Name**: policy preset and profile buttons showed "Use preset" but were named "Use the Strict preset", so voice control ("click Use preset") failed. | axe-core in a real browser (jsdom cannot see it) | Names are now "Use preset: Strict". `src/test/a11y.ts` checks label-in-name on every page test |
| 6 | Medium (a11y) | **Horizontal page scroll at 360-390 px** on the audit result: a wide preview stretched an implicit single-column grid. 24 grids had the same latent flaw. | Real-browser mobile emulation | `grid-cols-1` on every responsive grid. source guard `src/styles/layout.test.ts` |
| 7 | Low | **Helper scripts were Windows-only** (`Scripts\python.exe`, `npm.cmd`, backslash paths and regexes). | Cross-platform review | `_common.ps1` selects `bin/python` and `npm` off Windows; paths use `/`. **Only the Windows side could be run here** (see Linux note in `docs/installation-linux.md` for what was verified later) |
| 8 | Low | **Duplicated report-field logic** between the CLI and API reports (two copies of the whitelist could drift apart). | Duplicate-block scan | One `analysis_summary()` in `reporting/sanitized.py`; a test asserts both reports share it |
| 9 | Low | **Bandit parsed free text after `# nosec` as test ids** (warnings on every audit run). | Audit output | Explanations moved before the marker |
| 10 | Info | **Stale documentation**: "no breach lookup exists yet", "no CSP yet", "0.25 s at 100 characters". | Review | `security.md`, `analysis-engine.md`, ADR 0003, `frontend.md` corrected |

Also added: error-path tests for `reuse build` / `reuse info` (`cli/advanced.py` coverage 81% to 99%) and a raw U+FEFF in a test was replaced by an explicit escape.

## What was checked and found sound

* **Password exposure and logging.** With `PASSAUDIT_LOG_LEVEL=debug` on a real uvicorn process, a
  canary password was sent in valid requests, broken JSON, a JSON key, a URL query, a URL path,
  headers (`X-Canary`, `Cookie`, `Authorization`), an over-long body, and through the batch,
  policy and report routes. It appeared nowhere in stdout or stderr, and the access log recorded
  only method, known route, status, duration and a server-generated request id. Error bodies never
  echo input; unknown field names are redacted.
* **CORS.** The allowed origin is granted without credentials; `evil.example`, `Origin: null`,
  `DELETE` and an unlisted request header are all refused. Cross-origin POSTs get no grant.
* **Host header (DNS rebinding).** `evil.example`, `127.0.0.1.evil.example`,
  `localhost.evil.example`, an unterminated IPv6 literal, an empty Host, a missing Host and two
  Host headers are refused with 400; `LOCALHOST:8000` is accepted (case-insensitive).
* **Rate limiting.** A 130-request burst hit `429` with `Retry-After`; `/health` stayed reachable;
  other routes stayed limited. The key is the socket peer; `X-Forwarded-For` is ignored.
* **Framing.** A 70 kB body is `413`; a chunked body over the limit is cut off with `413`; a query
  string on a POST is `400`; invalid or oversized `Content-Length` is `400`.
* **Input validation.** Seeded mutation fuzzing (types swapped, hostile strings, lone surrogates,
  NaN, huge integers, 60-deep and 5000-deep nesting, truncated JSON, wrong root type): every
  response is a documented status in the uniform error envelope. Reproduce a deep run with
  `PASSAUDIT_FUZZ_ITERATIONS=5000 pytest backend/tests/api/test_fuzz.py`.
* **Engine robustness.** 6,000 random passwords over 13 alphabets (combining marks, bidi
  overrides, NUL, surrogates, emoji ZWJ sequences, case-folding oddities, repeats up to 1024
  characters): never raised; slowest 492 ms; no result or report entry contained the password.
* **Browser.** Under the real CSP header, the audit works end to end and all pages render; an
  injected cross-origin `fetch`, inline script, `eval` and a foreign image are all blocked by the
  browser; the app itself triggers no violation and makes no request to another origin.
* **Accessibility.** axe-core with every rule enabled (colour contrast included) reports 0
  violations on the overview, audit (empty and with a result), batch, policies and settings pages
  in the dark and light themes, and on the audit result and batch pages at 390 px.
* **Performance** (production build, headless Edge, local backend): largest contentful paint
  52-104 ms on every page except the first cold load (900 ms); cumulative layout shift 0.000-0.066;
  no long tasks; JS heap 12-58 MB. The JS bundle is 451 kB (135 kB gzipped).
* **Maintainability.** A duplicate-block scan (8+ similar lines) over the backend found 3 clusters
  and the frontend 2. The notable one (the shared option lists of the `audit`, `batch` and
  `policy check` commands) is inherent to Typer's explicit signatures and was left alone;
  the report-field duplicate was merged (finding 8).

## Not changed, by decision

* **No per-request time budget** and no cancellation when a client disconnects. Work per password
  is now bounded (about 0.5 s worst case measured), the concurrency cap defaults to 2, requests are
  rate limited, and the service is loopback-only. A batch of 50 worst-case passwords still holds a
  worker for roughly 25 s. Documented in `security.md`.
* **The reuse key file's permissions are not checked when read**, and `--force` on an existing
  file does not tighten them. Documented.
* **CSP via meta tag cannot carry `frame-ancestors`.** The header form is provided by
  `vite preview` and by the Docker web image (`docs/docker.md`).
* **Typer option signatures repeat** across three commands (accepted, above).

## Limits of this audit

* **Windows only until Phase 10.** The Phase 9 run was Windows 11. Linux and container
  verification is reported in Phase 10 (`docs/installation-linux.md`, `docs/docker.md`).
* **The real-browser scripts (CSP check, axe, performance, overflow probe) are not in the
  repository**; they drive Edge over the DevTools protocol and were kept as scratch files. The
  automated tests above guard the same properties as far as jsdom allows; repeat the real-browser
  steps manually before a release (see `docs/release-checklist.md`).
* **No real call to the external breach service was ever made** in any phase; tests use fake
  transports.
* This is a code-and-behaviour audit by the project's author-assistant, not an independent
  penetration test.
