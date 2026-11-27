# PassAudit HTTP API (v1)

Packages: `backend/src/passaudit/api/` and `backend/src/passaudit/main.py` (FastAPI). The API is
a thin layer over the [analysis engine](analysis-engine.md): every result is produced by
`passaudit.analysis`, and a test enforces that the API contains no detection or scoring code of
its own.

> **Local only.** The API has **no authentication** and must not be exposed. It binds to
> `127.0.0.1`, the settings refuse any other bind address unless
> `PASSAUDIT_ALLOW_NON_LOOPBACK_BIND=true`, and the `Host` header is allow-listed. See
> [security.md](security.md) before changing any of that.

## Running it

| How | Command | Address |
| --- | --- | --- |
| Windows, with reload | `.\scripts\dev.ps1 -Only backend` | `http://127.0.0.1:8000` |
| Linux / macOS, with reload | `make dev-api` | `http://127.0.0.1:8000` |
| Any platform, no reload | `.venv/bin/uvicorn passaudit.main:app --host 127.0.0.1 --port 8000 --no-access-log` (Windows: `.\.venv\Scripts\python.exe -m uvicorn ...`) | `http://127.0.0.1:8000` |
| Docker Compose | `docker compose up --build -d --wait` ([docker.md](docker.md)) | `http://127.0.0.1:8080/api/v1/...` through the web container; the API itself is not published |

Always pass `--no-access-log` when you start uvicorn yourself: its access log records query
strings, and PassAudit writes its own sanitized log instead.

Interactive docs (development only): <http://127.0.0.1:8000/docs>; machine-readable schema:
`/openapi.json`. The API returns `404` for both (and `/redoc`) when `PASSAUDIT_ENV=production`,
which is what the Docker image uses. (Behind the Docker web container those two paths show the web
app, because nginx serves the single-page app for every non-`/api/` path.)

A first request, from a shell on Linux or macOS or in Git Bash (PowerShell examples follow below):

```bash
curl -s http://127.0.0.1:8000/api/v1/health
curl -s http://127.0.0.1:8000/api/v1/audit -H 'Content-Type: application/json' \
     -d '{"password": "Summer2024!", "policy": {"min_length": 14}}'
```

Note that a password in a `curl -d` argument is visible in your shell history and in the process
list while curl runs. That is acceptable for test passwords like these; for real ones, read the
body from a file or stdin (`-d @body.json`, `-d @-`).

## Endpoints

All under `/api/v1`. Passwords are sent **only in JSON request bodies** of `POST` requests.

| Method & path | Purpose | Success body |
| --- | --- | --- |
| `GET /health` | Liveness probe (exempt from rate limiting) | `{"status": "ok", "version": "..."}` |
| `GET /limits` | The limits this server enforces | sizes, batch limit, rate-limit settings |
| `POST /audit` | Analyse one password | the engine's `PasswordAnalysis` |
| `POST /audit/batch` | Analyse several passwords | `{count, summary, results[]}` |
| `POST /policy/validate` | Check one password against a policy, rule by rule | `{compliant, length, rules[], violations[]}` |
| `GET /policy/default` | The default policy (a template for custom ones) | `PasswordPolicy` |

### `POST /audit`

```powershell
$body = @{
  password = 'Summer2024!'
  policy   = @{ min_length = 14 }
  context  = @{ usage = 'online_account'; personal_info = @('Jane Doe'); reused_elsewhere = $false }
} | ConvertTo-Json -Depth 5
Invoke-RestMethod http://127.0.0.1:8000/api/v1/audit -Method Post -ContentType 'application/json' -Body $body
```

* `password` (required, string): at most `max_password_length` characters (default 1024).
* `policy` (optional): any `PasswordPolicy` fields; defaults apply otherwise
  (`GET /policy/default`). Unknown fields are rejected.
* `context` (optional): `usage` (`general`, `online_account`, `privileged_account`,
  `master_password`, `encryption_key`), `personal_info` (up to 50 strings of up to 256
  characters), `reused_elsewhere`.

The response is exactly the engine's `PasswordAnalysis` (strength, entropy with limitations,
findings with positions only, policy result, transparent risk score, recommendations). It never
contains the password. See [analysis-engine.md](analysis-engine.md).

### `POST /policy/validate`

Same request body as `/audit`. Returns one entry per **enabled** rule with a human-readable
`requirement`, `status` (`pass`/`fail`) and, for failures, `required`, `actual` and `message`,
plus the engine's raw `violations`.

### `POST /audit/batch`

```json
{ "items": [ {"id": "alice", "password": "..."}, {"id": "bob", "password": "..."} ],
  "policy": {"min_length": 12}, "context": {"usage": "online_account"}, "detail": "summary" }
```

* One `policy` and `context` apply to every item. `id` is optional (max 128 characters), is
  sanitised to 64 printable characters, and is replaced by `[redacted]` if it contains its own
  password. It is echoed back to correlate results and is never logged.
* `detail`: `summary` (default; a compact record per item) or `full` (embeds each full
  `PasswordAnalysis`).
* Identical passwords in the batch are flagged `reused_in_batch` and analysed with
  `reused_elsewhere = true`.
* `summary` rolls up counts: risk levels, strength scores, policy compliance, finding kinds,
  recommendation codes, average/max risk, reuse.
* **Limits (strict, all configurable):** at most `batch_max_items` passwords (default **50**),
  each at most `max_password_length`, body at most `batch_max_body_bytes` (default **1 MiB**).
  One over-long password rejects the whole request (`422`, with the item *index*, never its
  content). Each password costs one rate-limit unit.

### Limits at a glance

| Limit | Default | Setting | Violation |
| --- | --- | --- | --- |
| Password length | 1024 chars | `PASSAUDIT_MAX_PASSWORD_LENGTH` | `422 password_too_long` |
| Body, single endpoints | 64 KiB | `PASSAUDIT_MAX_BODY_BYTES` | `413 payload_too_large` |
| Body, batch | 1 MiB | `PASSAUDIT_BATCH_MAX_BODY_BYTES` | `413 payload_too_large` |
| Passwords per batch | 50 (schema ceiling 1000) | `PASSAUDIT_BATCH_MAX_ITEMS` | `422 batch_too_large` |
| `personal_info` | 50 items x 256 chars | fixed by the engine | `422 validation_error` |
| Rate | burst 100, refill 300/min | see below | `429 rate_limited` |
| Concurrent analyses | 2 (queue wait 10 s) | `PASSAUDIT_MAX_CONCURRENT_ANALYSES` | `503 server_busy` |

`GET /limits` reports the live values so clients can size their requests.

## Errors

Every non-2xx response, whatever produced it (a route, validation, the router, a middleware),
has this shape:

```json
{ "error": { "code": "validation_error",
             "message": "The request body failed validation.",
             "request_id": "5d6595a9f603486a839fa7991538c6d9",
             "details": [ {"loc": ["body", "policy", "min_length"], "type": "greater_than_equal",
                           "message": "Input should be greater than or equal to 0"} ] } }
```

`details` appears only for validation failures and holds *locations and fixed descriptions*,
never the rejected value. Unknown field **names** are shown as `<unknown field>` (a secret
mistakenly used as a JSON key must not come back). At most 20 details are returned.
`request_id` equals the `X-Request-ID` response header; quote it when reporting a problem.

| Status | `code` | When |
| --- | --- | --- |
| 400 | `query_string_not_allowed` | a query string on a `POST` (passwords belong in the body) |
| 400 | `host_not_allowed` | `Host` header not in the allow-list |
| 400 | `bad_request` | malformed `Content-Length` |
| 404 | `not_found` | unknown path (the path is not echoed) |
| 405 | `method_not_allowed` | wrong method (an `Allow` header is sent) |
| 413 | `payload_too_large` | body over the limit (checked from `Content-Length` and while streaming) |
| 415 | `unsupported_media_type` | `Content-Type` is not `application/json` |
| 422 | `validation_error` | schema/validation failure, invalid JSON, non-object body |
| 422 | `password_too_long`, `batch_too_large` | size limits |
| 429 | `rate_limited` | rate limit; `Retry-After` and `X-RateLimit-*` headers set |
| 500 | `internal_error` | unexpected failure; no details are returned |
| 503 | `server_busy` | analysis queue wait exceeded; `Retry-After` set |

## Rate limiting (design)

* **Algorithm: token bucket per client.** A bucket holds `rate_limit_burst` tokens (default
  100) and refills at `rate_limit_per_minute / 60` per second (default 300/min = 5/s). Bursts
  are allowed; the sustained rate is the refill rate.
* **Cost units, not request counts.** A single-password request costs 1, a batch costs one
  unit per password. Analysis is CPU-bound (a few milliseconds typically; about 0.5 s is the worst
  case measured over thousands of adversarial inputs, after the Phase 9 work budget), so cost
  tracks the resource an attacker could exhaust.
* **Charged early, settled late.** The middleware charges 1 unit to *every* non-exempt request
  before any body is read - so invalid and oversized requests are not free. A batch route
  charges the remaining `items - 1` after validation and before any analysis; if it cannot be
  paid, nothing is analysed and the response is `429`. Denied requests consume nothing.
* **Client key: the socket peer address.** `X-Forwarded-For` is **not** trusted (a local client
  could forge it). If the service is ever put behind a reverse proxy, change `client_key`
  deliberately and only trust the proxy's address.
* **Exempt:** `GET /health`, `/docs`, `/openapi.json`, and CORS preflights.
* **Headers:** `X-RateLimit-Limit`, `-Remaining`, `-Reset` on every limited route (reflecting the
  balance *after* a batch charge), plus `Retry-After` on `429`. All are exposed to browsers via
  CORS.
* **Bounded memory:** at most 10 000 buckets are tracked; idle (fully refilled) ones go first,
  then least-recently-used. (Evicting an active bucket resets that client's limit - acceptable
  for a local service, noted for any wider deployment.)
* **Pluggable:** `RateLimiter` is a protocol (`async acquire(key, cost)`); the in-memory
  implementation is **per process**. Several workers or hosts would each have their own bucket;
  that needs a shared store (e.g. Redis) behind the same interface.
* **Concurrency is limited separately:** analysis runs in worker threads, at most
  `max_concurrent_analyses` at once. A request waits up to `analysis_queue_timeout_seconds`
  for a slot, then gets `503` (`zxcvbn` calls are additionally serialised inside the engine).
* Disable with `PASSAUDIT_RATE_LIMIT_ENABLED=false` (e.g. for load tests). The burst must be
  at least `batch_max_items`, or a full batch could never be afforded (start-up error).

## Request-body privacy

The threat: a password reaching a log, a cache, an error message, a URL or another party.

| Control | Implementation |
| --- | --- |
| Passwords only in JSON bodies | query strings are rejected on `POST`s *before* routing; `Content-Type` must be `application/json` (also blocks cross-site form posts) |
| Bodies are never read by middleware | pure-ASGI middleware only counts bytes; a test fails if `.body()` or `request.json` appears in the API code |
| Bounded bodies | `Content-Length` checked up front; streamed (chunked) bodies are cut off at the limit |
| No body/URL logging | uvicorn's access log (which records query strings) is **disabled by the app at start-up**; `dev.ps1` also passes `--no-access-log` |
| Sanitised access log | `passaudit.access` records method, a **known** route path (anything else is `[unmatched]`), status, duration and request id. Never the query string, headers, body, or an unknown path (a password typed into a URL by mistake). Unknown HTTP methods are logged as `[other]` |
| Safe error logging | an unexpected exception is logged as its **class name** and request id only - no message, no traceback |
| Errors never echo input | custom validation handler (locations only), framework `detail` strings are not forwarded, unknown field names redacted, 404 does not echo the path |
| Secrets masked in models | `SecretStr` + `hide_input_in_errors` on every model that can hold a password or personal info |
| No caching | `Cache-Control: no-store` on every response; no cookies are ever set |
| Server-generated request ids | client-supplied ids are ignored (no log injection) |
| Results contain no password | the engine's results hold positions and fixed-text advice; batch ids are sanitised and redacted |

Tests (`backend/tests/api/test_privacy.py`) send canary passwords in bodies, query strings,
paths, headers, JSON keys and invalid payloads, then search every response, every log record
and stdout/stderr for the canary and for all 6-character fragments of it.

**What this cannot protect against:** anything outside the process - a reverse proxy or
network capture that logs bodies, browser history of a page that builds URLs, or malware on
the machine. Python also cannot wipe strings from memory (see security.md).

## Other security behaviour

* **Local only:** loopback bind enforced in `Settings`; `Host` allow-list
  (`PASSAUDIT_ALLOWED_HOSTS`, default `localhost`, `127.0.0.1`, `[::1]`) defends against DNS
  rebinding; the offending host is not echoed.
* **CORS:** exact-origin allow-list (`PASSAUDIT_CORS_ORIGINS`; wildcards, paths and trailing
  slashes are refused at start-up), methods `GET`/`POST`, header `Content-Type`, **no
  credentials**, preflight cached 600 s. CORS headers are also present on error responses, so
  a browser app can read `429`/`413`/`422` details.
* **Security headers** on every response, including errors: `nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and a restrictive CSP (relaxed
  only for `/docs` and `/openapi.json` in development).
* **Middleware order** (outermost first): request context -> CORS -> host guard -> rate limit
  -> request guard -> router. Request context is outermost so *every* response gets a request
  id and security headers; it also converts an unexpected exception into the generic `500`.

## Configuration

All settings are `PASSAUDIT_*` environment variables (or `.env`); see `.env.example`.
Notable start-up validations: non-loopback `host` refused; wildcard/malformed CORS origins and
wildcard/port-bearing allowed hosts refused; `rate_limit_burst >= batch_max_items`;
`batch_max_body_bytes >= max_body_bytes`.

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/api       # API integration tests (249)
.\scripts\test.ps1 -Only backend                              # everything, with coverage
```

On Linux: `.venv/bin/python -m pytest backend/tests/api` or `make test-backend`. The mutation
fuzzer (`test_fuzz.py`) runs 150 mutated requests per route by default;
`PASSAUDIT_FUZZ_ITERATIONS=5000` runs a deep pass. Against a running Docker stack,
`python docker/smoke_test.py` checks the proxy, the container isolation and the logs.

`backend/tests/api/`: `test_endpoints` (health, audit, policy, batch; includes proof that the API
output equals the engine's), `test_guards` (request/Host guards, error envelope, CORS, 500s),
`test_ratelimit` (bucket, middleware, batch cost, concurrency), `test_privacy` (canary sweep of
responses and logs), `test_config_and_openapi` (settings validators, OpenAPI document),
`test_architecture` (layering and no-duplication rules), `test_robustness` (defence-in-depth
branches). `asgi_call` in `conftest.py` drives the app at ASGI level for chunked bodies, odd
headers and chosen client addresses.

## Phase 8 additions

### Opt-in checks and profiles on `/audit`, `/audit/batch`, `/policy/validate`

```json
{ "password": "...", "profile": "enterprise",
  "exposure": { "breach": "online", "reuse": true } }
```

* `profile` selects a named policy (`GET /policy/profiles`) *instead of* `policy` (both -> `422`).
  Its usage applies unless `context.usage` is given. An unknown name is `422 unknown_profile`
  and is not echoed.
* `exposure.breach`: `off` (default), `local` (server-side hash file, no network) or `online`
  (k-anonymity range query; only a 5-character hash prefix is sent). `exposure.reuse`: compare
  with the operator's authorised reuse index.
* Refusals happen before any work: `403 external_lookups_disabled` (online not enabled by the
  operator), `422 feature_unavailable` (local file / reuse index not configured).
* The result gains `exposure`: `{"breach": {"status": "clean|breached|unavailable", "source",
  "count"}, "reuse": {"status": "clean|reused", "sources": [...]}}` - or `null` when nothing was
  requested. `unavailable` means **unchecked**. A breach raises the risk score to at least 85 and
  puts `change_breached_password` first in the advice.
* **Cost:** an online check costs one extra rate-limit unit per password (batches: double).
* Batch items gain `breach` and `reuse_datasets`; the batch summary gains `breached` and
  `reused_in_datasets`.
* `/policy/validate` rules can now have `status: "unchecked"` (e.g. `block_breached_passwords`
  when no breach check was requested).

### `GET /capabilities`

What this server can actually do: `external_lookups_enabled`, `breach.{local,online,online_host}`,
`reuse_index.{available,datasets,authorization_reference}`, `profiles[]`, dictionary sizes. No
paths, no keys, no digests. Clients (the web UI) use it to offer only real options.

### `GET /policy/profiles`, `GET /policy/profiles/{name}`

Built-in and operator-defined profiles (`name`, `title`, `description`, full `policy`, `usage`,
`builtin`). Operators add profiles with `PASSAUDIT_POLICY_PROFILES_PATH`.

### `POST /audit/report`

Same body as `/audit/batch` (`detail: full` embeds each full analysis). Returns a **sanitized,
sealed report** (schema version 2): whitelisted per-password entries, summary, the policy and
profile used, an `external_checks` block (modes, host, dataset names, authorisation reference),
a fixed `limitations` list and an `integrity.checksum` (SHA-256; not a signature). The report is
refused with `422` if it would contain any submitted password or personal detail (for example a
label equal to a personal detail).

### New settings

`PASSAUDIT_BREACH_API_URL`, `_BREACH_TIMEOUT_SECONDS`, `_BREACH_BATCH_DEADLINE_SECONDS`,
`_BREACH_LOCAL_FILE`, `_REUSE_INDEX_PATH` / `_REUSE_KEY_FILE` / `_REUSE_AUTHORIZATION_REFERENCE`
(all three required together), `_POLICY_PROFILES_PATH`, `_DICTIONARY_PATHS`. A configured file
that is unusable stops start-up with a fixed message (no path, no content). See `.env.example`
and [security.md](security.md#phase-8-exposure-checks-reuse-auditing-and-sanitized-reports).

## Versioning

The URL prefix `/api/v1` is the contract version. Additive changes (new optional fields,
endpoints) stay in v1; breaking changes will be introduced as `/api/v2` alongside it. Error
`code` values are part of the contract. The engine's `PasswordAnalysis.version` identifies the
analysis schema.
