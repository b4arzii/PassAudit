# Changelog

All notable changes to PassAudit are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). The API contract version is the URL prefix (`/api/v1`).

## [Unreleased]

Nothing yet.

## [0.1.0] - not yet released

The first release candidate. Everything below exists in the tree; the date is set when the release
is tagged (see [docs/release-checklist.md](docs/release-checklist.md)).

### Added

* **Analysis engine** (`passaudit.analysis`): zxcvbn strength, entropy with documented limits,
  detection of repeats, sequences, keyboard walks, dates, dictionary words and names (reported as
  positions, never text), configurable policies and profiles, a transparent 0-100 risk score,
  fixed-text recommendations.
* **Command-line interface** (`passaudit`): `audit`, `batch`, `policy check|show|profiles`,
  `reuse build|info`, `version`; hidden prompt, stdin or file input (never argv); sanitized JSON
  and CSV reports; documented exit codes.
* **HTTP API** (`/api/v1`): `audit`, `audit/batch`, `audit/report`, `policy/*`, `capabilities`,
  `health`, `limits`; strict size and rate limits, Host and CORS guards, one sanitized error format,
  request-body privacy controls.
* **Web app** (React 19, TypeScript): Audit, Batch and Policies workspaces, light and dark themes,
  accessible components, sanitized report export, a strict Content-Security-Policy.
* **Opt-in privacy-preserving checks**: breach checking by k-anonymity (online, only a 5-character
  hash prefix) or against a local hash file; authorised reuse auditing with a keyed HMAC index;
  sealed, leak-guarded reports.
* **Containers**: `Dockerfile` (api and web targets), `docker-compose.yml` (API on an internal
  network, web published on `127.0.0.1` only, no-network CLI service), optional overrides for local
  data sets and for the online breach check.
* **CI and release**: GitHub Actions (Linux and Windows build and test, dependency audit, container
  smoke test), an artifact-only release build, Dependabot.
* **Documentation**: installation guides for Windows and Linux, Docker guide, CLI and API
  references, architecture, security model, privacy, QA report, release checklist, ADRs.
* **License**: MIT, with third-party notices.

### Security

* A work budget in the zxcvbn adapter bounds the cost of leetspeak-dense input (a 100-character
  password of leet symbols took about 2.5 s; now bounded to a few hundred milliseconds).
* Online breach lookups through `POST /policy/validate` now cost the same extra rate-limit unit as
  through `/audit`.
* A non-ASCII `Content-Length` header is now rejected with `400` instead of failing with a `500`.
* The frontend build ships a strict Content-Security-Policy (`connect-src 'self'`, no inline script,
  no `eval`).
* Container: nginx neither writes request lines to any log nor spools request bodies to disk.
* Settings treat an empty environment value as "not set" (an empty `PASSAUDIT_BREACH_LOCAL_FILE`
  used to become the current directory).

### Fixed

* Accessibility: policy preset and profile buttons now contain their visible label in their
  accessible name (WCAG 2.5.3), and no page scrolls horizontally on a phone-width viewport.
* A report-field list that was duplicated between the CLI and the API reports is now defined once.
* Documentation that had drifted from the code (CSV columns, test counts, cost figures, "no breach
  lookup", "no CSP").

### Known limitations

See [docs/security.md](docs/security.md#known-gaps): no authentication (local use only), small
bundled dictionaries, no per-request analysis time budget, report integrity is a checksum and not a
signature, and the Docker stack shares one rate limit between all clients.
