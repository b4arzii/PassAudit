# PassAudit Architecture

> Everything described here is implemented, except what is listed under "Planned". The sections
> "Implemented in Phase N" record how the system grew; the first sections describe it as it is.

## Goals

- **Local-first.** Passwords are analysed on the user's machine. Nothing leaves it unless the
  user explicitly opts in.
- **Safe by construction.** Secrets are treated as toxic data: short-lived, never logged, never
  persisted (see [security.md](security.md) and [privacy.md](privacy.md)).
- **Boring, typed, tested.** Strict typing on both sides, a single quality gate
  (`scripts\check.ps1` / `make check`), small dependency surface.

## System overview

```
 Browser (React SPA)                              Terminal
        |  same-origin  POST /api/v1/*                |
        v                                             v
 FastAPI service (loopback only)               passaudit CLI (Typer + Rich)
   |  middleware: request context -> CORS             |  hidden prompt / stdin / files
   |  -> Host guard -> rate limit -> request guard    |  never argv
   |  api/v1 routes, one error format                 |
   +----------------------+---------------------------+
                          v
              analysis engine  (passaudit.analysis; pure Python, no I/O, no network)
              zxcvbn adapter . patterns . keyboard . dates . dictionaries . policy . risk score
                          ^
                          | ExposureSignals (results only; the engine never performs lookups)
      +-------------------+--------------------+---------------------+
      | passaudit.breach  | passaudit.reuse    | passaudit.reporting |   opt-in, one job each
      | k-anonymity check | keyed HMAC index   | whitelisted, leak-  |
      | (the only module  | of authorised      | guarded, sealed     |
      |  that may open a  | datasets           | reports             |
      |  socket)          |                    |                     |
      +-------------------+--------------------+---------------------+
```

In development the browser never talks to the backend cross-origin: Vite proxies `/api` to
`127.0.0.1:8000`, so CORS is a defence-in-depth control, not a functional dependency. The
dependency rules (engine imports none of the other packages; the API imports no engine internals;
only `breach/providers.py` imports network code) are enforced by architecture tests.

## Deployment

| Mode | How | Shape |
| --- | --- | --- |
| Development | `scripts\dev.ps1` / `make dev-api` + `make dev-web` | uvicorn on `127.0.0.1:8000`, Vite on `127.0.0.1:5173` proxying `/api` |
| CLI only | `pip install .` | no server at all |
| Containers | `docker compose up` ([docker.md](docker.md), [ADR 0009](adr/0009-containers-and-release.md)) | nginx (`web`, published on `127.0.0.1:8080`) serves the built SPA under a strict CSP and proxies `/api/` to `api` (internal network, no published port, no internet route); a no-network `cli` service for one-off runs |

```
 host 127.0.0.1:8080 --> web (nginx, unprivileged) --> api (uvicorn, unprivileged, read-only)
                         network: frontend + backend     network: backend (internal: no egress)
```

There is no authentication and no TLS anywhere: every mode is for one person on one machine.

## Repository layout

```
PassAudit/
|-- backend/
|   |-- src/passaudit/        Python package (src layout)
|   |   |-- config.py         Settings (pydantic-settings)
|   |   |-- main.py           App factory: wires settings, middleware, rate limiter, routes
|   |   |-- analysis/         Password analysis engine (independent of FastAPI)
|   |   |   |-- analyzer.py   Orchestration, AnalyzerConfig, analyze_password()
|   |   |   |-- models.py     Typed request/result models and enums
|   |   |   |-- strength.py   zxcvbn adapter (thread-safe, bounded, state-scrubbing)
|   |   |   |-- entropy.py    charset / Shannon / guess-based entropy + limitations
|   |   |   |-- patterns.py   repeats and sequences
|   |   |   |-- keyboard.py   keyboard-walk detection (5 layouts)
|   |   |   |-- wordlist.py   local dictionary matching (+ data/common_passwords.txt)
|   |   |   |-- personal.py   personal-information matching
|   |   |   |-- policy.py     configurable policy validation
|   |   |   |-- scoring.py    transparent risk score
|   |   |   `-- recommendations.py  context-aware advice
|   |   |-- cli/              Command-line interface (depends on analysis/, never on FastAPI)
|   |   |   |-- app.py        Typer app + SafeGroup (all errors, exit codes, redaction)
|   |   |   |-- commands.py   audit, batch, policy check/show, version
|   |   |   |-- inputs.py     hidden prompt, stdin, policy/word-list/batch file readers
|   |   |   |-- reports.py    sanitized JSON/CSV builders and safe file writing
|   |   |   |-- render.py     Rich terminal views
|   |   |   |-- results.py    verdicts (--fail-on) and batch summaries
|   |   |   `-- policy_view.py  enabled-rule descriptions for policy check
|   |   |-- api/              HTTP API (depends on analysis/, never on cli/)
|   |   |   |-- v1.py         routes: health, limits, audit, audit/batch, policy/*
|   |   |   |-- schemas.py    request/response models (engine models reused)
|   |   |   |-- service.py    limits, thread offloading, bounded concurrency
|   |   |   |-- errors.py     the one error format, handlers, OpenAPI error responses
|   |   |   |-- middleware.py request context, host guard, rate limit, request guard
|   |   |   `-- ratelimit.py  token-bucket limiter (pluggable protocol)
|   |   |-- breach/           opt-in breach checks (k-anonymity range API, local hash file)
|   |   |-- reuse/            keyed reuse index of authorised datasets
|   |   |-- reporting/        whitelisted, leak-guarded, sealed reports (API and CLI)
|   |   |-- profiles.py       loads operator policy profiles from a file
|   |   |-- __main__.py       `python -m passaudit`
|   |   `-- py.typed
|   |-- tests/                pytest suite (analysis, api, cli, breach, reuse, reporting)
|   `-- requirements.lock.txt Verified dependency snapshot (used by the Docker build)
|-- frontend/                 React + TypeScript + Vite + Tailwind SPA
|   |-- csp.ts                the Content-Security-Policy (build meta tag, preview header, nginx)
|   `-- src/                  api/ (typed client), state/, pages/, components/, lib/, demo/
|-- docker/                   nginx.conf (web image) and smoke_test.py
|-- docs/                     Documentation, ADRs, screenshots
|-- scripts/                  PowerShell developer tooling (Windows; also pwsh on Linux)
|-- .github/                  CI, release-build and Dependabot configuration
|-- Dockerfile, docker-compose*.yml   containers (api, web, cli) and optional overrides
|-- Makefile                  Linux / macOS developer shortcuts
|-- pyproject.toml            Python packaging + ruff / mypy / pytest / bandit config
|-- .env.example              Documented configuration template
|-- LICENSE, THIRD_PARTY_NOTICES.md, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md
`-- README.md
```

## Implemented in Phase 1

| Area              | What exists                                                              |
| ----------------- | ------------------------------------------------------------------------ |
| Backend skeleton  | App factory, typed settings, CORS allow-list, security headers           |
| Liveness endpoint | `GET /api/v1/health` -> `{"status": "ok", "version": ...}`               |
| Frontend skeleton | Vite + React 19 + strict TypeScript, dev proxy (superseded by Phase 5)   |
| Tooling           | ruff, mypy `--strict`, pytest + coverage, bandit, ESLint, Prettier, Vitest |
| Scripts           | `setup`, `dev`, `lint`, `format`, `typecheck`, `test`, `audit`, `check`, `clean`, `freeze` |

## Implemented in Phase 2

The **analysis engine** (`passaudit.analysis`, see [analysis-engine.md](analysis-engine.md)):
strength via zxcvbn, entropy with documented limitations, repeat / sequence / keyboard
detection, local dictionary matching, configurable policy validation, a transparent 0-100 risk
score and context-aware recommendations. It is a library with typed input/output models; it
performs no logging, printing, persistence or network access and does not import FastAPI,
`passaudit.main` or `passaudit.config` (all enforced by tests). It adds one runtime
dependency, `zxcvbn` (pure Python).

## Implemented in Phase 3

The **CLI** (`passaudit.cli`, see [cli.md](cli.md)): `audit`, `batch`, `policy check`,
`policy show`, `version`. Hidden-prompt/stdin/file password input (never argv), Rich terminal
reports, sanitized JSON and CSV reports, documented exit codes, validation before any secret is
read, and a single hardened error path. It imports only `passaudit.analysis` (enforced by a
test). Adds `typer` and `rich` as runtime dependencies (pure Python).

## Implemented in Phase 4

The **HTTP API** (`passaudit.api` + `passaudit.main`, see [api.md](api.md)): versioned `/api/v1`
endpoints for single audit, batch audit (strict limits), policy validation, health and limits;
Pydantic validation; one sanitized error format; CORS; a token-bucket rate-limiting design with
per-password cost; request-body privacy controls (JSON-only bodies, no query strings, bounded
and never-logged bodies, sanitized access log); Host allow-listing; loopback-only enforcement;
OpenAPI. It reuses the engine and imports none of its internals. Logic shared with the CLI
(per-rule policy results, batch summary, reuse detection, label sanitising) now lives in
`passaudit.analysis` and is used by both front ends.

## Implemented in Phase 5

The **frontend design system and application shell** (see [frontend.md](frontend.md)): colour
tokens for dark and light themes, a theme provider with a no-flash bootstrap, a responsive shell
(sidebar, header, mobile drawer, route announcer), and an accessible component library
(buttons, cards, form controls, tables, badges, dialogs, toasts, loading states). It makes no API
calls yet and contains no password input on any page; Audit, Batch and Policies are placeholders.
Fonts are bundled, the main bundle is ~97 kB gzipped, and the browser stores only UI
preferences (theme, sidebar state).

## Implemented in Phase 7

The **web workspaces** (see [frontend.md](frontend.md) and
[ADR 0007](adr/0007-frontend-api-integration.md)): a typed API client (`frontend/src/api`), one
`useAsyncAction` hook for loading/success/error with cancellation and stale-response protection,
Audit / Batch / Policies pages, a single error presenter, in-memory session history, and
client-side sanitized report export. The browser talks to the backend only through the
same-origin `/api/v1` path (Vite dev proxy), sends passwords only in `POST` bodies, and stores only
UI preferences and policy rules. Verified by 277 frontend tests (including leak scans of
storage, URLs, console, DOM, session and exports) and a manual 152-check real-browser run against the
real backend.

## Implemented in Phase 8

New packages beside the engine, each with one job (see [ADR 0008](adr/0008-advanced-security-features.md)):

| Package | Job | Network? |
| --- | --- | --- |
| `passaudit.breach` | k-anonymity breach lookups (online range API, local sorted hash file), grouping, caching | **only `breach/providers.py`**, only when enabled |
| `passaudit.reuse` | keyed (HMAC) reuse index of authorised datasets | no |
| `passaudit.reporting` | whitelisted report entries, leak guard, integrity checksum | no |
| `passaudit.profiles` | loading policy profiles from a file | no |
| `passaudit.analysis` (extended) | dates, stepped sequences, keyboard walks, dictionaries, profile model, exposure signals | no |

The engine takes lookup results as `ExposureSignals`; it never performs them. API additions:
`/capabilities`, `/policy/profiles`, `/audit/report`, `profile` and `exposure` request fields. CLI
additions: `policy profiles`, `reuse build|info`, and the profile / dictionary / breach / reuse options.

## Phase 9: audit

A full engineering and security audit ([qa-report.md](qa-report.md)). Architecture-relevant
outcomes: a work budget in the zxcvbn adapter (bounded analysis cost), a Content-Security-Policy
for the built frontend (`frontend/csp.ts`), one shared definition of report-safe analysis fields
(`reporting.analysis_summary`), and platform-independent helper scripts.

## Phase 10: release packaging

Containers, CI and release documentation ([ADR 0009](adr/0009-containers-and-release.md)): a
two-service Compose stack that keeps the unauthenticated API off the network, an MIT license with
third-party notices, GitHub Actions (build and test on Linux and Windows, container smoke test,
dependency audit, artifact-only release build), installation guides for Windows and Linux, and a
release checklist.

## Planned (not implemented)

- **Authentication** - required before the API may ever leave loopback (see security.md).
- **Report signing** and key management (reports carry an integrity checksum only).
- A per-request analysis time budget with cancellation (see security.md, known gaps).

## Key decisions

Recorded as ADRs in [docs/adr](adr/):

- [0001 - Technology stack and repository layout](adr/0001-technology-stack.md)
- [0002 - Dependencies must run under Windows Application Control](adr/0002-application-control-compatible-dependencies.md)
- [0003 - Analysis engine design](adr/0003-analysis-engine-design.md)
- [0004 - CLI design](adr/0004-cli-design.md)
- [0005 - HTTP API design](adr/0005-http-api-design.md)
- [0006 - Frontend design system](adr/0006-frontend-design-system.md)
- [0007 - Frontend/API integration](adr/0007-frontend-api-integration.md)
- [0008 - Advanced security features](adr/0008-advanced-security-features.md)
- [0009 - Containers, CI and release](adr/0009-containers-and-release.md)
