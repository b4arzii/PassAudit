# ADR 0005: HTTP API design

- Status: Accepted (Phase 4)
- Date: 2026-11-26

## Context

Phase 4 adds the FastAPI backend that a future UI (and other local tools) will call. It handles
passwords, has no authentication, and is meant to run on the user's own machine only. Goals:
a versioned, consistent, documented API; strict resource limits; and a design in which a
password cannot leak through logs, errors, URLs or caches - while reusing the analysis engine
without duplicating any of it.

## Decisions

1. **The API is a thin layer.** `passaudit.api` maps HTTP to `passaudit.analysis` and nothing
   else. The engine's `AnalysisRequest` is the request body of `/audit` and `/policy/validate`
   (subclassed only to add OpenAPI examples), and `PasswordAnalysis` is the `/audit` response.
   An architecture test forbids imports of engine internals and any detection/scoring code in
   the API. Logic that both the CLI and the API need - per-rule policy results, batch summary
   statistics, in-batch reuse detection, label sanitising - was *moved into the engine
   package* (`policy_view`, `summary`, `batch`) and the CLI now uses it too, so each exists once.
2. **Versioned by URL prefix** (`/api/v1`); additive changes stay in v1, breaking ones become
   `/api/v2`. Error `code` strings are part of the contract.
3. **Passwords only in JSON bodies of `POST` requests.** Query strings are rejected on
   state-changing requests before routing; `Content-Type` must be `application/json` (this also
   forces a CORS preflight for cross-origin browser calls). No GET endpoint takes a password.
4. **One error format for every failure**, produced in one module and used by routes, framework
   handlers and middleware alike. It never echoes request content: validation details carry
   locations and fixed messages only, unknown field names are redacted, framework `detail`
   strings are dropped, unexpected exceptions become a generic `500` and are logged by class
   name only. `ApiError` subclasses `HTTPException` because FastAPI turns any other exception
   raised while reading the body into a generic `400`, which would hide the `413`.
5. **Pure-ASGI middleware, never `BaseHTTPMiddleware`**, so bodies stream through untouched and
   size limits are enforced during receipt. Order: request context -> CORS -> host guard ->
   rate limit -> request guard -> router. The outermost layer guarantees a request id and
   security headers on *every* response, including rejections and the last-resort `500`.
6. **Sanitised access log replaces uvicorn's.** uvicorn's access log records the query string,
   so the app disables it at start-up (and `dev.ps1` passes `--no-access-log`) and logs only
   method, *known* route path (else `[unmatched]`), status, duration and a server-generated
   request id.
7. **Local-only is enforced, not documented.** `Settings` refuses a non-loopback bind without an
   explicit opt-in, the `Host` header is allow-listed (DNS-rebinding defence), CORS accepts
   exact origins only and never credentials.
8. **Rate limiting by cost units with a pluggable store.** Token bucket per socket peer; a batch
   costs one unit per password; every non-exempt request is charged 1 unit *before* its body is
   read and batches pay the remainder after validation. `X-Forwarded-For` is deliberately not
   trusted. The limiter is a protocol so a shared store can replace the in-memory one if the
   service is ever scaled out. The burst must cover a full batch (start-up validation).
9. **Bounded CPU.** Analysis is CPU-bound and runs in worker threads behind a capacity limiter;
   waiting longer than a configured time yields `503` rather than unbounded queueing. Per-
   password, per-body and per-batch limits are checked before any analysis.
10. **Strict batch limits, all-or-nothing.** At most 50 passwords (configurable, schema ceiling
    1000), 1 MiB body, each password within the length limit; one violation rejects the whole
    request with the offending item *indexes* (never content).

## Consequences

- No new runtime dependencies (FastAPI, Starlette, anyio, pydantic were already present).
- The in-memory limiter is per process; the documented deployment is one local worker.
- Recent FastAPI wraps included routers, so `app.routes` no longer lists API paths; the access
  logger's known-path set is built from the v1 router. A test (`test_privacy`) would fail if
  every request were logged as `[unmatched]`.
- Clients that put a secret in a URL or send a non-JSON body get a clear `400`/`415` instead of
  silent acceptance; this is intentional friction.
- Authentication is still absent. Until it exists the loopback/Host/CORS controls are the only
  barrier, so exposing the service is explicitly unsupported.
