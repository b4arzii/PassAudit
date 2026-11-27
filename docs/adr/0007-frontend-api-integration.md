# ADR 0007: Frontend / API integration

- Status: Accepted (Phase 7)
- Date: 2026-11-26

## Context

Phase 7 connects the React frontend to the FastAPI backend: password analysis, policy checking,
batch auditing, error handling, loading and success states, secure password input and sanitized
report export. The hard constraint is that a submitted password must never be stored or exposed in
browser logs, local/session storage, URLs or reports. Constraints carried over: local-only
service (ADR 0005), Windows Application Control (ADR 0002), the design system (ADR 0006).

## Decisions

1. **Same-origin requests through a proxy.** The browser calls `/api/v1/...`; Vite proxies it to
   `127.0.0.1:8000` in development. No CORS preflight, no second origin to trust, and the API's
   Host allow-list and loopback bind stay unchanged. `VITE_API_BASE_URL` can override the base.
2. **A small typed client, no HTTP library.** `fetch` with `cache: no-store`, `credentials: omit`,
   `referrerPolicy: no-referrer`; bodies only on POST; no logging. It validates the *shape* of
   each success response (a cheap guard against a frontend/backend version mismatch), maps every
   failure to one `ApiRequestError`, and never copies thrown messages into user-visible text.
3. **A bare 5xx means "unreachable".** The API answers every error with its JSON envelope, so a
   5xx without one comes from a proxy or gateway with nothing behind it. It is classified as a
   network error, so the user is told to start the service instead of seeing a mystery server
   error. Found by running the real stack with the backend stopped.
4. **Secrets live in the owning page's state, and nowhere else.** No context, store, ref
   registry or persistence layer ever holds a password. After a successful request the field
   (and a pasted batch / loaded file) is cleared; after a failure it is kept so *Retry* works. An
   opt-in "keep the password in the form" exists, but it only skips the clearing - still memory
   only. Results carry no password by construction (the engine returns positions and advice).
5. **Sessions hold results, not requests.** `SessionProvider` keeps analysis results and records
   (bounded to 25 runs) in memory for the overview; it is lost on reload. `useAsyncAction` stores
   only the response or error, so the request body (with the password) is not retained by it.
6. **The full policy is sent with every request.** Sending only overrides would make the UI depend
   on the frontend's copy of the defaults matching the backend's. (They do - verified against
   `GET /policy/default` - but an explicit policy cannot drift.)
7. **Policy editing validates like the backend and applies atomically.** Text boxes keep what is
   typed; a change applies only when the whole policy is valid, otherwise errors are listed and
   the last valid policy stays in force. Policies persist as *rules only*.
8. **Reports from results only.** Builders take `AnalysisRecord`s / policy results, which have no
   password field. Exports are generated in the browser, formula-neutralised for spreadsheets,
   given restricted file names, and labelled `sanitized`; demo data is labelled in the file, every
   CSV row and the file name.
9. **Cancellation and staleness are the hook's job.** `useAsyncAction` aborts the previous call on
   a new run or unmount and discards late results; buttons ignore clicks while loading but stay
   focusable.
10. **Client-side limits mirror the server's** (read from `/limits`, with documented fallbacks), so
    mistakes are caught before sending. Messages give counts and line numbers, never content. The
    server remains the authority; its own rejections are displayed too.
11. **No masking for the batch paste box.** A native textarea cannot be masked portably; the UI
    states this and offers *Upload file*, where the list is parsed without being displayed.

## Consequences

* The privacy guarantee is testable and tested: integration tests and a real-browser run submit
  canary passwords and scan storage, cookies, IndexedDB, URLs, headers, request/response bodies,
  console output, DOM, session history and downloaded exports.
* Production hosting must provide the same-origin `/api` route (reverse proxy) - which
  [api.md](../api.md) already says is unsupported until `client_key` and proxy trust are designed.
* Because passwords are cleared on success, re-running an audit with a different policy needs the
  input again - the intended trade-off; the privacy toggle exists for people who prefer otherwise.
