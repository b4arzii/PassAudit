# ADR 0009: Containers, CI and release packaging

- Status: Accepted (Phase 10)
- Date: 2026-11-27

## Context

Phase 10 prepares PassAudit for a public GitHub release: container images, CI, installation guides,
a license and a release process. The binding constraints are the project's own: the API has **no
authentication** and must stay local, no network call may happen by default, and nothing may be
published, pushed or deployed without the owner's explicit decision.

## Decisions

1. **Two services, not one container.** `web` (nginx, unprivileged) serves the built frontend and
   proxies `/api/` to `api` (uvicorn, unprivileged). Alternatives considered: have FastAPI serve
   the static files (would put a file server and a CSP policy inside the API and change its
   tested header behaviour), or one container running both processes (no isolation between them,
   needs a supervisor). Two services keep each image single-purpose and let the API stay
   unpublished.
2. **The API is never published.** It is attached only to an `internal` Compose network, so it has
   no route to the internet and no port on the host; only `web` is published, and only on
   `127.0.0.1`. Inside the image the API binds `0.0.0.0` with
   `PASSAUDIT_ALLOW_NON_LOOPBACK_BIND=true`, which would be unsafe anywhere else: the safeguard is
   the network topology, documented and tested (`docker/smoke_test.py`).
3. **Egress is a second, explicit switch.** Opt-in lookups need the server flag *and* a request
   (ADR 0008); in containers they additionally need `docker-compose.egress.yml`, which is the only
   thing that gives the API a route out. Local data sets are a separate override
   (`docker-compose.data.yml`) mounted read-only.
4. **Hardening is configuration, not hope.** Non-root users, read-only root file systems, `tmpfs`
   for `/tmp`, all capabilities dropped, `no-new-privileges`, process and memory limits. The CLI
   service has `network_mode: none`.
5. **nginx must not undo the privacy rules.** Access log off; error log at `crit` (it quotes
   request lines otherwise); request bodies kept in memory (`client_body_buffer_size` at least
   `client_max_body_size`) because nginx would spool larger bodies to a temp file. The first
   container test found both leaks; they are now asserted by the smoke test.
6. **One CSP, three places.** `frontend/csp.ts` is the source; the build injects it as a meta tag,
   `vite preview` and nginx send it as a header (a test asserts nginx's copy equals the source).
7. **Reproducible enough.** The Python image installs from `backend/requirements.lock.txt`, the web
   build from `package-lock.json` with `npm ci`. Base images are pinned to a minor tag, not a
   digest: digests rot and are the maintainer's call at release time (release checklist).
8. **MIT license.** All runtime dependencies are permissive; the bundled data lists are
   project-authored; the OFL fonts ship with their license text. `THIRD_PARTY_NOTICES.md` is
   generated from the locked versions. `Private :: Do Not Upload` stays in the classifiers so a
   PyPI upload is a deliberate act.
9. **CI proves, never publishes.** The workflow runs the full gate on Linux (Python 3.12-3.14) and
   Windows (3.12), audits dependencies, and builds and smoke-tests the containers, with a
   read-only token. The release workflow builds the wheel, sdist and frontend archive and keeps
   them as workflow artifacts only: no registry push, no PyPI upload, no GitHub Release.
10. **Linux gets a first-class path** without PowerShell: a `Makefile` mirroring the scripts, and
    helper scripts that choose `bin/python` and `npm` off Windows.

## Consequences

* A user can run the whole system with one command and without installing Python or Node.
* The shared rate limit in Compose sees one client (nginx), so it cannot separate users; the stack
  is for one person on one machine.
* Anyone who can use the Docker socket can read container memory; this is documented as out of
  scope, like malware on the host.
* Publishing (tags, releases, registry images, PyPI) remains a manual, reviewed step.

## Verified

Images build; the stack becomes healthy; the smoke test (24 checks) passes, including the API port
not being reachable, no egress, unprivileged users, read-only file systems, capability set empty,
no password in any log, and a 450 kB batch body not spooled to disk; the UI works in a real browser
through the proxy under the CSP. See the release checklist's verification record.
