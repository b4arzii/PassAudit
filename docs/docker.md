# Running PassAudit with Docker

The repository ships a `Dockerfile` (two targets) and a `docker-compose.yml`. They are for running
PassAudit **on your own machine**: the design assumes loopback access, because the API has no
authentication ([security.md](security.md)).

```bash
docker compose up --build -d --wait      # build, start, wait until healthy
# open http://127.0.0.1:8080
docker compose down                      # stop and remove the containers
```

Requires Docker Engine or Docker Desktop with Compose v2. Tested with Docker 29 and Compose 5 on
Docker Desktop (Windows 11, Linux containers).

## What runs

| Service | Image target | Role | Reachable from |
| --- | --- | --- | --- |
| `web` | `web` (nginx, unprivileged) | Serves the built frontend; forwards `/api/` to `api` | `127.0.0.1:8080` on the host |
| `api` | `api` (Python 3.12, uvicorn, unprivileged) | The FastAPI service | `web` only (internal network) |
| `cli` | `api`, entrypoint `passaudit` | One-off command-line runs (profile `cli`) | nobody; no network at all |

The browser talks to `web` only, on one origin, so no CORS configuration is needed.

## Security posture

These are properties of the files in this repository, each checked by
`docker/smoke_test.py` against a running stack:

* **The API is not published.** It exposes port 8000 to the `backend` network only; connecting to
  `127.0.0.1:8000` from the host fails. Inside the image it binds `0.0.0.0` (with
  `PASSAUDIT_ALLOW_NON_LOOPBACK_BIND=true`), which is only acceptable because of this. **Do not
  add a `ports:` entry for `api`.**
* **The web port is published on `127.0.0.1` only.** To use another port set
  `PASSAUDIT_WEB_PORT`; keep the `127.0.0.1` part. Publishing it on all interfaces exposes an
  unauthenticated service to your network.
* **No internet access by default.** `backend` is an `internal` network, so the `api` container has
  no route out: it cannot make the online breach check, or any other call, unless you add
  [`docker-compose.egress.yml`](#optional-online-breach-check).
* **Unprivileged and read-only.** Both services run as non-root users (`api`: uid 10001), with a
  read-only root file system (`/tmp` is a `tmpfs`), every Linux capability dropped,
  `no-new-privileges`, and process and memory limits.
* **No request lines are logged.** nginx's access log is off and its error log only records
  critical conditions (it would otherwise quote URLs); the API logs method, known route, status,
  duration and a request id. Request bodies are kept in memory and never spooled to disk by nginx.
* **Strict Content-Security-Policy and security headers** are sent by `web`
  (`docker/nginx.conf`, kept identical to `frontend/csp.ts` by a test).
* **Images contain no secrets or data.** `.dockerignore` excludes `.env*`, keys, `data/` and the
  Git history; configuration is only passed at run time.

### Things this setup cannot do

* **All users share one rate limit.** Every request reaches the API from the `web` container, so
  the per-client rate limit sees a single client. That is fine for one person on one machine, and
  unsuitable for sharing the service.
* **No authentication, no TLS.** Do not put it behind a public reverse proxy. See
  [security.md](security.md#known-gaps).
* **`docker compose` itself trusts whoever can use the Docker socket.** Anyone who can run Docker
  commands on the host can read container memory, including any password being analysed.

## Command-line use

The `cli` service has no network, no published port, and reads the password from standard input
(never from arguments):

```bash
printf '%s\n' 'correct horse battery staple' | docker compose run --rm -T cli audit --stdin -f json
docker compose run --rm cli version
docker compose run --rm cli policy profiles
```

Use `-T` when piping. Without `--stdin`, `cli audit` asks for the password at a hidden prompt, which
needs an interactive terminal. All options are in [cli.md](cli.md).

## Configuration

Compose reads a `.env` file in the project root for the variables it interpolates:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PASSAUDIT_WEB_PORT` | `8080` | Host port for the web app (on `127.0.0.1`) |
| `PASSAUDIT_LOG_LEVEL` | `info` | `critical`, `error`, `warning`, `info`, `debug` |
| `PASSAUDIT_RATE_LIMIT_PER_MINUTE` / `_BURST` | `300` / `100` | Shared rate limit (see above) |
| `PASSAUDIT_BATCH_MAX_ITEMS` | `50` | Passwords per batch request |
| `PASSAUDIT_MAX_CONCURRENT_ANALYSES` | `2` | Parallel analyses |

Every other `PASSAUDIT_*` setting in [`.env.example`](../.env.example) can be added to the `api`
service's `environment:` in a Compose override file. The dev-time `.env` created by
`scripts/setup.ps1` / `make setup` sets `PASSAUDIT_HOST=127.0.0.1`; Compose ignores it for the
containers because `docker-compose.yml` sets the container values explicitly.

## Optional: local data sets

For a local breach hash file (no network), a reuse index, or extra policy profiles, mount a folder
read-only with the override file:

```bash
mkdir data                 # git-ignored; put pwned-sorted.txt, reuse.idx, ... here
export PASSAUDIT_BREACH_LOCAL_FILE=/data/pwned-sorted.txt
docker compose -f docker-compose.yml -f docker-compose.data.yml up -d --wait
```

(PowerShell: `$env:PASSAUDIT_BREACH_LOCAL_FILE = '/data/pwned-sorted.txt'`.) The folder
(`PASSAUDIT_DATA_DIR`, default `./data`) is mounted read-only at `/data` for both `api` and `cli`.
Create it yourself first: if it is missing, Docker may create it silently (on Linux, owned by
root). Reuse auditing also needs `PASSAUDIT_REUSE_INDEX_PATH`, `PASSAUDIT_REUSE_KEY_FILE` and
`PASSAUDIT_REUSE_AUTHORIZATION_REFERENCE`; read
[security.md](security.md#authorized-reuse-auditing-local-datasets) first. Build the index with
the native CLI ([Windows](installation-windows.md) / [Linux](installation-linux.md), `passaudit reuse build`)
and copy it and its key file into `data/`: the containers cannot write there, by design.

Verified: with a one-line hash file for `letmein`, `/api/v1/capabilities` reported the local check
as available and an audit with `exposure.breach = "local"` returned `breached`, count 99, risk 85;
a write to `/data` failed with "Read-only file system".

## Optional: online breach check

```bash
docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d --wait
```

This is the **only** way PassAudit makes a network call, and it needs two things that are separate
on purpose: the server-side switch (`PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED=true`, set by this file)
**and** a request that asks for it. What is sent, to whom and what it reveals is in
[privacy.md](privacy.md#the-online-breach-check). If that is not acceptable, do not use this file;
the local hash file above needs no network. Return to the default (no egress) with a plain
`docker compose up -d --wait`.

## Building the images separately

```bash
docker build --target api -t passaudit-api .
docker build --target web -t passaudit-web .
```

Python dependencies are installed from `backend/requirements.lock.txt` (the verified snapshot, not
hash-pinned); Node dependencies from `package-lock.json` with `npm ci`. Base images are pinned to a
minor version tag (`python:3.12-slim`, `node:22-slim`, `nginx-unprivileged:1.28-alpine`), not to
digests: pin digests if you need bit-for-bit reproducible builds.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `failed to connect to the docker API` | Docker Desktop is not running |
| `port is already allocated` | Set another `PASSAUDIT_WEB_PORT` |
| The page loads but the API is "unreachable" | `docker compose logs api`; check `docker compose ps` shows `api` healthy |
| `host_not_allowed` (400) | You opened the app by a name other than `localhost` / `127.0.0.1` / `[::1]` |
| A data set is "not available" | The file is not under `./data`, or the matching `PASSAUDIT_*` variable was not exported before `docker compose up` |
| Online check: `external_lookups_disabled` (403) | You did not add `docker-compose.egress.yml`, or `PASSAUDIT_EXTERNAL_LOOKUPS_ENABLED` is overridden to `false` |
