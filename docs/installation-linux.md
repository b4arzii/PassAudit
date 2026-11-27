# Installing PassAudit on Linux

Three ways, from least to most effort. All of them keep the default promise: **nothing leaves your
machine unless you opt in** (see [privacy.md](privacy.md)).

| You want | Use | Needs |
| --- | --- | --- |
| The web app, one command | [Docker](#option-a-docker-recommended) | Docker Engine + Compose v2 |
| Only the command-line tool or the API | [Python only](#option-b-python-only-cli-and-api) | Python 3.12+ |
| To develop or run the tests | [Full development setup](#option-c-full-development-setup) | Python 3.12+, Node.js 22+ |

Verified on **Ubuntu 24.04 (x86-64) with Python 3.12 and Node.js 22.23**; see
[What was verified](#what-was-verified). Other distributions need the same packages under
different names. macOS works the same way with Homebrew (`brew install python@3.12 node@22`) but
has not been tested.

If you use a fork, clone your fork instead.

## Option A: Docker (recommended)

```bash
git clone https://github.com/b4arzii/PassAudit.git
cd PassAudit
docker compose up --build -d --wait
```

Open <http://127.0.0.1:8080>. Stop it with `docker compose down`.

The web app is published on `127.0.0.1` only; the API has no published port and no route to the
internet. Command-line use, local data sets and the optional online breach check are covered in
[docker.md](docker.md).

## Option B: Python only (CLI and API)

No Node.js is needed.

```bash
# Debian / Ubuntu. Other distributions: install Python 3.12+ with venv and pip.
sudo apt update
sudo apt install -y git curl python3 python3-venv python3-pip

git clone https://github.com/b4arzii/PassAudit.git
cd PassAudit
python3 -m venv .venv
.venv/bin/pip install .
```

Use a virtual environment: recent Debian and Ubuntu releases refuse `pip install` into the system
Python ("externally-managed-environment").

Check it works:

```bash
.venv/bin/passaudit version
printf '%s\n' 'correct horse battery staple' | .venv/bin/passaudit audit --stdin -f json | head -20
```

`passaudit audit` without `--stdin` asks for the password at a hidden prompt. Passwords are never
accepted as command-line arguments, because those appear in `ps` and shell history. All commands
are in [cli.md](cli.md).

Run the API (loopback only, no authentication):

```bash
.venv/bin/uvicorn passaudit.main:app --host 127.0.0.1 --port 8000 --no-access-log
curl -s http://127.0.0.1:8000/api/v1/health          # {"status":"ok","version":"0.1.0"}
curl -s http://127.0.0.1:8000/api/v1/audit -H 'Content-Type: application/json' \
     -d '{"password":"Summer2024!"}'
```

`--no-access-log` matters: uvicorn's own access log records URLs and query strings; PassAudit
writes its own sanitized log. Full reference: [api.md](api.md).

## Option C: Full development setup

You also need **Node.js 22 or newer** for the web app and its tests. Ubuntu 24.04's packaged Node
is too old, so install the official build and check its signature file's hash:

```bash
sudo apt install -y xz-utils make
NODE_VERSION=22.23.5          # any current 22.x LTS from https://nodejs.org/en/download
cd /tmp
curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt"
grep " node-v${NODE_VERSION}-linux-x64.tar.xz\$" SHASUMS256.txt | sha256sum -c -
sudo tar -xJf "node-v${NODE_VERSION}-linux-x64.tar.xz" -C /usr/local --strip-components=1
node --version && npm --version
```

(On ARM, use `linux-arm64` in both file names.) A version manager such as `nvm` works as well.

Then, from the repository:

```bash
make setup          # .venv, Python and npm dependencies, and a .env copied from .env.example
make check          # format, lint, type-check, all tests, production build
make dev-api        # terminal 1: http://127.0.0.1:8000
make dev-web        # terminal 2: http://127.0.0.1:5173
```

`make help` lists every target. Without `make`, the equivalents are:

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
(cd frontend && npm ci)
.venv/bin/python -m pytest --cov                 # backend tests
(cd frontend && npm test && npm run build)       # frontend tests and production build
```

If you use PowerShell 7 on Linux, `pwsh ./scripts/setup.ps1` and `pwsh ./scripts/check.ps1` do the
same as `make setup` and `make check`.

## Configuration

Copy `.env.example` to `.env` (`make setup` does) and edit it. Every variable is documented in the
file. The defaults bind to loopback, allow no outbound lookups and keep interactive API docs on
(`/docs`, development only). Never put secrets in `VITE_*` variables: they reach the browser.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `The virtual environment was not created successfully because ensurepip is not available` | `sudo apt install python3-venv` |
| `error: externally-managed-environment` | Install into a virtual environment, as above |
| `npm ci` or Vite fails with a syntax error | Node.js is older than 22; check `node --version` |
| `Address already in use` | Something else owns port 8000 or 5173: `ss -ltnp \| grep -E ':(8000\|5173)'` |
| `host_not_allowed` (400) from the API | You called it with a `Host` that is not `localhost`, `127.0.0.1` or `[::1]`. This is DNS-rebinding protection; see `PASSAUDIT_ALLOWED_HOSTS` |
| `host must be a loopback address` at start-up | You set `PASSAUDIT_HOST` to a non-loopback address. The API has no authentication; read [security.md](security.md) before changing this |

## Uninstall

Delete the repository folder (it contains `.venv` and `frontend/node_modules`). For Docker:
`docker compose down --rmi local`. Nothing is installed outside the folder, except Node.js if you
used the tarball above (`sudo rm -rf /usr/local/{bin/node,bin/npm,bin/npx,lib/node_modules,include/node}`).

## What was verified

On a clean `ubuntu:24.04` container (Python 3.12.3), following Options B and C literally: install,
`passaudit version`, a CLI audit over stdin, the API answering `/health` and `/audit`, `pytest`,
`ruff`, `mypy`, `vitest` and the production build. The exact results are in
[release-checklist.md](release-checklist.md#verification-record).
