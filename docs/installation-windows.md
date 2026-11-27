# Installing PassAudit on Windows

Three ways, from least to most effort. All of them keep the default promise: **nothing leaves your
machine unless you opt in** (see [privacy.md](privacy.md)).

| You want | Use | Needs |
| --- | --- | --- |
| The web app, one command | [Docker Desktop](#option-a-docker-desktop) | Docker Desktop |
| Only the command-line tool or the API | [Python only](#option-b-python-only-cli-and-api) | Python 3.12+ |
| To develop, run the tests, or run the web app natively | [Full development setup](#option-c-full-development-setup) | Python 3.12+, Node.js 22+ |

Windows 11 with Windows PowerShell 5.1 (the one that ships with Windows) is the platform this
project was built and tested on. PowerShell 7 works too. Commands below are for PowerShell;
if you use a fork, clone your fork instead.

## Prerequisites

Install what your option needs. `winget` ships with current Windows:

```powershell
winget install --id Python.Python.3.12 -e         # Python 3.12 (3.13 and 3.14 also work)
winget install --id OpenJS.NodeJS.LTS -e           # Node.js LTS (needs to be 22 or newer; Option C only)
winget install --id Git.Git -e                     # optional, to clone
winget install --id Docker.DockerDesktop -e        # optional, Option A only
```

Open a **new** PowerShell window afterwards so `PATH` is refreshed, then check:

```powershell
py -3.12 --version        # Python 3.12.x
node --version            # v22.x or newer (Option C)
```

## Option A: Docker Desktop

Start Docker Desktop, then:

```powershell
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

```powershell
git clone https://github.com/b4arzii/PassAudit.git
cd PassAudit
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
```

Check it works:

```powershell
.\.venv\Scripts\python.exe -m passaudit version
'correct horse battery staple' | .\.venv\Scripts\python.exe -m passaudit audit --stdin -f json
```

`python -m passaudit` is the same as the `passaudit` command; it is used here because Windows
Smart App Control or Application Control can block the generated `passaudit.exe` launcher (see
[Troubleshooting](#troubleshooting)). `passaudit audit` without `--stdin` asks for the password at
a hidden prompt. Passwords are never accepted as command-line arguments, because those appear in
process lists and shell history. All commands are in [cli.md](cli.md).

Run the API (loopback only, no authentication):

```powershell
.\.venv\Scripts\python.exe -m uvicorn passaudit.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

In a second window:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
$body = @{ password = 'Summer2024!' } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/v1/audit -Method Post -ContentType 'application/json' -Body $body
```

`--no-access-log` matters: uvicorn's own access log records URLs and query strings; PassAudit
writes its own sanitized log. Full reference: [api.md](api.md).

## Option C: Full development setup

```powershell
git clone https://github.com/b4arzii/PassAudit.git
cd PassAudit
.\scripts\setup.ps1        # .venv, Python and npm dependencies, and a .env copied from .env.example
.\scripts\check.ps1        # format, lint, type-check, all tests, production build
.\scripts\dev.ps1          # API on http://127.0.0.1:8000 and web app on http://127.0.0.1:5173
```

`setup.ps1` is safe to re-run (`-Recreate` rebuilds the virtual environment). `dev.ps1` opens the
two servers in separate windows (`-Only backend` or `-Only frontend` starts one). Add `-Audit` to
`check.ps1` to include `bandit`, `pip-audit` and `npm audit`. The other scripts
(`format.ps1`, `lint.ps1`, `typecheck.ps1`, `test.ps1`, `clean.ps1`, `freeze.ps1`,
`passaudit.ps1`) are listed in the [development guide](development.md#daily-commands).

Use the CLI from the project environment without activating anything:

```powershell
.\scripts\passaudit.ps1 version
'correct horse battery staple' | .\scripts\passaudit.ps1 audit --stdin -f json
```

## Configuration

Copy `.env.example` to `.env` (`setup.ps1` does) and edit it. Every variable is documented in the
file. The defaults bind to loopback, allow no outbound lookups and keep interactive API docs on
(`/docs`, development only). Never put secrets in `VITE_*` variables: they reach the browser.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `running scripts is disabled on this system` | Run once per window: `Set-ExecutionPolicy -Scope Process Bypass`, or prefix a script with `powershell -ExecutionPolicy Bypass -File` |
| `passaudit.exe` or `bandit.exe` "was blocked" / "Access is denied" | Smart App Control or Application Control. Use `python -m passaudit`, `scripts\passaudit.ps1`, or `python -m bandit`. Details: [ADR 0002](adr/0002-application-control-compatible-dependencies.md) |
| `setup.ps1` warns that mypy or pip-audit "native extensions are blocked" | Expected under Application Control; the script installs pure-Python builds automatically |
| A script stops with `NativeCommandError` after an `npm warn ...` line | In Windows PowerShell 5.1, redirecting or piping a script's output (`2>&1`, `\| Select-String`) turns harmless stderr warnings into errors. Run `setup.ps1` / `check.ps1` without redirection, or use PowerShell 7 |
| `py` is not recognised | Install Python from python.org with the "py launcher" option, or use `python` instead of `py -3.12` |
| `Python 3.12+ required` | The first `python` on `PATH` is older; install 3.12+ or use `py -3.12` |
| `npm ci` fails or Vite refuses to start | Node.js is older than 22: `node --version` |
| `Address already in use` | Another program uses port 8000 or 5173: `Get-NetTCPConnection -LocalPort 8000 -State Listen` |
| Vitest reports `Invalid Chai property: toHaveAttribute` | You ran it from Git Bash; run `npm test` from PowerShell |
| `host_not_allowed` (400) from the API | You called it with a `Host` that is not `localhost`, `127.0.0.1` or `[::1]` (DNS-rebinding protection); see `PASSAUDIT_ALLOWED_HOSTS` |
| `host must be a loopback address` at start-up | You set `PASSAUDIT_HOST` to a non-loopback address. The API has no authentication; read [security.md](security.md) first |

Windows Defender Firewall should not prompt: PassAudit binds to `127.0.0.1` only, which is not
reachable from other machines.

## Uninstall

Delete the repository folder (it contains `.venv` and `frontend\node_modules`). For Docker:
`docker compose down --rmi local`. Nothing is written outside the folder.

## What was verified

On Windows 11 (Windows PowerShell 5.1, Python 3.12, Node.js 24): a fresh copy of the project in a
different folder, following Options B and C literally. The exact results are in
[release-checklist.md](release-checklist.md#verification-record).
