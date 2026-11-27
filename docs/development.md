# Development Guide

Primary platform: **Windows 11**, **PowerShell** (Windows PowerShell 5.1 and PowerShell 7 both
work). **Linux** is supported through the `Makefile` (`make help`); see
[installation-linux.md](installation-linux.md). The PowerShell scripts below and the `make`
targets do the same jobs:

| PowerShell | make | |
| --- | --- | --- |
| `scripts\setup.ps1` | `make setup` | environment and dependencies |
| `scripts\check.ps1` | `make check` | the full quality gate |
| `scripts\check.ps1 -Audit` | `make check audit` | plus bandit, pip-audit, npm audit |
| `scripts\dev.ps1 -Only backend` / `-Only frontend` | `make dev-api` / `make dev-web` | dev servers |
| `scripts\test.ps1` | `make test` | backend and frontend tests |

Containers: `docker compose up --build -d --wait` ([docker.md](docker.md)).

## Prerequisites

| Tool    | Version | Notes                                          |
| ------- | ------- | ---------------------------------------------- |
| Python  | 3.12+   | Installed via the `py` launcher or on `PATH`   |
| Node.js | 22+     | npm is used (no pnpm/yarn required)            |
| Git     | any     | Optional for running, needed for contributing  |

## First-time setup

```powershell
.\scripts\setup.ps1          # creates .venv, installs backend + frontend deps, creates .env
.\scripts\setup.ps1 -Recreate  # rebuild the virtual environment from scratch
```

If script execution is blocked: `powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1`.

## Daily commands

| Command                           | What it does                                              |
| --------------------------------- | --------------------------------------------------------- |
| `.\scripts\dev.ps1`               | Start backend (:8000) and frontend (:5173) in two windows |
| `.\scripts\dev.ps1 -Only backend` | Backend only, with auto-reload                            |
| `.\scripts\format.ps1`            | Auto-format (ruff format + prettier); `-Check` verifies   |
| `.\scripts\lint.ps1`              | ruff + ESLint; `-Fix` applies safe fixes                  |
| `.\scripts\typecheck.ps1`         | mypy `--strict` + `tsc`                                   |
| `.\scripts\test.ps1`              | pytest (with coverage) + Vitest; `-Only backend\|frontend` |
| `.\scripts\check.ps1`             | Everything above + frontend build. **Run before commits** |
| `.\scripts\check.ps1 -Audit`      | Also bandit, pip-audit, npm audit (needs network)         |
| `.\scripts\clean.ps1`             | Remove caches/build output; `-All` also removes `.venv`, `node_modules` |
| `.\scripts\freeze.ps1`            | Refresh `backend/requirements.lock.txt`                    |

Direct tool access (after setup):

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -k health
cd frontend; npm run test:watch   # run the frontend toolchain from PowerShell, not Git Bash
```

API docs in development: <http://127.0.0.1:8000/docs>.

Call the API once the backend is running (`.\scripts\dev.ps1 -Only backend`):

```powershell
$b = @{ password = 'Summer2024!' } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/v1/audit -Method Post -ContentType 'application/json' -Body $b
```

See [api.md](api.md); interactive docs are at <http://127.0.0.1:8000/docs>. API tests only:
`.\.venv\Scripts\python.exe -m pytest backend/tests/api`.

Run the CLI (no server needed):

```powershell
.\scripts\passaudit.ps1 --help
.\scripts\passaudit.ps1 audit
```

See [cli.md](cli.md). Try the analysis engine from a Python shell:

```powershell
.\.venv\Scripts\python.exe -c "from passaudit.analysis import analyze_password as a; r = a('Summer2024!'); print(r.risk.score, r.risk.level.value)"
```

Engine tests only: `.\.venv\Scripts\python.exe -m pytest backend/tests/analysis`; CLI tests only:
`.\.venv\Scripts\python.exe -m pytest backend/tests/cli`. See
[analysis-engine.md](analysis-engine.md) for the full guide.

## Configuration

Settings come from `PASSAUDIT_*` environment variables or `.env` (see `.env.example`).
`.env` is git-ignored. Frontend variables must be `VITE_*` and are **public** - never put
secrets in them.

## Code standards

- **Python:** ruff (lint + format, line length 100), mypy strict, pytest. Source in
  `backend/src/passaudit`, tests in `backend/tests`.
- **TypeScript:** `strict` plus `noUncheckedIndexedAccess` / `exactOptionalPropertyTypes`,
  ESLint `strictTypeChecked`, Prettier (single quotes, 100 cols).
- Line endings: LF everywhere except `*.ps1` (CRLF), enforced by `.gitattributes` / `.editorconfig`.
- Keep PowerShell scripts ASCII-only (Windows PowerShell 5.1 misreads BOM-less UTF-8).

## Windows Application Control (Smart App Control) notes

On machines where Smart App Control or WDAC is enforcing, unsigned native binaries without
established reputation are blocked (`An Application Control policy has blocked this file`).
Phase 1 was developed on such a machine, so the toolchain is arranged to avoid the problem:

- **mypy:** newest releases need compiled `librt`. `setup.ps1` detects this and installs the
  pure-Python build (`mypy<1.19`, `--no-binary`).
- **pip-audit:** `tomli` / `charset-normalizer` are installed from source (pure Python).
- **Frontend:** Vite 7 is used (Vite 8's rolldown binary is blocked); `rollup` is replaced by
  the WebAssembly build `@rollup/wasm-node` and `esbuild` is pinned to 0.25.12 through npm
  `overrides` in `frontend/package.json`.
- `uvicorn` is installed without the `[standard]` extra (avoids `httptools` / `watchfiles`).

On an unrestricted machine you can drop these workarounds; see
[ADR 0002](adr/0002-application-control-compatible-dependencies.md) for how to revisit them.

## Troubleshooting

| Symptom                                           | Fix                                                        |
| ------------------------------------------------- | ---------------------------------------------------------- |
| `Virtual environment not found`                   | Run `.\scripts\setup.ps1`                                  |
| `An Application Control policy has blocked this file` | See the section above; re-run `setup.ps1`, or `-Recreate` |
| Port 5173 in use                                  | Vite runs with `strictPort`; stop the other process        |
| Port 8000 in use                                  | Change `PASSAUDIT_PORT` in `.env`, and the proxy target in `frontend/vite.config.ts` |
| Orphaned `python.exe` on :8000 after killing a window | End the process, or close dev windows with Ctrl+C       |
