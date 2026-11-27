# ADR 0001: Technology stack and repository layout

- Status: Accepted (Phase 1)
- Date: 2026-11-26

## Context

PassAudit is a local-first password auditing tool developed on Windows 11 with Python 3.12,
Node 24, and PowerShell. It needs an HTTP API plus a browser UI, strong typing, and a small,
reviewable dependency set.

## Decision

- **Backend:** Python 3.12, FastAPI, pydantic v2 / pydantic-settings, uvicorn. `src/` layout so
  tests import the installed package, not the working directory.
- **Frontend:** React 19, TypeScript (strict), Vite 7, Vitest.
- **Quality tooling:** ruff (lint+format), mypy strict, pytest (+coverage), bandit, pip-audit;
  ESLint (typescript-eslint strict-type-checked), Prettier, `npm audit`.
- **Packaging:** a single root `pyproject.toml` (setuptools backend) owns Python metadata and all
  Python tool configuration; `frontend/` is a self-contained npm project with a committed lockfile.
- **Automation:** PowerShell scripts in `scripts/` as the single entry point for every task.
  No Makefile/task runner dependency on Windows.
- **Monorepo:** one repository, `backend/` and `frontend/` side by side, joined in development
  by the Vite `/api` proxy.

## Alternatives considered

- **uv / Poetry** for Python dependency management - capable, but plain `venv` + `pip` + PEP 621
  metadata has zero extra bootstrap and works on every machine. Revisit if a hash-pinned lock
  becomes a requirement.
- **Flask / Django** - FastAPI gives typed request/response models and OpenAPI with less code.
- **pnpm / yarn** - not installed; npm is sufficient.
- **Separate `pyproject.toml` under `backend/`** - rejected for now; one config root keeps ruff,
  mypy and pytest consistent. Can be split when backend gets its own deployment artifact.

## Consequences

- Contributors need Python 3.12+ and Node 22+ only.
- Python reproducibility relies on version ranges plus a reference snapshot, not a hashed lock.
- Everything runs through `scripts\check.ps1`, which is the intended CI entry point later.
