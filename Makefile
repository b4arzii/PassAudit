# PassAudit developer shortcuts for Linux and macOS (the PowerShell scripts in scripts/ are the
# Windows equivalents). `make help` lists the targets.

SHELL := /bin/bash
VENV ?= .venv
PY := $(VENV)/bin/python
NPM := npm --prefix frontend

.DEFAULT_GOAL := help
.PHONY: help setup setup-backend setup-frontend format format-check lint typecheck test \
        test-backend test-frontend build-web check audit dev-api dev-web docker-up docker-down \
        clean

help: ## List the targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

# ------------------------------------------------------------------------------------ setup
$(PY):
	python3 -m venv $(VENV)

setup: setup-backend setup-frontend .env ## Create .venv, install everything, create .env

setup-backend: $(PY) ## Python virtual environment + backend dependencies
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

setup-frontend: ## Frontend dependencies (needs Node.js 22+)
	$(NPM) ci

.env:
	cp .env.example .env

# --------------------------------------------------------------------------- quality checks
format: ## Format the code (ruff, Prettier)
	$(PY) -m ruff format .
	$(NPM) run format

format-check: ## Check formatting without changing files
	$(PY) -m ruff format --check .
	$(NPM) run format:check

lint: ## ruff + ESLint
	$(PY) -m ruff check .
	$(NPM) run lint

typecheck: ## mypy --strict + tsc
	$(PY) -m mypy
	$(NPM) run typecheck

test-backend: ## pytest with coverage
	$(PY) -m pytest --cov

test-frontend: ## Vitest
	$(NPM) test

test: test-backend test-frontend ## All tests

build-web: ## Production build of the frontend
	$(NPM) run build

check: format-check lint typecheck test build-web ## The full quality gate

audit: ## bandit, pip-audit, npm audit
	$(PY) -m bandit -q -c pyproject.toml -r backend/src
	$(PY) -m pip_audit
	$(NPM) run audit

# ----------------------------------------------------------------------------------- running
dev-api: ## API on http://127.0.0.1:8000 (reloads on change)
	$(PY) -m uvicorn passaudit.main:app --host 127.0.0.1 --port 8000 --reload \
		--reload-dir backend/src --no-access-log

dev-web: ## Frontend on http://127.0.0.1:5173 (run dev-api in another terminal)
	$(NPM) run dev

docker-up: ## Build and start the containers on http://127.0.0.1:8080
	docker compose up --build -d --wait

docker-down: ## Stop the containers
	docker compose down

clean: ## Remove caches and build output
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml \
		frontend/dist frontend/coverage
	find . -name __pycache__ -type d -not -path './.venv/*' -not -path '*/node_modules/*' \
		-prune -exec rm -rf {} +
