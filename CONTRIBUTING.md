# Contributing to PassAudit

Thanks for helping. The rules below exist because this tool handles passwords: a contribution that
breaks the privacy guarantees is a bug even if every test passes.

## Ground rules

1. **Never log, store, print or send a password** or anything derived from it (a hash, a prefix, a
   mask, a fragment) - not at debug level, not in an exception message, not in a test fixture you
   commit. The full list is "Non-negotiable rules for future code" in
   [docs/security.md](docs/security.md).
2. **No network calls** except in `backend/src/passaudit/breach/providers.py`, and only behind the
   two opt-in switches. An architecture test fails otherwise.
3. **Do not commit** `.env`, key files, data sets, breach corpora or real passwords. Use obviously
   fake ones (`Zq7!xKp#9mWv$L2nRb`, `correct horse battery staple`).
4. **Report vulnerabilities privately**: see [SECURITY.md](SECURITY.md).

## Set up

[Windows](docs/installation-windows.md) or [Linux](docs/installation-linux.md), "Full development
setup". In short: `make setup` (Linux/macOS) or `.\scripts\setup.ps1` (Windows).

## Before you open a pull request

```bash
make check             # Linux/macOS          Windows: .\scripts\check.ps1
make audit             #                              .\scripts\check.ps1 -Audit
```

That runs, and CI repeats on Linux and Windows:

| Tool | What it enforces |
| --- | --- |
| `ruff format` / Prettier | formatting |
| `ruff check` / ESLint (`strictTypeChecked`) | lint, including security rules (`S`) |
| `mypy --strict` / `tsc` | types |
| `pytest --cov` / Vitest | tests (branch coverage is reported; keep it from dropping) |
| `bandit`, `pip-audit`, `npm audit` | static security analysis and known-vulnerable dependencies |

Also:

* **Add a test** for every behaviour change. Security properties get a *canary test*: put a
  distinctive fake password through the code path and assert that it appears nowhere in outputs,
  logs, files or reports (see `backend/tests/api/test_privacy.py` for the pattern).
* **Keep docs true.** If you change behaviour, change the page that describes it. Documentation
  examples are run before releases ([release checklist](docs/release-checklist.md)).
* **Explain decisions that are not obvious** in the commit message, and add an
  [ADR](docs/adr/) for architectural ones.
* Keep changes focused. Do not reformat unrelated code.
* Frontend changes: check both themes and a phone-width viewport, keep keyboard access and
  accessible names intact (`axe-core` runs in the tests), and do not add a third-party origin: the
  Content-Security-Policy (`frontend/csp.ts`) would block it, deliberately.

## Style

Python: ruff, line length 100, type hints everywhere, `from __future__ import annotations`.
TypeScript: strict, no `any`, named exports, single quotes. LF line endings (`.ps1` files use CRLF).
See [docs/development.md](docs/development.md).

## Dependencies

Add a runtime dependency only with a clear need, and prefer the standard library. New runtime
dependencies must have a permissive license and be added to
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Pin by compatible range in `pyproject.toml` /
`package.json`, commit `frontend/package-lock.json`, and run the audits.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
