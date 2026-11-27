# ADR 0002: Dependencies must run under Windows Application Control

- Status: Accepted (Phase 1)
- Date: 2026-11-26

## Context

The development machine runs Windows 11 with **Smart App Control in enforcement mode**
(`VerifiedAndReputablePolicyState = 1`). It blocks unsigned native code (`.exe`, `.pyd`, `.node`)
that lacks cloud reputation - typically the newest release of a package. Observed in Phase 1:

| Component                                   | Result                |
| ------------------------------------------- | --------------------- |
| `mypy` 2.x (`librt`, `ast_serialize`)       | blocked               |
| `httptools` (from `uvicorn[standard]`)      | blocked               |
| `tomli`, `charset-normalizer` compiled wheels (`pip-audit`) | blocked |
| Vite 8 (`rolldown` `.node` binding)         | blocked               |
| `@rollup/rollup-win32-x64-msvc` (latest)    | blocked               |
| `esbuild` 0.28.x                            | blocked               |
| `esbuild` 0.25.12 / 0.24.2 / 0.21.5         | runs                  |
| `pydantic-core`, `ruff`                     | runs                  |

Turning Smart App Control off would weaken the machine's protection (and has historically been
hard to undo), so it is **not** an acceptable fix; the project adapts to the policy instead.

## Decision

Choose toolchain versions and install modes that avoid blocked binaries, and encode the choices
so setup is reproducible:

- Python: pure-Python builds where compiled ones are blocked (`pip --no-binary`), automated in
  `scripts\setup.ps1`. `uvicorn` without the `[standard]` extra.
- Frontend: Vite 7 + Vitest 4 + `@vitejs/plugin-react` 5; npm `overrides` replace `rollup` with
  `@rollup/wasm-node` and pin `esbuild` to 0.25.12.
- `setup.ps1` probes each tool after install and falls back automatically, so unrestricted
  machines still get the normal compiled packages.

## Consequences

- Pure-Python mypy is slower than the compiled build (acceptable at this code size).
- Vite 7 / Vitest 4 are one major behind the newest releases.
- The `esbuild` pin and the rollup WASM override are workarounds that should be re-evaluated
  periodically.

## Revisiting

To test whether a workaround is still needed, remove the `overrides` block (or the
`--no-binary` fallback), run `scripts\setup.ps1 -Recreate` followed by `scripts\check.ps1`, and
keep the change only if every step passes. Check the policy state with:

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy').VerifiedAndReputablePolicyState
# 0 = off, 1 = enforce, 2 = evaluation
```
