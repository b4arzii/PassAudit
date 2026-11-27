# ADR 0004: CLI design

- Status: Accepted (Phase 3)
- Date: 2026-11-26

## Context

Phase 3 adds a professional command-line interface on top of the analysis engine. A password
tool's CLI has failure modes ordinary CLIs do not: argv is world-readable, frameworks print
tracebacks with local variables, parsing errors echo what the user typed, and reports are
shared. Constraints: Typer + Rich, Windows 11 with Application Control, no change to the engine.

## Decisions

1. **No way to pass a password on the command line.** No `--password` option or password
   argument exists (a test walks the whole command tree to enforce it). Input is a hidden
   `getpass` prompt, `--stdin`, or - for batch - a file. A stray argument is rejected without
   echoing it. The only positional argument is the batch file path.
2. **Refuse to prompt without a terminal** instead of falling back to a visible prompt; the
   error points to `--stdin`. The prompt text goes to stderr so stdout can be a clean report.
3. **One hardened entry point (`SafeGroup`).** It overrides `main`, turns every exception into a
   fixed message plus an exit code, disables Typer's pretty exceptions (which print locals), and
   for unexpected errors prints only the exception **class name**. It also rewrites Click-style
   usage errors so rejected values are replaced by the rule they broke.
4. **Click-agnostic.** Typer 0.29 vendors a private Click (`typer._click`) and no longer depends
   on `click`. Importing `click` would silently catch nothing. Errors are identified by class
   name/attributes and only Typer's public API is used, which also works on older Typer.
5. **Documented exit codes** (0 ok, 1 check failed, 2 usage, 3 input, 4 output, 70 internal,
   130 interrupted) so scripts can distinguish "password is weak" from "tool misused".
   `audit`/`batch` fail on any policy violation or when risk reaches `--fail-on` (default
   `high`).
6. **Validate configuration before asking for a secret** (policy, word list, personal info,
   output options), so a typo never costs the user a retyped password.
7. **Reports are whitelisted, not filtered.** Report builders copy named fields from the
   password-free engine result; there is no code path that reads the password. Batch labels are
   the only free text and are sanitised and redacted if they contain the password. CSV cells
   are protected against spreadsheet formula injection.
8. **Never destroy user data.** Reports refuse to overwrite without `--force`, and never write
   over a batch input file.
9. **Batch is bounded and streaming-safe.** Bounded line reads, an entry cap, over-long lines
   reported (not stored), password references dropped after analysis, duplicates detected
   in memory only.
10. **ASCII-only terminal glyphs and words, not colour alone,** for pass/fail; user-supplied
    text is escaped and made encodable. A `scripts\passaudit.ps1` wrapper exists because the
    generated `passaudit.exe` launcher can be blocked by Application Control (ADR 0002).

## Consequences

- New runtime dependencies `typer` and `rich` (pure Python; Typer 0.29 adds `shellingham`,
  `annotated-doc`). The CLI imports only `passaudit.analysis` - not FastAPI.
- The CLI depends on a few Typer behaviours (vendored exception names, `param.min/max`); tests
  fail if an upgrade changes them, because error sanitisation is security-relevant.
- Shell completion is disabled (`add_completion=False`) to avoid writing to user profiles.
- Residual risks (history of piped secrets, plaintext batch files, no memory wiping) are
  documented in `docs/cli.md` and `docs/security.md`.
