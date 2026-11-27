# PassAudit Command-Line Interface

Package: `backend/src/passaudit/cli/` (Typer + Rich). The CLI uses the
[analysis engine](analysis-engine.md) directly and does not need FastAPI, Node.js or a running
server. It makes no network call unless you pass `--breach online --allow-external`.

| Command | Purpose |
| --- | --- |
| `passaudit audit` | Audit **one** password: strength, weaknesses, policy, risk score, advice |
| `passaudit batch FILE` | Audit **many** passwords from a file; summary, reuse detection, reports |
| `passaudit policy check` | Check one password against a policy, rule by rule |
| `passaudit policy show` | Print the effective policy as JSON (a template for `--policy`) |
| `passaudit policy profiles` | List the built-in and custom policy profiles |
| `passaudit reuse build` / `reuse info` | Build / inspect an authorised reuse index (see [Phase 8 options](#phase-8-options-and-commands)) |
| `passaudit version` | Show the version (`--verbose` adds engine and dependency versions) |
| `passaudit --help` | Help for any command: `passaudit <command> --help` |

Global options: `--no-color` (the `NO_COLOR` environment variable is also honoured),
`--version` / `-V`, `--help` / `-h`. Running `passaudit` with no arguments prints the help.

## Running it

Install first: [Windows](installation-windows.md), [Linux](installation-linux.md) or
[Docker](docker.md). The examples in this page write `passaudit ...`; use whichever form fits how
you installed it:

| Installed with | Run it as |
| --- | --- |
| Linux or macOS virtual environment | `.venv/bin/passaudit audit` (or activate the venv: `source .venv/bin/activate`) |
| Windows virtual environment | `.\.venv\Scripts\python.exe -m passaudit audit`, or `.\scripts\passaudit.ps1 audit` |
| Docker Compose | `docker compose run --rm cli audit` (add `-T` when piping: `... run --rm -T cli audit --stdin`) |
| Any platform | `python -m passaudit audit` with the venv's Python |

The console script `passaudit` is declared in `pyproject.toml`, but on Windows machines with
Application Control (see [ADR 0002](adr/0002-application-control-compatible-dependencies.md))
the generated `passaudit.exe` launcher can be **blocked**; `python -m passaudit` and
`scripts\passaudit.ps1` always work. The wrapper preserves the exit code and piping. The Windows
`.\scripts\passaudit.ps1` form is used in the PowerShell examples below.

On Linux and macOS, the same commands read, for example:

```bash
printf '%s\n' 'correct horse battery staple' | .venv/bin/passaudit audit --stdin -f json
.venv/bin/passaudit batch passwords.txt -f json -o report.json
```

## How passwords are entered (and never entered)

**There is no `--password` option, and no command accepts a password as an argument.** Command
lines are visible to other processes and end up in shell history. Instead:

| Method | Command | Notes |
| --- | --- | --- |
| Hidden prompt | `passaudit audit` | Nothing is echoed (`getpass`). The prompt text is written to **stderr**, so redirecting stdout to a file cannot capture it. Needs a real terminal. |
| Standard input | `passaudit audit --stdin` | First line of stdin, decoded as UTF-8 (a BOM is ignored). For scripts: `'secret' \| .\scripts\passaudit.ps1 audit --stdin`. |
| File | `passaudit batch passwords.txt` | `-` reads the list from stdin. |

Without a terminal and without `--stdin` the command refuses to run (exit 3) rather than
silently falling back to an echoing prompt. A password typed after a command by mistake is
rejected and **not echoed back**:

```text
> passaudit audit hunter2
Error: Unexpected extra argument. PassAudit never accepts a password on the command line. ...
```

Windows PowerShell 5.1 pipes text to programs as ASCII by default. `scripts\passaudit.ps1`
switches to UTF-8 for you; if you call `python -m passaudit` directly with a non-ASCII password,
set `$OutputEncoding = [Text.UTF8Encoding]::new($false)` first.

## `passaudit audit`

```powershell
.\scripts\passaudit.ps1 audit                                   # hidden prompt, terminal report
.\scripts\passaudit.ps1 audit --usage master_password -d        # stricter target, full detail
'correct horse battery staple' | .\scripts\passaudit.ps1 audit --stdin --format json
.\scripts\passaudit.ps1 audit --policy corp.toml --personal-info-file me.txt
```

The terminal view shows an overview panel (risk score with bar and level, strength, length,
entropy estimate, usage target, policy, verdict), findings with **1-based character ranges**
(never the characters themselves), the policy rules, and prioritised recommendations.
`--details` / `-d` adds the crack-time estimates and the full risk-score breakdown.

| Option | Meaning |
| --- | --- |
| `--stdin` | Read the password from stdin instead of the hidden prompt |
| `--policy FILE`, `--min-length N`, `--min-strength-score N` | Policy file and overrides (see [Policies](#policy-files)) |
| `--usage` | `general` (default), `online_account`, `privileged_account`, `master_password`, `encryption_key` |
| `--reused` | Tell the audit the password is used on more than one service |
| `--personal-info-file FILE` | One personal string per line (name, username, e-mail...); max 50 lines of 256 characters; `#` comments allowed |
| `--wordlist FILE` | Custom blocklist, one password per line (replaces the bundled list) |
| `--max-length N` | Longest accepted password, 1-65536 (default 1024). Longer input is rejected, never truncated |
| `--format text\|json\|csv`, `-f` | Output format (default `text`) |
| `--output FILE`, `-o` | Write the json/csv report to a file (the terminal view is still shown) |
| `--force` | Allow `--output` to overwrite an existing file |
| `--fail-on none\|moderate\|high\|critical` | Risk level that fails the run (default `high`) |
| `--details`, `-d` / `--quiet`, `-q` | More / less terminal output |

Settings are validated **before** the password is requested, so a typo in `--policy` fails
immediately instead of after you have typed a secret.

## `passaudit batch`

```powershell
.\scripts\passaudit.ps1 batch passwords.txt                        # one password per line
.\scripts\passaudit.ps1 batch export.csv --input-format csv        # needs a header row
.\scripts\passaudit.ps1 batch export.csv --input-format csv --password-column secret --label-column user
.\scripts\passaudit.ps1 batch passwords.txt -f json -o report.json # summary on screen, report in a file
Get-Content passwords.txt | .\scripts\passaudit.ps1 batch - -f csv > results.csv
```

* **Identification.** Entries are identified by their position (`index`), source line number and
  an optional label. Labels come from the CSV `--label-column`; they are stripped of control
  characters, limited to 64 characters, and replaced by `[redacted]` if they contain the
  password (a password pasted into the label column cannot leak).
* **Reuse.** Identical passwords within the file are detected and flagged `reused_in_batch`;
  those entries are analysed with the "reused elsewhere" context.
* **Blank lines** are skipped and counted. Leading/trailing spaces are part of the password.
  UTF-8 with or without BOM, LF or CRLF.
* **Over-long passwords** (`--max-length`) are not analysed; they are reported as
  `error: too_long` and count as failures. Lines are read with a bounded buffer, so a
  multi-megabyte line cannot exhaust memory.
* **`--max-entries`** (default 10 000) refuses larger files instead of silently truncating.
* **Memory.** Each password reference is dropped as soon as it has been analysed; duplicates
  are detected in memory only.
* **CSV input pitfall.** `--input-format csv` treats the first row as a header. Feeding it a
  plain password list fails with "no column named 'password'" - and the message deliberately
  does not list the columns, because here the "header" would be a password.

Text view: summary panel, risk distribution, and a table of the highest-risk entries
(`--show N`, default 15). JSON adds per-entry records (`--detailed` embeds the full analysis).

## `passaudit policy check` / `policy show`

```powershell
.\scripts\passaudit.ps1 policy check --policy corp.toml          # prompt, rule-by-rule table
'Zq7!xKp#9mWv$L2nRb' | .\scripts\passaudit.ps1 policy check --stdin --min-digits 3 --min-uppercase 1
.\scripts\passaudit.ps1 policy show --min-length 16 > policy.json   # start a policy file
```

`policy check` lists only the rules that are **enabled** and marks each `PASS` / `FAIL` with the
reason. Extra override options (beyond `--min-length` / `--min-strength-score`):
`--min-lowercase`, `--min-uppercase`, `--min-digits`, `--min-symbols`, `--max-repeat-run`,
`--no-whitespace`. The policy rules are documented in
[analysis-engine.md](analysis-engine.md#password-policy).

### Policy files

`--policy FILE` accepts `.json` or `.toml`. Fields are those of the engine's `PasswordPolicy`;
they may sit at the top level or inside a `policy` table. Unknown fields and out-of-range values
are rejected with a precise message (values are never echoed). Precedence: **built-in defaults,
then the file, then command-line overrides.**

```toml
# corp.toml
[policy]
min_length = 14
min_uppercase = 1
min_digits = 1
min_symbols = 1
max_repeat_run = 3
min_strength_score = 3
```

## Phase 8 options and commands

Available on `audit`, `batch` and (where noted) `policy check`:

| Option | Meaning |
| --- | --- |
| `--profile NAME` / `--profiles-file FILE` | a named policy (`policy profiles` lists them); overrides like `--min-length` apply on top; not combinable with `--policy`; a profile's usage applies unless `--usage` is given |
| `--dictionary FILE` (repeatable) | extra word list for dictionary analysis |
| `--breach local --breach-file FILE` | search a sorted `SHA1[:count]` hash file; no network |
| `--breach online --allow-external` | ask a k-anonymity range service about a 5-character hash prefix per distinct password; prints what it sends first; `--breach-url` (https only) selects a mirror. Without `--allow-external` it is a usage error and nothing happens |
| `--reuse-index FILE --reuse-key-file FILE --confirm-authorized --authorization-ref TEXT` | compare with an authorised reuse index (`audit`, `batch`); all four are required |

```powershell
passaudit policy profiles
passaudit audit --stdin --profile high-security --breach local --breach-file pwned-sorted.txt
passaudit reuse build --source hr-export=hr.txt --source vpn=vpn.txt `
  --index-out reuse.idx --key-file reuse.key --confirm-authorized --authorization-ref TICKET-42
passaudit batch pw.txt -f json -o report.json --reuse-index reuse.idx --reuse-key-file reuse.key `
  --confirm-authorized --authorization-ref TICKET-42
passaudit reuse info --index reuse.idx --key-file reuse.key
```

* A failed lookup never fails the audit: the result says `unavailable` (**unchecked**), and a
  rule needing the lookup prints `NOT CHECKED`.
* JSON reports are schema version 2: they add `external_checks` (modes, host, dataset names,
  authorisation reference - no data) and `integrity.checksum`, and are **refused** (exit 4) if they
  would contain a submitted password or personal detail. CSV gains `breach` and `reuse_datasets`.
* `reuse build` creates the key file if missing (never overwrites an index without `--force`),
  streams datasets, stores only HMAC digests, and refuses to run without the authorisation flags.

## Exit codes

| Code | Meaning | Examples |
| --- | --- | --- |
| `0` | Success; everything passed | policy satisfied and risk below `--fail-on` |
| `1` | The check ran but **failed** | policy violation, risk level at/above `--fail-on`, any batch entry failed or was too long |
| `2` | Usage error | unknown option, extra argument, `--output` without `--format json\|csv`, report path equals an input file |
| `3` | Input error | no terminal for the prompt, empty/invalid password input, bad policy or word list, missing batch file, no passwords in file |
| `4` | Report could not be written | file exists (no `--force`), directory missing, path is a directory |
| `70` | Unexpected internal error | only the exception **class** is printed |
| `130` | Interrupted | Ctrl-C, or end of input at the prompt |

`audit` and `batch` fail on **any policy violation**, or when the risk level reaches
`--fail-on` (default `high`; `none` checks the policy only). `policy check` fails on policy
violations only. Use it in scripts:

```powershell
'secret' | .\scripts\passaudit.ps1 audit --stdin -q
if ($LASTEXITCODE -eq 1) { 'password rejected' }
```

## Reports

`--format json` and `--format csv` produce **sanitized** reports - to stdout, or to a file with
`--output`. In a report:

* **Never present:** the password, any hash/prefix/mask/fragment of it, personal-information
  strings, matched words, file names of policy/word-list/personal-info files.
* **Present:** positions and lengths, finding kinds, scores, levels, strength labels,
  `guesses_log10`, estimated bits, policy rule names, recommendation codes, settings (counts and
  flags), timestamp (UTC), tool and engine versions, and the optional sanitized batch label.

| Report | Shape |
| --- | --- |
| `audit` JSON | `report`, `settings`, `policy`, `verdict`, `analysis` (the full engine result) |
| `batch` JSON | `report`, `settings`, `policy`, `summary`, `results[]` (compact; `--detailed` adds `analysis`) |
| `policy check` JSON | `report`, `settings`, `policy`, `verdict`, `length`, `rules[]` |
| `audit` / `batch` CSV | one row per password, columns `index,line,label,status,error,length,risk_score,risk_level,strength_score,strength_label,guesses_log10,estimated_bits,policy_compliant,policy_violations,findings,recommendations,reused_in_batch,breach,reuse_datasets,failed,fail_reasons` |
| `policy check` CSV | `rule,requirement,status,required,actual,message` |

JSON is ASCII-only and indented; CSV is UTF-8 with `\n` line endings, list values joined by `;`.
**Spreadsheet formula injection** is neutralised: a label (or any text cell) beginning with
`=`, `+`, `-`, `@`, tab or CR is written with a leading `'`.

Writing safety: an existing `--output` file is **not overwritten** without `--force`, and a
report path equal to the batch **input file** is refused even with `--force` (so a mistyped
`-o` cannot destroy your password list).

## Security properties

| Guarantee | How | Test |
| --- | --- | --- |
| Passwords never on argv | no password option/argument exists; stray arguments rejected without echo | `test_basic.py`, `test_security_cli.py::test_no_command_accepts_a_password_argument_or_option` |
| Prompt really hidden | `getpass`; prompt on stderr; refuses non-terminals | `test_audit.py`, mutation check (`hide_input=False` is caught) |
| Rejected option values not echoed | values in usage errors are replaced by the rule (choices / range) | `test_basic.py` |
| No traceback or locals ever shown | Typer pretty exceptions disabled; `SafeGroup` prints the exception **class** only (exit 70) | `test_security_cli.py::test_unexpected_exception_shows_only_its_class` |
| Nothing logged or printed behind your back | no `logging`/`print`/`subprocess`/network imports (AST test); runtime log capture | `test_security_cli.py` |
| Outputs and reports free of secrets | whitelisted fields from the password-free engine result; canary passwords and personal info searched for in every command x format | `test_security_cli.py::test_no_secret_reaches_any_output_or_report_file` |
| Terminal-safe output | Rich markup escaped; labels sanitised; ASCII-only glyphs; unencodable characters replaced | `test_batch.py`, `test_units.py` |
| Bounded work | length caps on prompt, stdin and batch lines; entry cap; zxcvbn truncation (engine) | `test_audit.py`, `test_batch.py` |
| No overwriting by accident | `x` open mode unless `--force`; input path protected | `test_audit.py`, `test_batch.py`, `test_units.py` |

**Residual risks** (inherent, not fixable in the CLI): a password you *pipe* may appear in your
shell history if you typed it into the command (`echo secret | ...` - prefer the hidden prompt
or a secret manager); batch input files contain the passwords in plain text on disk -
delete or encrypt them; Python cannot wipe strings from memory (see
[security.md](security.md)); a terminal that records its screen records what is printed
(passwords are never printed, but the prompt is `stderr`).

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/cli      # CLI tests only (294)
.\scripts\test.ps1 -Only backend                             # everything, with coverage
```

On Linux: `.venv/bin/python -m pytest backend/tests/cli` or `make test-backend`.

`backend/tests/cli/`: `test_basic` (help, version, usage errors), `test_audit`,
`test_batch`, `test_policy_cmd`, `test_units` (verdicts, reports, input parsing, rendering),
`test_security_cli` (leak matrix, static guarantees), `test_process` (real `python -m passaudit`
subprocesses), `test_phase8_cli` (profiles, breach, reuse, sealed reports) and `test_phase9_cli`
(reuse error paths). Tests use Typer's `CliRunner`; the interactive prompt is tested by feeding the
runner's input stream, with the terminal check (`inputs.stdin_is_tty`) patched to "interactive".

## Design notes

* **Typer bundles its own Click** since 0.29 (`typer._click`). The CLI therefore imports neither
  and recognises click-style errors by class name and attributes, so it also works with older
  Typer releases that use the real `click` package.
* Every failure funnels through one place (`SafeGroup` in `cli/app.py`), which is how exit
  codes, redaction and "no tracebacks" are guaranteed uniformly. See
  [ADR 0004](adr/0004-cli-design.md).
