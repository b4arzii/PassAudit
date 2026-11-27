# Security policy

PassAudit handles passwords, so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue** for a vulnerability, and never include real credentials in a
report.

Report it privately, in this order of preference:

1. **GitHub private vulnerability reporting**: on the repository, *Security* > *Report a
   vulnerability*. (The maintainer must have enabled it; see the release checklist.)
2. If that is not available, contact the maintainer directly, using the contact details on the
   maintainer's GitHub profile.

Include: what you found, the version (`passaudit version`), how to reproduce it with a test
password, and what you think the impact is. A fix and a regression test are welcome but not
required.

This is a small project maintained on a best-effort basis: there is no service-level agreement.
You can expect an acknowledgement, an assessment, and credit in the changelog if you want it.

## Supported versions

Only the latest release receives security fixes.

## What counts as a vulnerability

In scope (examples):

* any way for a **submitted password, personal detail or derived value** to reach a log, a file, a
  URL, a response body, a report, browser storage, or a third party - against the rules in
  [docs/privacy.md](docs/privacy.md);
* a way to make the opt-in breach check send more than the 5-character hash prefix, or to send
  anything without both opt-in switches;
* bypassing the local-only protections (loopback bind, `Host` allow-list, CORS, rate limits, size
  limits) or the Content-Security-Policy;
* a container or configuration default that exposes the API beyond the local machine;
* remote code execution, path traversal or arbitrary file read through any input;
* a dependency vulnerability that is reachable in PassAudit's usage.

Out of scope (known and documented in [docs/security.md](docs/security.md#known-gaps)):

* the API having **no authentication**: it is built for one person on one machine and refuses to
  bind to a non-loopback address unless you override it explicitly. Exposing it anyway is a
  deployment error, not a vulnerability;
* attacks that need control of the machine, the browser, or the Docker socket (malware, extensions,
  memory dumps);
* Python and JavaScript not wiping strings from memory;
* denial of service by a local user who can already run the CLI;
* the report checksum not being a signature (it says so);
* findings that only apply to the development server (`/docs`, Vite).

## How PassAudit tries to stay safe

The design and its limits are in [docs/security.md](docs/security.md) (threat model, controls and
the test that verifies each one) and [docs/qa-report.md](docs/qa-report.md) (the audit that was
done and what it found). CI runs `bandit`, `pip-audit` and `npm audit`, and Dependabot proposes
dependency updates weekly.
