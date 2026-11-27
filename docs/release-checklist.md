# Release checklist

How to turn this repository into a GitHub release. **Nothing in this repository publishes,
pushes or deploys anything**: CI only builds and tests, and the release workflow only produces
workflow artifacts. Every step marked **(manual)** below is a deliberate act by the maintainer.

## 1. Decisions only the maintainer can make

| Decision | Where | Notes |
| --- | --- | --- |
| **Copyright holder** | `LICENSE` (currently "PassAudit contributors") | Put the real name or organisation, then keep `pyproject.toml` `authors` in step |
| **Confirm MIT** | `LICENSE`, `pyproject.toml`, `frontend/package.json` | Chosen because all runtime dependencies are permissive and the bundled data is project-authored (see `THIRD_PARTY_NOTICES.md`). It is a legal decision: confirm it, or replace all three |
| **Repository address** | the clone commands in `docs/installation-*.md` and `docs/docker.md` | Set to `https://github.com/b4arzii/PassAudit.git`; change it if the repository moves or is renamed |
| **PyPI?** | `pyproject.toml` classifier `Private :: Do Not Upload` | Keep it unless you decide to publish to PyPI; removing it is that decision |
| **Container registry?** | none configured | Images are built locally; pushing to a registry is a separate decision and needs a new workflow |
| **Version** | `backend/src/passaudit/__init__.py`, `pyproject.toml`, `frontend/package.json` and `package-lock.json` | `backend/tests/test_release_metadata.py` fails if they differ, or if `CHANGELOG.md` lacks the entry |

## 2. Repository settings (manual, on GitHub, after creating the repository)

* **Security**: enable *Private vulnerability reporting* (Settings > Code security); `SECURITY.md`
  points to it. Enable Dependabot alerts and security updates; `.github/dependabot.yml` is already
  there.
* **Branch protection** on `main`: require the CI jobs (Backend x4, Frontend, Dependency audit,
  Containers), require pull requests, forbid force pushes.
* **Actions**: allow only GitHub-owned actions (the workflows use `actions/checkout`,
  `setup-python`, `setup-node`, `upload-artifact`); keep the default workflow token read-only.
* Optional: pin each `uses:` to a full commit SHA (Dependabot keeps it current) and the base images
  in the `Dockerfile` to digests, for supply-chain hardening. Both are noted as known gaps.

## 3. Before tagging: verify

Run on the commit you intend to tag. All of these have already been run on the tree this
checklist ships with; the results are in the [verification record](#verification-record).

```bash
# 1. Full gate (format, lint, types, tests, production build) and security audits
make check && make audit                 # Windows: .\scripts\check.ps1 -Audit

# 2. Containers: build, start, smoke-test, stop
docker compose up --build -d --wait
python docker/smoke_test.py              # 24 checks; must print "ALL PASSED"
docker compose down

# 3. Release artifacts build and install (what the release workflow does)
python -m pip install build && python -m build --outdir dist
python -m venv /tmp/rel && /tmp/rel/bin/pip install dist/*.whl && /tmp/rel/bin/passaudit version
```

Then, **by hand** (the real-browser checks are not in the repository; they need a browser):

* [ ] Open the Docker stack (<http://127.0.0.1:8080>) in a current browser. Audit a test password;
  open the developer tools and confirm there are **no CSP violations** and **no requests to any
  other origin**.
* [ ] Run axe (the browser extension, or `axe-core` in the console) on every page in the light and
  dark themes. Expect 0 violations.
* [ ] Resize to 360 px wide: no horizontal scrolling.
* [ ] Follow [installation-windows.md](installation-windows.md) and
  [installation-linux.md](installation-linux.md) literally on a clean machine or container, for
  each option you intend to support.
* [ ] Re-run the CLI and API examples in [cli.md](cli.md) and [api.md](api.md).
* [ ] Run the deep fuzz pass: `PASSAUDIT_FUZZ_ITERATIONS=4000 pytest backend/tests/api/test_fuzz.py`.

Keep the documentation honest:

* [ ] Update the test counts and coverage quoted in `README.md`, `docs/cli.md`, `docs/api.md`.
* [ ] Regenerate `THIRD_PARTY_NOTICES.md` if any runtime dependency changed (Python:
  `importlib.metadata` closure of `passaudit`; frontend: `npm ls --omit=dev --all --long`).
* [ ] Refresh `backend/requirements.lock.txt` (`scripts\freeze.ps1`) only from a green tree: the
  Docker build installs from it.
* [ ] Move the `CHANGELOG.md` entry from "not yet released" to the release date.
* [ ] Re-read `docs/security.md` "Known gaps" and `docs/qa-report.md`: are they still true?
* [ ] `git status` shows no `.env`, key, data set, screenshot of a real password, or personal path
  (`grep -rIl --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=.git "AppData\|/Users/" .`
  finds nothing).

## 4. Tag and release (manual)

Nothing below has been done. The repository currently has **no commits**.

```bash
git add -A && git status                # read the list: no secrets, no data
git commit -m "PassAudit 0.1.0"
git remote add origin https://github.com/b4arzii/PassAudit.git   # already configured
git push -u origin main                 # CI runs; wait for it to pass on all jobs
git tag -s v0.1.0 -m "PassAudit 0.1.0"  # signed tag (or -a for an annotated one)
git push origin v0.1.0                  # the release workflow builds the artifacts
```

Then, on GitHub:

1. Download the `passaudit-release-v0.1.0` artifact from the workflow run; check `SHA256SUMS.txt`.
2. Create a **draft** release from the tag; paste the `CHANGELOG.md` entry as the notes; attach the
   wheel, sdist, `passaudit-web-dist.tar.gz` and `SHA256SUMS.txt`.
3. Read the draft once more, then publish.

Do not publish to PyPI or a container registry unless you have decided to (section 1).

## 5. After the release

* [ ] Test the published instructions from a clean machine with the real clone URL.
* [ ] Start a new `## [Unreleased]` section in `CHANGELOG.md`.
* [ ] Watch the first Dependabot pull requests; merge them only when CI is green.

## Verification record

Results of the checks above on the tree this checklist ships with (2026-11-27). "Clean" means a
fresh copy of the project with no `.venv`, `node_modules`, build output or `.env`, placed in a
folder whose path contains a space on Windows.

| Check | Environment | Result |
| --- | --- | --- |
| Windows Option B (`pip install .`, CLI, API) | Windows 11, PowerShell 5.1, Python 3.12.9, clean copy | pass: install, `passaudit version`, CLI audit over stdin (no password in output), API `/health` and `/audit` |
| Windows Option C (`setup.ps1`, `check.ps1 -Audit`) | same, Node.js 24, clean copy | pass: **1211 backend tests, 98% coverage; 299 frontend tests**; ruff, mypy, ESLint, Prettier, tsc, build; bandit, pip-audit, npm audit clean |
| Linux Options B and C, literally as in the guide | clean `ubuntu:24.04` container, Python 3.12.3, Node.js 22.23.5 (checksum verified) | pass: `make setup`, `make check` (**1211 backend, 299 frontend tests**, build), `make audit` (no vulnerabilities); CLI and API examples |
| Backend on newer Python | `python:3.13-slim`, `python:3.14-slim` (Debian) | pass: ruff, mypy, 1170 tests each (run before the 41 release-hygiene tests were added) |
| Containers: build, health, `docker/smoke_test.py` | Docker 29.8, Compose 5.5, Docker Desktop (Linux engine) | pass: both images build; stack healthy; **24/24 checks** (API unreachable from host, no egress, non-root, read-only, no capabilities, no password in any log, no request body spooled) |
| Real browser through the containers | Edge, headless, port 8080 | pass: audit works under the CSP; cross-origin `fetch`, inline script, `eval`, foreign image blocked; no app CSP violations; no request left the origin |
| Data and egress overrides | Docker Desktop | pass: local breach file found `letmein` (count 99, risk 85) on a read-only mount; egress override adds the second network and enables the online check; the base stack returns to internal-only |
| Wheel and sdist (what `release.yml` builds) | `python:3.12-slim` | pass: wheel has the data files, license, entry point and `py.typed`, no tests; sdist holds no `.env`, key or frontend; the installed wheel runs |
| Workflow files | `actionlint` | pass (one finding fixed); all YAML parses |
| CLI and API documentation examples | Windows venv, Docker stack | pass after fixing one stale table (CSV columns); the API's `/docs` is 404 in production |
| Secrets and personal paths | whole tree | none found (credential patterns; user name, e-mail, local paths) |

Not verified: macOS; a real run of the GitHub Actions workflows (they have never run, and
`actionlint` only checks syntax); Windows with Python 3.13 or 3.14; the optional online breach check
against the real service (no external call was ever made); ARM; Docker on a Linux host (only
Docker Desktop).
