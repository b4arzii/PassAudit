## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## Checklist

- [ ] `make check` / `scripts\check.ps1` passes locally (and `-Audit` if dependencies changed)
- [ ] Tests added or updated; a security-relevant change has a canary test
- [ ] Docs updated where behaviour changed (README, docs/, `.env.example`, CHANGELOG)
- [ ] **No password, real credential, `.env`, key or data set** is included, in code, tests, fixtures or screenshots
- [ ] No new outbound network call, third-party origin or telemetry (or it is opt-in, documented, and in `breach/providers.py`)
- [ ] New runtime dependency? Permissive license, added to `THIRD_PARTY_NOTICES.md`
