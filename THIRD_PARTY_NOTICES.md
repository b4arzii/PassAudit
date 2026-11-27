# Third-party notices

PassAudit itself is released under the [MIT License](LICENSE). It depends on the open-source
components below. This list covers what runs in production (the Python runtime closure and the
frontend's production dependencies), generated from the locked versions in this repository;
development tools (ruff, mypy, pytest, Vite, ESLint, ...) are not distributed with it. Each
component remains under its own license; see its package for the full text.

All of them are permissive licenses compatible with MIT. None is copyleft.

## Bundled fonts (SIL Open Font License 1.1)

The built frontend includes these fonts, self-hosted (no CDN is contacted). The OFL requires the
license to accompany the font files; the full texts are served with the application at
`/licenses/` and kept in [`frontend/public/licenses/`](frontend/public/licenses/).

| Font | Copyright | Package | License text |
| --- | --- | --- | --- |
| Inter | The Inter Project Authors (<https://github.com/rsms/inter>) | `@fontsource-variable/inter` 5.3.0 | [OFL-Inter.txt](frontend/public/licenses/OFL-Inter.txt) |
| JetBrains Mono | The JetBrains Mono Project Authors (<https://github.com/JetBrains/JetBrainsMono>) | `@fontsource-variable/jetbrains-mono` 5.3.0 | [OFL-JetBrains-Mono.txt](frontend/public/licenses/OFL-JetBrains-Mono.txt) |

## Python runtime dependencies

| Package | Version | License |
| --- | --- | --- |
| annotated-doc | 0.0.7 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.16.0 | MIT |
| click | 8.5.1 | BSD-3-Clause |
| colorama (Windows only) | 0.4.6 | BSD-3-Clause |
| fastapi | 0.165.0 | MIT |
| h11 | 0.16.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| markdown-it-py | 4.3.0 | MIT |
| mdurl | 0.1.2 | MIT |
| opentelemetry-api | 1.45.2 | Apache-2.0 |
| pydantic | 2.14.4 | MIT |
| pydantic-core | 2.50.5 | MIT |
| pydantic-settings | 2.16.3 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| rich | 15.0.0 | MIT |
| shellingham | 1.5.4 | ISC |
| starlette | 1.10.0 | BSD-3-Clause |
| typer | 0.29.3 | MIT |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.5 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |
| zxcvbn | 4.5.0 | MIT |

## Frontend production dependencies

| Package | Version | License |
| --- | --- | --- |
| @fontsource-variable/inter | 5.3.0 | OFL-1.1 |
| @fontsource-variable/jetbrains-mono | 5.3.0 | OFL-1.1 |
| cookie | 1.1.1 | MIT |
| lucide-react | 1.81.0 | ISC |
| react | 19.3.1 | MIT |
| react-dom | 19.3.1 | MIT |
| react-router | 7.18.7 | MIT |
| react-router-dom | 7.18.7 | MIT |
| scheduler | 0.28.0 | MIT |
| set-cookie-parser | 2.7.3 | MIT |

## Container images

The Docker images are built from `python:3.12-slim`, `node:22-slim` (build stage only) and
`nginxinc/nginx-unprivileged:1.28-alpine`, which carry their own licenses (Debian packages,
Python Software Foundation License, nginx BSD-2-Clause, Alpine/musl and others). Their license
information is available inside each image.

## Data

The word, name and common-password lists in `backend/src/passaudit/analysis/data/` are small
hand-written samples created for this project and are covered by the MIT License. PassAudit does
not bundle any breach corpus.

## Regenerating this list

Versions and licenses come from `importlib.metadata` in the project's virtual environment
(Python) and `npm ls --omit=dev --all --long` (frontend). Regenerate after dependency changes; this
is a step in [docs/release-checklist.md](docs/release-checklist.md).
