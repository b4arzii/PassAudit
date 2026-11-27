# syntax=docker/dockerfile:1.7
#
# PassAudit container images. Two runnable targets share this file:
#
#   api  - the FastAPI service (and the `passaudit` CLI) as an unprivileged user
#   web  - nginx serving the built frontend and proxying /api to the api service
#
#   docker build --target api -t passaudit-api .
#   docker build --target web -t passaudit-web .
#
# See docs/docker.md. Nothing in an image contains a password, a .env file or any data set:
# .dockerignore excludes them and the images only receive their configuration at run time.

# ------------------------------------------------------------------------------ python build
FROM python:3.12-slim AS py-build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src

# Dependencies first (cached until the lock or metadata change), pinned by the verified snapshot.
COPY backend/requirements.lock.txt backend/requirements.lock.txt
COPY pyproject.toml README.md LICENSE ./
COPY backend/src backend/src
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -c backend/requirements.lock.txt .

# ---------------------------------------------------------------------------------- api image
FROM python:3.12-slim AS api

LABEL org.opencontainers.image.title="PassAudit API" \
      org.opencontainers.image.description="Local-first password auditing API and CLI" \
      org.opencontainers.image.licenses="MIT"

# An unprivileged user with no home directory and no shell.
RUN groupadd --system --gid 10001 passaudit \
    && useradd --system --uid 10001 --gid passaudit --no-create-home --shell /usr/sbin/nologin passaudit

COPY --from=py-build /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PASSAUDIT_ENV=production \
    PASSAUDIT_PORT=8000

# The API has no authentication. Inside the image it must listen on all interfaces so that the
# web container can reach it; that is only safe because Compose attaches it to an internal
# network and publishes no port for it. Never publish this port to a network you do not control.
ENV PASSAUDIT_HOST=0.0.0.0 \
    PASSAUDIT_ALLOW_NON_LOOPBACK_BIND=true

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3).status == 200 else 1)"]

# uvicorn's own access log records query strings; the app writes a sanitized one instead.
CMD ["uvicorn", "passaudit.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

# -------------------------------------------------------------------------- frontend build
FROM node:25-slim AS web-build

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------------- web image
FROM nginxinc/nginx-unprivileged:1.28-alpine AS web

LABEL org.opencontainers.image.title="PassAudit web" \
      org.opencontainers.image.description="PassAudit frontend behind a strict Content-Security-Policy" \
      org.opencontainers.image.licenses="MIT"

COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=web-build /app/frontend/dist /usr/share/nginx/html

EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=4s --start-period=5s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/"]
