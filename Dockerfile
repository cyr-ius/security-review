# syntax=docker/dockerfile:1
#
# Image of security-review-mcp: one image, two processes sharing the database.
#
#   docker build -t security-review-mcp .   # SQLite and PostgreSQL (driver included)
#
# stdio (developer workstation, the MCP host starts the container itself):
#   docker run -i --rm -v secreview-data:/var/lib/secreview security-review-mcp \
#       serve --transport stdio
#
# Shared server (see docker-compose.yml): the MCP server (default entrypoint, MCP on /mcp) and
# the controller (REST API on /api/v1, web interface on /ui, administration commands) run in
# two containers. Enable TLS (SECREVIEW_TLS_CERTFILE, SECREVIEW_TLS_KEYFILE) or put them behind
# a reverse proxy that enforces it:
#   docker run --rm -v secreview-data:/var/lib/secreview --entrypoint security-review-controller \
#       security-review-mcp db upgrade
#   docker run -d -p 127.0.0.1:8080:8000 -v secreview-data:/var/lib/secreview \
#       --entrypoint security-review-controller security-review-mcp serve --host 0.0.0.0
#   docker run -d -p 127.0.0.1:8000:8000 -v secreview-data:/var/lib/secreview security-review-mcp \
#       serve --host 0.0.0.0 --port 8000
# (SQLite in a shared volume is for a single host only: use PostgreSQL otherwise.)

# Base images are written out (no ARG) so that Dependabot can propose their updates
FROM ghcr.io/astral-sh/uv:0.13.5 AS uv

# ---------------------------------------------------------------------------
# Web stage: build the Angular interface (served on /ui by the controller)
# ---------------------------------------------------------------------------
# The bundle does not depend on the architecture: built once, on the platform of the builder
FROM --platform=$BUILDPLATFORM node:26-slim AS web

WORKDIR /web/web

# Dependencies first: this layer is reused as long as package-lock.json does not change
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund

# The build writes into ../src/security_review_mcp/webui (see web/angular.json)
COPY web/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Build stage: resolve dependencies from uv.lock into a self-contained venv
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS builder

COPY --from=uv /uv /bin/uv

# Byte-compile for faster start-up, copy files out of the cache, never download a Python
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

# Dependencies first: this layer is reused as long as uv.lock does not change
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-editable --extra postgres

# Then the project itself (README.md is required by the setuptools build)
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY --from=web /web/src/security_review_mcp/webui ./src/security_review_mcp/webui
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable --extra postgres

# ---------------------------------------------------------------------------
# Runtime stage: no build tools, no sources, non-root user
# ---------------------------------------------------------------------------
FROM python:3.14-slim

LABEL org.opencontainers.image.title="security-review-mcp" \
      org.opencontainers.image.description="MCP server for security code review"

RUN groupadd --system --gid 10001 secreview \
    && useradd --system --uid 10001 --gid secreview --no-create-home \
       --shell /usr/sbin/nologin secreview \
    && mkdir -p /var/lib/secreview \
    && chown secreview:secreview /var/lib/secreview

# Same path as in the build stage: the venv scripts reference it
COPY --from=builder /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECREVIEW_DATABASE_URL=sqlite:////var/lib/secreview/security_reports.db

# The admin password hash and the project tokens are stored in the database. At its first start
# the controller creates the administrator "admin" (SECREVIEW_ADMIN_USERNAME) with a random
# password, never logged, replaced with
#   docker compose exec controller security-review-controller user reset-password admin

# Reports database (SQLite) lives in the volume, with the internal rules imported with
#   docker run --rm -v secreview-data:/var/lib/secreview -v ./rules.d:/rules:ro \
#       --entrypoint security-review-controller IMAGE rules import /rules
WORKDIR /var/lib/secreview
VOLUME ["/var/lib/secreview"]

USER secreview

# MCP server (serve) or controller (serve)
EXPOSE 8000

# /healthz of the HTTP MCP server or of the controller (always healthy in stdio: no port)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "security_review_mcp.healthcheck"]

# HTTP MCP server by default (`serve`); arguments replace the command: `serve` with its
# transport options (`--transport stdio` for a local host), or `enroll`. The controller and its
# commands (serve, db, token, rules...) use --entrypoint security-review-controller (Docker) or
# command: (Compose, Kubernetes).
ENTRYPOINT ["security-review-mcp"]
CMD ["serve"]
