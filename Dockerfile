# syntax=docker/dockerfile:1
#
# Image of the security-review-mcp server.
#
#   docker build -t security-review-mcp .
#   docker build -t security-review-mcp:pg --build-arg EXTRAS=postgres .   # PostgreSQL driver
#
# stdio (developer workstation, the MCP host starts the container itself):
#   docker run -i --rm -v secreview-data:/data security-review-mcp
#
# Streamable HTTP (shared server, MCP on /mcp and web interface on /ui). Bearer tokens are
# stored in the database (`security-review-mcp token create`); enable TLS (SECREVIEW_TLS_CERTFILE,
# SECREVIEW_TLS_KEYFILE) or put the server behind a reverse proxy that enforces it:
#   docker run -d -p 127.0.0.1:8000:8000 -v secreview-data:/data security-review-mcp \
#       --transport streamable-http --host 0.0.0.0 --port 8000

ARG PYTHON_VERSION=3.12
ARG NODE_VERSION=24

# ---------------------------------------------------------------------------
# Web stage: build the Angular interface (served on /ui with streamable-http)
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-slim AS web

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
FROM python:${PYTHON_VERSION}-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /bin/uv

# Byte-compile for faster start-up, copy files out of the cache, never download a Python
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

# Optional extra from pyproject.toml (e.g. "postgres")
ARG EXTRAS=""

# Dependencies first: this layer is reused as long as uv.lock does not change
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-editable ${EXTRAS:+--extra "$EXTRAS"}

# Then the project itself (README.md is required by the setuptools build)
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY --from=web /web/src/security_review_mcp/webui ./src/security_review_mcp/webui
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable ${EXTRAS:+--extra "$EXTRAS"}

# ---------------------------------------------------------------------------
# Runtime stage: no build tools, no sources, non-root user
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim

LABEL org.opencontainers.image.title="security-review-mcp" \
      org.opencontainers.image.description="MCP server for security code review"

RUN groupadd --system --gid 10001 secreview \
    && useradd --system --uid 10001 --gid secreview --no-create-home \
       --shell /usr/sbin/nologin secreview \
    && mkdir -p /data \
    && chown secreview:secreview /data

# Same path as in the build stage: the venv scripts reference it
COPY --from=builder /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECREVIEW_DATABASE_URL=sqlite:////data/security_reports.db \
    SECREVIEW_AUTH_BOOTSTRAP_ADMIN=true

# The admin password hash and the project tokens are stored in the database

# Reports database (SQLite) lives in the volume, with the internal rules imported with
#   docker run --rm -v secreview-data:/data -v ./rules.d:/rules:ro IMAGE rules import /rules
WORKDIR /data
VOLUME ["/data"]

USER secreview

# Only used with --transport streamable-http
EXPOSE 8000

# Arguments are passed through: transport options or CLI commands (gate, sarif, trend, deps...)
ENTRYPOINT ["security-review-mcp"]
