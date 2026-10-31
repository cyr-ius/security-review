# syntax=docker/dockerfile:1
#
# Image of security-review-mcp: one image, two processes sharing the database.
#
#   docker build -t security-review-mcp .   # SQLite and PostgreSQL (driver included)
#   docker build --target opengrep -t security-review-mcp:opengrep .   # plus the OpenGrep engine
#   docker build --target stdio -t security-review-mcp:stdio .   # MCP server alone, in stdio
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
#       --entrypoint security-review-controller security-review-mcp serve
#   docker run -d -p 127.0.0.1:8000:8000 -v secreview-data:/var/lib/secreview security-review-mcp
# Both processes listen on every interface of the container (SECREVIEW_HOST=0.0.0.0): the address
# of the host they are reachable on is chosen when publishing the port (-p 127.0.0.1:...).
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
# Build stage of the stdio image: same venv without the PostgreSQL driver (stdio accepts SQLite
# only) nor the web interface (served by the controller)
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS builder-stdio

COPY --from=uv /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-editable

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable

# ---------------------------------------------------------------------------
# OpenGrep stage: pinned binary of the OpenGrep engine of the controller, checked against its
# SHA-256 digest (same release as .devcontainer/install-opengrep.sh). To upgrade, change the
# version and both digests (field "digest" of the release assets on
# https://api.github.com/repos/opengrep/opengrep/releases).
# ---------------------------------------------------------------------------
FROM scratch AS opengrep-amd64
ADD --checksum=sha256:dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147 --chmod=0755 \
    https://github.com/opengrep/opengrep/releases/download/v1.31.0/opengrep_manylinux_x86 /opengrep

FROM scratch AS opengrep-arm64
ADD --checksum=sha256:2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d --chmod=0755 \
    https://github.com/opengrep/opengrep/releases/download/v1.31.0/opengrep_manylinux_aarch64 /opengrep

# Only the stage of the target architecture is built. OpenGrep extracts its bundle (~250 MB) in
# $XDG_CACHE_HOME at its first run: extracted once here, read-only, so that a scan neither
# extracts it again nor can alter it. A separate stage: the layer copied from it into the image
# does not change with the application, registries reuse it from one version to the next.
FROM opengrep-${TARGETARCH} AS opengrep-binary

FROM python:3.14-slim AS opengrep-bundle
COPY --from=opengrep-binary /opengrep /usr/local/bin/opengrep
RUN XDG_CACHE_HOME=/opt/opengrep/cache HOME=/tmp opengrep --version \
    && chmod -R a-w,a+rX /opt/opengrep

# ---------------------------------------------------------------------------
# Base of the runtime images: no build tools, no sources, non-root user
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS base

RUN groupadd --system --gid 10001 secreview \
    && useradd --system --uid 10001 --gid secreview --no-create-home \
       --shell /usr/sbin/nologin secreview \
    && mkdir -p /var/lib/secreview \
    && chown secreview:secreview /var/lib/secreview

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECREVIEW_DATABASE_URL=sqlite:////var/lib/secreview/security_reports.db

WORKDIR /var/lib/secreview

# ---------------------------------------------------------------------------
# Image of the MCP server alone, in stdio (target "stdio", "-stdio" tags), started by the host of
# a developer (VS Code...) with docker run -i: local SQLite database in the volume, no port, no
# controller use (no web interface, no PostgreSQL driver)
# ---------------------------------------------------------------------------
FROM base AS stdio

LABEL org.opencontainers.image.title="security-review" \
      org.opencontainers.image.description="Security code review: MCP server in stdio for a local host"

COPY --from=builder-stdio /app/.venv /app/.venv

VOLUME ["/var/lib/secreview"]

USER secreview

# The host talks to the server on stdin / stdout: run with docker run -i
ENTRYPOINT ["security-review-mcp"]
CMD ["serve", "--transport", "stdio"]

# ---------------------------------------------------------------------------
# Runtime stage of the MCP server and the controller
# ---------------------------------------------------------------------------
FROM base AS runtime

LABEL org.opencontainers.image.title="security-review" \
      org.opencontainers.image.description="Security code review: MCP server and controller (REST API, web interface, CI/CD gate)"

# Same path as in the build stage: the venv scripts reference it
COPY --from=builder /app/.venv /app/.venv

# A process listening on 127.0.0.1 is unreachable from outside its container: listen on every
# interface, the published port (-p 127.0.0.1:..., ports: in Compose) limits the exposure
ENV SECREVIEW_HOST=0.0.0.0 \
    SECREVIEW_OPENGREP_ENABLED=false

# The admin password hash and the project tokens are stored in the database. At its first start
# the controller creates the administrator "admin" (SECREVIEW_ADMIN_USERNAME) with a random
# password, never logged, replaced with
#   docker compose exec controller security-review-controller user reset-password admin

# Reports database (SQLite) lives in the volume, with the internal rules imported with
#   docker run --rm -v secreview-data:/var/lib/secreview -v ./rules.d:/rules:ro \
#       --entrypoint security-review-controller IMAGE rules import /rules
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

# ---------------------------------------------------------------------------
# Image with the OpenGrep engine of the controller (target "opengrep", "-opengrep" tags): binary
# and extracted bundle owned by root, read-only
# ---------------------------------------------------------------------------
FROM runtime AS opengrep

COPY --from=opengrep-bundle /usr/local/bin/opengrep /usr/local/bin/opengrep
COPY --from=opengrep-bundle /opt/opengrep /opt/opengrep
ENV XDG_CACHE_HOME=/opt/opengrep/cache \
    SECREVIEW_OPENGREP_ENABLED=true

# ---------------------------------------------------------------------------
# Default image (last stage): without OpenGrep
# ---------------------------------------------------------------------------
FROM runtime
