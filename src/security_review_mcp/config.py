"""Application settings loaded from environment variables."""

import logging
import sys
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Server settings (prefix: SECREVIEW_)."""

    model_config = SettingsConfigDict(
        env_prefix="SECREVIEW_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # SQLite by default (zero setup).
    # PostgreSQL example: postgresql+psycopg2://user:pass@host:5432/secreview
    database_url: str = "sqlite:///./security_reports.db"
    database_echo: bool = False
    # Migrate the schema (Alembic) when the controller, the stdio MCP server or a CLI command
    # starts. Set it to false when a dedicated job runs `security-review-controller db upgrade`
    # (Kubernetes): they then only check the schema. The HTTP MCP server never migrates.
    db_auto_upgrade: bool = True

    # MCP server transport: "stdio" (local host such as VS Code) or "streamable-http" (shared
    # server). host and port are used by the HTTP MCP server and by the controller.
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000

    # Bearer authentication of the HTTP MCP server and of the controller. Tokens are stored in
    # the database (SHA-256 digests only) and managed with `security-review-controller token`.
    # This makes the controller generate a one-time administrator password on its first start
    # (enabled in the Docker image).
    auth_bootstrap_admin: bool = False

    # Enrollment (HTTP MCP server, once a token exists): a client without a token reaches a
    # restricted MCP server that only lets it request a project token, and POST /api/v1/enroll
    # on the MCP server accepts the same request. The token works once an administrator
    # approves it on the controller.
    enrollment: bool = True

    # Optional TLS served by uvicorn (HTTP MCP server and controller), enabled by tls_certfile.
    # tls_client_ca additionally requires client certificates signed by this CA (mutual TLS).
    tls_certfile: str | None = None
    tls_keyfile: str | None = None
    tls_keyfile_password: str | None = None
    tls_client_ca: str | None = None
    # Without tls_certfile, serve HTTPS with a self-signed certificate generated at start-up
    # (new key on every start, for tests or an internal network; not trusted by clients).
    tls_self_signed: bool = False

    # Controller: REST API on /api/v1 and, with web_ui, the Angular application on /ui.
    # web_ui_dir overrides the directory of the built application (default: bundled files).
    web_ui: bool = True
    web_ui_dir: str | None = None

    log_level: str = "INFO"

    # Hard limits to protect the server and the database
    max_content_chars: int = 200_000
    max_findings_per_report: int = 500
    max_dependency_chars: int = 1_000_000
    max_list_limit: int = 100


@lru_cache
def get_settings() -> Settings:
    """Return the cached settings instance."""
    return Settings()


def configure_logging(level: str) -> None:
    """Send the logs to stderr: stdout is reserved for the MCP protocol with stdio."""
    logging.basicConfig(
        level=level.upper(),
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
