"""Application settings loaded from environment variables."""

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

    # Transport: "stdio" (local host such as VS Code) or "streamable-http" (CI/CD, shared server)
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000

    # Built-in bearer authentication (streamable-http only), disabled when no token is set.
    # Comma-separated entries "[label:]token" or "[label:]sha256:<hex>"; the file holds one
    # entry per line (# for comments). Generate entries with `security-review-mcp token`.
    auth_tokens: str | None = None
    auth_tokens_file: str | None = None

    # Optional TLS served by uvicorn (streamable-http only), enabled by tls_certfile.
    # tls_client_ca additionally requires client certificates signed by this CA (mutual TLS).
    tls_certfile: str | None = None
    tls_keyfile: str | None = None
    tls_keyfile_password: str | None = None
    tls_client_ca: str | None = None

    log_level: str = "INFO"

    # Directory holding internal rule packs (*.toml). Keep it writable by administrators only.
    rules_dir: str | None = None

    # Hard limits to protect the server and the database
    max_content_chars: int = 200_000
    max_findings_per_report: int = 500
    max_dependency_chars: int = 1_000_000
    max_list_limit: int = 100


@lru_cache
def get_settings() -> Settings:
    """Return the cached settings instance."""
    return Settings()
