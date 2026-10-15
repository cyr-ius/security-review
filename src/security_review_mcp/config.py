"""Application settings loaded from environment variables."""

import logging
import sys
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Language name or code given to the agent (for example "French", "fr", "pt-BR"): letters,
# spaces, hyphens, underscores and parentheses only, so that it cannot carry instructions.
REPORT_LANGUAGE_MAX_CHARS = 40


def check_report_language(value: str) -> str:
    """Return the stripped report language, or raise ValueError if it is not a plain name."""
    language = value.strip()
    if len(language) > REPORT_LANGUAGE_MAX_CHARS:
        raise ValueError(f"report language too long (max {REPORT_LANGUAGE_MAX_CHARS} chars)")
    if not all(c.isalpha() or c in " -_()" for c in language):
        raise ValueError(
            "report language must be a language name or code, for example French, fr or pt-BR"
        )
    return language


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
    # PostgreSQL: postgresql+psycopg2://user:pass@host:5432/db  # secreview:ignore GEN-007
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
    # This makes the controller create the web user "admin" with a random password, logged once,
    # on its first start while no web user exists (enabled in the Docker image).
    auth_bootstrap_admin: bool = False

    # Controller only: sessions of the web interface (password and OIDC logins), tokens signed
    # with session_secret (at least 32 characters, shared by the replicas; random per start when
    # unset) and valid session_hours (1 to 24).
    session_secret: str | None = None
    session_hours: int = 8

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
    # Extra names of the self-signed certificate, comma-separated: the DNS names or IP addresses
    # the clients use (localhost, 127.0.0.1, ::1, the hostname and --host are always included).
    tls_self_signed_hosts: str | None = None

    # Controller: REST API on /api/v1 and, with web_ui, the Angular application on /ui.
    # web_ui_dir overrides the directory of the built application (default: bundled files).
    web_ui: bool = True
    web_ui_dir: str | None = None

    # Controller only: OpenID Connect login to the web interface (authorization code + PKCE),
    # disabled by default. oidc_redirect_uri is the public URL of /api/v1/auth/oidc/callback,
    # registered at the provider. oidc_client_secret is empty for a public client. The values of
    # oidc_roles_claim (dotted path allowed, e.g. realm_access.roles) are matched against the
    # role mappings stored in the database (web interface) and the comma-separated groups below
    # (every project; highest role wins, see role_mapping); without a match, oidc_default_role
    # ("", "reader" or "triager") applies. A login opens the SSO web user named by
    # oidc_username_claim: with oidc_auto_create_users it is created at the first login (when its
    # groups or the default role give it a role), otherwise an administrator creates it first.
    # Sessions use session_secret and session_hours. oidc_cafile replaces the system CA bundle
    # for the provider.
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str | None = None
    oidc_redirect_uri: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_roles_claim: str = "groups"
    oidc_admin_groups: str = ""
    oidc_triager_groups: str = ""
    oidc_reader_groups: str = ""
    oidc_default_role: str = ""
    oidc_username_claim: str = "preferred_username"
    oidc_auto_create_users: bool = False
    oidc_display_name: str = "SSO"
    oidc_cafile: str | None = None

    # Controller only: HTTP proxy of its outgoing connections (OSV download, SSO identity
    # provider), http://[user:password@]host:port, and the comma-separated hosts reached without
    # it (no_proxy: a domain also covers its subdomains, an IP address or CIDR range the URLs
    # whose host is such an address, * every host; the loopback interface is always direct).
    # Without proxy, urllib applies HTTPS_PROXY / NO_PROXY. Both can be overridden in the web
    # interface (Paramètres, see app_settings).
    proxy: str | None = None
    no_proxy: str | None = None

    # Controller only: download the OSV exports (all.zip of each ecosystem) from osv_url and
    # import them every osv_update_interval_hours. Disabled by default (the MCP server never
    # connects anywhere). osv_cafile is a CA bundle used instead of the system one (mirror or
    # TLS-inspecting proxy).
    osv_auto_update: bool = False
    osv_update_interval_hours: int = 24
    osv_url: str = "https://osv-vulnerabilities.storage.googleapis.com"
    osv_ecosystems: str = "PyPI,npm,Maven"
    osv_cafile: str | None = None
    osv_max_download_mb: int = 1024

    # Language of the review reports (reply and free-text fields of save_security_report), for
    # example "French". Empty: the agent chooses. The `report_language` argument of the review
    # prompts overrides it. Severities, categories, statuses and rule ids stay in English.
    report_language: str = ""

    log_level: str = "INFO"

    # Hard limits to protect the server and the database
    max_content_chars: int = 200_000
    max_findings_per_report: int = 500
    max_dependency_chars: int = 1_000_000
    max_list_limit: int = 100

    @field_validator("proxy", "no_proxy")
    @classmethod
    def _empty_is_unset(cls, value: str | None) -> str | None:
        """An empty variable means no value (an empty stored proxy means a direct connection)."""
        return value.strip() or None if value is not None else None

    @field_validator("report_language")
    @classmethod
    def _check_report_language(cls, value: str) -> str:
        """Reject a report language that is not a plain language name or code."""
        return check_report_language(value)


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
