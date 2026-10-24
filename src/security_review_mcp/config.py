"""Application settings loaded from environment variables."""

import ipaddress
import logging
import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Language name or code given to the agent (for example "French", "fr", "pt-BR"): letters,
# spaces, hyphens, underscores and parentheses only, so that it cannot carry instructions.
REPORT_LANGUAGE_MAX_CHARS = 40

# Upper bound of the retention of the reports without findings (100 years)
MAX_RETENTION_DAYS = 36_500
# Upper bound of SECREVIEW_AUDIT_MAX_EVENTS
MAX_AUDIT_EVENTS = 100_000_000


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


def default_database_url() -> SecretStr:
    """SQLite file of the user: ``$XDG_DATA_HOME/security-review-mcp/security_reports.db``.

    ``XDG_DATA_HOME`` defaults to ``~/.local/share`` (a relative value is ignored, as the XDG
    specification requires). Without a home directory (container run with an arbitrary user),
    the file is ``./security_reports.db``, as in version 1.0.
    """
    data_home = os.environ.get("XDG_DATA_HOME", "")
    try:
        base = Path(data_home) if Path(data_home).is_absolute() else Path.home() / ".local/share"
    except RuntimeError:
        return SecretStr("sqlite:///./security_reports.db")
    return SecretStr(f"sqlite:///{base / 'security-review-mcp' / 'security_reports.db'}")


class Settings(BaseSettings):
    """Server settings (prefix: SECREVIEW_)."""

    model_config = SettingsConfigDict(
        env_prefix="SECREVIEW_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # SQLite by default (zero setup), in the user data directory: the same file whatever the
    # directory the host starts the server from (see default_database_url).
    # PostgreSQL: postgresql+psycopg2://user:pass@host:5432/db  # secreview:ignore GEN-007
    # A secret (it may hold a password): never shown in a repr nor in a log
    database_url: SecretStr = Field(default_factory=default_database_url)
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
    # Controller only: on its first start, while no web user exists, the controller creates the
    # local administrator admin_username (member of the group "administrators") with a random
    # password that nobody knows: an operator sets one with `security-review-controller user
    # reset-password <admin_username>`, which prints it once, and the user changes it at its
    # first login.
    admin_username: str = "admin"

    # HTTP MCP server only: accept requests without a token while no token is stored. Off by
    # default: an exposed server stays closed (fail closed) until a first token exists; a server
    # listening on a loopback address is open in that case anyway. Never enable it on a server
    # reachable from the network.
    allow_unauthenticated: bool = False

    # Controller only: sessions of the web interface (password and OIDC logins), tokens signed
    # with secret_key (at least 32 characters, shared by the replicas) and valid
    # session_hours (1 to 24). Unset, a random secret is drawn at each start: sessions then
    # end at restart and are not shared between replicas.
    secret_key: SecretStr | None = None
    session_hours: int = 8

    # Enrollment (HTTP MCP server, once a token exists): a client without a token reaches a
    # restricted MCP server that only lets it request its project, and POST /api/v1/enroll on
    # the MCP server accepts the same request. The project stays pending until a user holding
    # projects.create approves it (Projects screen or `project approve`); a request nobody
    # approved within project_enrollment_ttl_days is deleted. No token is created: the developer
    # signs in to the web interface and creates a personal MCP token there.
    enrollment: bool = True
    project_enrollment_ttl_days: int = Field(default=7, ge=1, le=365)
    # Public URL of the web interface (controller), e.g. https://secreview.example.com/ui. The
    # MCP server gives it to the clients without a valid token (enrollment, 401), so that the
    # user knows where to sign in and create a personal MCP token. Unset: no link is given.
    web_url: str | None = None

    # Client commands only (`security-review-mcp scan-deps`, used by commit hooks and
    # pipelines): URL of the shared MCP server (default of --url) and the bearer token sent to
    # it. Never used by the servers. Read from SECREVIEW_MCP_URL (an alias ignores env_prefix).
    server_url: str | None = Field(default=None, validation_alias=AliasChoices("secreview_mcp_url"))
    token: str | None = None

    # Optional TLS served by uvicorn (HTTP MCP server and controller), enabled by tls_certfile.
    # tls_client_ca additionally requires client certificates signed by this CA (mutual TLS).
    tls_certfile: str | None = None
    tls_keyfile: str | None = None
    tls_keyfile_password: SecretStr | None = None
    tls_client_ca: str | None = None

    # Reverse proxies (comma-separated IP addresses or CIDR ranges, "*" for any) whose
    # X-Forwarded-For and X-Forwarded-Proto headers give the client address, used by the login
    # throttling, the enrollment limits and the logs (HTTP MCP server and controller). Unset:
    # uvicorn's default (FORWARDED_ALLOW_IPS variable, else 127.0.0.1). Behind an Ingress, set
    # the address range of the proxy, or every client shares the address of the proxy.
    forwarded_allow_ips: str | None = None

    # Controller only: requests to the REST API per client address and per window of
    # rate_limit_window_seconds, counted in the database (shared by every worker and replica).
    # The login routes (/api/v1/auth/) have their own, stricter, limit. Over the limit: 429.
    rate_limit_enabled: bool = True
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)
    rate_limit_max_requests: int = Field(default=600, ge=1)
    rate_limit_auth_max_requests: int = Field(default=30, ge=1)

    # Controller: REST API on /api/v1 and, with web_ui, the Angular application on /ui.
    # web_ui_dir overrides the directory of the built application (default: bundled files).
    web_ui: bool = True
    web_ui_dir: str | None = None
    # Controller: Swagger documentation of the REST API (/api/docs) and its OpenAPI schema
    # (/api/openapi.json), disabled by default. Its files come with the web interface build:
    # nothing is loaded from the Internet.
    swagger_enabled: bool = False

    # Controller only: OpenID Connect login to the web interface (authorization code + PKCE),
    # disabled by default. oidc_redirect_uri is the public URL of /api/v1/auth/oidc/callback,
    # registered at the provider. oidc_client_secret is empty for a public client. The values of
    # oidc_roles_claim (dotted path allowed, e.g. realm_access.roles) are matched against the
    # names of the groups of the web interface (see access_control): the user joins each group
    # of that name, and oidc_default_group (if set) in any case. oidc_admin_groups lists
    # comma-separated OIDC groups that hold the admin role: such a group is created at the first
    # login of one of its members when it does not exist yet. A login opens the OIDC web user
    # named by oidc_username_claim: with oidc_auto_create_users it is created at the first login
    # (when its groups give it a permission), otherwise an administrator creates it first.
    # Sessions use secret_key and session_hours. oidc_cafile replaces the system CA bundle
    # for the provider. Every oidc_* setting but oidc_cafile can also be set in the web
    # interface; a variable that is set takes precedence (see app_settings).
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: SecretStr | None = None
    oidc_redirect_uri: str = ""
    oidc_scope: str = "openid profile email"
    oidc_roles_claim: str = "groups"
    oidc_admin_groups: str = ""
    oidc_default_group: str = ""
    oidc_username_claim: str = "preferred_username"
    oidc_auto_create_users: bool = False
    oidc_display_name: str = "OIDC"
    oidc_cafile: str | None = None
    # Controller only: with OIDC enabled, refuse the password login of the local web users (the
    # login page then only offers the identity provider). A variable only, never changed in the
    # web interface: unsetting it is the way back when the provider is unavailable.
    oidc_only: bool = False

    # Controller only: HTTP proxy of its outgoing connections (OSV download, OIDC identity
    # provider), from the standard variables, without the SECREVIEW_ prefix (lowercase names
    # accepted): HTTPS_PROXY, else HTTP_PROXY, http://[user:password@]host:port (host:port
    # means http://host:port), and NO_PROXY, the comma-separated hosts reached without it (a
    # domain also covers its subdomains, an IP address the URLs whose host is that address, *
    # every host; the loopback interface is always direct). Each one not set can be set in the
    # web interface (Paramètres, see app_settings); when set, it takes precedence there.
    # An empty variable counts as unset. Settings(https_proxy=...) sets the proxy (the aliases
    # only: populating by name would read SECREVIEW_PROXY again).
    proxy: str | None = Field(
        default=None, validation_alias=AliasChoices("https_proxy", "http_proxy")
    )
    no_proxy: str | None = Field(default=None, validation_alias=AliasChoices("no_proxy"))

    # Controller only: download the OSV exports (all.zip of each ecosystem) from osv_url and
    # import them every osv_update_interval_hours. Disabled by default (the MCP server never
    # connects anywhere). osv_cafile is a CA bundle used instead of the system one (mirror or
    # TLS-inspecting proxy).
    osv_auto_update: bool = False
    osv_update_interval_hours: int = 24
    osv_url: str = "https://osv-vulnerabilities.storage.googleapis.com"
    osv_ecosystems: str = "PyPI,npm,Maven,Go,crates.io,NuGet"
    osv_cafile: str | None = None
    osv_max_download_mb: int = 1024

    # Language of the review reports (reply and free-text fields of save_security_report), for
    # example "French". Empty: the agent chooses. The `report_language` argument of the review
    # prompts overrides it. Severities, categories, statuses and rule ids stay in English.
    # When the variable is not set, an administrator can choose it in the web interface.
    report_language: str = ""

    # Controller only: delete the reports without any finding (clean reviews) older than
    # empty_report_retention_days, checked at start then every day. The latest report of each
    # project is always kept. 0 disables the purge.
    empty_report_retention_days: int = Field(default=90, ge=0, le=MAX_RETENTION_DAYS)

    # Longest validity, in days, of a triage decision "accepted" or "false_positive": its expiry
    # date may not be later. Once expired, the finding counts as open again (gate, posture).
    max_dismissal_days: int = Field(default=365, ge=1, le=MAX_RETENTION_DAYS)
    # Controller only: a person may accept a risk without an expiry date ("No expiry" in the web
    # interface); the acceptance then lasts until someone reopens the finding. False: every
    # acceptance needs an expiry date. A false positive always needs one.
    permanent_acceptance_enabled: bool = True
    # Controller only: lowest severity whose risk acceptance needs a reason and an expiry date
    # (see permanent_acceptance_enabled). A less severe finding is accepted by a plain
    # validation, which closes it with no reason and no expiry date. Empty: every acceptance
    # needs them.
    risk_acceptance_min_severity: Literal["critical", "high", "medium", "low", "info"] | None = (
        "medium"
    )

    # Longest validity, in days, of a bearer token created or rotated (CLI, web interface,
    # enrollment), which is also its default validity. 0: tokens never expire unless an expiry is
    # asked for at creation or rotation.
    token_max_days: int = Field(default=0, ge=0, le=MAX_RETENTION_DAYS)
    # Controller only: personal tokens a web user may hold of each kind (REST API and MCP),
    # created in My account. Revoke one to create another.
    personal_tokens_per_user: int = Field(default=1, ge=1, le=10)

    # Controller only: delete the audit events older than audit_retention_days, checked at start
    # then every day. 0 keeps them forever.
    audit_retention_days: int = Field(default=365, ge=0, le=MAX_RETENTION_DAYS)
    # Controller only: also keep at most audit_max_events events (the oldest are deleted by the
    # same daily purge). 0: no limit.
    audit_max_events: int = Field(default=0, ge=0, le=MAX_AUDIT_EVENTS)
    # Controller only: send each audit event, as JSON, to a syslog server: udp://host:port,
    # tcp://host:port or unix:///dev/log (no TLS: use a local relay such as rsyslog for it).
    # Disabled by default. The controller forwards the events of every process (MCP server and
    # CLI included) from the database, each event once even with several replicas. Not proxied.
    # Each one not set can be set on the Audit log page of the web interface; when set, it takes
    # precedence there. An empty address variable counts as unset.
    audit_syslog_address: str | None = None
    audit_syslog_facility: str = "local0"

    # Controller only: Prometheus metrics on /metrics, reached with a token of role "metrics" or
    # "admin". false: /metrics answers 404.
    metrics_enabled: bool = True

    # Controller only: the About page searches GitHub for a newer release (latest release of
    # the repository, HTTPS, through the outgoing proxy, cached 6 hours). Disabled by default: an
    # outgoing connection.
    update_check_enabled: bool = False

    # Controller only: send findings as tickets to ticketing systems (see ticketing): Jira and
    # ServiceNow, plus the third-party connectors (Python entry points of the group
    # security_review_mcp.ticketing) whose names ticketing_plugins lists, comma separated (a
    # connector installed but not listed is never loaded). By hand from the web interface, or
    # automatically for the projects given a severity threshold. Outgoing connections (HTTPS
    # only, through the outgoing proxy): every connector is off until an administrator switches
    # it on in the web interface (Connectors screen). ticketing_enabled is the lock of the
    # operator: false, nothing is sent and the switches are locked off. ticketing_interval_seconds
    # is the period of the automatic sending; ticketing_cafile replaces the system CA bundle
    # (internal certificate authority). The connection of each system is read from its own
    # variables, SECREVIEW_<KIND>_<FIELD> (SECREVIEW_JIRA_URL...), or set in the web interface.
    ticketing_enabled: bool = True
    ticketing_interval_seconds: int = Field(default=300, ge=30, le=86_400)
    ticketing_cafile: str | None = None
    ticketing_plugins: str = ""

    log_level: str = "INFO"

    # Hard limits to protect the server and the database
    max_content_chars: int = 200_000
    max_findings_per_report: int = 500
    max_dependency_chars: int = 1_000_000
    max_list_limit: int = 100
    # MCP server only: size of the body of a request of an authenticated MCP client (413 above);
    # a client without a token, sent to the enrollment server, gets a fixed bound of 64 KiB
    max_mcp_request_mb: int = Field(default=16, ge=1, le=1024)
    # Controller only: bounds of the scans sent by security-review-ci (POST /api/v1/ci/scan/...):
    # size of the request body (413 above), files per request, and size of one scanned source
    # file (a larger one is reported as skipped)
    max_scan_request_mb: int = Field(default=64, ge=1, le=1024)
    max_scan_files: int = Field(default=10_000, ge=1)
    max_scan_file_chars: int = Field(default=1_048_576, ge=1)

    @field_validator("proxy", "no_proxy", "audit_syslog_address", "web_url", "ticketing_cafile")
    @classmethod
    def _empty_is_unset(cls, value: str | None) -> str | None:
        """An empty variable means no value (an empty stored proxy means a direct connection)."""
        return value.strip() or None if value is not None else None

    @field_validator("ticketing_enabled", mode="before")
    @classmethod
    def _empty_lock_is_open(cls, value: object) -> object:
        """An empty variable leaves the switches of the web interface in charge."""
        if isinstance(value, str) and not value.strip():
            return True
        return value

    @field_validator("risk_acceptance_min_severity", mode="before")
    @classmethod
    def _empty_severity_is_unset(cls, value: object) -> object:
        """An empty variable means no threshold: every acceptance needs a reason and a date."""
        if isinstance(value, str):
            return value.strip().lower() or None
        return value

    @field_validator("proxy")
    @classmethod
    def _default_proxy_scheme(cls, value: str | None) -> str | None:
        """Read a proxy given as host:port, as curl does, as http://host:port."""
        if value and "://" not in value:
            return f"http://{value}"
        return value

    @field_validator("web_url")
    @classmethod
    def _check_web_url(cls, value: str | None) -> str | None:
        """Accept an http(s) URL without credentials: it is shown to unauthenticated clients."""
        if value is None:
            return None
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("SECREVIEW_WEB_URL must be an http(s) URL")
        if parts.username or parts.password:
            raise ValueError("SECREVIEW_WEB_URL must not contain credentials")
        return value.rstrip("/")

    @field_validator("forwarded_allow_ips")
    @classmethod
    def _check_forwarded_allow_ips(cls, value: str | None) -> str | None:
        """Accept "*" or a list of IP addresses and CIDR ranges; an empty value means unset."""
        if value is None or not value.strip():
            return None
        entries = [entry.strip() for entry in value.split(",") if entry.strip()]
        if entries != ["*"]:
            for entry in entries:
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    raise ValueError(
                        f"forwarded_allow_ips: not an IP address or CIDR range: {entry!r}"
                    ) from None
        return ",".join(entries)

    @field_validator("report_language")
    @classmethod
    def _check_report_language(cls, value: str) -> str:
        """Reject a report language that is not a plain language name or code."""
        return check_report_language(value)


def secret_value(secret: SecretStr | None) -> str | None:
    """Clear value of a secret setting (None when unset)."""
    return None if secret is None else secret.get_secret_value()


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
