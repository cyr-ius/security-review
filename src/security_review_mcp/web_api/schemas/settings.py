"""Schemas of the settings, the advisory database and the OIDC settings."""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ... import app_settings, proxy
from ...config import CONTROLLER_URL_MAX_CHARS, REPORT_LANGUAGE_MAX_CHARS
from ...observability import audit_syslog

# ── Settings, advisories and OIDC ─────────────────────────────────────────────


class ReportLanguageUpdate(BaseModel):
    """Body of PUT /settings/report-language: "" lets the agent choose, null removes the stored
    value. Refused (422) when SECREVIEW_REPORT_LANGUAGE is set: the variable takes precedence."""

    value: str | None = Field(default=None, max_length=REPORT_LANGUAGE_MAX_CHARS)


class FixSeverityUpdate(BaseModel):
    """Body of PUT /settings/fix-severity: lowest severity of the findings the agent must fix,
    "" for no instruction, null removes the stored value. Refused (422) when
    SECREVIEW_FIX_MIN_SEVERITY is set: the variable takes precedence."""

    value: Literal["", "critical", "high", "medium", "low", "info"] | None = None


class ControllerUrlUpdate(BaseModel):
    """Body of PUT /settings/controller-url: public root URL of the controller, whose web
    interface (/ui) the MCP server gives to the clients without a valid token; null or ""
    removes the stored value. Refused (422) when SECREVIEW_PUBLIC_URL is set on the
    controller: the variable takes precedence."""

    value: str | None = Field(default=None, max_length=CONTROLLER_URL_MAX_CHARS)


class McpScanDelegationUpdate(BaseModel):
    """Body of PUT /settings/mcp-scan-delegation: delegate scan_code of the MCP server to the
    public URL of the controller (the MCP server relays the token of its callers there). Refused
    (422) when turned on while that URL is unknown, or while SECREVIEW_SCANCODE_DELEGATED is set."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool


class ProxyUpdate(BaseModel):
    """Body of PUT /settings/proxy: proxy of the outgoing connections of the controller.

    A field left out is unchanged, ``null`` removes the stored value. A value is refused (422)
    when its variable is set (HTTPS_PROXY or HTTP_PROXY, NO_PROXY): the variable takes
    precedence. ``url`` ``""`` connects directly; a password sent back as returned by the API
    (``***``) keeps the stored one.
    """

    model_config = ConfigDict(extra="forbid")

    url: str | None = Field(default=None, max_length=proxy.MAX_PROXY_URL_CHARS)
    no_proxy: str | None = Field(default=None, max_length=proxy.MAX_NO_PROXY_CHARS)


class ReportLanguageSetting(BaseModel):
    """Language of the reports: stored value, variable, whether the variable is set (it then
    takes precedence over the stored value), effective value."""

    value: str | None
    env: str
    env_set: bool
    effective: str


class FixSeveritySetting(BaseModel):
    """Lowest severity the agent must fix: stored value, variable, whether the variable is set (it
    then takes precedence over the stored value), effective value ("": no instruction)."""

    value: str | None
    env: str
    env_set: bool
    effective: str


class ControllerUrlSetting(BaseModel):
    """Public root URL of the controller: stored value (set here or copied from the variable of the
    controller at start), variable, whether it is set (it then takes precedence), effective
    value."""

    value: str | None
    env: str | None
    env_set: bool
    effective: str | None


class McpScanDelegationSetting(BaseModel):
    """Delegation of scan_code to the controller: whether it is turned on, the URL used (None
    while off or while the URL is unknown), and whether SECREVIEW_SCANCODE_DELEGATED sets it (the
    web interface then cannot change it)."""

    enabled: bool
    url: str | None
    env_set: bool


class ProxyValue(BaseModel):
    """A proxy setting: stored in the web interface, variable, and whether the variable is set
    (it then takes precedence over the stored value)."""

    value: str | None
    env: str | None
    env_set: bool


class ProxyEffective(BaseModel):
    """Proxy actually used and where it comes from."""

    url: str | None
    no_proxy: str | None
    # environment: HTTPS_PROXY (else HTTP_PROXY); none: direct connection
    source: Literal["web", "environment", "none"]


class ProxySettings(BaseModel):
    """Proxy of the outgoing connections of the controller (passwords replaced by ``***``)."""

    url: ProxyValue
    no_proxy: ProxyValue
    effective: ProxyEffective


class OsvEcosystemsUpdate(BaseModel):
    """Body of PUT /settings/osv-ecosystems: ecosystems downloaded by the controller.

    ``null`` removes the stored value (SECREVIEW_OSV_ECOSYSTEMS, or its default, applies again).
    Refused (422) when the variable is set, the list is empty or holds an unsupported ecosystem.
    """

    model_config = ConfigDict(extra="forbid")

    ecosystems: list[Annotated[str, Field(max_length=20)]] | None = Field(max_length=20)


class OsvDownloadUpdate(BaseModel):
    """Body of PUT /settings/osv-download: turn on or off the OSV download of the controller and
    set its interval in hours; a field left out is unchanged.

    Refused (422) when the variable of a given field is set (SECREVIEW_OSV_AUTO_UPDATE,
    SECREVIEW_OSV_UPDATE_INTERVAL_HOURS), or when the download settings are invalid.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    update_interval_hours: int | None = Field(default=None, ge=1, le=8760)


class OsvBoolSetting(BaseModel):
    """The OSV download turned on or off in the web interface (None: never set) and whether
    SECREVIEW_OSV_AUTO_UPDATE is set (it then takes precedence)."""

    value: bool | None
    env_set: bool


class OsvIntervalSetting(BaseModel):
    """Interval of the OSV download set in the web interface (None: never set) and whether
    SECREVIEW_OSV_UPDATE_INTERVAL_HOURS is set (it then takes precedence)."""

    value: int | None
    env_set: bool


class OsvEcosystemsSetting(BaseModel):
    """Ecosystems of the OSV download: stored value, variable, whether the variable is set (it
    then takes precedence over the stored value), effective value (comma separated) and the
    ecosystems that can be chosen."""

    value: list[str] | None
    env: str
    env_set: bool
    effective: str
    supported: list[str]


class OsvSettings(BaseModel):
    """Download of the OSV advisories: effective state and interval (``download`` and
    ``interval`` give the values of the web interface; those and the ecosystems may be changed
    there while their variable is not set), source and limits (variables only)."""

    download_enabled: bool
    update_interval_hours: int
    download: OsvBoolSetting
    interval: OsvIntervalSetting
    url: str
    ecosystems: OsvEcosystemsSetting
    cafile: str | None
    max_download_mb: int


class AuditSyslogUpdate(BaseModel):
    """Body of PUT /settings/audit-syslog: syslog server of the audit log.

    A field left out is unchanged, ``null`` (or an empty address) deletes the stored value. A
    value whose variable is set (SECREVIEW_AUDIT_SYSLOG_ADDRESS, SECREVIEW_AUDIT_SYSLOG_FACILITY)
    is refused: the variable takes precedence. Only udp://, tcp:// and tls:// addresses may be set
    here.
    """

    model_config = ConfigDict(extra="forbid")

    address: str | None = Field(default=None, max_length=audit_syslog.MAX_ADDRESS_CHARS)
    facility: str | None = Field(default=None, max_length=20)


class SyslogValue(BaseModel):
    """A syslog setting: stored in the web interface, variable, and whether the variable is set
    (it then takes precedence and the stored value is ignored)."""

    value: str | None
    env: str | None
    env_set: bool


class SyslogEffective(BaseModel):
    """Syslog server actually used and where it comes from."""

    address: str | None
    facility: str
    # environment: SECREVIEW_AUDIT_SYSLOG_ADDRESS is set; none: the events are not forwarded
    source: Literal["web", "environment", "none"]


class AuditSyslogSettings(BaseModel):
    """Syslog server of the audit log: stored values, variables and effective destination."""

    address: SyslogValue
    facility: SyslogValue
    effective: SyslogEffective
    facilities: list[str]


class AppSettings(BaseModel):
    """Settings of the web interface, their variables and their effective values."""

    report_language: ReportLanguageSetting
    fix_min_severity: FixSeveritySetting
    controller_url: ControllerUrlSetting
    mcp_scan_delegation: McpScanDelegationSetting
    proxy: ProxySettings
    osv: OsvSettings


class AdvisoryDatabase(BaseModel):
    """Size and freshness of the advisory database."""

    loaded: bool
    advisories: int
    by_ecosystem: dict[str, int]
    last_imported_at: str | None
    age_days: int | None
    stale: bool


class AdvisoryUpdate(BaseModel):
    """One OSV update of the history."""

    id: int
    trigger: str
    triggered_by: str | None
    status: str
    source: str
    started_at: str
    finished_at: str | None
    # Per ecosystem, or {"error": ...} when the whole update failed
    results: dict[str, Any]


class AdvisoryOverview(BaseModel):
    """State of the advisory database and history of its updates."""

    database: AdvisoryDatabase
    download_enabled: bool
    running: bool
    updates: list[AdvisoryUpdate]


class AdvisoryUpdateStarted(BaseModel):
    """Identifier of the OSV update started in the background."""

    id: int


_OidcText = Annotated[str, Field(max_length=app_settings.MAX_OIDC_VALUE_CHARS)]


class OidcSettingsUpdate(BaseModel):
    """Body of PUT /oidc/settings and POST /oidc/settings/test.

    A field left out is unchanged, ``null`` removes the stored value. A value is refused (422)
    when its ``SECREVIEW_OIDC_*`` variable is set: the variable takes precedence. A client
    secret sent back as returned by the API (``***``) keeps the stored one; ``""`` makes the
    client public.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    issuer: _OidcText | None = None
    client_id: _OidcText | None = None
    client_secret: _OidcText | None = None
    redirect_uri: _OidcText | None = None
    scope: _OidcText | None = None
    roles_claim: _OidcText | None = None
    username_claim: _OidcText | None = None
    admin_groups: _OidcText | None = None
    auto_create_users: bool | None = None
    display_name: _OidcText | None = None


class OidcSettingValue(BaseModel):
    """One OIDC setting: stored value, variable, whether the variable is set (it then takes
    precedence over the stored value), effective value."""

    value: bool | str | None
    env: bool | str | None
    env_set: bool
    effective: bool | str | None


class OidcSettings(BaseModel):
    """OIDC settings of the controller (a set client secret is replaced by ``***``)."""

    fields: dict[str, OidcSettingValue]
    # SECREVIEW_OIDC_CAFILE, variable only
    cafile: str | None
    callback_path: str
    # The OIDC login is enabled and valid on this controller
    active: bool


class OidcTestStep(BaseModel):
    """One step of the test of an identity provider."""

    name: str
    ok: bool
    detail: str


class OidcTestResult(BaseModel):
    """Outcome of the test of an identity provider."""

    success: bool
    steps: list[OidcTestStep]
