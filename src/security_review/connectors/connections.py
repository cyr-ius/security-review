"""Connections of the connectors: values of the fields of each connector.

Each field (the ``url`` added by the controller, then those the connector declares) is read from
the variable ``SECREVIEW_<KIND>_<FIELD>`` (``SECREVIEW_JIRA_URL``), else from the value stored in
the web interface (table ``appsetting``, key ``connector_<kind>_<field>``), else its default. A
variable that is set (not empty) always wins: the web interface cannot change it.

Secrets are stored as given, never returned (``***``) nor logged; ``***`` sent back keeps the
stored one. A secret is bound to its URL: changing the host of a connection requires entering
its secrets again in the same change, and is refused when a secret comes from a variable.
Otherwise whoever may change the settings could send a stored token to a host of their choice
(a send or a connection test).

Each connector has its switch (key ``connector:<kind>:enabled``, ``:`` never being in a field
key), off until an administrator switches it on: nothing is sent through a connector switched
off. SECREVIEW_CONNECTORS_ENABLED=false locks them all off (see enabled).
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from pydantic import create_model
from pydantic_settings import BaseSettings, SettingsConfigDict

from ..app_settings import PASSWORD_MASK, _apply, _stored
from ..config import Settings
from ..observability import audit
from ..storage.database import session_scope
from .api import MAX_FIELD_CHARS, URL_FIELD, Connector, ConnectorField

MAX_URL_CHARS = 500


def check_base_url(value: str, name: str) -> str:
    """Return the base URL of a system without its final slash, or raise ValueError unless it is
    an https://host[:port][/path] URL without credentials, query nor fragment."""
    url = value.strip()
    if len(url) > MAX_URL_CHARS:
        raise ValueError(f"{name} too long (max {MAX_URL_CHARS} chars)")
    if any(c.isspace() or not c.isprintable() for c in url):
        raise ValueError(f"{name} must not contain spaces or control characters")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018  (raises ValueError on an invalid port)
    except ValueError as exc:
        raise ValueError(f"invalid {name}: {exc}") from None
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"{name} must be an https:// URL")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ValueError(f"{name} must not contain credentials")
    if parts.query or parts.fragment:
        raise ValueError(f"{name} must not have a query or a fragment")
    return url.rstrip("/")


def _origin(url: str) -> tuple[str, str]:
    """Scheme and host (with port) of a URL, lowercased."""
    parts = urlsplit(url)
    return parts.scheme.lower(), parts.netloc.lower()


def url_field(connector: Connector) -> ConnectorField:
    """The URL field every connector gets."""
    return ConnectorField(
        name=URL_FIELD,
        label="URL",
        required=True,
        help=connector.url_help,
        placeholder=connector.url_placeholder,
        max_length=MAX_URL_CHARS,
        translations=connector.url_translations,
    )


def all_fields(connector: Connector) -> tuple[ConnectorField, ...]:
    """The fields of a connection: the URL, then those of the connector."""
    return (url_field(connector), *connector.fields)


def variable(connector: Connector, name: str) -> str:
    """Variable of a field: SECREVIEW_JIRA_URL..."""
    return f"SECREVIEW_{connector.kind}_{name}".upper()


def _key(connector: Connector, name: str) -> str:
    """Key of a stored field."""
    return f"connector_{connector.kind}_{name}"


def _enabled_key(connector: Connector) -> str:
    """Key of the stored switch of a connector."""
    return f"connector:{connector.kind}:enabled"


def enabled(connector: Connector, settings: Settings) -> bool:
    """True when the controller may send findings through ``connector``: not locked by
    SECREVIEW_CONNECTORS_ENABLED=false, and switched on (a connector never switched is off)."""
    if not settings.connectors_enabled:
        return False
    return _stored().get(_enabled_key(connector)) == "true"


def set_enabled(connector: Connector, on: bool, actor: str, settings: Settings) -> None:
    """Switch a connector on or off; the change is audited.

    Raises:
        ValueError: If the variable locks the switches, or the connection to switch on is not
            configured.
    """
    if not settings.connectors_enabled:
        raise ValueError("SECREVIEW_CONNECTORS_ENABLED is false: the connectors are locked off")
    if on and not resolve(connector).configured:
        raise ValueError(f"configure the {connector.name} connection before switching it on")
    with session_scope() as session:
        _apply(session, {_enabled_key(connector): "true" if on else "false"}, actor)
        audit.record(
            session,
            audit.AuditAction.CONNECTOR_CHANGED,
            actor,
            "setting",
            connector.kind,
            details={"enabled": on},
        )


def check_value(connector: Connector, spec: ConnectorField, value: str) -> str:
    """Return the value to store for a field, or raise ValueError."""
    if spec.name == URL_FIELD:
        return check_base_url(value, f"{connector.name} URL")
    return spec.check(value)


def _environment(connector: Connector) -> dict[str, str]:
    """Values of the fields set by a variable (not empty), read like the other settings
    (environment, then the .env file of the controller)."""
    config = SettingsConfigDict(
        env_prefix=f"SECREVIEW_{connector.kind}_".upper(),
        env_file=Settings.model_config.get("env_file"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    base = type("ConnectorVariables", (BaseSettings,), {"model_config": config})
    model = create_model(  # type: ignore[call-overload]
        f"{connector.kind.title()}Variables",
        __base__=base,
        **{spec.name: (str | None, None) for spec in all_fields(connector)},
    )
    values = model().model_dump()
    return {name: value.strip() for name, value in values.items() if value and value.strip()}


@dataclass(frozen=True)
class ConnectionState:
    """Values of a connection: from the variables, stored, and effective (defaults applied)."""

    connector: Connector
    env: Mapping[str, str]
    stored: Mapping[str, str]
    values: Mapping[str, str] = field(default_factory=dict)

    @property
    def base_url(self) -> str:
        """URL of the system, without final slash ("" when not set)."""
        return self.values.get(URL_FIELD, "").rstrip("/")

    @property
    def configured(self) -> bool:
        """True when every required field has a value."""
        return all(
            self.values.get(spec.name) for spec in all_fields(self.connector) if spec.required
        )

    def secrets(self) -> list[str]:
        """Values of the secret fields."""
        return [
            self.values[spec.name]
            for spec in self.connector.fields
            if spec.secret and self.values.get(spec.name)
        ]


def _state(
    connector: Connector, stored: Mapping[str, str], env: Mapping[str, str]
) -> ConnectionState:
    """Effective values: variable, else stored, else default."""
    values = {
        spec.name: env.get(spec.name) or stored.get(spec.name) or spec.default
        for spec in all_fields(connector)
    }
    return ConnectionState(connector, env, stored, {k: v for k, v in values.items() if v})


def _stored_values(connector: Connector, rows: Mapping[str, str]) -> dict[str, str]:
    """Stored values of a connector, by field name."""
    return {
        spec.name: rows[_key(connector, spec.name)]
        for spec in all_fields(connector)
        if rows.get(_key(connector, spec.name))
    }


def resolve(connector: Connector) -> ConnectionState:
    """Current values of the connection of ``connector``."""
    return _state(connector, _stored_values(connector, _stored()), _environment(connector))


def _changes(
    connector: Connector, values: Mapping[str, str | None], state: ConnectionState
) -> dict[str, str | None]:
    """Check ``values`` (field name to value; None or "" removes the stored value; a secret equal
    to PASSWORD_MASK is unchanged) and return them by field name.

    Raises:
        ValueError: If a name is unknown, a value invalid or its variable set, or if the URL
            changes host without its secrets entered again.
    """
    specs = {spec.name: spec for spec in all_fields(connector)}
    changes: dict[str, str | None] = {}
    for name, value in values.items():
        spec = specs.get(name)
        if spec is None:
            raise ValueError(f"unknown {connector.name} setting: {name}")
        if spec.secret and value == PASSWORD_MASK:
            continue
        if value is None or value.strip() == "":
            changes[name] = None
            continue
        if name in state.env:
            raise ValueError(
                f"{variable(connector, name)} is set: it takes precedence, change the variable"
            )
        if len(value) > MAX_FIELD_CHARS:
            raise ValueError(f"{spec.label} too long (max {MAX_FIELD_CHARS} chars)")
        changes[name] = check_value(connector, spec, value)
    _check_secrets_follow_url(connector, changes, state)
    return changes


def _check_secrets_follow_url(
    connector: Connector, changes: Mapping[str, str | None], state: ConnectionState
) -> None:
    """Refuse a URL stored in the web interface for secrets entered for another host.

    A secret set by a variable only goes to a URL set by a variable. A secret stored in the web
    interface goes to a new host (or to a URL set where there was none, after a deletion for
    instance) only when it is entered again in the same change.
    """
    new_url = changes.get(URL_FIELD)
    if not new_url:
        return
    if state.base_url and _origin(new_url) == _origin(state.base_url):
        return
    for spec in connector.fields:
        if not spec.secret or not state.values.get(spec.name):
            continue
        if spec.name in state.env:
            raise ValueError(
                f"{variable(connector, spec.name)} is set: the URL of the connection cannot "
                "change in the web interface"
            )
        if not changes.get(spec.name):
            raise ValueError(f"the URL changed: enter the {spec.label} again")


def set_connection(connector: Connector, values: Mapping[str, str | None], actor: str) -> None:
    """Store fields of a connection (see _changes); the change is audited, secrets masked.

    Raises:
        ValueError: If a value is refused; nothing is stored then.
    """
    changes = _changes(connector, values, resolve(connector))
    if not changes:
        return
    secret = {spec.name for spec in connector.fields if spec.secret}
    shown = {
        name: (PASSWORD_MASK if value and name in secret else value)
        for name, value in changes.items()
    }
    with session_scope() as session:
        _apply(session, {_key(connector, n): v for n, v in changes.items()}, actor)
        audit.record(
            session,
            audit.AuditAction.CONNECTOR_CHANGED,
            actor,
            "setting",
            connector.kind,
            details=shown,
        )


def candidate(connector: Connector, values: Mapping[str, str | None]) -> ConnectionState:
    """The connection ``values`` would give (see set_connection), without storing them, to test
    it before saving.

    Raises:
        ValueError: If a value is refused.
    """
    state = resolve(connector)
    changes = _changes(connector, values, state)
    stored = dict(state.stored)
    for name, value in changes.items():
        if value is None:
            stored.pop(name, None)
        else:
            stored[name] = value
    return _state(connector, stored, state.env)


def _shown(spec: ConnectorField, value: str | None) -> str | None:
    """A value as returned by the API: a set secret is masked."""
    if spec.secret:
        return PASSWORD_MASK if value else None
    return value


def _describe_field(spec: ConnectorField) -> dict[str, Any]:
    """Declaration of a field for the web interface."""
    return {
        "name": spec.name,
        "label": spec.label,
        "help": spec.help,
        "placeholder": spec.placeholder,
        "secret": spec.secret,
        "required": spec.required,
        "translations": {lang: dict(texts) for lang, texts in spec.translations.items()},
    }


def describe(connector: Connector, builtin: bool, settings: Settings) -> dict[str, Any]:
    """Describe a connection: its fields (declaration, stored value, variable, effective value,
    secrets masked), whether it is configured and switched on, and its destination field."""
    state = resolve(connector)
    return {
        "kind": connector.kind,
        "name": connector.name,
        "builtin": builtin,
        "configured": state.configured,
        "enabled": enabled(connector, settings),
        "fields": [
            _describe_field(spec)
            | {
                "variable": variable(connector, spec.name),
                "value": _shown(spec, state.stored.get(spec.name)),
                "env": _shown(spec, state.env.get(spec.name)),
                "env_set": spec.name in state.env,
                "effective": _shown(spec, state.values.get(spec.name)),
            }
            for spec in all_fields(connector)
        ],
        "destination": _describe_field(connector.destination),
    }


def validate_environment(connector: Connector) -> None:
    """Check the values the variables give to a connector (at the start of the controller).

    Raises:
        ValueError: If one of them is invalid.
    """
    env = _environment(connector)
    for spec in all_fields(connector):
        if spec.name in env:
            try:
                check_value(connector, spec, env[spec.name])
            except ValueError as exc:
                raise ValueError(f"{variable(connector, spec.name)}: {exc}") from None
