"""Registry of the ticketing connectors: the built-in ones and the allowed third-party ones.

A third-party connector is a Python entry point of the group ``security_review_mcp.ticketing``
(see api). It is loaded only when its entry point name is listed in SECREVIEW_TICKETING_PLUGINS:
installing a package is not enough. Every connector is checked when it is loaded (version of the
API, kind, fields); an invalid or missing allowed connector stops the controller at start (see
validate_settings) rather than being skipped silently. Only the controller loads connectors.
"""

import importlib.metadata
import logging
from functools import lru_cache

from ..config import Settings, get_settings
from .api import (
    API_VERSION,
    ENTRY_POINT_GROUP,
    FIELD_PATTERN,
    KIND_PATTERN,
    MAX_NAME_CHARS,
    URL_FIELD,
    ConnectorField,
    TicketConnector,
)
from .jira import JiraConnector
from .servicenow import ServiceNowConnector

logger = logging.getLogger(__name__)

BUILTINS: tuple[type[TicketConnector], ...] = (JiraConnector, ServiceNowConnector)
# Field names the controller gives to every connector
RESERVED_FIELDS = frozenset({URL_FIELD, "destination"})
MAX_PLUGINS = 20


def plugin_names(value: str) -> list[str]:
    """Entry point names listed in SECREVIEW_TICKETING_PLUGINS (comma separated)."""
    names = [name.strip() for name in value.split(",") if name.strip()]
    if len(names) > MAX_PLUGINS:
        raise ValueError(f"SECREVIEW_TICKETING_PLUGINS lists more than {MAX_PLUGINS} connectors")
    return names


def _check_field(field: ConnectorField, owner: str) -> None:
    """Raise ValueError when a declared field is unusable."""
    if not isinstance(field, ConnectorField):
        raise ValueError(f"{owner}: fields must be ConnectorField instances")
    if not FIELD_PATTERN.fullmatch(field.name):
        raise ValueError(f"{owner}: invalid field name {field.name!r}")
    if not (field.label and field.label.isprintable() and len(field.label) <= 80):
        raise ValueError(f"{owner}: field {field.name} needs a short label")


def check_connector(connector: TicketConnector, source: str) -> None:
    """Raise ValueError unless ``connector`` follows the API (see api.TicketConnector)."""
    if not isinstance(connector, TicketConnector):
        raise ValueError(f"{source}: not a TicketConnector")
    if connector.api_version != API_VERSION:
        raise ValueError(
            f"{source}: written for ticketing API {connector.api_version}, "
            f"this controller provides {API_VERSION}"
        )
    kind = getattr(connector, "kind", "")
    if not isinstance(kind, str) or not KIND_PATTERN.fullmatch(kind) or kind == "ticketing":
        raise ValueError(f"{source}: invalid kind {kind!r}")
    name = getattr(connector, "name", "")
    if not (isinstance(name, str) and name.isprintable() and 0 < len(name) <= MAX_NAME_CHARS):
        raise ValueError(f"{source}: invalid name")
    names = [field.name for field in connector.fields]
    for field in connector.fields:
        _check_field(field, source)
    if len(set(names)) != len(names) or RESERVED_FIELDS & set(names):
        raise ValueError(f"{source}: duplicate or reserved field name")
    _check_field(getattr(connector, "destination", None), source)  # type: ignore[arg-type]
    # SECREVIEW_<KIND>_<FIELD> must not be a variable of the server itself
    taken = set(Settings.model_fields) & {f"{kind}_{name}" for name in [URL_FIELD, *names]}
    if taken:
        raise ValueError(f"{source}: kind {kind} clashes with the setting {sorted(taken)[0]}")


def _load_plugins(names: list[str]) -> list[TicketConnector]:
    """Load the allowed entry points."""
    found = {ep.name: ep for ep in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)}
    connectors = []
    for name in names:
        if name not in found:
            raise ValueError(f"ticketing connector {name!r} is not installed ({ENTRY_POINT_GROUP})")
        try:
            loaded = found[name].load()
            connector = loaded() if isinstance(loaded, type) else loaded
        except Exception as exc:
            raise ValueError(f"ticketing connector {name!r} cannot be loaded: {exc}") from None
        check_connector(connector, f"ticketing connector {name!r}")
        connectors.append(connector)
        logger.info("Ticketing connector %s loaded (%s)", connector.kind, name)
    return connectors


@lru_cache(maxsize=4)
def _connectors(plugins: str) -> dict[str, TicketConnector]:
    """Connectors by kind for one value of SECREVIEW_TICKETING_PLUGINS."""
    connectors: dict[str, TicketConnector] = {}
    for connector in [cls() for cls in BUILTINS] + _load_plugins(plugin_names(plugins)):
        check_connector(connector, connector.__class__.__name__)
        if connector.kind in connectors:
            raise ValueError(f"two ticketing connectors have the kind {connector.kind}")
        connectors[connector.kind] = connector
    return connectors


def connectors(settings: Settings | None = None) -> dict[str, TicketConnector]:
    """Every available connector, by kind (built-in first).

    Raises:
        ValueError: If an allowed third-party connector is missing or invalid.
    """
    return _connectors((settings or get_settings()).ticketing_plugins)


def get(kind: str, settings: Settings | None = None) -> TicketConnector:
    """The connector of ``kind``.

    Raises:
        LookupError: If no connector has this kind.
    """
    found = connectors(settings).get(kind)
    if found is None:
        raise LookupError(f"unknown ticketing system: {kind}")
    return found


def is_builtin(connector: TicketConnector) -> bool:
    """True for a connector shipped with the server."""
    return type(connector) in BUILTINS


def clear_cache() -> None:
    """Forget the loaded connectors (tests)."""
    _connectors.cache_clear()
