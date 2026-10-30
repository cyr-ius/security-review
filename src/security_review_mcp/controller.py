"""Controller entry point (``security-review-controller``): web interface, REST API, database
and administration.

The controller runs apart from the MCP server (``security-review-mcp``), in its own process,
container or pod; both share the database. ``serve`` serves the REST API (``/api/v1``) and the
Angular application (``/ui``); the other commands are the operator commands of
cli.CONTROLLER_COMMANDS (``db``, ``token``, ``user``, ``role``, ``rules``...). The pipeline
commands (``gate``, ``sarif``, ``trend``) belong to ``security-review-ci`` (ci_client).
"""

import argparse
import logging
import sys

from . import __version__, app_settings, cli, connectors, http_server, web_api
from .auth import oidc, token_store, web_users
from .config import Settings, configure_logging, get_settings
from .deps import advisory_sync
from .observability import audit_syslog
from .rules import registry
from .storage import retention
from .storage.database import SchemaError, init_db

logger = logging.getLogger("security_review_mcp.controller")

USAGE = """\
usage: security-review-controller COMMAND [options]

Controller of security-review-controller: web interface, REST API, database and administration.

commands:
  serve        serve the REST API (/api/v1) and the web interface (/ui)
  db           migrate the schema (upgrade), show its revision (status), purge reports (prune)
  token        manage the bearer tokens
  user         manage the web users (local and OIDC) and their roles
  role         list the roles (with their permissions) and the OIDC mappings
  project      list, approve or reject the projects requested by an enrollment
  audit        read or purge the audit log (triage decisions, tokens, enrollments, access)
  rules        manage the internal rules and checklists
  advisories   import, download or inspect the OSV advisory database

Run `security-review-controller COMMAND --help` for the options of a command, `--version` for
the version.
Pipeline commands (gate, sarif, trend, scan-code, scan-deps) are run by security-review-ci.
"""


def _log_bootstrap_admin(created: bool, settings: Settings) -> None:
    """Tell the operator how to set the password of the initial administrator, once created."""
    if not created:
        return
    name = settings.admin_username.strip()
    logger.warning(
        "Initial Web UI administrator '%s' created: set its password with "
        "`security-review-controller user reset-password %s`",
        name,
        name,
    )


def serve(argv: list[str]) -> None:
    """Run ``security-review-controller serve``: the REST API and the web interface."""
    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog="security-review-controller serve",
        description="Serve the REST API (/api/v1) and the web interface (/ui).",
    )
    http_server.add_listen_arguments(parser, settings)
    args = parser.parse_args(argv)
    settings = http_server.with_tls_arguments(settings, args)
    configure_logging(settings.log_level)
    if settings.legacy_controller_url:
        logger.warning(
            "SECREVIEW_CONTROLLER_URL is deprecated on the Controller server: set "
            "SECREVIEW_PUBLIC_URL instead (SECREVIEW_CONTROLLER_URL remains the variable of "
            "security-review-ci)"
        )

    try:
        init_db()
        # The MCP server reads the URL of the controller, and of its own endpoint while the
        # OAuth login is enabled, in the database; the OAuth routes need them (create_app)
        app_settings.sync_controller_url(settings)
        app_settings.sync_mcp_oauth(settings)
        app_settings.sync_personal_mcp_tokens(settings)
        # SECREVIEW_MCP_OAUTH_ENABLED, or the value stored in the web interface
        oauth_enabled = app_settings.effective_settings(settings).mcp_oauth_enabled
        oauth = app_settings.describe_mcp_oauth(settings)
        if oauth["enabled"]["effective"] and not oauth_enabled:
            logger.warning(
                "OAuth login of the MCP clients suspended: set the URL of the MCP endpoint "
                "(SECREVIEW_MCP_URL or the Tokens page of the web interface)"
            )
        if not settings.personal_tokens_enabled:
            logger.warning(
                "SECREVIEW_PERSONAL_TOKENS_ENABLED=false: the personal MCP and CI tokens and the "
                "OAuth grants are refused"
            )
        if not settings.personal_mcp_tokens:
            if revoked := token_store.revoke_personal_mcp_tokens("environment"):
                logger.warning("Personal MCP tokens off: %d tokens revoked", revoked)
            if not oauth_enabled:
                logger.warning(
                    "SECREVIEW_PERSONAL_MCP_TOKENS=false without the OAuth login: the "
                    "developers can no longer connect their MCP client by themselves"
                )
        store = token_store.DatabaseTokenStore(include_users=True)
        tls = http_server.tls_options(settings)
        signer = oidc.session_signer(settings)
        # The SECREVIEW_OIDC_* variables are checked here; the settings changed in the web
        # interface are checked when they are stored (an invalid mix only disables OIDC)
        oidc.from_settings(settings, signer)
        web_app = web_api.create_app(args.host, ui=settings.web_ui, signer=signer)
        if settings.osv_auto_update:
            advisory_sync.validate_settings(settings)
        audit_syslog.validate_settings(settings)
        connectors.validate_settings(settings)
        bootstrap_created = web_users.ensure_bootstrap_admin(settings.admin_username)
    except (ValueError, SchemaError) as exc:
        parser.error(str(exc))
    registry.reload()
    logger.info("Controller server %s listening on %s:%d", __version__, args.host, args.port)
    _log_bootstrap_admin(bootstrap_created, settings)
    if settings.web_ui:
        logger.info("Web interface enabled on /ui (REST API on /api/v1)")
    oidc_login = web_app.state.oidc.current()
    updater = advisory_sync.AdvisoryUpdater(settings) if settings.osv_auto_update else None
    if updater:
        updater.start()
    days, audit_days = settings.empty_report_retention_days, settings.audit_retention_days
    audit_max = settings.audit_max_events
    pruner = (
        retention.ReportPruner(days, audit_retention_days=audit_days, audit_max_events=audit_max)
        if days or audit_days or audit_max
        else None
    )
    if pruner:
        pruner.start()
    # Always running: the syslog server may be set in the web interface at any time
    forwarder = audit_syslog.AuditForwarder(
        settings, current=lambda: app_settings.effective_settings(settings)
    )
    forwarder.start()
    dispatcher = (
        connectors.ExportDispatcher(
            settings, current=lambda: app_settings.effective_settings(settings)
        )
        if settings.connectors_enabled
        else None
    )
    if dispatcher:
        dispatcher.start()
    try:
        http_server.serve(
            http_server.build_controller_app(
                web_app,
                store,
                web_users.SessionVerifier(signer),
                require_auth=oidc_login is not None,
                settings=settings,
            ),
            args.host,
            args.port,
            store,
            tls,
            settings.log_level,
            settings.forwarded_allow_ips,
        )
    finally:
        if updater:
            updater.stop()
        if pruner:
            pruner.stop()
        forwarder.stop()
        if dispatcher:
            dispatcher.stop()


def main(argv: list[str] | None = None) -> None:
    """Run a controller command."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    command = arguments[0] if arguments else None
    if command == "serve":
        serve(arguments[1:])
    elif command in cli.CONTROLLER_COMMANDS:
        sys.exit(cli.run(arguments))
    elif command in ("-h", "--help"):
        print(USAGE, end="")
    elif command == "--version":
        print(f"security-review-controller {__version__}")
    else:
        print(USAGE, end="", file=sys.stderr)
        if command is not None:
            print(f"\nerror: unknown command '{command}'", file=sys.stderr)
        sys.exit(cli.EXIT_ERROR)


if __name__ == "__main__":
    main()
