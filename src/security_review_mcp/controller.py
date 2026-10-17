"""Controller entry point (``security-review-controller``): web interface, REST API, database
and administration.

The controller runs apart from the MCP server (``security-review-mcp``), in its own process,
container or pod; both share the database. ``serve`` serves the REST API (``/api/v1``) and the
Angular application (``/ui``); the other commands are the operator commands of
cli.CONTROLLER_COMMANDS (``db``, ``token``, ``user``, ``group``, ``rules``...). The pipeline
commands (``gate``, ``sarif``, ``trend``) belong to ``security-review-ci`` (ci_client).
"""

import argparse
import logging
import sys

from . import (
    advisory_sync,
    cli,
    http_server,
    oidc,
    registry,
    retention,
    token_store,
    web_api,
    web_users,
)
from .config import configure_logging, get_settings
from .database import SchemaError, init_db

logger = logging.getLogger("security_review_mcp.controller")

USAGE = """\
usage: security-review-controller COMMAND [options]

Controller of security-review-mcp: web interface, REST API, database and administration.

commands:
  serve        serve the REST API (/api/v1) and the web interface (/ui)
  db           migrate the schema (upgrade), show its revision (status), purge reports (prune)
  token        manage the bearer tokens and the enrollment requests
  user         manage the web users (local and SSO) and the groups they belong to
  group        list the groups of web users and the roles (with their permissions)
  audit        read or purge the audit log (triage decisions, tokens, enrollments, access)
  rules        manage the internal rules and checklists
  advisories   import, download or inspect the OSV advisory database
  code         pattern-scan every file of a codebase
  deps         scan dependency manifests and lockfiles

Run `security-review-controller COMMAND --help` for the options of a command.
Pipeline commands (gate, sarif, trend) are run by security-review-ci.
"""


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

    try:
        init_db()
        store = token_store.DatabaseTokenStore(include_users=True)
        tls = http_server.tls_options(settings)
        signer = oidc.session_signer(settings)
        # The SECREVIEW_OIDC_* variables are checked here; the settings changed in the web
        # interface are checked when they are stored (an invalid mix only disables SSO)
        oidc.from_settings(settings, signer)
        web_app = web_api.create_app(args.host, ui=settings.web_ui, signer=signer)
        if settings.osv_auto_update:
            advisory_sync.validate_settings(settings)
    except (ValueError, SchemaError) as exc:
        parser.error(str(exc))
    registry.reload()
    bootstrap_password = (
        web_users.ensure_bootstrap_admin() if settings.auth_bootstrap_admin else None
    )
    if bootstrap_password:
        logger.warning(
            "Initial Web UI administrator created: user '%s', password (shown once): %s",
            web_users.BOOTSTRAP_USERNAME,
            bootstrap_password,
        )
    if settings.web_ui:
        logger.info("Web interface enabled on /ui (REST API on /api/v1)")
    oidc_login = web_app.state.oidc.current()
    updater = advisory_sync.AdvisoryUpdater(settings) if settings.osv_auto_update else None
    if updater:
        updater.start()
    days, audit_days = settings.empty_report_retention_days, settings.audit_retention_days
    pruner = (
        retention.ReportPruner(days, audit_retention_days=audit_days)
        if days or audit_days
        else None
    )
    if pruner:
        pruner.start()
    try:
        http_server.serve(
            http_server.build_controller_app(
                web_app,
                store,
                web_users.SessionVerifier(signer),
                require_auth=oidc_login is not None,
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
    else:
        print(USAGE, end="", file=sys.stderr)
        if command is not None:
            print(f"\nerror: unknown command '{command}'", file=sys.stderr)
        sys.exit(cli.EXIT_ERROR)


if __name__ == "__main__":
    main()
