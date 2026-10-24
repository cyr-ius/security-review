"""Command line helpers for pipelines and administrators (no MCP client or agent needed).

``security-review-controller`` runs ``db``, ``advisories``, ``rules``, ``token``, ``user``,
``group``, ``project`` and ``audit`` (CONTROLLER_COMMANDS);
``security-review-mcp`` runs ``enroll`` and ``scan-deps`` (MCP_COMMANDS). The code and
dependency scans of a pipeline are run by ``security-review-ci`` (see ci_client), which sends
the files to the controller. Exit codes follow the
same convention everywhere: 0 success, 1 blocked (findings found, schema not up to date),
2 usage or data error.
"""

import argparse
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from . import ci_client, http_server
from .auth import access_control, token_store, web_users
from .clients import enrollment, remote_scan
from .config import get_settings
from .deps import advisories, advisory_sync
from .observability import audit
from .reports import services
from .reports.services import NotFoundError
from .rules import registry, rule_store, rules_loader
from .storage.database import SchemaError, init_db, schema_status, session_scope, upgrade_db
from .storage.models import SEVERITY_RANK, Severity

EXIT_PASSED = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

MAX_FILE_BYTES = 50 * 1024 * 1024
_SEVERITY_CHOICES = [s.value for s in Severity]


def _fail(message: str) -> int:
    """Print an error as JSON on stderr and return the error exit code."""
    print(json.dumps({"error": message}), file=sys.stderr)
    return EXIT_ERROR


def _read_text(path: Path) -> str:
    """Read a text file chosen by the operator (bounded size)."""
    if not path.is_file():
        raise ValueError(f"File not found: {path}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"File too large (> {MAX_FILE_BYTES} bytes): {path}")
    return path.read_text(encoding="utf-8", errors="replace")


# ── advisories ───────────────────────────────────────────────────────────────


def advisories_command(argv: list[str]) -> int:
    """Run ``security-review-controller advisories``: import or inspect the OSV database."""
    parser = argparse.ArgumentParser(
        prog="security-review-controller advisories",
        description="Manage the offline advisory database.",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    importer = actions.add_parser("import", help="import OSV records (.json, directory or .zip)")
    importer.add_argument("path")
    importer.add_argument(
        "--ecosystem",
        action="append",
        help="ecosystem to keep (PyPI, npm, Maven, Go, crates.io, NuGet); repeat the option; "
        "default: all of them",
    )
    actions.add_parser("status", help="show the size and age of the database")
    updater = actions.add_parser(
        "update", help="download the OSV exports (SECREVIEW_OSV_URL) and import them"
    )
    updater.add_argument(
        "--ecosystem",
        action="append",
        help="ecosystem to download; repeat the option; default: SECREVIEW_OSV_ECOSYSTEMS",
    )
    args = parser.parse_args(argv)

    try:
        init_db()
        if args.action == "import":
            stats = advisories.import_advisories(args.path, set(args.ecosystem or []) or None)
            print(json.dumps(stats, indent=2))
        elif args.action == "update":
            return _advisories_update(args.ecosystem)
        else:
            print(json.dumps(advisories.advisory_status(), indent=2))
    except (ValueError, OSError) as exc:
        return _fail(str(exc))
    return EXIT_PASSED


def _advisories_update(names: list[str] | None) -> int:
    """Download and import the OSV exports; exit 2 when an ecosystem could not be updated."""
    settings = get_settings()
    if names:
        settings = settings.model_copy(update={"osv_ecosystems": ",".join(names)})
    result = advisory_sync.run_update(settings, "cli")
    print(json.dumps(result, indent=2))
    failed = any("error" in stats for stats in result["ecosystems"].values())
    return EXIT_ERROR if failed else EXIT_PASSED


# ── scan-deps output ─────────────────────────────────────────────────────────


def _blocking(result: dict, threshold: int) -> int:
    """Count the vulnerabilities and hygiene issues that reach the threshold."""
    entries = result["vulnerabilities"] + result["hygiene"]
    return sum(1 for e in entries if SEVERITY_RANK[Severity(e["severity"])] >= threshold)


def _print_deps(
    results: list[dict], fail_on: str, output_format: str, saved: dict | None = None
) -> int:
    """Print the dependency scans and return the exit code (blocked at ``fail_on``).

    ``saved`` is the answer of save_security_report when the result was stored (--save).
    """
    threshold = SEVERITY_RANK[Severity(fail_on)]
    blocked = sum(_blocking(r, threshold) for r in results)
    if output_format == "json":
        slim = [{k: v for k, v in r.items() if k != "components"} for r in results]
        answer = {"blocked": blocked > 0, "blocking_findings": blocked, "files": slim}
        if saved:
            answer["saved_report"] = saved
        print(json.dumps(answer, indent=2))
    else:
        ci_client.print_deps_text(results, blocked, fail_on)
        if saved:
            ci_client.print_saved_line({"saved_report": saved}, saved.get("project", ""))
    return EXIT_BLOCKED if blocked else EXIT_PASSED


# ── token ────────────────────────────────────────────────────────────────────


def token_command(argv: list[str]) -> int:
    """Run ``security-review-controller token``: manage the bearer tokens stored in the database."""
    parser = argparse.ArgumentParser(
        prog="security-review-controller token",
        description="Manage the bearer tokens of the HTTP transport (stored as SHA-256 digests).",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    creator = actions.add_parser("create", help="create a token and print its secret once")
    creator.add_argument("--label", required=True, help="unique name of the client (in the logs)")
    creator.add_argument(
        "--role",
        # api tokens have a role or an owner: created in the web interface
        choices=sorted(role.value for role in http_server.TOKEN_ROLES - {http_server.Role.API}),
        default=http_server.DEFAULT_ROLE.value,
        help="mcp (default): MCP endpoint; admin: MCP and REST API; ci: pipeline routes only "
        "(security-review-ci), needs --project; metrics: Prometheus endpoint of the controller "
        "only. A person reaches the web interface with a web user and its groups; api tokens "
        "(REST API, Swagger) are created in the web interface",
    )
    creator.add_argument(
        "--project",
        action="append",
        help="restrict the token to this project (MCP tools and REST API); repeat it to "
        "give several projects",
    )
    creator.add_argument(
        "--expires-in-days",
        type=int,
        help="validity of the token (default: SECREVIEW_TOKEN_MAX_DAYS, no expiry when it is 0)",
    )
    lister = actions.add_parser("list", help="list the tokens (never their secret or hash)")
    lister.add_argument("--project", help="only the tokens that reach this project")
    revoker = actions.add_parser("revoke", help="delete a token by id or label")
    revoker.add_argument("token", help="token id or label")
    rotator = actions.add_parser(
        "rotate", help="replace the secret of a token (same label, role and projects)"
    )
    rotator.add_argument("token", help="token id or label")
    rotator.add_argument(
        "--grace-hours",
        type=int,
        default=0,
        help="hours during which the previous secret keeps working (default: 0, max "
        f"{token_store.MAX_ROTATION_GRACE_HOURS})",
    )
    rotator.add_argument(
        "--expires-in-days",
        type=int,
        help="validity of the new secret (default: SECREVIEW_TOKEN_MAX_DAYS, no expiry when 0)",
    )
    args = parser.parse_args(argv)

    try:
        init_db()
        if args.action == "create":
            result: object = token_store.create_token(
                args.label, args.role, args.project, args.expires_in_days, audit.CLI_ACTOR
            )
        elif args.action == "list":
            result = token_store.list_tokens(args.project)
        elif args.action == "rotate":
            result = token_store.rotate_token(
                args.token, args.grace_hours, args.expires_in_days, audit.CLI_ACTOR
            )
        else:
            result = token_store.revoke_token(args.token, audit.CLI_ACTOR)
            if not token_store.DatabaseTokenStore().has_tokens():
                # Without any token the HTTP MCP server refuses every client (fail closed)
                warning = (
                    "No token left: the MCP endpoint refuses every client except enrollments "
                    "(it is open if it listens on localhost or with "
                    "SECREVIEW_ALLOW_UNAUTHENTICATED)"
                )
                print(json.dumps({"warning": warning}), file=sys.stderr)
    except ValueError as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


# ── audit ────────────────────────────────────────────────────────────────────


def _since(value: str) -> datetime:
    """Parse --since: a date (00:00 UTC) or an ISO 8601 date and time (UTC when naive)."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an ISO 8601 date: {value!r}") from None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def audit_command(argv: list[str]) -> int:
    """Run ``security-review-controller audit``: read the audit log."""
    parser = argparse.ArgumentParser(
        prog="security-review-controller audit",
        description="Read the audit log: triage decisions, agent proposals, tokens and "
        "enrollments, newest first.",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    lister = actions.add_parser("list", help="print the audit events as JSON")
    lister.add_argument(
        "--action",
        dest="event",
        choices=[item.value for item in audit.AuditAction],
        help="only this kind of event",
    )
    lister.add_argument("--project", help="only the events of this project")
    lister.add_argument("--actor", help="only this actor (user:NAME, token:LABEL, cli, anonymous)")
    lister.add_argument(
        "--since", type=_since, help="only the events from this date (ISO 8601, UTC)"
    )
    lister.add_argument("--limit", type=int, default=50, help="capped by SECREVIEW_MAX_LIST_LIMIT")
    lister.add_argument("--offset", type=int, default=0)
    pruner = actions.add_parser(
        "prune", help="delete the events older than the retention period, then beyond the limit"
    )
    pruner.add_argument(
        "--days",
        type=int,
        default=None,
        help="retention in days (default: SECREVIEW_AUDIT_RETENTION_DAYS; 0 keeps all)",
    )
    pruner.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="events kept at most (default: SECREVIEW_AUDIT_MAX_EVENTS; 0: no limit)",
    )
    args = parser.parse_args(argv)

    try:
        init_db()
        if args.action == "prune":
            result = audit.prune_events(args.days, args.max_events)
        else:
            result = audit.list_events(
                args.event, args.project, args.actor, args.since, args.limit, args.offset
            )
    except (ValueError, SchemaError) as exc:
        return _fail(str(exc))
    except SQLAlchemyError as exc:
        return _fail(f"Database error: {type(exc).__name__}")
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


# ── user ─────────────────────────────────────────────────────────────────────


def _read_password(from_stdin: bool) -> str | None:
    """Password read on the first line of stdin with --password-stdin; None: generate one."""
    if not from_stdin:
        return None
    password = sys.stdin.readline().rstrip("\r\n")
    if not password:
        raise ValueError("--password-stdin: no password read on stdin")
    return password


def user_command(argv: list[str]) -> int:
    """Run ``security-review-controller user``: manage the web users (local and OIDC)."""
    parser = argparse.ArgumentParser(
        prog="security-review-controller user",
        description="Manage the web users, the only accounts of the web interface: local users "
        "log in with a username and a password (stored as scrypt hashes), OIDC users (--sso) with "
        "the identity provider. Without --password-stdin, a random password is generated for a "
        "local user and printed once.",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    creator = actions.add_parser("create", help="create a web user")
    creator.add_argument(
        "username",
        help="login name (letters, digits and . _ @ -); for --sso, the exact username claim",
    )
    creator.add_argument(
        "--sso",
        action="store_true",
        help="OIDC user (OpenID Connect): no password, logs in with the identity provider",
    )
    creator.add_argument(
        "--group",
        action="append",
        help="group the user joins (repeatable); its roles give the permissions of the user",
    )
    creator.add_argument("--password-stdin", action="store_true", help="read the password on stdin")
    actions.add_parser("list", help="list the web users (never their password hash)")
    updater = actions.add_parser(
        "set-groups", help="replace the groups given to a user (its OIDC groups are kept)"
    )
    updater.add_argument("username", help="username or id")
    updater.add_argument(
        "--group",
        action="append",
        help=f"group (repeatable; none: no group); {access_control.ADMIN_GROUP} is created "
        "with the admin role when missing",
    )
    resetter = actions.add_parser(
        "reset-password", help="replace the password of a user and end its sessions"
    )
    resetter.add_argument("username", help="username or id")
    resetter.add_argument(
        "--password-stdin", action="store_true", help="read the password on stdin"
    )
    deleter = actions.add_parser(
        "delete", help="delete a user (the last holder of users.manage is kept)"
    )
    deleter.add_argument("username", help="username or id")
    args = parser.parse_args(argv)
    if args.action == "create" and args.sso and args.password_stdin:
        parser.error("create: an OIDC user (--sso) has no password")

    try:
        init_db()
        if args.action == "create":
            result: object = web_users.create_user(
                args.username,
                None if args.sso else _read_password(args.password_stdin),
                _group_ids(args.group),
                "cli",
                web_users.AUTH_OIDC if args.sso else web_users.AUTH_LOCAL,
            )
        elif args.action == "list":
            result = web_users.list_users()
        else:
            user_id = web_users.find_user(args.username)["id"]
            if args.action == "set-groups":
                result = web_users.update_user(user_id, _group_ids(args.group), "cli")
            elif args.action == "reset-password":
                result = web_users.set_password(user_id, _read_password(args.password_stdin))
            else:
                result = web_users.delete_user(user_id, "cli")
    except (ValueError, NotFoundError) as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


def _group_ids(names: list[str] | None) -> list[int]:
    """Ids of the groups named on the command line; ``administrators`` is created if missing
    (so that an operator can always restore an administrator)."""
    with session_scope() as session:
        if access_control.ADMIN_GROUP in (names or []):
            access_control.ensure_admin_group(session)
        return access_control.find_groups(session, names or [])


# ── group ────────────────────────────────────────────────────────────────────


def group_command(argv: list[str]) -> int:
    """Run ``security-review-controller group``: list the groups and the roles."""
    parser = argparse.ArgumentParser(
        prog="security-review-controller group",
        description="List the groups of web users (with their roles and members) or the roles "
        "(with their permissions). Groups and roles are managed in the web interface.",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("list", help="list the groups, their roles and their members")
    actions.add_parser("roles", help="list the roles and their permissions")
    args = parser.parse_args(argv)
    try:
        init_db()
        if args.action == "list":
            result: object = access_control.list_groups()
        else:
            result = access_control.list_roles()
    except ValueError as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


# ── project ──────────────────────────────────────────────────────────────────


def project_command(argv: list[str]) -> int:
    """Run ``security-review-controller project``: handle the projects requested by enrollment."""
    parser = argparse.ArgumentParser(
        prog="security-review-controller project",
        description="List, approve or reject the projects requested by an enrollment. An "
        "approval creates the project (its group project:<project>, without any member); a "
        "request nobody approved within SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS is deleted.",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("list", help="list the pending projects (requester, address, expiry)")
    approver = actions.add_parser("approve", help="create a pending project")
    approver.add_argument("id", type=int, help="id of the pending project (see list)")
    rejecter = actions.add_parser("reject", help="delete a pending project request")
    rejecter.add_argument("id", type=int, help="id of the pending project (see list)")
    args = parser.parse_args(argv)
    try:
        init_db()
        if args.action == "list":
            result: object = access_control.list_enrollments()
        elif args.action == "approve":
            result = access_control.approve_enrollment(args.id, audit.CLI_ACTOR)
        else:
            result = access_control.reject_enrollment(args.id, audit.CLI_ACTOR)
    except (ValueError, NotFoundError) as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


# ── enroll ───────────────────────────────────────────────────────────────────


def enroll_command(argv: list[str]) -> int:
    """Run ``security-review-mcp enroll``: request the project of a repository on a server."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp enroll",
        description="Request a project on a shared server (unchanged when it exists); an "
        "administrator approves it. No token is created: sign in to the web interface of the "
        "server (web_url of the answer), create a personal MCP token there and ask an "
        "administrator for access to the project.",
    )
    parser.add_argument(
        "--url", required=True, help="server URL, for example https://secreview.example.com"
    )
    parser.add_argument("--project", required=True, help="project name used for the reports")
    parser.add_argument(
        "--requested-by",
        help="who asks (name, email or team), for the administrator (default: your login name)",
    )
    parser.add_argument("--cafile", help="CA bundle used to verify the server certificate")
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="allow plain HTTP to a non-loopback server",
    )
    args = parser.parse_args(argv)
    try:
        result = enrollment.request_enrollment(
            args.url,
            args.project,
            requested_by=args.requested_by or enrollment.local_username(),
            cafile=args.cafile,
            allow_http=args.allow_http,
        )
    except ValueError as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


# ── scan-deps ────────────────────────────────────────────────────────────────

DEPRECATED_SCAN_DEPS = (
    "warning: security-review-mcp scan-deps is deprecated and will be removed in a major "
    "version: use security-review-ci scan-deps (controller URL and a personal ci token)"
)


def scan_deps_command(argv: list[str]) -> int:
    """Run ``security-review-mcp scan-deps``: scan dependency files with a shared server.

    Deprecated: ``security-review-ci scan-deps`` sends the files to the controller instead, with
    a ci token (personal on a workstation); this command will be removed in a major version.
    """
    print(DEPRECATED_SCAN_DEPS, file=sys.stderr)
    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog="security-review-mcp scan-deps",
        description="Deprecated: use security-review-ci scan-deps. Scan dependency manifests "
        "and lockfiles with the advisory database of a shared MCP server (commit hooks, "
        "pipelines). The token is read from SECREVIEW_TOKEN "
        "or, with --token-stdin, from the standard input.",
    )
    parser.add_argument("files", nargs="+", help="manifests or lockfiles")
    parser.add_argument(
        "--url",
        default=settings.server_url,
        help="server URL, for example https://secreview.example.com (default: SECREVIEW_MCP_URL)",
    )
    parser.add_argument(
        "--fail-on",
        choices=_SEVERITY_CHOICES,
        default=Severity.HIGH.value,
        help="exit 1 when a finding reaches this severity (default: %(default)s)",
    )
    parser.add_argument(
        "--format", choices=["json", "text"], default="text", help="output (default: %(default)s)"
    )
    parser.add_argument(
        "--require-database",
        action="store_true",
        help="exit 2 when the vulnerability check could not run (no advisory database)",
    )
    parser.add_argument(
        "--skip-unconfigured",
        action="store_true",
        help="exit 0 with a warning when no server URL is configured (shared commit hooks)",
    )
    parser.add_argument(
        "--token-stdin", action="store_true", help="read the token on stdin (not SECREVIEW_TOKEN)"
    )
    parser.add_argument("--cafile", help="CA bundle used to verify the server certificate")
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="allow plain HTTP to a non-loopback server (the token would travel in clear)",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="store the result as a dependency-scan report of --project on the server",
    )
    parser.add_argument("--project", help="project name of the report (with --save)")
    parser.add_argument("--repository", help="repository URL stored with the report")
    parser.add_argument("--branch", help="branch stored with the report")
    parser.add_argument("--commit", help="commit stored with the report")
    parser.add_argument("--author", help="username of the developer, stored with the report")
    args = parser.parse_args(argv)
    if args.save and not args.project:
        return _fail("--save needs --project")
    if not args.url:
        if args.skip_unconfigured:
            print(
                "warning: dependency scan skipped (SECREVIEW_MCP_URL is not set)",
                file=sys.stderr,
            )
            return EXIT_PASSED
        return _fail("No server URL: give --url or set SECREVIEW_MCP_URL")
    token = settings.token
    if args.token_stdin:
        # Never on the command line: it would show in the process list and the shell history
        token = sys.stdin.readline().strip()
        if not token:
            return _fail("--token-stdin: no token read on stdin")

    try:
        files: list[tuple[str, str]] = []
        for name in args.files:
            path = Path(name)
            # The content leaves the machine: never follow a link to another file
            if path.is_symlink():
                raise ValueError(f"Refusing to read a symbolic link: {path}")
            files.append((path.name, _read_text(path)))
        results = remote_scan.scan_files(
            args.url, files, token=token, cafile=args.cafile, allow_http=args.allow_http
        )
    except (ValueError, OSError) as exc:
        return _fail(str(exc))

    if ci_client.warn_unchecked(results) and args.require_database:
        return _fail("vulnerability check could not run and --require-database was given")
    saved = None
    if args.save:
        fields = {
            "repository": args.repository,
            "branch": args.branch,
            "commit_sha": args.commit,
            "author": args.author,
        }
        try:
            saved = remote_scan.save_report(
                args.url,
                results,
                args.project,
                fields,
                token=token,
                cafile=args.cafile,
                allow_http=args.allow_http,
            )
        except ValueError as exc:
            return _fail(str(exc))
    return _print_deps(results, args.fail_on, args.format, saved)


# ── rules ────────────────────────────────────────────────────────────────────


def _read_pack(path: Path) -> tuple[str, str]:
    """Read one rule pack chosen by the operator; symbolic links are not followed."""
    if path.is_symlink():
        raise ValueError(f"Refusing to read a symbolic link: {path}")
    if not path.is_file():
        raise ValueError(f"File not found: {path}")
    if path.stat().st_size > rules_loader.MAX_PACK_BYTES:
        raise ValueError(f"Rule pack larger than {rules_loader.MAX_PACK_BYTES} bytes: {path}")
    return path.name, path.read_text(encoding="utf-8")


def _collect_packs(names: list[str]) -> list[tuple[str, str]]:
    """Read the given packs; a directory contributes its ``*.toml`` files in name order."""
    packs: list[tuple[str, str]] = []
    for name in names:
        path = Path(name)
        if path.is_dir() and not path.is_symlink():
            files = sorted(path.glob("*.toml"))
            if not files:
                raise ValueError(f"No *.toml rule pack in {path}")
            for file in files:
                if file.is_symlink():
                    print(f"skipped: {file} (symbolic link)", file=sys.stderr)
                    continue
                packs.append(_read_pack(file))
        else:
            packs.append(_read_pack(path))
    return packs


def _print_rules_text(rows: list[dict]) -> None:
    """Print one line per rule: id, severity, origin (builtin, modified, custom), state, title."""
    for row in rows:
        state = "enabled" if row["enabled"] else "disabled"
        origin = "modified" if row["modified"] else row["origin"]
        print(f"{row['id']:<12} {row['severity']:<8} {origin:<8} {state:<8} {row['title']}")
    disabled = sum(1 for row in rows if not row["enabled"])
    print(f"{len(rows)} rule(s), {disabled} disabled")


def rules_command(argv: list[str]) -> int:
    """Run ``security-review-controller rules``: manage the internal rules in the database."""
    parser = argparse.ArgumentParser(
        prog="security-review-controller rules",
        description="Manage the internal scan rules and checklist items stored in the database.",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    lister = actions.add_parser("list", help="list every rule (default and custom) and its state")
    lister.add_argument("--language", help="only the rules that apply to this language")
    lister.add_argument("--custom", action="store_true", help="only the custom rules")
    lister.add_argument("--format", choices=["text", "json"], default="text")
    importer = actions.add_parser("import", help="import TOML rule packs (files or directories)")
    importer.add_argument("paths", nargs="+", metavar="PATH")
    importer.add_argument(
        "--replace",
        action="store_true",
        help="first reset the stored rules, checklist items and disabled states to the defaults",
    )
    exporter = actions.add_parser("export", help="export the stored content as a TOML pack")
    exporter.add_argument("--output", "-o", help="file to write (default: standard output)")
    for action, text in (("enable", "enable"), ("disable", "disable")):
        toggler = actions.add_parser(action, help=f"{text} default or custom rules")
        toggler.add_argument("ids", nargs="+", metavar="ID")
    remover = actions.add_parser(
        "delete", help="delete custom rules or checklist items (default ones cannot be deleted)"
    )
    remover.add_argument("ids", nargs="+", metavar="ID")
    args = parser.parse_args(argv)

    try:
        init_db()
        if args.action == "list":
            current = registry.reload()  # always the current state of the database
            rows = registry.describe_rules(args.language, include_disabled=True)
            if args.custom:
                rows = [row for row in rows if row["origin"] == "custom"]
            for message in current.errors:
                print(f"warning: {message}", file=sys.stderr)
            if args.format == "text":
                _print_rules_text(rows)
                return EXIT_PASSED
            result: object = rows
        elif args.action == "import":
            result = rule_store.import_packs(_collect_packs(args.paths), args.replace)
        elif args.action == "export":
            text = rule_store.export_pack()
            if not args.output:
                print(text, end="")
                return EXIT_PASSED
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"Internal rules written to {args.output}", file=sys.stderr)
            return EXIT_PASSED
        elif args.action in ("enable", "disable"):
            changed = rule_store.set_enabled(args.ids, args.action == "enable")
            result = {f"{args.action}d": changed}
        else:
            result = rule_store.delete_entries(args.ids)
    except (ValueError, OSError, UnicodeDecodeError) as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


# ── db ───────────────────────────────────────────────────────────────────────


def db_command(argv: list[str]) -> int:
    """Run ``security-review-controller db``: migrate the schema, show its revision or purge."""
    parser = argparse.ArgumentParser(
        prog="security-review-controller db", description="Manage the database schema."
    )
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("upgrade", help="migrate the schema to this version and seed the rules")
    actions.add_parser("status", help="show the schema revision (exit code 1 when outdated)")
    prune = actions.add_parser(
        "prune", help="delete the reports without findings older than the retention period"
    )
    prune.add_argument(
        "--days",
        type=int,
        default=None,
        help="retention in days (default: SECREVIEW_EMPTY_REPORT_RETENTION_DAYS; 0 keeps all)",
    )
    args = parser.parse_args(argv)
    if args.action == "prune":
        try:
            init_db()
            result = services.prune_empty_reports(args.days)
        except (ValueError, SchemaError) as exc:
            return _fail(str(exc))
        except SQLAlchemyError as exc:
            return _fail(f"Database error: {type(exc).__name__}")
        print(json.dumps(result, indent=2))
        return EXIT_PASSED
    try:
        if args.action == "upgrade":
            upgrade_db()
        status = schema_status()
    except SQLAlchemyError as exc:
        return _fail(f"Database error: {type(exc).__name__}")
    print(json.dumps(status, indent=2))
    return EXIT_PASSED if status["up_to_date"] else EXIT_BLOCKED


# Commands of security-review-controller (database and administration); the pipeline
# commands gate, sarif and trend belong to security-review-ci (ci_client)
CONTROLLER_COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "db": db_command,
    "advisories": advisories_command,
    "rules": rules_command,
    "token": token_command,
    "audit": audit_command,
    "user": user_command,
    "group": group_command,
    "project": project_command,
}
# Commands of security-review-mcp (client side of a shared MCP server)
MCP_COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "enroll": enroll_command,
    "scan-deps": scan_deps_command,
}
COMMANDS = CONTROLLER_COMMANDS | MCP_COMMANDS


def run(argv: list[str]) -> int:
    """Run the command named by ``argv[0]`` and return its exit code."""
    try:
        return COMMANDS[argv[0]](argv[1:])
    except SchemaError as exc:
        return _fail(str(exc))
