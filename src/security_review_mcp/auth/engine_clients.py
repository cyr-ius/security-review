"""Scan engines enrolled with the controller, and their OAuth access tokens.

A scan engine (security-review-scan-engine) reads no database: at its start it enrolls with the
shared secret of the engines (SECREVIEW_SCAN_ENGINE_TOKEN, ``POST /engine/v1/enroll``, see
engines.enrollment) and gets its own OAuth client, a client id and a client secret given once.
It then asks for an access token with the ``client_credentials`` grant (``POST
/engine/v1/token``), valid SECREVIEW_SCAN_ENGINE_ACCESS_TOKEN_MINUTES, which it renews before it
expires. That token has the ``engine`` role: it only reaches the routes of the REST API under
``/api/v1/engine/`` (the rules, the heartbeat), and nothing else reaches them.

At its enrollment an engine gives the root URL where the controller sends it the scans: an IP
address in SECREVIEW_SCAN_ENGINE_NETWORKS (private and loopback addresses by default), so that
the files of the code scans never leave these networks; no address to configure on the
controller. Every HEARTBEAT_SECONDS the engine sends its free OpenGrep slots: the controller
sends each scan to an engine whose heartbeat is recent (ACTIVE_SECONDS), the freest first.

Only the SHA-256 digests of the client secret and of the current access token are stored,
compared in constant time. An administrator lists and revokes the engines (web interface, CLI);
a revoked engine is refused at once, and enrolls again only when it restarts. An engine not seen
for SECREVIEW_SCAN_ENGINE_RETENTION_DAYS (a replica gone without leaving) is deleted. The
enrollments, revocations and deletions are recorded in the audit log.
"""

import hashlib
import hmac
import ipaddress
import logging
import random
import secrets
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlmodel import Session, col, select

from ..config import check_scan_engine_url, get_settings, scan_engine_networks
from ..http_server import Role, TokenInfo
from ..observability import audit
from ..observability.audit import AuditAction
from ..storage.database import session_scope
from ..storage.models import ScanEngine, as_utc, utcnow

logger = logging.getLogger("security_review_mcp.engines")

CLIENT_ID_PREFIX = "eng_"
# Engines enrolled at the same time: a holder of the shared secret cannot fill the table
MAX_ENGINES = 1000
MAX_NAME_CHARS = 200
MAX_VERSION_CHARS = 40
# Writes of the last use of an access token are spaced by this much (not one per request)
LAST_SEEN_RESOLUTION = timedelta(minutes=5)
# Actor of the deletions of the engines not seen for too long
SYSTEM_ACTOR = "system"
# An engine receives scans while its last heartbeat is younger than this (it beats every 30 s)
ACTIVE_SECONDS = 90
# Bound of the free slots an engine reports
MAX_SLOTS = 1024


class InvalidClientError(ValueError):
    """Unknown, revoked or wrong client credentials (OAuth ``invalid_client``)."""


def _digest(value: str) -> str:
    """SHA-256 of a secret, as stored."""
    return hashlib.sha256(value.encode()).hexdigest()


def _clean(value: str, limit: int) -> str:
    """A printable, bounded name or version given by an engine."""
    cleaned = "".join(c if c.isprintable() else "?" for c in value.strip())[:limit]
    return cleaned or "unknown"


def _public(row: ScanEngine) -> dict[str, Any]:
    """An engine as shown to the administrators (never a secret nor a digest)."""
    return {
        "id": row.id,
        "name": row.name,
        "version": row.version,
        "address": row.address,
        "url": row.url,
        "active": _active(row),
        "free_codebase_slots": row.free_codebase_slots,
        "free_fragment_slots": row.free_fragment_slots,
        "enrolled_at": as_utc(row.enrolled_at).isoformat(),
        "last_seen_at": as_utc(row.last_seen_at).isoformat(),
        "heartbeat_at": as_utc(row.heartbeat_at).isoformat() if row.heartbeat_at else None,
    }


def _active(row: ScanEngine) -> bool:
    """True while the last heartbeat of the engine is recent."""
    return row.heartbeat_at is not None and as_utc(row.heartbeat_at) > utcnow() - timedelta(
        seconds=ACTIVE_SECONDS
    )


def check_engine_url(url: str) -> str:
    """The URL an engine advertises, checked: an http(s) root URL whose host is an IP address of
    SECREVIEW_SCAN_ENGINE_NETWORKS (never a name: no DNS answer can send the files elsewhere).

    Raises:
        ValueError: If the URL is malformed or its host is not such an IP address.
    """
    cleaned = check_scan_engine_url(url, "The URL of the scan engine")
    if cleaned is None:
        raise ValueError("The scan engine gave no URL")
    try:
        host = ipaddress.ip_address(urlsplit(cleaned).hostname or "")
    except ValueError:
        raise ValueError("The URL of the scan engine must have an IP address as host") from None
    if not any(
        host in network for network in scan_engine_networks(get_settings().scan_engine_networks)
    ):
        raise ValueError(
            f"The address {host} of the scan engine is outside SECREVIEW_SCAN_ENGINE_NETWORKS"
        )
    return cleaned


def _prune(session: Session) -> int:
    """Delete the engines not seen for SECREVIEW_SCAN_ENGINE_RETENTION_DAYS (audited)."""
    limit = utcnow() - timedelta(days=get_settings().scan_engine_retention_days)
    stale = session.exec(select(ScanEngine).where(ScanEngine.last_seen_at < limit)).all()
    for row in stale:
        audit.record(
            session,
            AuditAction.SCAN_ENGINE_EXPIRED,
            SYSTEM_ACTOR,
            "scan_engine",
            row.id,
            details={"name": row.name, "last_seen_at": as_utc(row.last_seen_at).isoformat()},
        )
        session.delete(row)
    return len(stale)


def enroll(name: str, version: str, url: str, address: str | None = None) -> dict[str, str]:
    """Enroll a scan engine reached at ``url`` (the caller has checked the shared secret) and
    return its client id and client secret, given once.

    Raises:
        ValueError: If the URL is refused (see check_engine_url), or MAX_ENGINES engines are
            already enrolled.
    """
    url = check_engine_url(url)
    client_id = CLIENT_ID_PREFIX + secrets.token_hex(12)
    client_secret = secrets.token_urlsafe(32)
    with session_scope() as session:
        _prune(session)
        if len(session.exec(select(ScanEngine.id)).all()) >= MAX_ENGINES:
            raise ValueError(
                f"{MAX_ENGINES} scan engines are enrolled: revoke the engines that are gone"
            )
        row = ScanEngine(
            id=client_id,
            name=_clean(name, MAX_NAME_CHARS),
            version=_clean(version, MAX_VERSION_CHARS),
            address=address[:64] if address else None,
            url=url,
            secret_hash=_digest(client_secret),
        )
        session.add(row)
        audit.record(
            session,
            AuditAction.SCAN_ENGINE_ENROLLED,
            f"engine:{row.name}",
            "scan_engine",
            client_id,
            details={
                "name": row.name,
                "version": row.version,
                "address": row.address,
                "url": url,
            },
        )
    logger.info("Scan engine %s enrolled (%s)", client_id, name[:MAX_NAME_CHARS])
    return {"client_id": client_id, "client_secret": client_secret}


def issue_token(client_id: str, client_secret: str) -> tuple[str, int]:
    """Check the credentials of an engine and return a new access token and its validity in
    seconds; the previous access token of the engine stops working.

    Raises:
        InvalidClientError: If the engine is unknown, revoked, or the secret is wrong.
    """
    minutes = get_settings().scan_engine_access_token_minutes
    access_token = secrets.token_urlsafe(32)
    now = utcnow()
    with session_scope() as session:
        row = session.get(ScanEngine, client_id[:64]) if client_id else None
        # Compared even for an unknown engine: the answer takes the same time
        expected = bytes.fromhex(row.secret_hash) if row else bytes(32)
        presented = hashlib.sha256(client_secret.encode()).digest()
        if not hmac.compare_digest(expected, presented) or row is None:
            raise InvalidClientError("Unknown or revoked scan engine")
        row.access_token_hash = _digest(access_token)
        row.access_expires_at = now + timedelta(minutes=minutes)
        row.last_seen_at = now
        session.add(row)
    return access_token, minutes * 60


def engine_info(session: Session, digest: bytes) -> TokenInfo | None:
    """Identity of the access token of an enrolled engine (see token_store), or None; an
    expired one is marked ``expired``."""
    row = session.exec(
        select(ScanEngine).where(ScanEngine.access_token_hash == digest.hex())
    ).first()
    if row is None or row.access_token_hash is None or row.access_expires_at is None:
        return None
    if not hmac.compare_digest(bytes.fromhex(row.access_token_hash), digest):
        return None
    now = utcnow()
    if as_utc(row.last_seen_at) < now - LAST_SEEN_RESOLUTION:
        row.last_seen_at = now
        session.add(row)
    return TokenInfo(
        f"engine:{row.name}:{row.id}",
        Role.ENGINE,
        token_id=row.id,
        expired=as_utc(row.access_expires_at) <= now,
    )


def list_engines() -> list[dict[str, Any]]:
    """The enrolled engines, the most recently seen first (the stale ones deleted first)."""
    with session_scope() as session:
        _prune(session)
        rows = session.exec(select(ScanEngine).order_by(col(ScanEngine.last_seen_at).desc())).all()
        return [_public(row) for row in rows]


def revoke_engine(engine_id: str, actor: str | None = None) -> dict[str, Any]:
    """Delete an enrolled engine: its access token and its client stop working at once.

    Raises:
        ValueError: If no engine has this id.
    """
    with session_scope() as session:
        row = session.get(ScanEngine, engine_id[:64])
        if row is None:
            raise ValueError(f"Scan engine '{engine_id[:64]}' was not found")
        public = _public(row)
        audit.record(
            session,
            AuditAction.SCAN_ENGINE_REVOKED,
            actor,
            "scan_engine",
            row.id,
            details={"name": row.name, "address": row.address},
        )
        session.delete(row)
    return public


def heartbeat(engine_id: str, free_codebase_slots: int, free_fragment_slots: int) -> None:
    """Record the heartbeat of an engine and its free OpenGrep slots.

    Raises:
        ValueError: If the engine was revoked meanwhile.
    """
    now = utcnow()
    with session_scope() as session:
        row = session.get(ScanEngine, engine_id[:64])
        if row is None:
            raise ValueError(f"Scan engine '{engine_id[:64]}' was not found")
        row.free_codebase_slots = max(0, min(free_codebase_slots, MAX_SLOTS))
        row.free_fragment_slots = max(0, min(free_fragment_slots, MAX_SLOTS))
        row.heartbeat_at = now
        row.last_seen_at = now
        session.add(row)


def active_engines(fragment: bool) -> list[tuple[str, str]]:
    """``(id, url)`` of the engines whose heartbeat is recent, those with the most free slots of
    the pool of the scan first (in random order among equals, to spread the scans)."""
    limit = utcnow() - timedelta(seconds=ACTIVE_SECONDS)
    with session_scope() as session:
        rows = session.exec(select(ScanEngine).where(col(ScanEngine.heartbeat_at) > limit)).all()
        engines = [
            (row.free_fragment_slots if fragment else row.free_codebase_slots, row.id, row.url)
            for row in rows
        ]
    random.shuffle(engines)  # secreview:ignore PY-008 (load spreading, no secret)
    engines.sort(key=lambda entry: entry[0], reverse=True)
    return [(engine_id, url) for _, engine_id, url in engines]
