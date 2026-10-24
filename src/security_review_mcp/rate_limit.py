"""Rate limiting of the controller, shared by its workers and replicas through the database.

Each limit counts the events of a key (an address, a username and an address...) in fixed time
windows stored in ``ratelimitcounter``; the count of a key is estimated over a sliding window
from the current and the previous fixed windows. Two uses:

- ``LoginThrottle``: failed logins, a username locked for an address after a few failures, an
  address after more failures on any username;
- ``RateLimitMiddleware``: requests to the REST API per client address, with a stricter limit
  on the login routes.

The keys are stored as SHA-256 digests: neither usernames nor addresses are kept in clear.
"""

import hashlib
import logging
import math
import threading
import time
from collections.abc import Callable

from fastapi.concurrency import run_in_threadpool
from sqlalchemy import delete
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, col, select
from starlette.types import ASGIApp, Receive, Scope, Send

from .storage.database import session_scope
from .storage.models import RateLimitCounter

logger = logging.getLogger("security_review_mcp.rate_limit")

# Seconds between two purges of the expired counters, in each process
PURGE_INTERVAL_SECONDS = 60
# Longest window a limit may have
MAX_WINDOW_SECONDS = 24 * 3600

_last_purge = 0.0
_purge_lock = threading.Lock()
# Longest window of the limits of this process: older counters are no longer read
_longest_window = 60


def _digest(*parts: str) -> str:
    """Stored key of the given parts (never the parts themselves)."""
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _upsert(session: Session, key: str, start: int) -> None:
    """Add one hit to the counter of a key and window (created at its first hit)."""
    table = RateLimitCounter.__table__  # type: ignore[attr-defined]
    dialect = session.get_bind().dialect.name
    if dialect in ("postgresql", "sqlite"):
        insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
        statement = (
            insert(table)
            .values(key=key, window_start=start, hits=1)
            .on_conflict_do_update(
                index_elements=["key", "window_start"], set_={"hits": table.c.hits + 1}
            )
        )
        session.execute(statement)
        return
    # Other databases: read then write; a concurrent first hit is retried once
    row = session.get(RateLimitCounter, (key, start))
    if row is None:
        try:
            with session.begin_nested():
                session.add(RateLimitCounter(key=key, window_start=start, hits=1))
            return
        except IntegrityError:
            row = session.get(RateLimitCounter, (key, start))
    if row is not None:
        row.hits += 1
        session.add(row)


def _purge(now: float) -> None:
    """Delete the expired counters, at most once per PURGE_INTERVAL_SECONDS per process.

    A counter is expired once it is older than two of the longest windows in use (the previous
    window is still read).
    """
    global _last_purge
    with _purge_lock:
        if now - _last_purge < PURGE_INTERVAL_SECONDS:
            return
        _last_purge = now
    limit = int(now) - 2 * _longest_window
    with session_scope() as session:
        session.execute(delete(RateLimitCounter).where(col(RateLimitCounter.window_start) < limit))


class RateLimit:
    """Count the events of keys over a sliding ``window`` of seconds."""

    def __init__(self, name: str, window: float, clock: Callable[[], float] = time.time) -> None:
        if not 1 <= window <= MAX_WINDOW_SECONDS:
            raise ValueError(f"A rate limit window lasts 1 to {MAX_WINDOW_SECONDS} seconds")
        self.name = name
        self.window = int(window)
        self.clock = clock
        global _longest_window
        with _purge_lock:
            _longest_window = max(_longest_window, self.window)

    def _windows(self, now: float) -> tuple[int, int, float]:
        """Start of the current and the previous windows, and the elapsed part of the current."""
        start = math.floor(now / self.window) * self.window
        return start, start - self.window, (now - start) / self.window

    def _key(self, parts: tuple[str, ...]) -> str:
        """Stored key of an event of this limit."""
        return _digest(self.name, *parts)

    def count(self, *parts: str) -> float:
        """Estimated number of events of a key during the last window."""
        now = self.clock()
        current, previous, elapsed = self._windows(now)
        key = self._key(parts)
        with session_scope() as session:
            rows = session.exec(
                select(RateLimitCounter.window_start, RateLimitCounter.hits).where(
                    RateLimitCounter.key == key,
                    col(RateLimitCounter.window_start).in_([current, previous]),
                )
            ).all()
        hits = dict(rows)
        return hits.get(current, 0) + hits.get(previous, 0) * (1 - elapsed)

    def hit(self, *parts: str) -> float:
        """Record an event of a key; return the estimated number of events, this one included."""
        now = self.clock()
        current, _, _ = self._windows(now)
        with session_scope() as session:
            _upsert(session, self._key(parts), current)
        _purge(now)
        return self.count(*parts)

    def reset(self, *parts: str) -> None:
        """Forget the events of a key."""
        with session_scope() as session:
            session.execute(
                delete(RateLimitCounter).where(col(RateLimitCounter.key) == self._key(parts))
            )


class LoginThrottle:
    """Failed logins of the last ``window`` seconds, shared by every worker and replica.

    A username is locked for an address after ``max_per_user`` failures, an address after
    ``max_per_address`` failures on any username.
    """

    def __init__(
        self,
        max_per_user: int = 5,
        max_per_address: int = 20,
        window: float = 15 * 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_per_user = max_per_user
        self.max_per_address = max_per_address
        self.window = window
        self._users = RateLimit("login-user", window, clock)
        self._addresses = RateLimit("login-address", window, clock)

    def blocked(self, username: str, address: str) -> bool:
        """True when this login must be refused without checking the password."""
        return (
            self._users.count(username.lower(), address) >= self.max_per_user
            or self._addresses.count(address) >= self.max_per_address
        )

    def failed(self, username: str, address: str) -> None:
        """Record a failed login."""
        self._users.hit(username.lower(), address)
        self._addresses.hit(address)

    def succeeded(self, username: str, address: str) -> None:
        """Forget the failures of a username for an address after a successful login."""
        self._users.reset(username.lower(), address)


class RateLimitMiddleware:
    """Refuse (429) the REST API requests of an address over its limit.

    Only ``/api/`` is counted (the files of the web interface are not); the login routes
    (``auth_prefix``) have their own, stricter, limit.
    """

    def __init__(
        self,
        app: ASGIApp,
        max_requests: int,
        max_auth_requests: int,
        window: float,
        auth_prefix: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.app = app
        self.max_requests = max_requests
        self.max_auth_requests = max_auth_requests
        self.window = int(window)
        self.auth_prefix = auth_prefix
        self.requests = RateLimit("api", window, clock)
        self.logins = RateLimit("auth", window, clock)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Count an API request of the client address, or refuse it."""
        path = scope.get("path", "")
        if scope["type"] != "http" or not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        address = client[0] if client else "unknown"
        if path.startswith(self.auth_prefix):
            limit, maximum = self.logins, self.max_auth_requests
        else:
            limit, maximum = self.requests, self.max_requests
        if await run_in_threadpool(limit.hit, address) > maximum:
            logger.warning("Too many requests from %s on %s: refused", address, limit.name)
            await _too_many(send, self.window)
            return
        await self.app(scope, receive, send)


async def _too_many(send: Send, retry_after: int) -> None:
    """Send a 429 answer."""
    body = b'{"detail":"Too many requests: try again later"}'
    await send(
        {
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"retry-after", str(retry_after).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
