"""Heartbeats of the running Controller and MCP server processes, shared through the database.

Each Controller process, and each MCP server of the HTTP transport, keeps a row of
``serverinstance`` up to date every HEARTBEAT_SECONDS, and at once (at most every
MIN_HEARTBEAT_SECONDS) when its activity changes; it deletes it when it stops cleanly. The
Scan engines page shows the processes whose heartbeat is younger than ACTIVE_SECONDS: an MCP
server with the scan_code calls it runs now, whether it delegates them to the Controller
server, and the agents that sent it a request in the last AGENT_ACTIVE_SECONDS. The rows of the
processes gone without stopping are deleted after STALE_RETENTION.

A process counts the requests it runs now by FAMILIES: an MCP server every tool call, prompt and
resource read of the agents (``code`` for the code scans, ``deps`` for the dependency scans,
``reports`` for the reports and the triage, ``reads`` for the rest), a Controller server the
scans it receives: ``code`` and ``deps`` from the MCP servers, ``pipeline`` from
``security-review-ci``. The page draws them as the parts of a ring.

An agent is never named after a person: it is an opaque key (an HMAC of its token id and of the
name of its MCP client, with a secret drawn at the start of the process, so neither reversible
nor comparable between processes) and the name and version its MCP client gives at the
initialization of the session (``clientInfo``, e.g. ``claude-code``), bounded and printable.

Shared by the two processes: no network, no module of the controller. The MCP server never
migrates the schema: while the table is missing (Controller server not upgraded yet), its
heartbeat fails, is logged, and is tried again.
"""

import hashlib
import hmac
import json
import logging
import secrets
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlmodel import col, select

from .. import __version__
from .database import session_scope
from .models import ServerInstance, ServerKind, as_utc, utcnow

logger = logging.getLogger("security_review_mcp.instances")

HEARTBEAT_SECONDS = 5
# A burst of scan_code calls starting and ending shares one heartbeat
MIN_HEARTBEAT_SECONDS = 1.0
ACTIVE_SECONDS = 30
STALE_RETENTION = timedelta(days=1)
# Bound of the scan_code calls an MCP server reports (a gauge, never above its threads)
MAX_PROCESSING = 100_000
# An agent shows while its last request is younger than this, or while a scan_code call runs
AGENT_ACTIVE_SECONDS = 300
# Agents an MCP server reports, the most recent first (the column holds 16000 characters)
MAX_AGENTS = 50
MAX_AGENTS_CHARS = 16000
MAX_CLIENT_CHARS = 64
MAX_CLIENT_VERSION_CHARS = 40
# Families of the requests a process counts, in the order of the parts of its ring
FAMILIES = ("code", "deps", "reports", "reads", "pipeline")
# Heartbeat of this process, for the routes and tools that count their requests (see track)
_current: ServerHeartbeat | None = None


def _printable(value: object, limit: int) -> str:
    """A name given by an MCP client, printable and bounded ('' when it is not a string)."""
    if not isinstance(value, str):
        return ""
    return "".join(c for c in value if c.isprintable()).strip()[:limit]


def _counts(value: object) -> dict[str, int]:
    """Requests running by family, bounded (an unknown family or a bad count gives 0)."""
    raw = value if isinstance(value, dict) else {}
    counts = {}
    for family in FAMILIES:
        count = raw.get(family)
        valid = isinstance(count, int) and not isinstance(count, bool)
        counts[family] = max(0, min(count, MAX_PROCESSING)) if valid else 0
    return counts


def _decode_processing(raw: str) -> dict[str, int]:
    """The requests of a row by family, checked (a malformed row gives zeros)."""
    try:
        return _counts(json.loads(raw or "{}"))
    except ValueError:
        return _counts(None)


def _encode_agents(agents: list[dict[str, Any]]) -> str:
    """The agents as JSON, dropping the oldest until the column holds them."""
    agents = agents[:MAX_AGENTS]
    while True:
        encoded = json.dumps(agents, separators=(",", ":"))
        if len(encoded) <= MAX_AGENTS_CHARS or not agents:
            return encoded
        agents = agents[:-1]


def _decode_agents(raw: str) -> list[dict[str, Any]]:
    """The agents of a row, checked (a malformed row gives none)."""
    try:
        agents = json.loads(raw or "[]")
    except ValueError:
        return []
    if not isinstance(agents, list):
        return []
    decoded = []
    for agent in agents[:MAX_AGENTS]:
        if not isinstance(agent, dict) or not isinstance(agent.get("id"), str):
            continue
        processing = agent.get("processing_fragments")
        decoded.append(
            {
                "id": agent["id"][:32],
                "client": _printable(agent.get("client"), MAX_CLIENT_CHARS),
                "client_version": _printable(agent.get("client_version"), MAX_CLIENT_VERSION_CHARS),
                "last_seen": _printable(agent.get("last_seen"), 40),
                "processing_fragments": max(0, min(processing, MAX_PROCESSING))
                if isinstance(processing, int)
                else 0,
                "processing": _counts(agent.get("processing")),
            }
        )
    return decoded


def register_instance(
    instance_id: str,
    kind: ServerKind,
    started_at: datetime,
    name: str = "",
    version: str = "",
) -> None:
    """Record a server process and delete the rows of the processes gone for a day."""
    now = utcnow()
    with session_scope() as session:
        stale = session.exec(
            select(ServerInstance).where(col(ServerInstance.heartbeat_at) < now - STALE_RETENTION)
        ).all()
        for instance in stale:
            session.delete(instance)
        session.add(
            ServerInstance(
                id=instance_id,
                kind=kind,
                name=name[:200],
                version=version[:40],
                started_at=started_at,
                heartbeat_at=now,
            )
        )


def heartbeat(
    instance_id: str,
    kind: ServerKind,
    started_at: datetime,
    name: str = "",
    version: str = "",
    **activity: Any,
) -> None:
    """Update the heartbeat of a server process and its ``activity`` (``delegated``,
    ``processing_fragments``), recording it again when its row is gone (deleted by another
    replica after a long pause, or a restored database)."""
    with session_scope() as session:
        instance = session.get(ServerInstance, instance_id)
        if instance is None:
            logger.info("Server instance record missing: recording it again")
            instance = ServerInstance(
                id=instance_id,
                kind=kind,
                name=name[:200],
                version=version[:40],
                started_at=started_at,
                heartbeat_at=utcnow(),
            )
        instance.heartbeat_at = utcnow()
        if "delegated" in activity:
            instance.delegated = bool(activity["delegated"])
        if "processing_fragments" in activity:
            instance.processing_fragments = max(
                0, min(int(activity["processing_fragments"]), MAX_PROCESSING)
            )
        if "processing" in activity:
            instance.processing = json.dumps(_counts(activity["processing"]), separators=(",", ":"))
        if "agents" in activity:
            instance.agents = _encode_agents(list(activity["agents"]))
        session.add(instance)


def unregister_instance(instance_id: str) -> None:
    """Delete a server process that stops cleanly."""
    with session_scope() as session:
        instance = session.get(ServerInstance, instance_id)
        if instance is not None:
            session.delete(instance)


def active_instances(kind: ServerKind) -> list[dict[str, Any]]:
    """The processes of ``kind`` whose heartbeat is recent, the oldest first."""
    limit = utcnow() - timedelta(seconds=ACTIVE_SECONDS)
    with session_scope() as session:
        rows = session.exec(
            select(ServerInstance)
            .where(ServerInstance.kind == kind, col(ServerInstance.heartbeat_at) > limit)
            .order_by(col(ServerInstance.started_at))
        ).all()
        return [
            {
                "id": row.id,
                "name": row.name,
                "version": row.version,
                "started_at": as_utc(row.started_at),
                "heartbeat_at": as_utc(row.heartbeat_at),
                "delegated": row.delegated,
                "processing_fragments": row.processing_fragments,
                "processing": _decode_processing(row.processing),
                "agents": _decode_agents(row.agents),
            }
            for row in rows
        ]


class _Agent:
    """An agent seen by this MCP server (see the module docstring)."""

    def __init__(self, client: str, client_version: str) -> None:
        self.client = client
        self.client_version = client_version
        self.last_seen = utcnow()
        # Requests running now, and the most run at once since the last heartbeat, by family
        self.processing = dict.fromkeys(FAMILIES, 0)
        self.peak = dict.fromkeys(FAMILIES, 0)

    @property
    def busy(self) -> bool:
        return any(self.processing.values())


class ServerHeartbeat:
    """Keep this process visible to every Controller replica through the shared database.

    ``delegated`` (MCP server) tells at each heartbeat whether scan_code goes to the Controller
    server; ``processing`` counts a request running now by family and wakes the heartbeat, which
    reports the most requests run at once since the previous one; ``seen`` records a request of
    an agent.
    """

    def __init__(self, kind: ServerKind, delegated: Callable[[], bool] | None = None) -> None:
        self.kind = kind
        self.instance_id = uuid4().hex
        self.started_at = utcnow()
        self.name = socket.gethostname()[:200]
        self._delegated = delegated
        self._processing = dict.fromkeys(FAMILIES, 0)
        # Most requests running at once since the last heartbeat: a request shorter than the
        # delay of the heartbeat still shows
        self._peak = dict.fromkeys(FAMILIES, 0)
        # Agents by opaque key, and the secret of their keys (never stored)
        self._agents: dict[str, _Agent] = {}
        self._agent_secret = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name=f"{kind.value}-instance-heartbeat", daemon=True
        )

    def start(self) -> None:
        """Record this process now (a failure is retried by the heartbeat), then keep its
        heartbeat until it stops."""
        try:
            register_instance(self.instance_id, self.kind, self.started_at, self.name, __version__)
        except Exception:
            logger.exception("Could not record the %s instance; retrying", self.kind.value)
        self._thread.start()
        global _current
        _current = self

    def stop(self) -> None:
        """Stop the heartbeat thread and delete this process from the active list."""
        global _current
        if _current is self:
            _current = None
        self._stop.set()
        self._wake.set()
        if self._thread.ident is not None:  # start may have failed before the thread ran
            self._thread.join(timeout=HEARTBEAT_SECONDS + 1)
        try:
            unregister_instance(self.instance_id)
        except Exception:
            logger.exception("Could not delete the %s instance", self.kind.value)

    def agent_key(self, token_id: object, client: str) -> str:
        """Opaque key of the agent using the token ``token_id`` with the MCP client ``client``."""
        message = f"{token_id}\0{client}".encode()
        return hmac.new(self._agent_secret, message, hashlib.sha256).hexdigest()[:16]

    def seen(self, token_id: object, client: object, client_version: object) -> str:
        """Record a request of an agent and return its key; a new agent wakes the heartbeat."""
        name = _printable(client, MAX_CLIENT_CHARS) or "unknown"
        version = _printable(client_version, MAX_CLIENT_VERSION_CHARS)
        key = self.agent_key(token_id, name)
        with self._lock:
            agent = self._agents.get(key)
            new = agent is None
            if agent is None:
                agent = self._agents[key] = _Agent(name, version)
                if len(self._agents) > MAX_AGENTS:
                    idle = [k for k, a in self._agents.items() if not a.busy]
                    if idle:
                        oldest = min(idle, key=lambda k: self._agents[k].last_seen)
                        del self._agents[oldest]
            agent.client_version = version or agent.client_version
            agent.last_seen = utcnow()
        if new:
            self._wake.set()
        return key

    @contextmanager
    def processing(self, agent: str | None = None, family: str = "code") -> Iterator[None]:
        """Count a request of ``family`` (of the agent ``agent``) as running while the block
        runs, waking the heartbeat when it starts and ends."""
        if family not in FAMILIES:
            raise ValueError(f"Unknown family of requests: {family!r}")
        with self._lock:
            self._processing[family] += 1
            self._peak[family] = max(self._peak[family], self._processing[family])
            counted = self._agents.get(agent) if agent else None
            if counted is not None:
                counted.processing[family] += 1
                counted.peak[family] = max(counted.peak[family], counted.processing[family])
        self._wake.set()
        try:
            yield
        finally:
            with self._lock:
                self._processing[family] -= 1
                if counted is not None:
                    counted.processing[family] -= 1
                    counted.last_seen = utcnow()
            self._wake.set()

    def _active_agents(self) -> list[dict[str, Any]]:
        """The agents seen lately or running a scan_code call, the most recent first; the others
        are forgotten. Called with the lock held."""
        limit = utcnow() - timedelta(seconds=AGENT_ACTIVE_SECONDS)
        for key in [k for k, a in self._agents.items() if a.last_seen < limit and not a.busy]:
            del self._agents[key]
        agents = []
        for key, agent in sorted(
            self._agents.items(), key=lambda item: item[1].last_seen, reverse=True
        ):
            agents.append(
                {
                    "id": key,
                    "client": agent.client,
                    "client_version": agent.client_version,
                    "last_seen": as_utc(agent.last_seen).isoformat(),
                    "processing_fragments": agent.peak["code"],
                    "processing": dict(agent.peak),
                }
            )
            agent.peak = dict(agent.processing)
        return agents[:MAX_AGENTS]

    def activity(self) -> dict[str, Any]:
        """What the heartbeat records besides its date."""
        with self._lock:
            processing, self._peak = self._peak, dict(self._processing)
            agents = self._active_agents()
        delegated = False
        if self._delegated is not None:
            try:
                delegated = self._delegated()
            except Exception:
                logger.exception("Could not read whether scan_code is delegated")
        return {
            "delegated": delegated,
            "processing_fragments": processing["code"],
            "processing": processing,
            "agents": agents,
        }

    def beat(self) -> None:
        """Write the heartbeat now."""
        heartbeat(
            self.instance_id,
            self.kind,
            self.started_at,
            self.name,
            __version__,
            **self.activity(),
        )

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(HEARTBEAT_SECONDS - MIN_HEARTBEAT_SECONDS)
            # A burst of changes shares one heartbeat
            if self._stop.wait(MIN_HEARTBEAT_SECONDS):
                return
            self._wake.clear()
            try:
                self.beat()
            except Exception:
                logger.exception("Could not update the %s instance heartbeat", self.kind.value)


@contextmanager
def track(family: str) -> Iterator[None]:
    """Count a request of ``family`` in the heartbeat of this process while the block runs
    (nothing when the process keeps no heartbeat, e.g. in tests or with stdio)."""
    heartbeat = _current
    if heartbeat is None:
        yield
        return
    with heartbeat.processing(family=family):
        yield
