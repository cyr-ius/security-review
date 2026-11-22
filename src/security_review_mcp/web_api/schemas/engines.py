"""Schemas of the scan engines and of the Activity page."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from ...engines import protocol as engine_protocol

# ── Scan engines ─────────────────────────────────────────────────────────────

# Answers of the routes read by the scan engines (their models are shared with the engines,
# which load no module of the controller)
EngineRuleSet = engine_protocol.EngineRuleSet
EngineOpenGrepManifest = engine_protocol.RuleManifest
EngineOpenGrepFetch = engine_protocol.RuleFetch
EngineOpenGrepContents = engine_protocol.RuleContents
EngineHeartbeat = engine_protocol.EngineHeartbeat


class ScanEnginePublic(BaseModel):
    """A scan engine enrolled with the controller (never its secret nor its token)."""

    id: str
    name: str
    version: str
    address: str | None = None
    # Where the controller sends the scans
    url: str
    # True while its heartbeat is recent: it receives scans
    active: bool
    free_codebase_slots: int
    free_fragment_slots: int
    # OpenGrep slots of each pool (0: the engine does not report them)
    codebase_slots: int = 0
    fragment_slots: int = 0
    # Since the engine started: scans done, files scanned, scans failed, scans refused when busy
    codebase_scans: int = 0
    fragment_scans: int = 0
    scanned_files: int = 0
    processing_files: int = 0
    processing_codebase_scans: int = 0
    processing_fragment_scans: int = 0
    failed_scans: int = 0
    busy_refusals: int = 0
    enrolled_at: datetime
    last_seen_at: datetime
    heartbeat_at: datetime | None = None


class ProcessingPublic(BaseModel):
    """The most requests a process or an agent ran at once since the previous heartbeat, by
    family: code scans, dependency scans, reports and triage, reads (tools, prompts, resources),
    and the scans sent by security-review-ci (Controller server only)."""

    code: int = 0
    deps: int = 0
    reports: int = 0
    reads: int = 0
    pipeline: int = 0


class ControllerScansPublic(BaseModel):
    """The code scans a Controller process runs itself (without scan engines, or when none
    scanned the files): the most run at once since the previous heartbeat by pool, their files,
    and its OpenGrep slots of each pool (0 without OpenGrep: the scans are then not limited)."""

    codebase: int = 0
    fragment: int = 0
    files: int = 0
    codebase_slots: int = 0
    fragment_slots: int = 0


class AgentActivityPublic(BaseModel):
    """An agent seen lately by an MCP server: an opaque key and its MCP client, never a person."""

    # Opaque key, only stable within one MCP server process
    id: str
    # Name and version given by its MCP client (clientInfo), e.g. claude-code
    client: str
    client_version: str
    last_seen: str
    # The most code scans (scan_code, start_codebase_scan) it ran at once since the previous
    # heartbeat, and all its requests by family
    processing_fragments: int
    processing: ProcessingPublic = ProcessingPublic()


class ServerInstancePublic(BaseModel):
    """A Controller or MCP server process whose heartbeat is recent."""

    id: str
    # Host name of the process (the pod name in Kubernetes) and its version
    name: str
    version: str
    started_at: datetime
    heartbeat_at: datetime
    # MCP server: scan_code goes to the Controller server, and the most scan_code calls run at
    # once since its previous heartbeat
    delegated: bool
    processing_fragments: int
    # The most requests run at once since the previous heartbeat, by family: the tool calls of the
    # agents (MCP server), the scans received (Controller server)
    processing: ProcessingPublic = ProcessingPublic()
    # Controller server: the code scans it runs itself and its OpenGrep slots
    scans: ControllerScansPublic = ControllerScansPublic()
    # MCP server: the agents that sent it a request lately, the most recent first
    agents: list[AgentActivityPublic] = []


class ScanEngineList(BaseModel):
    """The enrolled scan engines and how the controller uses them."""

    # True when the engines are on (SECREVIEW_SCAN_ENGINE_TOKEN set): they enroll, and the code
    # scans go to the active ones
    enabled: bool
    # When no engine scanned the files: refuse the scan (503) or scan on the controller
    # (SECREVIEW_SCAN_ENGINE_FALLBACK)
    fallback: Literal["refuse", "local"]
    # SECREVIEW_SCAN_ENGINE_FALLBACK is set: it wins, the fallback cannot be changed here
    fallback_locked: bool = False
    # Networks where the engines may advertise their address (SECREVIEW_SCAN_ENGINE_NETWORKS)
    networks: list[str]
    access_token_minutes: int
    retention_days: int
    controllers: list[ServerInstancePublic]
    # MCP servers of the HTTP transport: the scan_code fragments reach the Controller server
    # through them
    mcp_servers: list[ServerInstancePublic]
    engines: list[ScanEnginePublic]


class ScanEngineFallbackUpdate(BaseModel):
    """Body of PUT /scan-engines/fallback: what the controller does when no scan engine scanned
    the files. Refused (422) while SECREVIEW_SCAN_ENGINE_FALLBACK is set."""

    model_config = ConfigDict(extra="forbid")

    fallback: Literal["refuse", "local"]
