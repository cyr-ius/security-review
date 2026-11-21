"""Schemas of the rules, checklists, development standards and OpenGrep rule proposals."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field

from ... import standards
from ...rules import opengrep_rule_store, rules_loader
from ...storage.models import (
    MAX_STATUS_REASON_CHARS,
    RuleProposalStatus,
    Severity,
)
from .common import Origin

# ── Rules, checklists and development standards ─────────────────────────────


class RuleWrite(BaseModel):
    """A custom scan rule sent to the web API."""

    id: str = Field(min_length=3, max_length=rules_loader.MAX_ID_CHARS)
    title: str = Field(min_length=1, max_length=rules_loader.MAX_TITLE_CHARS)
    severity: Severity
    cwe: str = Field(default="", max_length=20)
    languages: list[Annotated[str, Field(max_length=32)]] = Field(min_length=1, max_length=32)
    pattern: str = Field(min_length=1, max_length=rules_loader.MAX_PATTERN_CHARS)
    advice: str = Field(default="", max_length=rules_loader.MAX_TEXT_CHARS)
    ignore_case: bool = True


class RuleEnabledUpdate(BaseModel):
    """Enabled state of a custom scan rule."""

    enabled: bool


class StoredRule(BaseModel):
    """A scan rule stored in the database (default or custom)."""

    id: str
    title: str
    severity: Severity
    cwe: str
    languages: list[str]
    pattern: str
    advice: str
    ignore_case: bool
    origin: Origin
    # True for a default rule edited by an administrator
    modified: bool
    enabled: bool
    updated_at: str


class RuleCatalog(BaseModel):
    """The stored rules and the diagnostics of the active registry."""

    rules: list[StoredRule]
    load_errors: list[str]


class RuleReload(BaseModel):
    """Summary returned after a rule change or a reload."""

    loaded_rules: int
    load_errors: list[str]


class ChecklistItemWrite(BaseModel):
    """A checklist item sent to the web API."""

    domain: str = Field(min_length=1, max_length=31)
    id: str = Field(min_length=3, max_length=rules_loader.MAX_ID_CHARS)
    title: str = Field(min_length=1, max_length=rules_loader.MAX_TITLE_CHARS)
    what_to_look_for: str = Field(min_length=1, max_length=rules_loader.MAX_TEXT_CHARS)
    cwe: str = Field(default="", max_length=20)


class StoredChecklistItem(BaseModel):
    """A checklist item stored in the database."""

    domain: str
    id: str
    title: str
    what_to_look_for: str
    cwe: str
    origin: Origin
    modified: bool


class ChecklistCatalog(BaseModel):
    """The stored checklist items and the diagnostics of the active registry."""

    checklist_items: list[StoredChecklistItem]
    load_errors: list[str]


class ChecklistReload(BaseModel):
    """Summary returned after a checklist item change."""

    loaded_checklist_items: int
    load_errors: list[str]


class StandardWrite(BaseModel):
    """A development standard sent to the web API (validated again by standards.normalize)."""

    slug: str = Field(min_length=1, max_length=50)
    title: str = Field(min_length=1, max_length=standards.MAX_TITLE_CHARS)
    description: str = Field(default="", max_length=standards.MAX_DESCRIPTION_CHARS)
    technologies: list[Annotated[str, Field(max_length=standards.MAX_KEYWORD_CHARS)]] = Field(
        default_factory=list, max_length=standards.MAX_KEYWORDS
    )
    file_patterns: list[Annotated[str, Field(max_length=standards.MAX_PATTERN_CHARS)]] = Field(
        default_factory=list, max_length=standards.MAX_KEYWORDS
    )
    content: str = Field(min_length=1, max_length=standards.MAX_CONTENT_CHARS)
    enabled: bool = True


class PackUpload(BaseModel):
    """A TOML pack (rules and checklists, or development standards) uploaded for import."""

    # File name, only used in the error messages
    name: str = Field(default="pack.toml", min_length=1, max_length=200)
    # Bounded again (in bytes) by rule_store.import_packs and standards.import_pack
    content: str = Field(min_length=1, max_length=standards.MAX_PACK_BYTES)


class RulePackImport(BaseModel):
    """Outcome of a rule pack import and the diagnostics of the reloaded registry."""

    files: list[str]
    rules: int
    checklist_items: int
    disabled_rules: int
    replaced: bool
    loaded_rules: int
    loaded_checklist_items: int
    load_errors: list[str]


class StandardPackImport(BaseModel):
    """Outcome of a development standards import: slugs created and replaced."""

    file: str
    created: list[str]
    updated: list[str]


class StandardSummary(BaseModel):
    """A development standard without its content."""

    slug: str
    title: str
    description: str
    technologies: list[str]
    file_patterns: list[str]
    enabled: bool
    content_chars: int
    updated_at: str
    updated_by: str | None


class Standard(StandardSummary):
    """A development standard with its Markdown content."""

    content: str
    created_at: str


class StandardCatalog(BaseModel):
    """The development standards, disabled ones included."""

    standards: list[StandardSummary]


class OpenGrepRuleProposalPublic(BaseModel):
    """An OpenGrep rule proposed by an agent during a review (see opengrep_proposals)."""

    id: int
    rule_id: str
    content: str
    reason: str
    test_code: str | None
    project: str
    status: RuleProposalStatus
    proposed_by: str
    proposed_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    decision_reason: str | None


class OpenGrepRuleProposalList(BaseModel):
    """OpenGrep rules proposed by agents, newest first."""

    proposals: list[OpenGrepRuleProposalPublic]
    # Proposals of the requested status, beyond the page
    total: int


class OpenGrepRuleApproval(BaseModel):
    """Body of POST /opengrep/proposals/{id}/approve: the YAML rule as corrected by the
    approver (default: as proposed); the rule id does not change."""

    content: str | None = Field(
        default=None, min_length=1, max_length=opengrep_rule_store.MAX_RULE_CHARS
    )


class OpenGrepRuleRejection(BaseModel):
    """Body of POST /opengrep/proposals/{id}/reject: an optional reason."""

    reason: str | None = Field(default=None, max_length=MAX_STATUS_REASON_CHARS)
