"""Review coverage: the checklist results, scan leads and files declared with a report.

The reviewer (an agent) declares which checklist items it walked through and which rules
raised ``scan_code`` leads. They are checked against the active registry when the report is
saved: unknown ids are dropped and reported as warnings, never refused, so that a review is
not lost at its last step. The files it read are compared with the files that have leads in the
code scan of its review group (see unreviewed_leads).
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from sqlmodel import select

from ..rules import registry
from ..storage.database import session_scope
from ..storage.models import (
    MAX_CHECKLIST_RESULTS,
    MAX_SCAN_RULES,
    MAX_SCANNED_PATH_CHARS,
    ChecklistOutcome,
    ChecklistResult,
    FindingCreate,
    OpenGrepRule,
    ScannedFile,
    ScanSummary,
    StoredChecklistResult,
    UnreviewedLead,
)

# Prefix of the rule id of an OpenGrep lead of scan_code (see engines.opengrep)
OPENGREP_PREFIX = "OPENGREP:"
# Length of the rule_id of a finding, to which the id of an OpenGrep lead is cut
MAX_RULE_ID_CHARS = 60

# Shape of a scan rule or checklist item id (PY-004, ACME-CL-01); advisory ids such as
# GHSA-xxxx-xxxx-xxxx or CVE-2024-1234 do not match it and are not checked
_RULE_ID_RE = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{1,4}")
# Most unknown ids listed in one warning
_MAX_LISTED = 20


@dataclass
class Coverage:
    """Checked coverage of a report, and what the reviewer should know about it."""

    checklist: list[StoredChecklistResult] = field(default_factory=list)
    scan_rules: list[str] = field(default_factory=list)
    # Items of the checklist domains used by the review that got no result (also stored in
    # checklist with the not_covered outcome)
    not_covered: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _listed(ids: list[str]) -> str:
    """Join ids for a warning, bounded."""
    more = f" and {len(ids) - _MAX_LISTED} more" if len(ids) > _MAX_LISTED else ""
    return ", ".join(ids[:_MAX_LISTED]) + more


def _rule_key(value: str) -> str:
    """Compared form of a declared rule id: an internal rule id in upper case (PY-004); an
    OpenGrep lead (``OPENGREP:<id>``, see engines.opengrep) keeps the case of its id."""
    value = value.strip()
    prefix, _, rule_id = value.partition(":")
    if rule_id and prefix.upper() == OPENGREP_PREFIX.rstrip(":"):
        return OPENGREP_PREFIX + rule_id.strip()
    return value.upper()


def _opengrep_rule_ids(declared: Iterable[str]) -> frozenset[str]:
    """The declared OpenGrep leads that name an installed OpenGrep rule, as scan_code returns
    them (``OPENGREP:<id>`` cut to the length of a finding rule_id)."""
    wanted = set(declared)
    if not wanted:
        return frozenset()
    with session_scope() as session:
        installed = session.exec(select(OpenGrepRule.id)).all()
    leads = {f"{OPENGREP_PREFIX}{rule_id}"[:MAX_RULE_ID_CHARS] for rule_id in installed}
    return frozenset(wanted & leads)


def check(
    checklist: list[ChecklistResult], scan_rules: list[str], findings: list[FindingCreate]
) -> Coverage:
    """Check the declared coverage against the active rules and checklists.

    Raises:
        ValueError: More results or rules than MAX_CHECKLIST_RESULTS or MAX_SCAN_RULES.
    """
    if len(checklist) > MAX_CHECKLIST_RESULTS or len(scan_rules) > MAX_SCAN_RULES:
        raise ValueError(
            f"Too many checklist results or scan rules; the limits are {MAX_CHECKLIST_RESULTS} "
            f"and {MAX_SCAN_RULES}"
        )
    coverage = Coverage()
    if not checklist:
        coverage.warnings.append(
            "No checklist result declared: the coverage of this review is unknown"
        )
    index = registry.checklist_index()
    results: dict[str, StoredChecklistResult] = {}
    unknown: list[str] = []
    for result in checklist:
        item_id = result.item_id.strip().upper()
        if item_id not in index:
            unknown.append(item_id)
            continue
        domain, item = index[item_id]
        # The last result of an item wins; the title is taken from the registry, not the agent
        results[item_id] = StoredChecklistResult(
            item_id=item_id, outcome=result.outcome, title=item.title, domain=domain
        )
    if unknown:
        coverage.warnings.append(f"Unknown checklist items ignored: {_listed(unknown)}")
    used = {r.domain for r in results.values()}
    missing = [
        StoredChecklistResult(
            item_id=item_id, outcome=ChecklistOutcome.NOT_COVERED, title=item.title, domain=domain
        )
        for item_id, (domain, item) in index.items()
        if domain in used and item_id not in results
    ]
    coverage.not_covered = [r.item_id for r in missing]
    coverage.checklist = [*results.values(), *missing]

    rules = registry.known_rule_ids()
    declared = list(dict.fromkeys(_rule_key(x) for x in scan_rules if x.strip()))
    known = rules | _opengrep_rule_ids(x for x in declared if x.startswith(OPENGREP_PREFIX))
    coverage.scan_rules = sorted(x for x in declared if x in known)
    if unknown_rules := [x for x in declared if x not in known]:
        coverage.warnings.append(f"Unknown scan rules ignored: {_listed(unknown_rules)}")

    cited = {(f.rule_id or "").strip().upper() for f in findings}
    unverified = sorted(
        x for x in cited if _RULE_ID_RE.fullmatch(x) and x not in rules and x not in index
    )
    if unverified:
        coverage.warnings.append(
            f"Finding rule_id not found among the rules and checklist items: {_listed(unverified)}"
        )
    return coverage


def normalize_path(path: str) -> str:
    """Compared form of a file path: forward slashes, without a leading ``./``, so that the
    paths declared by the agent match the paths sent by ``security-review-ci``."""
    path = path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path[:MAX_SCANNED_PATH_CHARS]


def summarize(files: list[ScannedFile]) -> ScanSummary:
    """Count the files of a scan for the reports linked to it."""
    return ScanSummary(
        files=sum(1 for f in files if f.reason is None),
        with_matches=sum(1 for f in files if f.matches > 0),
        skipped=sum(1 for f in files if f.reason is not None),
        unchecked=sum(1 for f in files if f.vulnerability_check not in (None, "performed")),
    )


def unreviewed_leads(
    scanned: list[ScannedFile], reviewed: Iterable[str], findings: list[FindingCreate]
) -> list[UnreviewedLead]:
    """The files with leads of a code scan that the agent neither declared it read nor cited
    in a finding, the most matches first: leads nobody verified."""
    read = {normalize_path(p) for p in reviewed}
    read |= {normalize_path(f.file_path) for f in findings if f.file_path}
    missed = [
        UnreviewedLead(path=f.path, matches=f.matches)
        for f in scanned
        if f.matches > 0 and normalize_path(f.path) not in read
    ]
    return sorted(missed, key=lambda lead: (-lead.matches, lead.path))
