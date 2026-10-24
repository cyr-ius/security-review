"""Review coverage: the checklist results and scan leads declared with a report.

The reviewer (an agent) declares which checklist items it walked through and which rules
raised ``scan_code`` leads. They are checked against the active registry when the report is
saved: unknown ids are dropped and reported as warnings, never refused, so that a review is
not lost at its last step.
"""

import re
from dataclasses import dataclass, field

from . import registry
from .storage.models import (
    MAX_CHECKLIST_RESULTS,
    MAX_SCAN_RULES,
    ChecklistOutcome,
    ChecklistResult,
    FindingCreate,
    StoredChecklistResult,
)

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
    declared = list(dict.fromkeys(x.strip().upper() for x in scan_rules if x.strip()))
    coverage.scan_rules = sorted(x for x in declared if x in rules)
    if unknown_rules := [x for x in declared if x not in rules]:
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
