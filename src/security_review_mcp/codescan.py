"""Whole-codebase pattern scan, run by the controller on the files sent by ``security-review-ci``.

The client (``ci_client.collect_sources``) lists and reads the files of a directory chosen by the
operator and sends their content to ``POST /api/v1/ci/scan/code``; this module scans that
content with the active rules and stores the matches as a report. It never reads the disk: the
paths are only labels, and the language of each file is detected again from its name.
Like ``scan_code``, the matches are leads to verify, not confirmed vulnerabilities.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from . import registry, sarif, services
from .ci_client import detect_language
from .config import get_settings
from .models import (
    SEVERITY_RANK,
    FindingCreate,
    FindingPublic,
    FindingStatus,
    ReviewType,
    Severity,
)

MAX_MATCHES_PER_FILE = 200
# Files not scanned listed in the scope of a stored report
MAX_SKIPPED_IN_SCOPE = 50
REVIEWER = "security-review-ci scan-code"


@dataclass(frozen=True)
class SourceFile:
    """A file sent by the client: its relative path (a label) and its content."""

    path: str
    content: str


def scan_files(
    files: Sequence[SourceFile],
    skipped: Sequence[tuple[str, str]] = (),
    listing: str = "git",
    root: str = ".",
    excluded: int = 0,
    unsupported: int = 0,
) -> dict:
    """Scan the files sent by the client with the active rules.

    Args:
        files: Files read by the client.
        skipped: Files the client could not send, with the reason (binary, too large...).
        listing: How the client listed the files (``git`` or ``walk``).
        root: Scanned directory, as given to the client (only shown in the report).
        excluded: Files skipped by an exclusion glob of the client (counted only).
        unsupported: Files of a type the scan does not support, counted by the client.

    Returns:
        The matches per file, the suppressed matches, the files skipped with their reason,
        and totals.

    Raises:
        ValueError: If there are more files than SECREVIEW_MAX_SCAN_FILES.
    """
    settings = get_settings()
    if len(files) + len(skipped) > settings.max_scan_files:
        raise ValueError(
            f"Too many files ({len(files) + len(skipped)}); the limit is "
            f"{settings.max_scan_files} (SECREVIEW_MAX_SCAN_FILES): exclude some of them"
        )
    results: list[dict] = []
    not_scanned = [{"file": path, "reason": reason} for path, reason in skipped]
    for source in files:
        language = detect_language(source.path)
        if language is None:
            unsupported += 1
            continue
        if len(source.content) > settings.max_scan_file_chars:
            reason = f"larger than {settings.max_scan_file_chars} characters on the controller"
            not_scanned.append({"file": source.path, "reason": reason})
            continue
        matches, suppressed = registry.scan(source.content, language, MAX_MATCHES_PER_FILE)
        results.append(
            {
                "file": source.path,
                "language": language,
                "lines": len(source.content.splitlines()),
                "matches": matches,
                "suppressed": suppressed,
                "truncated": len(matches) >= MAX_MATCHES_PER_FILE,
            }
        )

    by_severity = {s.value: 0 for s in Severity}
    for entry in results:
        for match in entry["matches"]:
            by_severity[match["severity"]] += 1
    return {
        "root": root,
        "listing": listing,
        "files_scanned": len(results),
        "files_skipped": len(not_scanned) + excluded,
        "files_unsupported": unsupported,
        "lines_scanned": sum(f["lines"] for f in results),
        "matches_count": sum(len(f["matches"]) for f in results),
        "suppressed_count": sum(len(f["suppressed"]) for f in results),
        "by_severity": by_severity,
        "files": results,
        "skipped": not_scanned,
    }


def blocking_count(result: dict, fail_on: Severity) -> int:
    """Count the matches whose severity reaches the threshold."""
    threshold = SEVERITY_RANK[fail_on]
    return sum(
        1
        for entry in result["files"]
        for match in entry["matches"]
        if SEVERITY_RANK[Severity(match["severity"])] >= threshold
    )


_SECRET_CWES = frozenset({"CWE-259", "CWE-321", "CWE-798"})


def _category(language: str, cwe: str | None) -> str:
    """Pick the finding category from the file language and the rule CWE."""
    if cwe in _SECRET_CWES:
        return "secret"
    if language in ("config", "yaml", "docker", "gitlab-ci", "jenkins"):
        return "configuration"
    return "code"


def to_findings(result: dict) -> list[FindingCreate]:
    """Convert the matches to findings, most severe first (ready for ``save_report``)."""
    findings: list[FindingCreate] = []
    for entry in result["files"]:
        for match in entry["matches"]:
            findings.append(
                FindingCreate(
                    title=match["title"],
                    severity=Severity(match["severity"]),
                    rule_id=match["rule_id"],
                    category=_category(entry["language"], match["cwe"]),
                    cwe=match["cwe"] or None,
                    file_path=entry["file"],
                    line_start=match["line"],
                    line_end=match["line"],
                    description=(
                        f"{match['title']}: pattern match found by the codebase scan. "
                        "It is a lead: confirm it by reading the surrounding code."
                    ),
                    evidence=match["excerpt"],
                    recommendation=match["advice"],
                )
            )
    findings.sort(key=lambda f: -SEVERITY_RANK[f.severity])
    return findings


def to_public(findings: list[FindingCreate]) -> list[FindingPublic]:
    """Give unsaved findings temporary ids so that they can be exported as SARIF."""
    return [
        FindingPublic(**f.model_dump(), id=index, report_id=0, status=FindingStatus.OPEN)
        for index, f in enumerate(findings, start=1)
    ]


def to_sarif(
    result: dict,
    project: str,
    saved: dict | None = None,
    repository: str | None = None,
    branch: str | None = None,
    commit_sha: str | None = None,
) -> dict:
    """Return the matches as a SARIF 2.1.0 log: the stored findings when the scan was saved
    (their ids are those of the database), the unsaved matches otherwise."""
    if saved:
        name, items = services.collect_sarif_items(saved["report_id"], None)
    else:
        name, now = project, datetime.now(UTC)
        items = [
            sarif.SarifItem(f, 0, name, repository, branch, commit_sha, now)
            for f in to_public(to_findings(result))
        ]
    return sarif.build_sarif(items, name)


def save(
    result: dict,
    project: str,
    repository: str | None = None,
    branch: str | None = None,
    commit_sha: str | None = None,
    author: str | None = None,
    submitted_by: str | None = None,
) -> dict:
    """Store the matches as a report; keep the most severe ones when there are too many.

    Raises:
        ValueError: Invalid report fields (author...).
    """
    findings = to_findings(result)
    limit = get_settings().max_findings_per_report
    summary = (
        f"Pattern scan of the whole codebase: {result['files_scanned']} file(s), "
        f"{result['matches_count']} match(es) to verify, {result['suppressed_count']} suppressed."
    )
    if len(findings) > limit:
        summary += f" Only the {limit} most severe matches are stored."
        findings = findings[:limit]
    skipped = [s["file"] for s in result["skipped"]]
    scope = f"Codebase {result['root']} ({result['files_scanned']} files scanned)"
    if skipped:
        scope += f"; not scanned: {', '.join(skipped[:MAX_SKIPPED_IN_SCOPE])}"
        if len(skipped) > MAX_SKIPPED_IN_SCOPE:
            scope += f" and {len(skipped) - MAX_SKIPPED_IN_SCOPE} more"
    return services.save_report(
        project=project,
        summary=summary,
        findings=findings,
        repository=repository,
        branch=branch,
        commit_sha=commit_sha,
        reviewer=REVIEWER,
        scope=scope,
        review_type=ReviewType.CODE_SCAN,
        author=author,
        submitted_by=submitted_by,
    )
