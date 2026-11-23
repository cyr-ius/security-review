"""Scan of source files with the active rules, then OpenGrep when it is enabled, in this process.

The CPU work of a code scan (``security-review-ci scan-code``) and of a fragment of scan_code:
the controller runs it itself, or sends it to the scan engines (see engines.backend), which run
this same function. The caller has already detected the language and bounded the files.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..config import get_settings
from ..rules import registry
from . import opengrep

# Matches kept per file (OpenGrep first, then the rules it does not repeat)
MAX_MATCHES_PER_FILE = 200

# CWEs that name the same weakness when a rule and an OpenGrep rule report the same line:
# code injection (94, 95), weak cryptography (326 key size, 327 algorithm, 328 hash)
_SAME_WEAKNESS = {"CWE-94": "CWE-95", "CWE-326": "CWE-327", "CWE-328": "CWE-327"}

# Severities from the least to the most critical
_SEVERITY_RANK = {name: rank for rank, name in enumerate(("info", "low", "medium", "high"))}
_SEVERITY_RANK["critical"] = len(_SEVERITY_RANK)


def _weakness(match: dict) -> tuple[int, str] | None:
    """Line and CWE (one of its family) of a match; None without a CWE."""
    cwe = match.get("cwe")
    if not cwe:
        return None
    return match["line"], _SAME_WEAKNESS.get(cwe, cwe)


def _merge(rule_matches: list[dict], opengrep_matches: list[dict]) -> tuple[list[dict], bool]:
    """Merge the matches of both engines of a file, without reporting a weakness twice.

    A rule match on the line and with the CWE of an OpenGrep match is dropped: OpenGrep, which
    follows the data flow, is the more precise of the two, and its matches are kept first so
    that the rules never push them out of MAX_MATCHES_PER_FILE. The OpenGrep match takes the
    severity of the rule when it is higher, so that the merge never lets a finding pass a gate.

    Returns:
        The matches, ordered by line, and whether some were cut.
    """
    same: dict[tuple[int, str], list[dict]] = {}
    for match in opengrep_matches:
        if (key := _weakness(match)) is not None:
            same.setdefault(key, []).append(match)
    kept = []
    for match in rule_matches:
        repeated = same.get(_weakness(match), [])
        for kept_match in repeated:
            kept_match["severity"] = max(
                kept_match["severity"], match["severity"], key=lambda s: _SEVERITY_RANK.get(s, 0)
            )
        if not repeated:
            kept.append(match)
    merged = (opengrep_matches + kept)[:MAX_MATCHES_PER_FILE]
    truncated = len(opengrep_matches) + len(kept) > MAX_MATCHES_PER_FILE
    return sorted(merged, key=lambda m: m["line"]), truncated


@dataclass(frozen=True)
class Source:
    """A file to scan: its relative path (a label), its scan language and its content."""

    path: str
    language: str
    content: str


def scan(
    sources: Sequence[Source], fragment: bool = False, opengrep_rules_dir: Path | None = None
) -> dict:
    """Scan ``sources`` with the active rules, then OpenGrep when it is enabled.

    A rule match that repeats an OpenGrep match (same line, same weakness) is dropped.

    OpenGrep runs the rules of ``opengrep_rules_dir``, a copy of the rules of the database
    (see engines.opengrep_snapshots), and none without it.
    A ``fragment`` of scan_code runs OpenGrep in its own slots, and not at all when
    SECREVIEW_OPENGREP_MAX_CONCURRENT_FRAGMENT_SCANS is 0.

    Returns:
        ``files``: one entry per source, in the same order (``matches``, ``suppressed`` and
        ``truncated``), and ``engines``: the engines that ran (``rules``, ``opengrep``).

    Raises:
        opengrep.OpenGrepError: If OpenGrep is enabled with rules but cannot run.
    """
    settings = get_settings()
    files: list[dict] = []
    for source in sources:
        matches, suppressed = registry.scan(source.content, source.language, MAX_MATCHES_PER_FILE)
        files.append(
            {
                "matches": matches,
                "suppressed": suppressed,
                "truncated": len(matches) >= MAX_MATCHES_PER_FILE,
            }
        )
    engines = ["rules"]
    if settings.opengrep_enabled and (
        not fragment or settings.opengrep_max_concurrent_fragment_scans
    ):
        engines.append("opengrep")
        # OpenGrep runs once per codebase, not once per file
        found = (
            opengrep.scan_files(
                [(s.path, s.content) for s in sources],
                fragment=fragment,
                rules_dir=opengrep_rules_dir,
            )
            if sources
            else {}
        )
        by_path = {source.path: entry for source, entry in zip(sources, files, strict=True)}
        for path, matches in found.items():
            entry = by_path.get(path)
            if entry is None:
                continue
            entry["matches"], truncated = _merge(entry["matches"], matches)
            entry["truncated"] = entry["truncated"] or truncated
    return {"files": files, "engines": engines}
