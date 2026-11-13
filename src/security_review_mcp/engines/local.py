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

# Matches kept per file (rules first, then OpenGrep)
MAX_MATCHES_PER_FILE = 200


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
            remaining = max(0, MAX_MATCHES_PER_FILE - len(entry["matches"]))
            entry["matches"].extend(matches[:remaining])
            entry["truncated"] = entry["truncated"] or len(matches) > remaining
    return {"files": files, "engines": engines}
