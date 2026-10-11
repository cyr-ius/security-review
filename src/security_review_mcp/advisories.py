"""Offline vulnerability database in the OSV format (https://ossf.github.io/osv-schema/).

The server may have no Internet access, so advisories are imported from files that an
administrator downloads elsewhere (for example the per-ecosystem ``all.zip`` archives
published by osv.dev) and copied to the server. Only PyPI, npm and Maven are kept.
"""

import json
import logging
import math
import re
import zipfile
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, func
from sqlmodel import col, select

from .database import session_scope
from .models import Advisory, AdvisoryAffected, Severity, utcnow
from .versions import compare_versions, version_key

logger = logging.getLogger(__name__)

SUPPORTED_ECOSYSTEMS: dict[str, str] = {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}
MAX_RECORD_BYTES = 5 * 1024 * 1024
BATCH_SIZE = 400
STALE_AFTER_DAYS = 30

_GHSA_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def canonical_ecosystem(name: str) -> str | None:
    """Return the canonical ecosystem name (PyPI, npm, Maven) or None if unsupported."""
    return SUPPORTED_ECOSYSTEMS.get(name.strip().lower())


def normalize_package(ecosystem: str, name: str) -> str:
    """Normalize a package name the way its ecosystem compares names."""
    cleaned = name.strip().lower()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", cleaned)
    return cleaned


# ── CVSS v3 base score (to derive a severity when the record has no label) ───

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS 3.1 round-up to one decimal."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score of a vector, or None if it cannot be parsed."""
    if not vector.startswith("CVSS:3"):
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        changed = metrics["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        exploitability = (
            8.22
            * _AV[metrics["AV"]]
            * _AC[metrics["AC"]]
            * privileges[metrics["PR"]]
            * _UI[metrics["UI"]]
        )
    except KeyError:
        return None
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    return _roundup(min((1.08 if changed else 1.0) * total, 10))


def severity_from_score(score: float) -> str | None:
    """Map a CVSS score to a severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return None


def extract_severity(record: dict) -> str | None:
    """Return critical/high/medium/low from an OSV record, or None when it has no severity."""
    candidates = [record.get("database_specific")]
    candidates += [a.get("database_specific") for a in record.get("affected", [])]
    candidates += [a.get("ecosystem_specific") for a in record.get("affected", [])]
    for source in candidates:
        if isinstance(source, dict):
            label = _GHSA_SEVERITY.get(str(source.get("severity", "")).upper())
            if label:
                return label
    for item in record.get("severity", []) or []:
        if isinstance(item, dict) and str(item.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_score(str(item.get("score", "")))
            if score is not None:
                return severity_from_score(score)
    return None


# ── Import ───────────────────────────────────────────────────────────────────


def _records_from_json(data: object) -> Iterator[dict]:
    """Yield the OSV records of a parsed JSON document (one record or a list of them)."""
    if isinstance(data, dict):
        yield data
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item


def iter_records(path: Path, stats: dict) -> Iterator[dict]:
    """Yield OSV records from a ``.json`` file, a directory tree or a ``.zip`` archive."""

    def parse(raw: bytes, name: str) -> Iterator[dict]:
        try:
            yield from _records_from_json(json.loads(raw))
        except (ValueError, UnicodeDecodeError) as exc:
            stats["errors"].append(f"{name}: {exc}")

    if path.is_dir():
        for file in sorted(path.rglob("*.json")):
            if file.stat().st_size > MAX_RECORD_BYTES:
                stats["errors"].append(f"{file.name}: larger than {MAX_RECORD_BYTES} bytes")
                continue
            yield from parse(file.read_bytes(), file.name)
    elif path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:  # members are read in memory, never extracted
            for info in archive.infolist():
                if not info.filename.lower().endswith(".json") or info.is_dir():
                    continue
                if info.file_size > MAX_RECORD_BYTES:
                    stats["errors"].append(f"{info.filename}: larger than {MAX_RECORD_BYTES} bytes")
                    continue
                yield from parse(archive.read(info), info.filename)
    elif path.is_file():
        if path.stat().st_size > 512 * MAX_RECORD_BYTES:
            stats["errors"].append(f"{path.name}: file too large")
            return
        yield from parse(path.read_bytes(), path.name)
    else:
        raise ValueError(f"Path not found: {path}")


def convert_record(
    record: dict, wanted: set[str]
) -> tuple[Advisory, list[AdvisoryAffected]] | None:
    """Convert an OSV record to rows; None when it is withdrawn or has nothing usable."""
    advisory_id = record.get("id")
    if not isinstance(advisory_id, str) or not advisory_id or record.get("withdrawn"):
        return None
    affected_rows: list[AdvisoryAffected] = []
    for entry in record.get("affected", []) or []:
        package = entry.get("package") or {}
        ecosystem = canonical_ecosystem(str(package.get("ecosystem", "")).split(":", 1)[0])
        name = package.get("name")
        if not ecosystem or ecosystem not in wanted or not isinstance(name, str):
            continue
        ranges = [
            {"type": r.get("type"), "events": r.get("events", [])}
            for r in entry.get("ranges", []) or []
            if r.get("type") in ("ECOSYSTEM", "SEMVER")
        ]
        versions = [str(v) for v in entry.get("versions", []) or []]
        if not ranges and not versions:
            continue  # only GIT ranges: cannot be matched against a released version
        fixed = [
            str(event["fixed"])
            for r in ranges
            for event in r["events"]
            if isinstance(event, dict) and "fixed" in event
        ]
        affected_rows.append(
            AdvisoryAffected(
                advisory_id=advisory_id,
                ecosystem=ecosystem,
                package=normalize_package(ecosystem, name),
                ranges=json.dumps(ranges),
                versions=json.dumps(versions),
                fixed=json.dumps(fixed),
            )
        )
    if not affected_rows:
        return None
    advisory = Advisory(
        id=advisory_id[:100],
        summary=str(record.get("summary") or record.get("details") or "")[:500],
        severity=extract_severity(record),
        aliases=json.dumps([str(a) for a in record.get("aliases", []) or []]),
        modified=str(record.get("modified") or "")[:40] or None,
        imported_at=utcnow(),
    )
    return advisory, affected_rows


def _flush(batch: list[tuple[Advisory, list[AdvisoryAffected]]]) -> None:
    """Replace the advisories of a batch (idempotent import)."""
    if not batch:
        return
    ids = [advisory.id for advisory, _ in batch]
    with session_scope() as session:
        session.execute(delete(AdvisoryAffected).where(col(AdvisoryAffected.advisory_id).in_(ids)))
        session.execute(delete(Advisory).where(col(Advisory.id).in_(ids)))
        session.add_all([advisory for advisory, _ in batch])
        session.flush()  # advisories first: the affected rows reference them
        session.add_all([row for _, rows in batch for row in rows])


def import_advisories(path: str | Path, ecosystems: set[str] | None = None) -> dict:
    """Import OSV advisories from a file, directory or zip archive.

    Args:
        path: ``.json`` file, directory of ``.json`` files, or ``.zip`` archive.
        ecosystems: Ecosystems to keep (default: PyPI, npm and Maven).

    Returns:
        Counters: ``read``, ``imported``, ``skipped`` and a list of ``errors`` (capped).
    """
    wanted = (
        {canonical_ecosystem(e) or e for e in ecosystems}
        if ecosystems
        else set(SUPPORTED_ECOSYSTEMS.values())
    )
    unknown = wanted - set(SUPPORTED_ECOSYSTEMS.values())
    if unknown:
        supported = sorted(SUPPORTED_ECOSYSTEMS.values())
        raise ValueError(f"Unsupported ecosystems {sorted(unknown)}; supported: {supported}")
    stats: dict = {"read": 0, "imported": 0, "skipped": 0, "errors": []}
    batch: list[tuple[Advisory, list[AdvisoryAffected]]] = []
    for record in iter_records(Path(path), stats):
        stats["read"] += 1
        converted = convert_record(record, wanted)
        if converted is None:
            stats["skipped"] += 1
            continue
        batch.append(converted)
        stats["imported"] += 1
        if len(batch) >= BATCH_SIZE:
            _flush(batch)
            batch = []
    _flush(batch)
    stats["errors"] = stats["errors"][:20]
    logger.info("Advisories imported: %s", {k: v for k, v in stats.items() if k != "errors"})
    return stats


def advisory_status() -> dict:
    """Describe the advisory database (size, freshness) so that results can be trusted."""
    with session_scope() as session:
        total = session.exec(select(func.count()).select_from(Advisory)).one()
        by_ecosystem = dict(
            session.exec(
                select(
                    AdvisoryAffected.ecosystem,
                    func.count(func.distinct(AdvisoryAffected.advisory_id)),
                ).group_by(AdvisoryAffected.ecosystem)  # type: ignore[arg-type]
            ).all()
        )
        latest = session.exec(select(func.max(Advisory.imported_at))).one()
    age_days = None
    if latest is not None:
        moment = latest if latest.tzinfo else latest.replace(tzinfo=UTC)
        age_days = (datetime.now(UTC) - moment).days
    return {
        "loaded": total > 0,
        "advisories": total,
        "by_ecosystem": by_ecosystem,
        "last_imported_at": latest.isoformat() if latest else None,
        "age_days": age_days,
        "stale": age_days is not None and age_days > STALE_AFTER_DAYS,
    }


# ── Matching ─────────────────────────────────────────────────────────────────


def is_affected(version: str, ranges: list[dict], versions: list[str]) -> bool:
    """Tell whether ``version`` is affected, following the OSV evaluation algorithm."""
    if any(compare_versions(version, listed) == 0 for listed in versions):
        return True
    for entry in ranges:
        events = [e for e in entry.get("events", []) if isinstance(e, dict) and len(e) == 1]

        def event_version(event: dict) -> str:
            return str(next(iter(event.values())))

        affected = False
        for event in sorted(events, key=lambda e: version_key(event_version(e))):
            kind, value = next(iter(event.items()))
            value = str(value)
            if kind == "introduced" and (value == "0" or compare_versions(version, value) >= 0):
                affected = True
            elif kind == "fixed" and compare_versions(version, value) >= 0:
                affected = False
            elif kind == "last_affected" and compare_versions(version, value) > 0:
                affected = False
        if affected:
            return True
    return False


def recommended_upgrade(version: str, fixed: list[str]) -> str | None:
    """Return the lowest fixed version that is newer than the installed one."""
    newer = [f for f in fixed if compare_versions(f, version) > 0]
    return min(newer, key=version_key) if newer else None


@dataclass(frozen=True)
class Query:
    """A component to look up."""

    ecosystem: str
    name: str
    version: str


def _merge_aliases(entries: list[dict]) -> list[dict]:
    """Merge advisories that describe the same issue (they share an id or an alias)."""
    merged: list[dict] = []
    for entry in entries:
        keys = {entry["advisory_id"], *entry["aliases"]}
        for existing in merged:
            if keys & existing["_keys"]:
                existing["_keys"] |= keys
                existing["also_known_as"] = sorted(existing["_keys"] - {existing["advisory_id"]})
                if existing["severity"] is None and entry["severity"] is not None:
                    existing["severity"] = entry["severity"]
                break
        else:
            entry["_keys"] = keys
            entry["also_known_as"] = sorted(keys - {entry["advisory_id"]})
            merged.append(entry)
    for entry in merged:
        del entry["_keys"]
    return merged


def find_vulnerabilities(queries: list[Query]) -> list[dict]:
    """Return the advisories that affect the given components (one entry per issue)."""
    by_package: dict[tuple[str, str], set[str]] = defaultdict(set)
    for query in queries:
        by_package[(query.ecosystem, normalize_package(query.ecosystem, query.name))].add(
            query.version
        )
    if not by_package:
        return []

    rows: dict[tuple[str, str], list[tuple[AdvisoryAffected, Advisory]]] = defaultdict(list)
    with session_scope() as session:
        for ecosystem in {eco for eco, _ in by_package}:
            names = sorted({name for eco, name in by_package if eco == ecosystem})
            for start in range(0, len(names), BATCH_SIZE):
                chunk = names[start : start + BATCH_SIZE]
                statement = (
                    select(AdvisoryAffected, Advisory)
                    .join(Advisory, col(Advisory.id) == col(AdvisoryAffected.advisory_id))
                    .where(
                        AdvisoryAffected.ecosystem == ecosystem,
                        col(AdvisoryAffected.package).in_(chunk),
                    )
                )
                for affected, advisory in session.exec(statement).all():
                    rows[(ecosystem, affected.package)].append((affected, advisory))
                    session.expunge(affected)
                    session.expunge(advisory)

    results: list[dict] = []
    for query in queries:
        key = (query.ecosystem, normalize_package(query.ecosystem, query.name))
        found: list[dict] = []
        for affected, advisory in rows.get(key, []):
            ranges = json.loads(affected.ranges)
            versions = json.loads(affected.versions)
            if not is_affected(query.version, ranges, versions):
                continue
            fixed = json.loads(affected.fixed)
            found.append(
                {
                    "advisory_id": advisory.id,
                    "aliases": json.loads(advisory.aliases),
                    "summary": advisory.summary,
                    "severity": advisory.severity,
                    "fixed_versions": fixed,
                    "recommended_upgrade": recommended_upgrade(query.version, fixed),
                }
            )
        for entry in _merge_aliases(found):
            entry.update(
                {"ecosystem": query.ecosystem, "package": query.name, "version": query.version}
            )
            results.append(entry)
    return results


def severity_or_default(label: str | None) -> Severity:
    """Return the Severity of an advisory label; unknown severities are reported as medium."""
    return Severity(label) if label else Severity.MEDIUM
