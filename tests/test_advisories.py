"""Tests for version comparison, the OSV import and advisory matching."""

import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from security_review_mcp import advisories
from security_review_mcp.advisories import Query
from security_review_mcp.database import session_scope
from security_review_mcp.models import Advisory
from security_review_mcp.versions import compare_versions, sort_versions


def osv(
    advisory_id="PYSEC-1",
    package="requests",
    ecosystem="PyPI",
    introduced="0",
    fixed="2.0.0",
    aliases=(),
    severity=None,
    versions=None,
    **extra,
):
    """Build a minimal OSV record."""
    events = [{"introduced": introduced}] + ([{"fixed": fixed}] if fixed else [])
    entry = {
        "package": {"ecosystem": ecosystem, "name": package},
        "ranges": [{"type": "ECOSYSTEM", "events": events}],
    }
    if versions:
        entry["versions"] = versions
    record = {
        "id": advisory_id,
        "summary": f"Issue in {package}",
        "aliases": list(aliases),
        "affected": [entry],
    }
    if severity:
        record["database_specific"] = {"severity": severity}
    record.update(extra)
    return record


# ── versions ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "left, right, expected",
    [
        ("1.0", "1.0.0", 0),
        ("1.2.3", "1.10.0", -1),
        ("1.0rc1", "1.0", -1),
        ("1.0.RELEASE", "1.0", 0),
        ("2.0.0-beta.1", "2.0.0", -1),
        ("1.0.1", "1.0.post1", 1),
        ("1.0.post1", "1.0", 1),
        ("1.0-SNAPSHOT", "1.0", -1),
        ("1.0a1", "1.0b1", -1),
        ("2.31.0", "2.9.1", 1),
        ("v1.2", "1.2", 0),
        ("1!2.0", "2.0", 0),
        ("22.0.0-next.0", "22.0.0-rc.2", -1),
        ("22.0.0-next.3", "22.0.0", -1),
        ("19.0.0-canary-1", "19.0.0-beta.1", -1),
        # Go: a pseudo-version after v1.2.3 sorts before v1.2.4; +incompatible is ignored
        ("v1.2.4-0.20210101000000-abcdef123456", "1.2.4", -1),
        ("v1.2.4-0.20210101000000-abcdef123456", "1.2.3", 1),
        ("v0.0.0-20220127200216-cd36cc0744dd", "0.0.0-20211209124913-491a49abca63", 1),
        ("v2.0.1+incompatible", "2.0.1", 0),
    ],
)
def test_compare_versions(left, right, expected):
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


def test_sort_versions():
    assert sort_versions(["1.10", "1.2", "1.2rc1", "1.2.1", "1.0"]) == [
        "1.0",
        "1.2rc1",
        "1.2",
        "1.2.1",
        "1.10",
    ]


# ── CVSS and severity ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "vector, score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_scores(vector, score):
    assert advisories.cvss3_score(vector) == score


def test_cvss_rejects_other_versions_and_garbage():
    assert advisories.cvss3_score("CVSS:4.0/AV:N") is None
    assert advisories.cvss3_score("CVSS:3.1/AV:N") is None


def test_extract_severity_sources():
    assert advisories.extract_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"
    vector = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    }
    assert advisories.extract_severity(vector) == "critical"
    assert advisories.extract_severity({}) is None


# ── matching ─────────────────────────────────────────────────────────────────


def test_is_affected_follows_the_osv_algorithm():
    ranges = [
        {
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "1.0"},
                {"fixed": "1.5"},
                {"introduced": "2.0"},
                {"fixed": "2.3"},
            ],
        }
    ]
    check = lambda v: advisories.is_affected(v, ranges, [])  # noqa: E731
    assert [check(v) for v in ("0.9", "1.0", "1.4.9", "1.5", "1.9", "2.0", "2.2", "2.3")] == [
        False,
        True,
        True,
        False,
        False,
        True,
        True,
        False,
    ]
    last = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.2.0"}]}]
    assert advisories.is_affected("1.2.0", last, []) and not advisories.is_affected(
        "1.2.1", last, []
    )
    assert advisories.is_affected("3.0", [], ["3.0"])  # explicit version list


def test_prerelease_ranges_do_not_affect_later_releases():
    # Real Angular ranges (GHSA-p3vc-36g9-x9gr): "next" pre-releases come before "rc" ones
    ranges = [
        {"type": "SEMVER", "events": [{"introduced": "22.0.0-next.0"}, {"fixed": "22.0.0-rc.2"}]},
        {"type": "SEMVER", "events": [{"introduced": "21.2.0-next.0"}, {"fixed": "21.2.0"}]},
    ]

    assert not advisories.is_affected("22.2.2", ranges, [])
    assert not advisories.is_affected("21.2.1", ranges, [])
    assert advisories.is_affected("22.0.0-next.5", ranges, [])
    assert advisories.is_affected("21.2.0-rc.1", ranges, [])


def test_recommended_upgrade_is_the_closest_newer_fix():
    assert advisories.recommended_upgrade("1.4", ["1.5", "2.3"]) == "1.5"
    assert advisories.recommended_upgrade("2.0", ["1.5", "2.3"]) == "2.3"
    assert advisories.recommended_upgrade("3.0", ["1.5"]) is None


# ── import ───────────────────────────────────────────────────────────────────


def write_dir(tmp_path, *records):
    """Write OSV records as separate JSON files."""
    for number, record in enumerate(records):
        (tmp_path / f"{number}.json").write_text(json.dumps(record))
    return tmp_path


def test_import_directory_and_find(tmp_path):
    stats = advisories.import_advisories(
        write_dir(
            tmp_path,
            osv("PYSEC-1", "Requests", fixed="2.20.0", severity="HIGH"),
            osv("GHSA-x", "left-pad", "npm", fixed="1.3.1"),
            osv("W-1", "x", withdrawn="2024-01-01T00:00:00Z"),
            osv("G-1", "foo", "RubyGems"),
            {
                "id": "GIT-1",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "git-only"},
                        "ranges": [{"type": "GIT", "events": []}],
                    }
                ],
            },
        )
    )
    assert stats["read"] == 5 and stats["imported"] == 2 and stats["skipped"] == 3

    found = advisories.find_vulnerabilities(
        [
            Query("PyPI", "requests", "2.19.0"),
            Query("PyPI", "requests", "2.20.0"),
            Query("npm", "left-pad", "1.0.0"),
        ]
    )
    by_package = {(f["package"], f["version"]): f for f in found}
    assert set(by_package) == {("requests", "2.19.0"), ("left-pad", "1.0.0")}
    assert by_package[("requests", "2.19.0")]["recommended_upgrade"] == "2.20.0"
    assert by_package[("requests", "2.19.0")]["severity"] == "high"


def test_one_advisory_affecting_several_queried_packages(tmp_path):
    record = osv("GHSA-multi", "httpx", fixed="1.0.0")
    record["affected"].append(
        {
            "package": {"ecosystem": "PyPI", "name": "httpcore"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
        }
    )
    advisories.import_advisories(write_dir(tmp_path, record))

    found = advisories.find_vulnerabilities(
        [Query("PyPI", "httpx", "0.9.0"), Query("PyPI", "httpcore", "0.9.0")]
    )

    assert {(f["package"], f["advisory_id"]) for f in found} == {
        ("httpx", "GHSA-multi"),
        ("httpcore", "GHSA-multi"),
    }


def test_pypi_names_are_normalized():
    assert advisories.normalize_package("PyPI", "Foo_Bar.baz") == "foo-bar-baz"
    assert advisories.normalize_package("Maven", "Org.Foo:Bar") == "org.foo:bar"
    assert advisories.normalize_package("crates.io", "Serde_JSON") == "serde-json"
    assert advisories.normalize_package("NuGet", "Newtonsoft.Json") == "newtonsoft.json"


def test_import_zip_and_idempotence(tmp_path):
    archive = tmp_path / "all.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("PYSEC-1.json", json.dumps(osv("PYSEC-1")))
        z.writestr("readme.txt", "ignored")
        z.writestr("list.json", json.dumps([osv("PYSEC-2", "flask"), osv("PYSEC-3", "django")]))
    first = advisories.import_advisories(archive)
    second = advisories.import_advisories(archive)
    assert first["imported"] == second["imported"] == 3
    assert advisories.advisory_status()["advisories"] == 3  # replaced, not duplicated


def test_import_reports_bad_files_and_unknown_ecosystems(tmp_path):
    (tmp_path / "bad.json").write_text("{not json")
    stats = advisories.import_advisories(tmp_path)
    assert stats["read"] == 0 and any("bad.json" in e for e in stats["errors"])
    with pytest.raises(ValueError):
        advisories.import_advisories(tmp_path, {"Cargo"})
    with pytest.raises(ValueError):
        advisories.import_advisories(tmp_path / "missing")


def test_ecosystem_filter(tmp_path):
    write_dir(tmp_path, osv("PYSEC-1"), osv("GHSA-x", "left-pad", "npm"))
    stats = advisories.import_advisories(tmp_path, {"npm"})
    assert stats["imported"] == 1
    assert advisories.advisory_status()["by_ecosystem"] == {"npm": 1}


def test_aliases_are_merged_into_one_entry(tmp_path):
    write_dir(
        tmp_path,
        osv("PYSEC-1", aliases=["CVE-2024-1"]),
        osv("GHSA-a", aliases=["CVE-2024-1"], severity="CRITICAL"),
        osv("PYSEC-9", aliases=["CVE-2024-2"]),
    )
    advisories.import_advisories(tmp_path)
    found = advisories.find_vulnerabilities([Query("PyPI", "requests", "1.0")])
    assert len(found) == 2
    merged = next(f for f in found if "CVE-2024-1" in f["also_known_as"])
    assert merged["severity"] == "critical"  # the merged entry keeps the known severity


def test_status_of_an_empty_and_a_stale_database(tmp_path):
    assert advisories.advisory_status() == {
        "loaded": False,
        "advisories": 0,
        "by_ecosystem": {},
        "last_imported_at": None,
        "age_days": None,
        "stale": False,
    }
    write_dir(tmp_path, osv())
    advisories.import_advisories(tmp_path)
    assert advisories.advisory_status()["stale"] is False
    with session_scope() as session:
        advisory = session.get(Advisory, "PYSEC-1")
        advisory.imported_at = datetime.now(UTC) - timedelta(days=45)
        session.add(advisory)
    status = advisories.advisory_status()
    assert status["stale"] is True and status["age_days"] >= 45
