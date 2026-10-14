"""Download of the OSV exports by the controller: settings, proxy, size limit and scheduling."""

import io
import json
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from test_advisories import osv

from security_review_mcp import advisories, advisory_sync, cli
from security_review_mcp.config import Settings

PROXY = "http://alice:s3cr3t@proxy.internal:3128"


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


def osv_zip(*records) -> bytes:
    """Build an all.zip export holding one JSON file per record."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for record in records:
            archive.writestr(f"{record['id']}.json", json.dumps(record))
    return buffer.getvalue()


class FakeResponse(io.BytesIO):
    """HTTP response returned by FakeOpener."""

    def __init__(self, body: bytes, length: str | None = None) -> None:
        """Serve ``body``, announcing ``length`` (default: its real size)."""
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body)) if length is None else length}


class FakeOpener:
    """Opener serving canned bodies by URL, recording the requests."""

    def __init__(self, bodies: dict[str, bytes | Exception]) -> None:
        """Map each URL to its body, or to the exception raised when it is opened."""
        self.bodies = bodies
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float) -> FakeResponse:
        """Return the body of the requested URL."""
        self.requests.append(request)
        body = self.bodies[request.full_url]
        if isinstance(body, Exception):
            raise body
        return FakeResponse(body)


@pytest.fixture
def opener(monkeypatch):
    """Replace the network with a FakeOpener; set its ``bodies`` in the test."""
    fake = FakeOpener({})
    monkeypatch.setattr(advisory_sync, "build_opener", lambda settings: fake)
    return fake


def url_of(ecosystem: str) -> str:
    """Default export URL of an ecosystem."""
    return f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"


# ── settings ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("values", "variable"),
    [
        ({"osv_url": "http://osv.example"}, "SECREVIEW_OSV_URL"),
        ({"osv_url": "file:///etc"}, "SECREVIEW_OSV_URL"),
        ({"osv_url": "https://user:pw@osv.example"}, "SECREVIEW_OSV_URL"),
        ({"osv_proxy": "socks5://proxy:1080"}, "SECREVIEW_OSV_PROXY"),
        ({"osv_proxy": "proxy:3128"}, "SECREVIEW_OSV_PROXY"),
        ({"osv_cafile": "/nonexistent/ca.pem"}, "SECREVIEW_OSV_CAFILE"),
        ({"osv_update_interval_hours": 0}, "SECREVIEW_OSV_UPDATE_INTERVAL_HOURS"),
        ({"osv_max_download_mb": 0}, "SECREVIEW_OSV_MAX_DOWNLOAD_MB"),
        ({"osv_ecosystems": "PyPI,Go"}, "SECREVIEW_OSV_ECOSYSTEMS"),
        ({"osv_ecosystems": " , "}, "SECREVIEW_OSV_ECOSYSTEMS"),
    ],
)
def test_invalid_settings_are_refused(values, variable):
    with pytest.raises(ValueError, match=variable):
        advisory_sync.validate_settings(make_settings(**values))


def test_default_settings_are_valid_and_ecosystems_are_canonical():
    advisory_sync.validate_settings(make_settings(osv_proxy=PROXY))

    settings = make_settings(osv_ecosystems="pypi, NPM,maven,PyPI")
    assert advisory_sync.ecosystems_of(settings) == ["PyPI", "npm", "Maven"]


def test_safe_url_drops_the_credentials():
    assert advisory_sync.safe_url(PROXY) == "http://proxy.internal:3128"
    assert advisory_sync.safe_url("http://proxy:3128") == "http://proxy:3128"


# ── opener and proxy ─────────────────────────────────────────────────────────


def proxies_of(opener: urllib.request.OpenerDirector) -> dict:
    """Return the proxies of the ProxyHandler of an opener."""
    (handler,) = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    return handler.proxies


def test_opener_uses_the_configured_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://other:8080")

    opener = advisory_sync.build_opener(make_settings(osv_proxy=PROXY))

    assert proxies_of(opener) == {"http": PROXY, "https": PROXY}


def test_opener_falls_back_to_the_standard_proxy_variables(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://corporate:8080")

    opener = advisory_sync.build_opener(make_settings())

    assert proxies_of(opener)["https"] == "http://corporate:8080"


def test_redirects_to_another_scheme_than_https_are_refused():
    handler = advisory_sync._HttpsRedirectOnly()
    request = urllib.request.Request(url_of("PyPI"))

    for target in ("http://mirror/all.zip", "ftp://mirror/all.zip", "file:///etc/passwd"):
        with pytest.raises(urllib.error.HTTPError, match="non-HTTPS"):
            handler.redirect_request(request, io.BytesIO(), 302, "Found", {}, target)
    redirected = handler.redirect_request(
        request, io.BytesIO(), 302, "Found", {}, "https://storage.example/all.zip"
    )
    assert redirected.full_url == "https://storage.example/all.zip"


# ── download ─────────────────────────────────────────────────────────────────


def test_download_streams_the_archive(tmp_path):
    body = osv_zip(osv())
    fake = FakeOpener({url_of("PyPI"): body})

    size = advisory_sync.download_export(fake, url_of("PyPI"), tmp_path / "a.zip", len(body))

    assert size == len(body) and (tmp_path / "a.zip").read_bytes() == body
    assert fake.requests[0].get_header("User-agent").startswith("security-review-mcp/")


@pytest.mark.parametrize("length", [None, "", "10"])
def test_download_refuses_an_archive_over_the_limit(tmp_path, length):
    fake = FakeOpener({})
    fake.open = lambda request, timeout: FakeResponse(b"x" * 64, length=length)

    with pytest.raises(ValueError, match="allowed"):
        advisory_sync.download_export(fake, url_of("npm"), tmp_path / "a.zip", 32)


def test_download_refuses_a_declared_size_over_the_limit_before_reading(tmp_path):
    fake = FakeOpener({})
    fake.open = lambda request, timeout: FakeResponse(b"", length=str(10**12))

    with pytest.raises(ValueError, match="1000000000000 bytes"):
        advisory_sync.download_export(fake, url_of("npm"), tmp_path / "a.zip", 1024)


def test_update_downloads_and_imports_each_ecosystem(opener, caplog):
    opener.bodies = {
        url_of("PyPI"): osv_zip(osv("PYSEC-1"), osv("PYSEC-2", package="flask")),
        url_of("npm"): osv_zip(osv("GHSA-1", package="lodash", ecosystem="npm")),
    }
    settings = make_settings(osv_ecosystems="PyPI,npm", osv_proxy=PROXY)

    with caplog.at_level("INFO", logger="security_review_mcp"):
        result = advisory_sync.update_advisories(settings)

    assert result["ecosystems"]["PyPI"]["imported"] == 2
    assert result["ecosystems"]["npm"]["imported"] == 1
    assert advisories.advisory_status()["by_ecosystem"] == {"PyPI": 2, "npm": 1}
    assert "proxy.internal:3128" in caplog.text and "s3cr3t" not in caplog.text


def test_update_keeps_only_the_ecosystem_of_each_archive(opener):
    opener.bodies = {url_of("PyPI"): osv_zip(osv("GHSA-2", package="lodash", ecosystem="npm"))}

    result = advisory_sync.update_advisories(make_settings(osv_ecosystems="PyPI"))

    assert result["ecosystems"]["PyPI"]["imported"] == 0
    assert advisories.advisory_status()["advisories"] == 0


def test_update_reports_a_failed_ecosystem_and_continues(opener):
    opener.bodies = {
        url_of("PyPI"): urllib.error.URLError("proxy refused the connection"),
        url_of("npm"): b"not a zip archive",
        url_of("Maven"): osv_zip(osv("GHSA-3", package="g:a", ecosystem="Maven")),
    }

    result = advisory_sync.update_advisories(make_settings())["ecosystems"]

    assert "proxy refused" in result["PyPI"]["error"]
    assert result["npm"]["error"].startswith("BadZipFile")
    assert result["Maven"]["imported"] == 1


def test_update_uses_a_mirror(opener):
    mirror = "https://nexus.internal/repository/osv/"
    opener.bodies = {"https://nexus.internal/repository/osv/PyPI/all.zip": osv_zip(osv())}

    result = advisory_sync.update_advisories(make_settings(osv_url=mirror, osv_ecosystems="pypi"))

    assert result == {"source": mirror, "ecosystems": {"PyPI": result["ecosystems"]["PyPI"]}}
    assert result["ecosystems"]["PyPI"]["imported"] == 1


def test_update_refuses_invalid_settings_before_any_download(opener):
    with pytest.raises(ValueError, match="SECREVIEW_OSV_URL"):
        advisory_sync.update_advisories(make_settings(osv_url="http://osv.example"))

    assert opener.requests == []


# ── scheduling ───────────────────────────────────────────────────────────────


def test_seconds_until_due():
    now = datetime(2026, 10, 14, 12, tzinfo=UTC)

    assert advisory_sync.seconds_until_due(None, 24, now) == 0
    assert advisory_sync.seconds_until_due(now - timedelta(hours=30), 24, now) == 0
    assert advisory_sync.seconds_until_due(now - timedelta(hours=20), 24, now) == 4 * 3600


def test_updater_waits_for_the_interval_after_an_import(tmp_path):
    updater = advisory_sync.AdvisoryUpdater(make_settings())
    assert updater.next_delay() == 0

    advisories.import_advisories(_write(tmp_path, osv()))

    assert 23 * 3600 < updater.next_delay() <= 24 * 3600


def _write(tmp_path, record):
    """Write an OSV record to a JSON file and return its path."""
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def test_updater_runs_an_update_when_due_then_stops(monkeypatch):
    updater = advisory_sync.AdvisoryUpdater(make_settings())
    calls = []

    def fake_update(settings):
        calls.append(settings)
        updater.stop()
        return {"source": settings.osv_url, "ecosystems": {"PyPI": {"error": "OSError: down"}}}

    monkeypatch.setattr(advisory_sync, "update_advisories", fake_update)

    updater.run()

    assert calls == [updater.settings]


def test_updater_survives_an_unexpected_error(monkeypatch, caplog):
    updater = advisory_sync.AdvisoryUpdater(make_settings())

    def broken_update(settings):
        updater.stop()
        raise RuntimeError("database is gone")

    monkeypatch.setattr(advisory_sync, "update_advisories", broken_update)

    with caplog.at_level("ERROR", logger="security_review_mcp"):
        updater.run()

    assert "next attempt in 1 hour" in caplog.text


def test_updater_does_nothing_once_stopped(monkeypatch):
    updater = advisory_sync.AdvisoryUpdater(make_settings())
    monkeypatch.setattr(advisory_sync, "update_advisories", pytest.fail)

    updater.stop()
    updater.run()


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_update_imports_and_reports(opener, monkeypatch, capsys):
    opener.bodies = {url_of("npm"): osv_zip(osv("GHSA-1", package="lodash", ecosystem="npm"))}

    assert cli.run(["advisories", "update", "--ecosystem", "npm"]) == cli.EXIT_PASSED

    result = json.loads(capsys.readouterr().out)
    assert list(result["ecosystems"]) == ["npm"]
    assert result["ecosystems"]["npm"]["imported"] == 1


def test_cli_update_exits_2_when_an_ecosystem_fails(opener, capsys):
    opener.bodies = {url_of("Maven"): urllib.error.URLError("timed out")}

    assert cli.run(["advisories", "update", "--ecosystem", "Maven"]) == cli.EXIT_ERROR
    assert "timed out" in json.loads(capsys.readouterr().out)["ecosystems"]["Maven"]["error"]


def test_cli_update_refuses_an_unknown_ecosystem(opener, capsys):
    assert cli.run(["advisories", "update", "--ecosystem", "Go"]) == cli.EXIT_ERROR
    assert "SECREVIEW_OSV_ECOSYSTEMS" in json.loads(capsys.readouterr().err)["error"]
    assert opener.requests == []
