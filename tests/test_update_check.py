"""Tests of the search for a newer release on GitHub."""

import io
import json
import urllib.error

import pytest

from security_review_mcp import __version__, update_check
from security_review_mcp.config import Settings


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file, with the check enabled."""
    return Settings(_env_file=None, **{"update_check_enabled": True, **values})


@pytest.fixture(autouse=True)
def fresh_cache():
    """Each test starts without a cached answer."""
    update_check.clear_cache()
    yield
    update_check.clear_cache()


class FakeOpener:
    """Opener that answers ``body`` (bytes) or raises ``error``, and records the requests."""

    def __init__(self, body: bytes = b"", error: Exception | None = None) -> None:
        self.body = body
        self.error = error
        self.requests: list = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if self.error is not None:
            raise self.error
        return io.BytesIO(self.body)


@pytest.fixture
def github(monkeypatch):
    """Replace the HTTPS opener; returns a function taking the fake answer."""
    openers: list[FakeOpener] = []

    def _answer(document=None, body: bytes | None = None, error: Exception | None = None):
        raw = body if body is not None else json.dumps(document).encode()
        opener = FakeOpener(raw, error)
        openers.append(opener)
        monkeypatch.setattr(update_check, "_opener", lambda settings: opener)
        return opener

    return _answer


def test_disabled_makes_no_request(github):
    opener = github({"tag_name": "v99.0.0"})

    status = update_check.check(make_settings(update_check_enabled=False))

    assert status["enabled"] is False and status["latest"] is None
    assert opener.requests == []


def test_a_newer_release_is_reported_and_cached(github):
    opener = github(
        {
            "tag_name": "v99.1.0",
            "html_url": "https://github.com/cyr-ius/security-review/releases/tag/v99.1.0",
        }
    )

    first = update_check.check(make_settings(), now=0)
    second = update_check.check(make_settings(), now=60)

    assert first["latest"] == "99.1.0" and first["update_available"] is True
    assert first["release_url"].endswith("/releases/tag/v99.1.0")
    assert first["current"] == __version__ and first["error"] is None
    assert second == first and len(opener.requests) == 1
    request, timeout = opener.requests[0]
    assert request.full_url == update_check.LATEST_RELEASE_URL and timeout == 10
    # Once the cache expires, GitHub is asked again
    update_check.check(make_settings(), now=update_check.CACHE_SECONDS + 1)
    assert len(opener.requests) == 2


def test_the_running_version_is_not_an_update(github):
    github({"tag_name": f"v{__version__}"})

    assert update_check.check(make_settings())["update_available"] is False


def test_a_foreign_release_link_is_replaced(github):
    github({"tag_name": "v99.0.0", "html_url": "https://evil.example.com/download"})

    status = update_check.check(make_settings())

    assert status["release_url"] == update_check.RELEASES_PAGE + "tag/v99.0.0"


@pytest.mark.parametrize(
    ("answer", "code"),
    [
        ({"error": urllib.error.URLError("timed out")}, "unreachable"),
        (
            {"error": urllib.error.HTTPError(update_check.LATEST_RELEASE_URL, 403, "x", {}, None)},
            "unreachable",
        ),
        ({"body": b"not json"}, "invalid"),
        ({"document": {"tag_name": "<script>"}}, "invalid"),
        ({"document": ["v1.0.0"]}, "invalid"),
        ({"body": b"x" * (update_check.MAX_RESPONSE_BYTES + 1)}, "invalid"),
    ],
)
def test_failures_give_a_short_code_only(github, caplog, answer, code):
    github(**answer)

    status = update_check.check(make_settings(), now=0)

    assert (status["latest"], status["error"]) == (None, code)
    assert "Search for a new version failed" in caplog.text


def test_the_proxy_credentials_are_never_logged(github, caplog):
    proxy = "http://bob:s3cret@proxy.internal:3128"  # secreview:ignore GEN-007 test value
    github(error=urllib.error.URLError(f"cannot connect to {proxy}"))

    update_check.check(make_settings(https_proxy=proxy))

    assert "s3cret" not in caplog.text and "bob:***@proxy.internal" in caplog.text


def test_the_opener_refuses_plain_http_redirects():
    opener = update_check._opener(make_settings())

    assert any(isinstance(h, update_check._HttpsRedirectOnly) for h in opener.handlers)
