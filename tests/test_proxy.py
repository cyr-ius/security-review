"""Proxy of the outgoing connections of the controller: URLs, no_proxy and urllib handler."""

import urllib.request

import pytest

from security_review_mcp import proxy
from security_review_mcp.config import Settings

PROXY = "http://alice:s3cr3t@proxy.internal:3128"


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


def test_masked_url_hides_the_password_only():
    assert proxy.masked_url(PROXY) == "http://alice:***@proxy.internal:3128"
    assert proxy.masked_url("http://proxy:3128") == "http://proxy:3128"


def test_check_no_proxy_normalizes_and_refuses_invalid_entries():
    assert proxy.check_no_proxy(" .Example.com , 10.0.0.1:8080,,[::1] ") == (
        ".Example.com,10.0.0.1:8080,[::1]"
    )
    for value in ("a b", "a" * 501, "host;rm", "example.com/path"):
        with pytest.raises(ValueError, match="invalid entry|too long"):
            proxy.check_no_proxy(value)
    for value in ("10.0.0.0/8", "fd00::/8"):
        with pytest.raises(ValueError, match="address ranges are not supported"):
            proxy.check_no_proxy(value)


@pytest.mark.parametrize(
    ("host", "no_proxy", "expected"),
    [
        ("osv.dev", "", False),
        ("localhost", "", True),
        ("127.0.0.5", "", True),
        ("::1", "", True),
        ("osv.dev", "*", True),
        ("osv.dev", "osv.dev", True),
        ("api.osv.dev", "osv.dev", True),
        ("api.osv.dev", ".osv.dev", True),
        ("api.osv.dev", "*.osv.dev", True),
        ("evilosv.dev", "osv.dev", False),
        ("OSV.dev", "osv.DEV:443", True),
        ("10.0.0.1", "10.0.0.1", True),
        ("10.0.0.2", "10.0.0.1", False),
        ("10.0.0.1", "10.0.0.1:8080", True),
        ("fd00::12", "[fd00::12]", True),
        ("fd00:0::12", "fd00::12", True),  # IPv6 addresses compared as addresses
        ("fd00::13", "fd00::12", False),
        # Address ranges are not supported: a CIDR entry (from NO_PROXY) matches no host
        ("10.20.30.40", "10.0.0.0/8", False),
        ("internal.example", "10.0.0.0/8", False),
        ("sso.corp.example", "10.0.0.0/8,.corp.example", True),
    ],
)
def test_bypasses(host, no_proxy, expected):
    assert proxy.bypasses(host, proxy.parse_no_proxy(no_proxy)) is expected


def test_the_proxy_comes_from_the_standard_variables(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://plain:8080")
    assert make_settings().proxy == "http://plain:8080"
    # HTTPS_PROXY wins over HTTP_PROXY; lowercase names are read too
    monkeypatch.setenv("https_proxy", PROXY)
    monkeypatch.setenv("no_proxy", ".corp.example")
    settings = make_settings()
    assert (settings.proxy, settings.no_proxy) == (PROXY, ".corp.example")


def test_the_former_secreview_proxy_variables_are_ignored(monkeypatch):
    monkeypatch.setenv("SECREVIEW_PROXY", PROXY)
    monkeypatch.setenv("SECREVIEW_NO_PROXY", ".corp.example")
    settings = make_settings()
    assert (settings.proxy, settings.no_proxy) == (None, None)


def test_a_proxy_without_scheme_is_http(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", " proxy.internal:3128 ")
    assert make_settings().proxy == "http://proxy.internal:3128"
    monkeypatch.setenv("HTTPS_PROXY", " ")
    assert make_settings().proxy is None


def test_without_proxy_the_connection_is_direct():
    for settings in (make_settings(), make_settings().model_copy(update={"proxy": ""})):
        handler = proxy.proxy_handler(settings)
        assert type(handler) is urllib.request.ProxyHandler and handler.proxies == {}


def test_the_proxy_is_used_except_for_the_bypassed_hosts():
    settings = make_settings(https_proxy=PROXY, no_proxy="internal.example,10.1.2.3")
    handler = proxy.proxy_handler(settings)

    proxied = urllib.request.Request("https://osv.dev/PyPI/all.zip")
    handler.proxy_open(proxied, PROXY, "https")
    # HTTPS goes through a CONNECT tunnel to the proxy
    assert proxied.host == "proxy.internal:3128"

    for url in (
        "https://sso.internal.example/realms",
        "http://localhost:8080/realms",
        "https://10.1.2.3:8443/realms",
    ):
        direct = urllib.request.Request(url)
        host = direct.host
        assert handler.proxy_open(direct, PROXY, "https") is None
        assert direct.host == host


def test_describe_proxy_masks_the_password():
    assert proxy.describe_proxy(make_settings(https_proxy=PROXY)) == (
        "http://alice:***@proxy.internal:3128"
    )
    assert proxy.describe_proxy(make_settings().model_copy(update={"proxy": ""})) is None
    assert proxy.describe_proxy(make_settings()) is None
