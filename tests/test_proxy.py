"""Proxy of the outgoing connections of the controller: URLs, no_proxy and urllib handler."""

import urllib.request

import pytest

from security_review_mcp import proxy
from security_review_mcp.config import Settings

PROXY = "http://alice:s3cr3t@proxy.internal:3128"


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


@pytest.fixture(autouse=True)
def no_environment_proxy(monkeypatch):
    """Ignore the proxy variables of the machine running the tests."""
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)


def test_masked_url_hides_the_password_only():
    assert proxy.masked_url(PROXY) == "http://alice:***@proxy.internal:3128"
    assert proxy.masked_url("http://proxy:3128") == "http://proxy:3128"


def test_check_no_proxy_normalizes_and_refuses_invalid_entries():
    assert proxy.check_no_proxy(" .Example.com , 10.0.0.1:8080,,[::1] ") == (
        ".Example.com,10.0.0.1:8080,[::1]"
    )
    assert proxy.check_no_proxy("10.0.0.0/8, 172.16.0.0/12,fd00::/8,[fd00::]/16") == (
        "10.0.0.0/8,172.16.0.0/12,fd00::/8,[fd00::]/16"
    )
    for value in ("a b", "a" * 501, "host;rm"):
        with pytest.raises(ValueError, match="invalid entry|too long"):
            proxy.check_no_proxy(value)
    for value in ("example.com/path", "10.0.0.0/33", "10.0.0/8x", "fd00::/129", "/8"):
        with pytest.raises(ValueError, match="invalid CIDR range"):
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
        # CIDR ranges: only for a host that is an IP address of the range
        ("10.20.30.40", "10.0.0.0/8", True),
        ("11.0.0.1", "10.0.0.0/8", False),
        ("192.168.1.200", "192.168.1.128/25", True),
        ("192.168.1.10", "192.168.1.128/25", False),
        ("192.168.1.10", "192.168.1.5/24", True),  # host bits are ignored
        ("fd00::12", "fd00::/8", True),
        ("2001:db8::1", "fd00::/8", False),
        ("fd00::12", "[fd00::]/8", True),
        ("fd00::12", "[fd00::12]", True),
        ("10.0.0.1", "fd00::/8", False),  # another IP version
        ("internal.example", "10.0.0.0/8", False),  # host names are never resolved
        ("sso.corp.example", "10.0.0.0/8,.corp.example", True),
    ],
)
def test_bypasses(host, no_proxy, expected):
    assert proxy.bypasses(host, proxy.parse_no_proxy(no_proxy)) is expected


def test_without_proxy_urllib_keeps_its_environment_handler():
    assert proxy.proxy_handler(make_settings()) is None


def test_an_empty_proxy_connects_directly(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://corporate:8080")
    handler = proxy.proxy_handler(make_settings().model_copy(update={"proxy": ""}))
    assert isinstance(handler, urllib.request.ProxyHandler) and handler.proxies == {}


def test_the_proxy_is_used_except_for_the_bypassed_hosts():
    settings = make_settings(proxy=PROXY, no_proxy="internal.example,10.0.0.0/8")
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


def test_describe_proxy_masks_the_password(monkeypatch):
    assert proxy.describe_proxy(make_settings(proxy=PROXY)) == (
        "http://alice:***@proxy.internal:3128",
        "proxy",
    )
    assert proxy.describe_proxy(make_settings().model_copy(update={"proxy": ""})) == (None, "none")
    monkeypatch.setenv("HTTPS_PROXY", "http://bob:pw@corporate:8080")
    assert proxy.describe_proxy(make_settings()) == ("http://bob:***@corporate:8080", "environment")
