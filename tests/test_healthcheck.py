"""Tests of the health check of the Docker image."""

import re
from pathlib import Path

import pytest

from security_review_mcp import healthcheck, http_server
from security_review_mcp.config import Settings

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def settings(monkeypatch):
    """Replace the settings read by the health check; returns a function taking overrides."""

    def _set(**values) -> None:
        current = Settings(_env_file=None, **values)
        monkeypatch.setattr(healthcheck, "get_settings", lambda: current)

    _set()
    return _set


@pytest.fixture
def requests(monkeypatch):
    """Record the requests of the check and answer with ``status`` (None: connection refused)."""
    calls: list[dict] = []
    answer = {"status": 200}

    class Response:
        def __init__(self, status: int) -> None:
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            return None

    def fake_urlopen(url, timeout, context):
        calls.append({"url": url, "timeout": timeout, "context": context})
        if answer["status"] is None:
            raise ConnectionRefusedError("refused")
        return Response(answer["status"])

    monkeypatch.setattr(healthcheck.urllib.request, "urlopen", fake_urlopen)
    return calls, answer


def test_the_health_path_is_the_one_served_by_both_processes():
    assert healthcheck.HEALTH_PATH == http_server.HEALTH_PATH


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["security-review-mcp"], None),
        (["security-review-mcp", "enroll", "--url", "https://mcp"], None),
        (
            ["security-review-mcp", "--transport", "streamable-http", "--port", "9000"],
            "http://127.0.0.1:9000/healthz",
        ),
        (
            ["security-review-mcp", "--transport=streamable-http"],
            "http://127.0.0.1:8000/healthz",
        ),
        (
            ["security-review-controller", "serve", "--host", "0.0.0.0"],
            "http://127.0.0.1:8000/healthz",
        ),
        (
            ["security-review-controller", "serve", "--tls-certfile", "/certs/tls.crt"],
            "https://127.0.0.1:8000/healthz",
        ),
    ],
)
def test_the_url_follows_the_command_of_the_container(settings, args, expected):
    assert healthcheck.health_url(args) == expected


def test_the_url_follows_the_settings_without_options(settings):
    settings(transport="streamable-http", port=8443, tls_certfile="/certs/tls.crt")

    assert healthcheck.health_url(["security-review-mcp"]) == "https://127.0.0.1:8443/healthz"


def test_stdio_is_healthy_without_any_request(settings, requests):
    assert healthcheck.main(["security-review-mcp"]) == 0
    assert requests[0] == []


def test_an_http_process_is_healthy_when_healthz_answers(settings, requests):
    calls, _ = requests

    assert healthcheck.main(["security-review-controller", "serve"]) == 0
    assert calls == [{"url": "http://127.0.0.1:8000/healthz", "timeout": 3, "context": None}]


@pytest.mark.parametrize("status", [None, 503])
def test_an_http_process_is_unhealthy_without_answer(settings, requests, capsys, status):
    requests[1]["status"] = status

    assert healthcheck.main(["security-review-controller", "serve"]) == 1
    assert "unhealthy" in capsys.readouterr().err


def test_https_trusts_only_the_certificate_of_the_process(settings, requests, monkeypatch):
    contexts = []
    monkeypatch.setattr(
        healthcheck, "tls_context", lambda certfile: contexts.append(certfile) or "pinned"
    )

    assert (
        healthcheck.main(["security-review-controller", "serve", "--tls-certfile", "/c.pem"]) == 0
    )
    assert contexts == ["/c.pem"] and requests[0][0]["context"] == "pinned"


def test_the_tls_context_checks_the_certificate_but_not_the_loopback_name(tmp_path):
    import ssl

    bad = tmp_path / "not-a-cert.pem"
    bad.write_text("not a certificate")
    with pytest.raises(ssl.SSLError):
        healthcheck.tls_context(str(bad))


def test_mutual_tls_is_not_requested(settings, requests):
    settings(tls_client_ca="/certs/ca.pem")

    assert healthcheck.main(["security-review-controller", "serve"]) == 0
    assert requests[0] == []


def test_the_container_command_is_read_from_proc(tmp_path):
    cmdline = tmp_path / "cmdline"
    cmdline.write_bytes(
        b"/app/.venv/bin/python\0/app/.venv/bin/security-review-controller\0serve\0"
    )

    assert healthcheck.container_command(cmdline)[-1] == "serve"
    assert healthcheck.container_command(tmp_path / "missing") == []


def test_the_image_declares_the_health_check():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    healthcheck_instruction = re.search(r"^HEALTHCHECK [^\n]*\\\n\s+CMD (.*)$", dockerfile, re.M)
    assert healthcheck_instruction is not None
    assert '"-m", "security_review_mcp.healthcheck"' in healthcheck_instruction.group(1)
