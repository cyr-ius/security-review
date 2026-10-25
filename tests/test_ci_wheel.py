"""Download of the pipeline client from the controller (clients/ci_wheel, ci_client_routes)."""

import hashlib
import re
import shutil
import subprocess
import sys

import pytest
from starlette.testclient import TestClient

from security_review_mcp import ci_client, http_server, web_api
from security_review_mcp.auth import token_store
from security_review_mcp.clients import ci_wheel
from security_review_mcp.config import get_settings
from security_review_mcp.http_server import Role

PAGE = "/api/ci-client/"


def controller(monkeypatch, enabled: bool) -> TestClient:
    """The controller app, with a stored token so that every other path needs one."""
    monkeypatch.setenv("SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED", str(enabled).lower())
    get_settings.cache_clear()
    token_store.create_token("jenkins", Role.CI, ["shop-api"])
    app = http_server.build_controller_app(
        web_api.create_app(ui=False), token_store.DatabaseTokenStore()
    )
    return TestClient(app, base_url="http://127.0.0.1")


def test_controller_serves_the_client_wheel_without_token(monkeypatch):
    client = controller(monkeypatch, enabled=True)
    assert client.get("/api/v1/ci/gate", params={"project": "shop-api"}).status_code == 401
    page = client.get(PAGE)
    assert page.status_code == 200
    href = re.search(r'href="([^"#]+)#sha256=([0-9a-f]{64})"', page.text)
    wheel = client.get(PAGE + href.group(1))
    assert wheel.status_code == 200
    assert hashlib.sha256(wheel.content).hexdigest() == href.group(2)
    assert client.get(PAGE + "other-1.0-py3-none-any.whl").status_code == 404


def test_client_download_is_disabled_by_default(monkeypatch):
    assert controller(monkeypatch, enabled=False).get(PAGE).status_code == 404


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is not installed")
def test_uv_installs_the_served_wheel_offline(tmp_path):
    # The contract with the developers: uv --no-index --find-links installs a working client
    wheel = ci_wheel.build_wheel()
    links = tmp_path / "links"
    links.mkdir()
    (links / wheel.filename).write_bytes(wheel.content)
    venv = tmp_path / "venv"
    subprocess.run(["uv", "venv", "-q", "--python", sys.executable, str(venv)], check=True)
    subprocess.run(
        ["uv", "pip", "install", "-q", "--python", str(venv / "bin" / "python")]
        + ["--no-index", "--find-links", str(links), ci_wheel.PROJECT],
        check=True,
    )
    result = subprocess.run(
        [str(venv / "bin" / "security-review-ci"), "gate", "--project", "shop-api"],
        capture_output=True,
        text=True,
        env={"SECREVIEW_TOKEN": "x"},
    )
    assert result.returncode == ci_client.EXIT_ERROR
    assert "No controller URL" in result.stderr
    assert ci_wheel.build_wheel().content == wheel.content
