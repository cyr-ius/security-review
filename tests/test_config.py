"""Tests of the settings, as seen by the test suite."""

import os

from security_review_mcp.config import Settings


def test_the_tests_ignore_the_env_file_of_the_working_directory(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(
        "SECREVIEW_SWAGGER_ENABLED=true\nSECREVIEW_DATABASE_URL=sqlite:///./dev.db\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    settings = Settings()

    assert settings.swagger_enabled is False
    assert settings.database_url != "sqlite:///./dev.db"


def test_the_tests_ignore_the_secreview_variables_of_the_shell():
    # Only the variables set by the fixtures of conftest.py remain
    assert [
        name
        for name in os.environ
        if name.upper().startswith("SECREVIEW_") and name != "SECREVIEW_SECRET_KEY_FILE"
    ] == []
