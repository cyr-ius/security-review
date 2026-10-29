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
    assert [name for name in os.environ if name.upper().startswith("SECREVIEW_")] == []


def test_an_empty_controller_url_counts_as_unset(monkeypatch):
    # Compose passes SECREVIEW_PUBLIC_URL="" to the controller when .env does not define it
    monkeypatch.setenv("SECREVIEW_PUBLIC_URL", "")

    assert Settings().controller_url is None


def test_the_former_name_of_the_public_url_is_read_when_it_is_not_set(monkeypatch):
    # SECREVIEW_CONTROLLER_URL is now the variable of security-review-ci: the controller still
    # reads it as its public URL (with a warning) until SECREVIEW_PUBLIC_URL is set
    monkeypatch.setenv("SECREVIEW_CONTROLLER_URL", "https://old.example/")
    settings = Settings()
    assert (settings.controller_url, settings.legacy_controller_url) == ("https://old.example",) * 2

    monkeypatch.setenv("SECREVIEW_PUBLIC_URL", "https://new.example")
    settings = Settings()
    assert (settings.controller_url, settings.legacy_controller_url) == (
        "https://new.example",
        None,
    )
