"""Tests for the background purge of the reports without findings."""

import logging

from security_review_mcp import audit, services
from security_review_mcp.storage import retention


def test_pruner_purges_at_start_then_stops(monkeypatch):
    calls: list[int] = []
    pruner = retention.ReportPruner(30, interval=3600)

    def fake_prune(days: int) -> dict:
        calls.append(days)
        pruner.stop()  # the loop then ends without waiting
        return {"retention_days": days, "deleted": 0}

    monkeypatch.setattr(services, "prune_empty_reports", fake_prune)
    pruner.run()

    assert calls == [30]


def test_pruner_logs_an_error_without_stopping(monkeypatch, caplog):
    def broken(days: int) -> dict:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(services, "prune_empty_reports", broken)
    with caplog.at_level(logging.ERROR, logger="security_review_mcp"):
        retention.ReportPruner(30).prune_once()

    assert "Purge of the reports without findings failed" in caplog.text


def test_pruner_also_purges_the_audit_log(monkeypatch):
    calls: list[tuple[str, int]] = []
    monkeypatch.setattr(
        services, "prune_empty_reports", lambda days: calls.append(("reports", days))
    )
    monkeypatch.setattr(
        audit, "prune_events", lambda days, limit: calls.append(("audit", days, limit))
    )

    retention.ReportPruner(30, audit_retention_days=365).prune_once()
    retention.ReportPruner(0, audit_retention_days=365).prune_once()
    retention.ReportPruner(30).prune_once()
    retention.ReportPruner(0, audit_max_events=1000).prune_once()

    assert calls == [
        ("reports", 30),
        ("audit", 365, 0),
        ("audit", 365, 0),
        ("reports", 30),
        ("audit", 0, 1000),
    ]


def test_a_failed_audit_purge_is_logged(monkeypatch, caplog):
    def broken(days: int, limit: int) -> dict:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(audit, "prune_events", broken)
    with caplog.at_level(logging.ERROR, logger="security_review_mcp"):
        retention.ReportPruner(0, audit_retention_days=30).prune_once()

    assert "Purge of the audit events failed" in caplog.text
