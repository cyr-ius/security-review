"""Tests for the background purge of the reports without findings."""

import logging

from security_review_mcp import retention, services


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
