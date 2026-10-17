"""Retention (controller): daily purge of the reports without findings and of the old audit
events."""

import logging
import threading

from . import audit, services

logger = logging.getLogger(__name__)

# Seconds between two purges
PRUNE_INTERVAL_SECONDS = 24 * 3600


class ReportPruner:
    """Background thread of the controller that deletes the old reports without findings and
    the old audit events (each purge is skipped when its retention is 0)."""

    def __init__(
        self,
        retention_days: int,
        interval: float = PRUNE_INTERVAL_SECONDS,
        audit_retention_days: int = 0,
    ) -> None:
        """Prepare the pruner; ``start`` launches the thread."""
        self.retention_days = retention_days
        self.audit_retention_days = audit_retention_days
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self.run, name="report-pruner", daemon=True)

    def prune_once(self) -> None:
        """Run one purge; an error is logged and retried at the next interval."""
        if self.retention_days:
            try:
                services.prune_empty_reports(self.retention_days)
            except Exception:
                logger.exception("Purge of the reports without findings failed")
        if self.audit_retention_days:
            try:
                audit.prune_events(self.audit_retention_days)
            except Exception:
                logger.exception("Purge of the audit events failed")

    def run(self) -> None:
        """Purge at once, then every interval, until ``stop`` is called."""
        self.prune_once()
        while not self._stop.wait(self.interval):
            self.prune_once()

    def start(self) -> None:
        """Start the background thread."""
        if self.retention_days:
            logger.info(
                "Reports without findings are deleted after %d days (latest report of each "
                "project kept)",
                self.retention_days,
            )
        if self.audit_retention_days:
            logger.info("Audit events are deleted after %d days", self.audit_retention_days)
        self._thread.start()

    def stop(self) -> None:
        """Ask the thread to stop."""
        self._stop.set()
