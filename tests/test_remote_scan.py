"""Scan of scan_code delegated to the controller (rules/remote_scan.py)."""

import http.client

import pytest

from security_review_mcp.rules import remote_scan


class _TruncatedAnswer:
    """Answer whose body stops before its Content-Length, as when the controller hangs up."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        raise http.client.IncompleteRead(b'{"matches": [', 100)


class _Opener:
    def open(self, request, timeout=None):
        return _TruncatedAnswer()


def test_a_truncated_answer_is_a_remote_scan_error(monkeypatch):
    """scan_code falls back to the local rules on RemoteScanError only: a truncated answer must
    become one instead of failing the tool."""
    monkeypatch.setattr(remote_scan, "_OPENER", _Opener())
    with pytest.raises(remote_scan.RemoteScanError, match="cannot be reached"):
        remote_scan.scan("https://controller.example", "Bearer test-token", "x = 1", "python", 5)
