"""Scan of scan_code delegated to the controller (rules/remote_scan.py)."""

import email.message
import http.client
import io
import urllib.error

import pytest

from security_review.rules import remote_scan


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


class _BusyThenFree:
    """Controller whose OpenGrep fragment slots are busy (503 with Retry-After) for the first
    ``busy`` calls, then scan the fragment."""

    def __init__(self, busy, retry_after="60"):
        self.busy = busy
        self.retry_after = retry_after
        self.calls = 0

    def open(self, request, timeout=None):
        self.calls += 1
        if self.calls <= self.busy:
            headers = email.message.Message()
            if self.retry_after is not None:
                headers["Retry-After"] = self.retry_after
            raise urllib.error.HTTPError(request.full_url, 503, "busy", headers, io.BytesIO())
        body = b'{"matches": [], "suppressed": [], "engines": ["rules", "opengrep"]}'
        return _Answer(body)


class _Answer:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self.body


@pytest.mark.parametrize(
    ("busy", "retry_after", "waits", "scanned"),
    [
        pytest.param(2, "60", [3, 3], True, id="busy-then-free"),
        pytest.param(1, "1", [1], True, id="shorter-retry-after"),
        pytest.param(5, "60", [3, 3], False, id="still-busy"),
        pytest.param(1, None, [], False, id="opengrep-down"),
    ],
)
def test_a_busy_controller_is_retried(monkeypatch, busy, retry_after, waits, scanned):
    """A 503 with Retry-After (every OpenGrep fragment slot taken) is retried after a short wait,
    capped below Retry-After; any other 503 is not: scan_code then scans with its own rules."""
    controller = _BusyThenFree(busy, retry_after)
    slept = []
    monkeypatch.setattr(remote_scan, "_OPENER", controller)
    monkeypatch.setattr(remote_scan, "_sleep", slept.append)

    def call():
        return remote_scan.scan(
            "https://controller.example",
            "Bearer test-token",
            "x = 1",
            "python",
            5,
            busy_retries=2,
            busy_wait=3,
        )

    if scanned:
        assert call()["engines"] == ["rules", "opengrep"]
    else:
        with pytest.raises(remote_scan.RemoteScanError, match="HTTP 503"):
            call()
    assert controller.calls == len(waits) + 1
    assert slept == waits
