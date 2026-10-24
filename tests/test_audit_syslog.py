"""Tests of the forwarding of the audit events to syslog."""

import json
import socket
import ssl
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlmodel import Session, select

from security_review_mcp.auth import token_store
from security_review_mcp.auth.token_store import Role
from security_review_mcp.config import Settings
from security_review_mcp.observability import audit_syslog
from security_review_mcp.storage.models import AppSetting, AuditEvent


def make_settings(**values) -> Settings:
    """Settings that ignore the developer's .env file."""
    return Settings(_env_file=None, **values)


def age_events(database, seconds: int = 60) -> None:
    """Make every audit event older than the settle delay."""
    with Session(database) as session:
        for event in session.exec(select(AuditEvent)).all():
            event.created_at = datetime.now(UTC) - timedelta(seconds=seconds)
            session.add(event)
        session.commit()


class FakeSocket:
    """Socket that records what is sent, or fails."""

    def __init__(self, fail: bool = False) -> None:
        self.sent: list[bytes] = []
        self.fail = fail

    def sendto(self, payload: bytes, address) -> None:
        if self.fail:
            raise ConnectionRefusedError("refused")
        self.sent.append(payload)


class FakeHandler:
    """SysLogHandler stand-in over UDP."""

    unixsocket = False
    socktype = socket.SOCK_DGRAM
    address = ("syslog.example.com", 514)
    facility = 16  # local0

    def __init__(self, fail: bool = False) -> None:
        self.socket = FakeSocket(fail)
        self.closed = False

    @staticmethod
    def encodePriority(facility: int, priority: str) -> int:  # noqa: N802 (logging API)
        return facility << 3 | 6

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("udp://syslog.example.com", (("syslog.example.com", 514), socket.SOCK_DGRAM)),
        ("udp://10.0.0.5:5514", (("10.0.0.5", 5514), socket.SOCK_DGRAM)),
        ("tcp://syslog.example.com:601", (("syslog.example.com", 601), socket.SOCK_STREAM)),
        ("tls://syslog.example.com", (("syslog.example.com", 6514), socket.SOCK_STREAM)),
        ("unix:///dev/log", ("/dev/log", socket.SOCK_DGRAM)),
    ],
)
def test_addresses_are_parsed(value, expected):
    assert audit_syslog.parse_address(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "syslog.example.com:514",
        "http://syslog.example.com",
        "udp://",
        "udp://user:secret@syslog.example.com",  # secreview:ignore GEN-007 test value
        "udp://syslog.example.com/path",
        "unix://host/dev/log",
        "udp://syslog.example.com:99999",
        "udp://sys log",
    ],
)
def test_invalid_addresses_are_refused(value):
    with pytest.raises(ValueError, match="SECREVIEW_AUDIT_SYSLOG_ADDRESS"):
        audit_syslog.parse_address(value)


def test_an_unknown_facility_is_refused():
    assert audit_syslog.facility("LOCAL0") == 16
    with pytest.raises(ValueError, match="SECREVIEW_AUDIT_SYSLOG_FACILITY"):
        audit_syslog.validate_settings(
            make_settings(audit_syslog_address="udp://syslog", audit_syslog_facility="nope")
        )


def test_the_first_batch_starts_after_the_history(database):
    token_store.create_token("before", Role.MCP)
    age_events(database)

    assert audit_syslog.claim_batch() == []
    token_store.create_token("after", Role.MCP)
    age_events(database)

    (event,) = audit_syslog.claim_batch()
    assert event["action"] == "token.created" and event["details"]["label"] == "after"
    assert audit_syslog.claim_batch() == []


def test_recent_events_wait_for_the_settle_delay(database):
    audit_syslog.claim_batch()
    token_store.create_token("now", Role.MCP)

    assert audit_syslog.claim_batch() == []
    age_events(database)
    assert len(audit_syslog.claim_batch()) == 1


def test_a_batch_claimed_by_another_replica_is_not_sent_twice(database, monkeypatch):
    audit_syslog.claim_batch()
    token_store.create_token("shared", Role.MCP)
    age_events(database)
    original = audit_syslog.update

    def raced(*args, **kwargs):
        # Another replica moves the cursor between the read and the conditional update
        with Session(database) as session:
            row = session.get(AppSetting, audit_syslog.AUDIT_SYSLOG_CURSOR)
            row.value = "999999"
            session.add(row)
            session.commit()
        return original(*args, **kwargs)

    monkeypatch.setattr(audit_syslog, "update", raced)
    assert audit_syslog.claim_batch() == []


def test_the_forwarder_sends_each_event_once_as_json(database, monkeypatch):
    handler = FakeHandler()
    monkeypatch.setattr(audit_syslog, "make_handler", lambda settings: handler)
    forwarder = audit_syslog.AuditForwarder(make_settings(audit_syslog_address="udp://syslog"))
    forwarder.forward_once()
    secret = token_store.create_token("ci", Role.MCP)["token"]
    age_events(database)

    assert forwarder.forward_once() == 1
    assert forwarder.forward_once() == 0
    (payload,) = handler.socket.sent
    priority, _, message = payload.decode().partition(">")
    assert priority == "<134"  # local0.info
    tag, _, body = message.partition(": ")
    event = json.loads(body)
    assert tag == "secreview-audit" and event["details"]["label"] == "ci"
    assert secret not in payload.decode()  # the token itself is never sent


def test_a_failed_sending_is_logged_without_retry(database, monkeypatch, caplog):
    handlers = [FakeHandler(fail=True), FakeHandler()]
    monkeypatch.setattr(audit_syslog, "make_handler", lambda settings: handlers.pop(0))
    forwarder = audit_syslog.AuditForwarder(make_settings(audit_syslog_address="udp://syslog"))
    forwarder.forward_once()
    token_store.create_token("lost", Role.MCP)
    age_events(database)

    assert forwarder.forward_once() == 0
    assert "Forwarding of 1 audit events to syslog failed" in caplog.text
    # The failed batch is not resent; the next one opens a new connection
    assert forwarder.forward_once() == 0
    token_store.create_token("next", Role.MCP)
    age_events(database)
    assert forwarder.forward_once() == 1 and handlers == []


def test_the_forwarder_writes_to_a_unix_socket(database):
    with tempfile.TemporaryDirectory(dir="/tmp") as directory:
        path = Path(directory) / "log"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server.bind(str(path))
        server.settimeout(2)
        try:
            forwarder = audit_syslog.AuditForwarder(
                make_settings(audit_syslog_address=f"unix://{path}")
            )
            forwarder.forward_once()
            token_store.create_token("local", Role.MCP)
            age_events(database)

            assert forwarder.forward_once() == 1
            assert b"secreview-audit: " in server.recv(65536)
        finally:
            forwarder.stop()
            server.close()


def self_signed(directory: Path) -> tuple[Path, Path]:
    """Write a self-signed certificate of localhost and its key; return their paths."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_the_forwarder_sends_over_tls_and_verifies_the_server(database, tmp_path, caplog):
    cert, key = self_signed(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)
    received: list[bytes] = []

    def serve(connections: int) -> None:
        for _ in range(connections):
            conn, _ = listener.accept()
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(5)
                    while chunk := tls.recv(65536):
                        received.append(chunk)
            except OSError:
                pass  # the client refused the certificate

    address = f"tls://localhost:{listener.getsockname()[1]}"
    server = threading.Thread(target=serve, args=(2,), daemon=True)
    server.start()
    # The system CA bundle does not know the certificate: nothing is sent
    untrusted = audit_syslog.AuditForwarder(make_settings(audit_syslog_address=address))
    trusted = audit_syslog.AuditForwarder(
        make_settings(audit_syslog_address=address, audit_syslog_cafile=str(cert))
    )
    try:
        untrusted.forward_once()
        trusted.forward_once()
        token_store.create_token("ci", Role.MCP)
        age_events(database)

        assert untrusted.forward_once() == 0
        assert "SSLCertVerificationError" in caplog.text
        token_store.create_token("other", Role.MCP)
        age_events(database)
        assert trusted.forward_once() == 1
    finally:
        untrusted.stop()
        trusted.stop()
        server.join(5)
        listener.close()
    # Octet counting of RFC 5425: the message is preceded by its length
    length, _, message = b"".join(received).partition(b" ")
    assert int(length) == len(message) and message.startswith(b"<134>secreview-audit: {")
    assert json.loads(message.partition(b": ")[2])["details"]["label"] == "other"


def test_a_missing_ca_file_refuses_the_forwarder(tmp_path):
    with pytest.raises(ValueError, match="SECREVIEW_AUDIT_SYSLOG_CAFILE"):
        audit_syslog.AuditForwarder(
            make_settings(
                audit_syslog_address="tls://syslog", audit_syslog_cafile=str(tmp_path / "ca.pem")
            )
        )


def test_invalid_settings_refuse_the_forwarder():
    with pytest.raises(ValueError):
        audit_syslog.AuditForwarder(make_settings(audit_syslog_address="syslog:514"))


@pytest.mark.parametrize(
    "value", ["udp://syslog.example.com:514", " tcp://10.0.0.5:601 ", "tls://syslog.example.com"]
)
def test_web_addresses_are_udp_tcp_or_tls(value):
    assert audit_syslog.check_web_address(value) == value.strip()


def test_a_unix_socket_cannot_be_set_in_the_web_interface():
    with pytest.raises(ValueError, match="Unix socket"):
        audit_syslog.check_web_address("unix:///dev/log")
    with pytest.raises(ValueError, match="SECREVIEW_AUDIT_SYSLOG_ADDRESS"):
        audit_syslog.check_web_address("syslog:514")


def test_the_forwarder_follows_the_current_settings(database, monkeypatch):
    built: list[tuple[str, str]] = []

    def handler_of(settings):
        built.append((settings.audit_syslog_address, settings.audit_syslog_facility))
        return FakeHandler()

    monkeypatch.setattr(audit_syslog, "make_handler", handler_of)
    current = {"value": make_settings()}
    forwarder = audit_syslog.AuditForwarder(make_settings(), current=lambda: current["value"])

    # No server: nothing is read nor sent, and the cursor stays absent
    token_store.create_token("unsent", Role.MCP)
    age_events(database)
    assert forwarder.forward_once() == 0
    with Session(database) as session:
        assert session.get(AppSetting, audit_syslog.AUDIT_SYSLOG_CURSOR) is None

    # A server set later: the events of the meantime are not sent
    current["value"] = make_settings(audit_syslog_address="udp://syslog")
    assert forwarder.forward_once() == 0
    token_store.create_token("sent", Role.MCP)
    age_events(database)
    assert forwarder.forward_once() == 1

    # A new facility opens a new connection
    current["value"] = make_settings(
        audit_syslog_address="udp://syslog", audit_syslog_facility="auth"
    )
    token_store.create_token("again", Role.MCP)
    age_events(database)
    assert forwarder.forward_once() == 1
    assert built == [("udp://syslog", "local0"), ("udp://syslog", "auth")]

    # Disabled again: the pending events, even recent, go to the previous server (the SIEM
    # receives the change), then the cursor is dropped so the history is skipped later
    token_store.create_token("last", Role.MCP)
    current["value"] = make_settings()
    assert forwarder.forward_once() == 1
    assert forwarder.forward_once() == 0
    with Session(database) as session:
        assert session.get(AppSetting, audit_syslog.AUDIT_SYSLOG_CURSOR) is None


def test_unreadable_settings_keep_the_cursor(database, monkeypatch, caplog):
    monkeypatch.setattr(audit_syslog, "make_handler", lambda settings: FakeHandler())
    current = {"broken": False}

    def read():
        if current["broken"]:
            raise RuntimeError("database unavailable")
        return make_settings(audit_syslog_address="udp://syslog")

    forwarder = audit_syslog.AuditForwarder(make_settings(), current=read)
    forwarder.forward_once()
    current["broken"] = True
    token_store.create_token("delayed", Role.MCP)
    age_events(database)

    assert forwarder.forward_once() == 0
    assert "Reading the syslog settings failed" in caplog.text
    # Not lost: sent once the settings can be read again
    current["broken"] = False
    assert forwarder.forward_once() == 1
