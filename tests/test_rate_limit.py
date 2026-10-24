"""Rate limiting shared through the database: login throttling and REST API limits."""

import math

import pytest
from sqlmodel import Session, select
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from security_review_mcp import http_server, rate_limit, token_store
from security_review_mcp.config import Settings
from security_review_mcp.storage.models import RateLimitCounter


class Clock:
    """A clock moved by the test."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture(autouse=True)
def no_throttled_purge(monkeypatch):
    """Each test may purge at once."""
    monkeypatch.setattr(rate_limit, "_last_purge", 0.0)


# ── Login throttling ─────────────────────────────────────────────────────────


def test_throttle_locks_a_username_per_address(clock):
    throttle = rate_limit.LoginThrottle(max_per_user=2, max_per_address=10, clock=clock)

    throttle.failed("Alice", "10.0.0.1")
    assert not throttle.blocked("alice", "10.0.0.1")
    throttle.failed("alice", "10.0.0.1")
    assert throttle.blocked("ALICE", "10.0.0.1")
    # Another address is not locked out by these failures
    assert not throttle.blocked("alice", "10.0.0.2")


def test_throttle_locks_an_address_trying_many_usernames(clock):
    throttle = rate_limit.LoginThrottle(max_per_user=5, max_per_address=3, clock=clock)

    for name in ("a", "b", "c"):
        throttle.failed(name, "10.0.0.1")

    assert throttle.blocked("d", "10.0.0.1")


def test_throttle_forgets_old_failures_and_successes(clock):
    throttle = rate_limit.LoginThrottle(max_per_user=1, max_per_address=10, clock=clock)
    throttle.failed("alice", "10.0.0.1")
    assert throttle.blocked("alice", "10.0.0.1")
    clock.now += 2 * throttle.window
    assert not throttle.blocked("alice", "10.0.0.1")

    throttle.failed("alice", "10.0.0.1")
    throttle.succeeded("alice", "10.0.0.1")
    assert not throttle.blocked("alice", "10.0.0.1")


def test_throttle_is_shared_by_every_worker(clock):
    # Two controller processes (workers or replicas) count the same failures
    first = rate_limit.LoginThrottle(max_per_user=2, max_per_address=10, clock=clock)
    second = rate_limit.LoginThrottle(max_per_user=2, max_per_address=10, clock=clock)

    first.failed("alice", "10.0.0.1")
    second.failed("alice", "10.0.0.1")

    assert first.blocked("alice", "10.0.0.1") and second.blocked("alice", "10.0.0.1")


def test_neither_usernames_nor_addresses_are_stored(database, clock):
    rate_limit.LoginThrottle(clock=clock).failed("alice", "10.0.0.1")

    with Session(database) as session:
        keys = session.exec(select(RateLimitCounter.key)).all()
    assert len(keys) == 2
    assert all(len(key) == 64 and "alice" not in key and "10.0.0.1" not in key for key in keys)


# ── Sliding window ───────────────────────────────────────────────────────────


def test_the_previous_window_counts_less_and_less(clock):
    limit = rate_limit.RateLimit("test", 60, clock)
    clock.now = 600.0  # start of a window
    for _ in range(10):
        limit.hit("10.0.0.1")

    clock.now = 660.0 + 15  # a quarter of the next window
    assert limit.count("10.0.0.1") == pytest.approx(7.5)
    clock.now = 720.0  # two windows later: forgotten
    assert limit.count("10.0.0.1") == 0


def test_invalid_window_is_refused():
    with pytest.raises(ValueError, match="window"):
        rate_limit.RateLimit("test", 0)


def test_expired_counters_are_purged(database, clock):
    limit = rate_limit.RateLimit("test", 60, clock)
    limit.hit("old")
    clock.now += 3 * rate_limit.MAX_WINDOW_SECONDS
    rate_limit._last_purge = 0.0

    limit.hit("new")

    with Session(database) as session:
        assert len(session.exec(select(RateLimitCounter)).all()) == 1


def test_counters_are_purged_after_two_of_the_longest_windows(database, clock, monkeypatch):
    limit = rate_limit.RateLimit("test", 60, clock)
    monkeypatch.setattr(rate_limit, "_longest_window", 60)
    limit.hit("old")

    clock.now += 30  # the next window: "old" is still read as the previous one, kept
    rate_limit._last_purge = 0.0
    limit.hit("new")
    with Session(database) as session:
        assert len(session.exec(select(RateLimitCounter)).all()) == 2

    clock.now += 120  # older than two windows: purged, only the current one is left
    rate_limit._last_purge = 0.0
    limit.hit("new")
    with Session(database) as session:
        (row,) = session.exec(select(RateLimitCounter)).all()
    assert row.window_start == math.floor(clock.now / 60) * 60


def test_a_longer_window_keeps_its_counters(monkeypatch):
    monkeypatch.setattr(rate_limit, "_longest_window", 60)

    rate_limit.RateLimit("test", 900)

    assert rate_limit._longest_window == 900


# ── REST API limit ───────────────────────────────────────────────────────────


def ok(_request):
    return PlainTextResponse("ok")


def limited_client(clock: Clock, max_requests: int = 3, max_auth_requests: int = 1) -> TestClient:
    app = Starlette(
        routes=[
            Route("/api/v1/projects", ok),
            Route("/api/v1/auth/login", ok, methods=["POST"]),
            Route("/ui/main.js", ok),
        ]
    )
    middleware = rate_limit.RateLimitMiddleware(
        app,
        max_requests=max_requests,
        max_auth_requests=max_auth_requests,
        window=60,
        auth_prefix=http_server.AUTH_PREFIX,
        clock=clock,
    )
    return TestClient(middleware, base_url="http://127.0.0.1")


def test_api_requests_over_the_limit_are_refused(clock):
    client = limited_client(clock)

    assert [client.get("/api/v1/projects").status_code for _ in range(4)] == [200, 200, 200, 429]
    refused = client.get("/api/v1/projects")
    assert refused.headers["retry-after"] == "60"
    assert refused.json() == {"detail": "Too many requests: try again later"}
    # The files of the web interface are not counted
    assert client.get("/ui/main.js").status_code == 200
    # The next window opens again
    clock.now += 120
    assert client.get("/api/v1/projects").status_code == 200


def test_login_routes_have_a_stricter_limit(clock):
    client = limited_client(clock, max_requests=100, max_auth_requests=2)

    codes = [client.post("/api/v1/auth/login").status_code for _ in range(3)]

    assert codes == [200, 200, 429]
    assert client.get("/api/v1/projects").status_code == 200


def test_the_limit_is_shared_by_every_worker(clock):
    first, second = limited_client(clock, max_requests=2), limited_client(clock, max_requests=2)

    assert first.get("/api/v1/projects").status_code == 200
    assert second.get("/api/v1/projects").status_code == 200
    assert first.get("/api/v1/projects").status_code == 429


def test_the_controller_limits_requests_before_checking_the_token():
    # Guessing tokens is limited too: refused requests (401) count
    token_store.create_token("admin", "admin")
    settings = Settings(_env_file=None, rate_limit_max_requests=2)
    app = http_server.build_controller_app(ok, token_store.DatabaseTokenStore(), settings=settings)
    client = TestClient(app, base_url="http://127.0.0.1")
    headers = {"Authorization": "Bearer wrong-token"}

    codes = [client.get("/api/v1/me", headers=headers).status_code for _ in range(3)]

    assert codes == [401, 401, 429]


def test_the_limit_can_be_disabled():
    token_store.create_token("admin", "admin")
    settings = Settings(_env_file=None, rate_limit_enabled=False, rate_limit_max_requests=1)
    app = http_server.build_controller_app(ok, token_store.DatabaseTokenStore(), settings=settings)
    client = TestClient(app, base_url="http://127.0.0.1")

    assert [client.get("/api/v1/me").status_code for _ in range(3)] == [401, 401, 401]
