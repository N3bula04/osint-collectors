import datetime as dt

import pytest

from osint_collectors import clock
from osint_collectors.http import (DEFAULT_BACKOFF_SECONDS, HttpClient, RateLimited, backoff_until,
                                   host_of, parse_retry_after, record_backoff)


def test_parse_retry_after_seconds_date_and_garbage():
    clock.set_fixed_time("2026-09-30T00:00:00+00:00")
    assert parse_retry_after("120") == 120
    assert parse_retry_after(" 7 ") == 7
    assert parse_retry_after("Wed, 30 Sep 2026 00:05:00 GMT") == 300
    assert parse_retry_after("Tue, 29 Sep 2026 00:00:00 GMT") == 0  # past date -> 0
    assert parse_retry_after(None) == DEFAULT_BACKOFF_SECONDS
    assert parse_retry_after("soon") == DEFAULT_BACKOFF_SECONDS


def test_host_of():
    assert host_of("https://rdap.org/domain/x.com") == "rdap.org"
    assert host_of("nonsense") == "nonsense"


def test_user_agent_is_sent(fake_server, client):
    srv = fake_server(lambda path, n: (200, {}, {"ok": True}))
    out = client.get(srv.url)
    assert out.kind == "response" and out.response.status_code == 200
    assert srv.requests[0]["headers"]["User-Agent"] == "osint-collectors-tests/0"


def test_429_raises_with_retry_after_and_is_not_retried(fake_server, client, sleeps):
    srv = fake_server(lambda path, n: (429, {"Retry-After": "90"}, "slow down"))
    with pytest.raises(RateLimited) as ei:
        client.get(srv.url, attempts=3)
    assert ei.value.retry_after == 90
    assert ei.value.host == srv.url.split("/")[2]
    assert "HTTP 429 rate limited by" in ei.value.detail and "Retry-After: 90" in ei.value.detail
    assert len(srv.requests) == 1 and sleeps == []


def test_429_without_retry_after_uses_default(fake_server, client):
    srv = fake_server(lambda path, n: (429, {}, ""))
    with pytest.raises(RateLimited) as ei:
        client.get(srv.url)
    assert ei.value.retry_after == DEFAULT_BACKOFF_SECONDS
    assert "Retry-After: not given" in ei.value.detail


def test_5xx_is_retried_then_succeeds(fake_server, client, sleeps):
    srv = fake_server(lambda path, n: (503, {}, "busy") if n < 3 else (200, {}, [1]))
    out = client.get(srv.url, attempts=3)
    assert out.kind == "response" and out.response.status_code == 200 and out.attempts == 3
    assert len(srv.requests) == 3
    assert sleeps == [2.0, 4.0]


def test_5xx_gives_up_after_attempts(fake_server, client, sleeps):
    srv = fake_server(lambda path, n: (502, {}, "bad gateway"))
    out = client.get(srv.url, attempts=2)
    assert out.kind == "response" and out.response.status_code == 502 and out.attempts == 2
    assert len(srv.requests) == 2 and sleeps == [2.0]


def test_4xx_is_not_retried(fake_server, client, sleeps):
    srv = fake_server(lambda path, n: (404, {}, "nope"))
    out = client.get(srv.url, attempts=3)
    assert out.response.status_code == 404 and len(srv.requests) == 1 and sleeps == []


def test_timeout_is_reported_and_retried(fake_server, client, sleeps):
    srv = fake_server(lambda path, n: (200, {}, [], 1.0))
    out = client.get(srv.url, timeout=0.2, attempts=2)
    assert out.kind == "timeout" and out.attempts == 2
    assert out.detail == "no answer within 0s"
    assert sleeps == [2.0]


def test_connection_error_is_not_retried(sleeps):
    # Port 9 on localhost with nothing listening -> connection refused.
    c = HttpClient(sleep=sleeps.append)
    out = c.get("http://127.0.0.1:9/", timeout=2, attempts=3)
    assert out.kind == "error" and out.detail.startswith("network error: ConnectionError")
    assert out.attempts == 1 and sleeps == []


def test_backoff_is_persisted_and_expires(cache):
    clock.set_fixed_time("2026-09-30T00:00:00+00:00")
    assert backoff_until(cache, "svc") is None
    until = record_backoff(cache, "svc", 60)
    assert until == dt.datetime(2026, 9, 30, 0, 1, tzinfo=dt.timezone.utc)
    assert backoff_until(cache, "svc") == until
    assert backoff_until(cache, "other") is None
    clock.set_fixed_time("2026-09-30T00:02:00+00:00")
    assert backoff_until(cache, "svc") is None


def test_backoff_ignores_refresh_flag(tmp_path):
    from osint_collectors.cache import Cache
    clock.set_fixed_time("2026-09-30T00:00:00+00:00")
    record_backoff(Cache(tmp_path), "svc", 60)
    assert backoff_until(Cache(tmp_path, refresh=True), "svc") is not None
    assert backoff_until(Cache(tmp_path, enabled=False), "svc") is None
