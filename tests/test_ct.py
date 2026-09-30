from osint_collectors import clock
from osint_collectors.ct import crtsh_fetch, is_cdn_placeholder, issuer_short, parse_ct_entries
from osint_collectors.http import backoff_until

ENTRY = {"id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "example.com",
         "name_value": "example.com\n*.example.com\nadmin@example.com", "not_before": "2026-01-01T00:00:00",
         "not_after": "2026-04-01T00:00:00"}


def test_ok_is_cached_and_sends_query(fake_server, cache, client):
    srv = fake_server(lambda path, n: (200, {}, [ENTRY]))
    status, entries, detail = crtsh_fetch(cache, "%.example.com", client=client, base_url=srv.url)
    assert (status, detail) == ("ok", "1 certificate entries") and entries == [ENTRY]
    assert "q=%25.example.com" in srv.requests[0]["path"] and "output=json" in srv.requests[0]["path"]
    status2, entries2, detail2 = crtsh_fetch(cache, "%.example.com", client=client, base_url=srv.url)
    assert status2 == "ok" and entries2 == [ENTRY] and detail2.startswith("cached (")
    assert len(srv.requests) == 1


def test_empty_is_cached(fake_server, cache, client):
    srv = fake_server(lambda path, n: (200, {}, []))
    assert crtsh_fetch(cache, "q", client=client, base_url=srv.url)[::2] == ("empty", "no certificates found")
    crtsh_fetch(cache, "q", client=client, base_url=srv.url)
    assert len(srv.requests) == 1


def test_timeout_is_not_cached(fake_server, cache, client):
    srv = fake_server(lambda path, n: (200, {}, [ENTRY], 1.0) if n <= 2 else (200, {}, [ENTRY]))
    status, _, detail = crtsh_fetch(cache, "q", timeout=0.2, client=client, base_url=srv.url, attempts=2)
    assert status == "timeout" and detail == "crt.sh did not answer within 0s (attempt 2)"
    status, _, detail = crtsh_fetch(cache, "q", timeout=5, client=client, base_url=srv.url, attempts=1)
    assert status == "ok" and not detail.startswith("cached")


def test_5xx_retried_then_error_not_cached(fake_server, cache, client, sleeps):
    srv = fake_server(lambda path, n: (503, {}, "busy"))
    status, _, detail = crtsh_fetch(cache, "q", client=client, base_url=srv.url)
    assert status == "error" and detail == "crt.sh HTTP 503 (attempt 3)"
    assert len(srv.requests) == 3 and sleeps == [2.0, 4.0]
    crtsh_fetch(cache, "q", client=client, base_url=srv.url)
    assert len(srv.requests) == 6  # error was not cached


def test_other_status_not_retried(fake_server, cache, client):
    srv = fake_server(lambda path, n: (400, {}, "bad"))
    assert crtsh_fetch(cache, "q", client=client, base_url=srv.url)[::2] == ("error", "crt.sh HTTP 400")
    assert len(srv.requests) == 1


def test_non_json_body(fake_server, cache, client):
    srv = fake_server(lambda path, n: (200, {}, "<html>"))
    assert crtsh_fetch(cache, "q", client=client, base_url=srv.url)[::2] == (
        "error", "crt.sh returned HTTP 200 but the body was not JSON")


def test_429_records_backoff_and_later_calls_skip(fake_server, cache, client, sleeps):
    clock.set_fixed_time("2026-09-30T00:00:00+00:00")
    srv = fake_server(lambda path, n: (429, {"Retry-After": "120"}, ""))
    status, _, detail = crtsh_fetch(cache, "q", client=client, base_url=srv.url)
    assert status == "error" and "HTTP 429" in detail and "2026-09-30T00:02:00+00:00" in detail
    assert len(srv.requests) == 1 and sleeps == []
    assert backoff_until(cache, "crtsh") is not None
    status, _, detail = crtsh_fetch(cache, "other", client=client, base_url=srv.url)
    assert status == "skipped" and len(srv.requests) == 1
    clock.set_fixed_time("2026-09-30T00:03:00+00:00")
    crtsh_fetch(cache, "other", client=client, base_url=srv.url)
    assert len(srv.requests) == 2


def test_parse_ct_entries_merges_and_cleans():
    rows = [ENTRY, dict(ENTRY, name_value="www.example.com"), {"id": "x"}, dict(ENTRY, id=2, issuer_name="odd")]
    certs = parse_ct_entries(rows, "example.com")
    assert sorted(certs) == [1, 2]
    assert certs[1]["names"] == {"example.com", "www.example.com"}
    assert certs[1]["issuer"] == "R11" and certs[1]["not_after"] == "2026-04-01"
    assert certs[2]["issuer"] == "odd"


def test_cdn_placeholder_and_issuer():
    assert is_cdn_placeholder("sni.cloudflaressl.com") and is_cdn_placeholder("a.b.fastly.net")
    assert not is_cdn_placeholder("notfastly.net")
    assert issuer_short("") == "unknown issuer"
