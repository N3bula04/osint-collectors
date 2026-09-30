import json

import pytest

from osint_collectors import clock
from osint_collectors.rdap import (RateLimited, entities_by_role, events, ip_block, load_saved_rdap,
                                   rdap_backoff_until, rdap_fetch, rdap_record_backoff, vcard)

DOMAIN = {"objectClassName": "domain", "ldhName": "example.com",
          "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
          "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                        "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                            ["email", {}, "text", "abuse@registrar.test"]]]}]}]}


def test_ok_cached(fake_server, cache, client):
    srv = fake_server(lambda path, n: (200, {"Content-Type": "application/rdap+json"}, DOMAIN))
    status, data, detail = rdap_fetch(cache, "domain", "example.com", client=client, redirector=srv.url)
    assert status == "ok" and data["ldhName"] == "example.com" and detail.startswith("HTTP 200 from 127.0.0.1")
    assert srv.requests[0]["path"] == "/domain/example.com"
    assert "rdap+json" in srv.requests[0]["headers"]["Accept"]
    assert rdap_fetch(cache, "domain", "example.com", client=client, redirector=srv.url)[2].startswith("cached")
    assert len(srv.requests) == 1


def test_404_is_empty_and_cached(fake_server, cache, client):
    srv = fake_server(lambda path, n: (404, {}, ""))
    status, data, detail = rdap_fetch(cache, "domain", "nx.test", client=client, redirector=srv.url)
    assert (status, data) == ("empty", None) and detail.startswith("HTTP 404")
    rdap_fetch(cache, "domain", "nx.test", client=client, redirector=srv.url)
    assert len(srv.requests) == 1


def test_5xx_falls_back_to_bootstrap_server(fake_server, cache, client, sleeps):
    auth = fake_server(lambda path, n: (200, {}, DOMAIN))
    boot = {"services": [[["com"], [auth.url]]]}

    def redirector(path, n):
        if path == "/dns.json":
            return 200, {}, boot
        return 502, {}, "bad gateway"
    red = fake_server(redirector)
    status, data, detail = rdap_fetch(cache, "domain", "example.com", client=client, redirector=red.url,
                                      bootstrap_urls={"domain": red.url + "dns.json"})
    assert status == "ok" and data["ldhName"] == "example.com"
    assert detail.startswith("rdap.org failed (HTTP 502 from ") and "bootstrap server: HTTP 200" in detail
    assert [r["path"] for r in red.requests] == ["/domain/example.com", "/domain/example.com", "/dns.json"]
    assert sleeps == [2.0]


def test_ip_bootstrap_lookup(fake_server, cache, client):
    auth = fake_server(lambda path, n: (200, {}, {"startAddress": "192.0.2.0", "endAddress": "192.0.2.255"}))
    boot = {"services": [[["192.0.2.0/24"], [auth.url]]]}
    red = fake_server(lambda path, n: (200, {}, boot) if path == "/ipv4.json" else (500, {}, ""))
    status, data, _ = rdap_fetch(cache, "ip", "192.0.2.10", client=client, redirector=red.url,
                                 bootstrap_urls={"ipv4": red.url + "ipv4.json"})
    assert status == "ok" and auth.requests[0]["path"] == "/ip/192.0.2.10"


def test_failure_without_bootstrap_not_cached(fake_server, cache, client):
    red = fake_server(lambda path, n: (500, {}, ""))
    status, _, detail = rdap_fetch(cache, "domain", "example.com", client=client, redirector=red.url,
                                   bootstrap_urls={"domain": red.url + "dns.json"})
    assert status == "error" and detail.endswith("IANA bootstrap lookup also unavailable")
    n = len(red.requests)
    rdap_fetch(cache, "domain", "example.com", client=client, redirector=red.url,
               bootstrap_urls={"domain": red.url + "dns.json"})
    assert len(red.requests) == 2 * n


def test_timeout_not_cached(fake_server, cache, client):
    red = fake_server(lambda path, n: (200, {}, DOMAIN, 1.0) if n <= 4 else (200, {}, DOMAIN))
    status, _, detail = rdap_fetch(cache, "domain", "example.com", timeout=0.2, client=client,
                                   redirector=red.url, bootstrap_urls={"domain": red.url + "dns.json"})
    assert status == "timeout" or status == "error"
    assert "no answer within 0s" in detail
    status, _, detail = rdap_fetch(cache, "domain", "example.com", timeout=5, client=client, redirector=red.url)
    assert status == "ok" and not detail.startswith("cached")


def test_429_raises_and_backoff_roundtrip(fake_server, cache, client):
    clock.set_fixed_time("2026-09-30T00:00:00+00:00")
    srv = fake_server(lambda path, n: (429, {"Retry-After": "30"}, ""))
    with pytest.raises(RateLimited) as ei:
        rdap_fetch(cache, "ip", "192.0.2.1", client=client, redirector=srv.url)
    assert ei.value.retry_after == 30 and len(srv.requests) == 1
    assert rdap_backoff_until(cache) is None
    until = rdap_record_backoff(cache, ei.value.retry_after)
    assert rdap_backoff_until(cache) == until


def test_json_helpers():
    roles = entities_by_role(DOMAIN)
    assert vcard(roles["registrar"][0]) == {"fn": "Example Registrar"}
    assert vcard(roles["abuse"][0]) == {"email": "abuse@registrar.test"}
    assert events(DOMAIN) == {"registration": "1995-08-14"}
    assert vcard({"vcardArray": "junk"}) == {}
    assert ip_block({"cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}]}) == "192.0.2.0/24"
    assert ip_block({"startAddress": "a", "endAddress": "b"}) == "a-b"


def test_load_saved_rdap(tmp_path):
    (tmp_path / "ip_2001-db8--1.json").write_text(json.dumps({"x": 1}))
    (tmp_path / "domain_bad.test.json").write_text("{nope")
    assert load_saved_rdap(tmp_path, "ip", "2001:db8::1") == ("ok", {"x": 1}, "loaded from ip_2001-db8--1.json (no network)")
    assert load_saved_rdap(tmp_path, "domain", "x.test") == ("empty", None, "no saved file domain_x.test.json in offline mode")
    assert load_saved_rdap(tmp_path, "domain", "bad.test")[0] == "error"
