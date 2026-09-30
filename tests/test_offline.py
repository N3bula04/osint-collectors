import json
import pathlib
import socket

import dns.resolver
import pytest
import requests

from osint_collectors import clock
from osint_collectors import dns as odns
from osint_collectors.cache import Cache
from osint_collectors.ct import crtsh_fetch, is_expired, parse_ct_entries
from osint_collectors.offline import FixtureResolver, NetworkBlockedError, network_blocked, offline_session
from osint_collectors.rdap import entities_by_role, events, ip_block, load_saved_rdap, rdap_fetch, vcard

FIX = pathlib.Path(__file__).parent / "fixtures"
FIXED = "2026-09-30T00:00:00+00:00"


def test_fixture_resolver_semantics():
    r = FixtureResolver(json.loads((FIX / "dns.json").read_text()))
    assert [x.to_text() for x in r.resolve("FIXTURE.test.", "A")] == ["192.0.2.10", "192.0.2.11"]
    with pytest.raises(dns.resolver.NoAnswer):
        r.resolve("fixture.test", "AAAA")       # status empty
    with pytest.raises(dns.resolver.NoAnswer):
        r.resolve("fixture.test", "NS")         # name known, type missing
    with pytest.raises(dns.resolver.NXDOMAIN):
        r.resolve("gone.fixture.test", "A")     # status nxdomain
    with pytest.raises(dns.resolver.NXDOMAIN):
        r.resolve("unknown.test", "A")          # name unknown
    assert [x.to_text() for x in r.resolve("10.2.0.192.in-addr.arpa.", "PTR")] == ["web1.fixture.test."]


def test_full_replay_with_network_blocked(tmp_path):
    cache = Cache(tmp_path / "cache", enabled=False)
    with offline_session(FIX, fixed_time=FIXED) as resolver:
        res = odns.make_resolver(None, 5.0)
        assert res is resolver
        assert odns.dns_query(res, cache, "fixture.test", "A") == ("ok", ["192.0.2.10", "192.0.2.11"], "2 record(s)")
        assert odns.dns_query(res, cache, "fixture.test", "AAAA")[0] == "empty"
        assert odns.dns_query(res, cache, "gone.fixture.test", "A")[0] == "nxdomain"
        rev = str(dns.reversename.from_address("192.0.2.10"))
        assert odns.dns_query(res, cache, rev, "PTR")[1] == ["web1.fixture.test."]

        certs = parse_ct_entries(json.loads((FIX / "crtsh.json").read_text()), "fixture.test")
        assert certs[1001]["names"] == {"fixture.test", "shop.fixture.test"}
        assert not is_expired(certs[1001]) and is_expired(certs[1002])  # judged against the pinned clock

        status, dom, detail = load_saved_rdap(FIX / "rdap", "domain", "fixture.test")
        assert (status, detail) == ("ok", "loaded from domain_fixture.test.json (no network)")
        assert vcard(entities_by_role(dom)["registrar"][0])["fn"] == "Fixture Registrar"
        assert events(dom)["registration"] == "2020-02-02"
        assert ip_block(load_saved_rdap(FIX / "rdap", "ip", "192.0.2.10")[1]) == "192.0.2.0/24"
        assert clock.now_iso() == FIXED

        # Anything that would touch the network fails loudly instead of leaking.
        with pytest.raises(NetworkBlockedError):
            crtsh_fetch(cache, "fixture.test")
        with pytest.raises(NetworkBlockedError):
            rdap_fetch(cache, "domain", "fixture.test")
        with pytest.raises(NetworkBlockedError):
            requests.get("https://example.com/")
        with pytest.raises(NetworkBlockedError):
            socket.create_connection(("127.0.0.1", 9))
        with pytest.raises(NetworkBlockedError):
            socket.getaddrinfo("example.com", 443)
        with pytest.raises(NetworkBlockedError):
            socket.socket()

    # Everything is restored afterwards.
    assert clock.now_iso() != FIXED
    assert not isinstance(odns.make_resolver(None, 1.0), FixtureResolver)
    s = socket.socket()
    s.close()


def test_network_blocked_restores_on_exception():
    orig = (socket.socket, socket.getaddrinfo, requests.Session.request, requests.get)
    with pytest.raises(ZeroDivisionError):
        with network_blocked():
            1 / 0
    assert (socket.socket, socket.getaddrinfo, requests.Session.request, requests.get) == orig


def test_offline_session_accepts_dict():
    with offline_session({"a.test:A": {"status": "ok", "answers": ["192.0.2.1"]}}) as r:
        assert odns.dns_query(r, Cache(pathlib.Path("."), enabled=False), "a.test", "A")[1] == ["192.0.2.1"]
