from ipaddress import IPv4Address, IPv4Network

import pytest
from dns.resolver import NoResolverConfiguration

from osint_collectors.ct import crtsh_fetch, parse_ct_entries
from osint_collectors.dns import dns_query, make_resolver
from osint_collectors.http import HttpClient, RateLimited
from osint_collectors.rdap import rdap_fetch

pytestmark = pytest.mark.live

DOMAIN = "example.com"
USER_AGENT = "osint-collectors-live/0.1 (+https://github.com/N3bula04/osint-collectors)"
BENCHMARK_NETWORK = IPv4Network("198.18.0.0/15")


def require_records(provider, status, detail):
    if status in ("timeout", "error", "skipped"):
        pytest.skip(f"{provider} unavailable: {status}: {detail}")
    assert status == "ok", (
        f"{provider} expected records for {DOMAIN}, got {status}: {detail}. "
        "Check for a provider or API change."
    )


def test_live_crtsh(cache):
    status, entries, detail = crtsh_fetch(cache, DOMAIN, client=HttpClient(user_agent=USER_AGENT))
    require_records("crt.sh", status, detail)
    certs = parse_ct_entries(entries)
    assert certs, "crt.sh returned no parseable certificates"
    assert any(DOMAIN in cert["names"] for cert in certs.values())


def test_live_rdap(cache):
    try:
        status, record, detail = rdap_fetch(cache, "domain", DOMAIN, client=HttpClient(user_agent=USER_AGENT))
    except RateLimited as exc:
        pytest.skip(f"RDAP unavailable: {exc}")
    require_records("RDAP", status, detail)
    assert isinstance(record, dict), "RDAP response is not a JSON object"
    name = record.get("ldhName")
    assert isinstance(name, str) and name.lower() == DOMAIN


def test_live_dns_a(cache):
    try:
        resolver = make_resolver()
    except NoResolverConfiguration as exc:
        pytest.skip(f"DNS unavailable: {exc}")
    status, answers, detail = dns_query(resolver, cache, DOMAIN, "A")
    require_records("DNS A", status, detail)
    assert answers, f"DNS returned no A records for {DOMAIN}. Check for a provider or API change."
    addresses = [IPv4Address(answer) for answer in answers]
    if all(address in BENCHMARK_NETWORK for address in addresses):
        pytest.skip("DNS resolver appears to intercept queries (all A answers are in 198.18.0.0/15)")
