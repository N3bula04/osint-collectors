# osint-collectors

A small Python library for collecting **public** internet infrastructure data:

- DNS records through a recursive resolver (dnspython)
- certificate transparency entries from [crt.sh](https://crt.sh/)
- registration data over RDAP (rdap.org, falling back to the IANA bootstrap servers)
- registrable-domain logic based on the Public Suffix List

It handles the parts every script like this ends up needing: a local JSON cache,
retries for flaky upstreams, honouring HTTP 429 / Retry-After, and an offline
replay mode that blocks the network so tests are reproducible.

## What this is (and isn't)

This is a personal project. I built it while learning threat-intelligence and
OSINT tooling, and it's part of my portfolio. It pulls shared code out of two of
my other projects, [osint-pivot-tool](https://github.com/N3bula04/osint-pivot-tool)
and Domain Brand Alert, so both use the same collectors.

- It **only collects and caches**. It doesn't rate, score or attribute anything.
  The tools that use it make those judgements.
- It queries free public services that have their own rate limits and terms.
  It's meant for small, occasional lookups by one person, not bulk scanning.
- It hasn't been audited, benchmarked at scale or used in production.
  Treat it as a well-tested hobby library, not a supported product.
- Coverage is limited to what's listed above. There's no passive DNS, no WHOIS
  over port 43 and no paid data sources.

## Install

It isn't on PyPI. Install it from a tag:

```bash
pip install "osint-collectors @ git+https://github.com/N3bula04/osint-collectors@v0.1.0"
```

For development:

```bash
git clone https://github.com/N3bula04/osint-collectors
cd osint-collectors
python -m pip install -e ".[test]"
python -m pytest -q
```

Requires Python 3.9+. Dependencies: `dnspython`, `requests`, `tldextract`.

## Usage

```python
from osint_collectors.cache import Cache
from osint_collectors.http import HttpClient
from osint_collectors.dns import make_resolver, dns_query
from osint_collectors.ct import crtsh_fetch, parse_ct_entries
from osint_collectors.rdap import rdap_fetch, RateLimited, rdap_record_backoff
from osint_collectors.psl import registrable_domain

cache = Cache(".cache")                      # one JSON file per query, 24h TTL
client = HttpClient(user_agent="my-tool/1.0 (+contact URL)")

status, answers, detail = dns_query(make_resolver(), cache, "example.com", "MX")

status, entries, detail = crtsh_fetch(cache, "example.com", client=client)
certs = parse_ct_entries(entries)            # {cert_id: {issuer, not_before, not_after, names}}

try:
    status, data, detail = rdap_fetch(cache, "domain", "example.com", client=client)
except RateLimited as e:                     # stop RDAP for this run and remember the window
    rdap_record_backoff(cache, e.retry_after)

registrable_domain("mail.example.co.uk")     # 'example.co.uk'
```

Every fetch returns `(status, data, detail)`. `status` is one of `ok`, `empty`,
`nxdomain`, `timeout`, `error` or `skipped`. `detail` is a short human-readable
explanation meant for reports. Only `ok`, `empty` and `nxdomain` are cached, so
a transient failure never sticks around.

### Rate limits

- 5xx responses and timeouts are retried with capped exponential backoff
  (crt.sh: 3 attempts, RDAP: 2). Connection errors are not retried.
- HTTP 429 is **not** retried. `HttpClient` raises `RateLimited` with the
  parsed `Retry-After` (seconds or HTTP date; 600 s if missing). `crtsh_fetch`
  saves the back-off and returns `skipped` until it ends. `rdap_fetch`
  re-raises, so the caller can stop every RDAP lookup for the run.
- Pauses between requests (for example 2 s between crt.sh queries) are up to
  the caller.

### Async callers

The library is synchronous (`requests`). From an async app such as FastAPI,
run it in a worker thread, e.g. `await asyncio.to_thread(crtsh_fetch, ...)`
or `run_in_threadpool`.

### Offline replay

```python
from osint_collectors.offline import offline_session

with offline_session("fixtures/", fixed_time="2026-09-30T00:00:00+00:00"):
    ...   # DNS comes from fixtures/dns.json; any socket/requests use raises NetworkBlockedError
```

`dns.json` maps `"name:RTYPE"` to `{"status": "ok"|"empty"|"nxdomain", "answers": [...]}`.
PTR keys use the IP address (`"192.0.2.10:PTR"`). Use `ct.parse_ct_entries` for saved
crt.sh JSON and `rdap.load_saved_rdap` for saved RDAP files.

## Tests

`python -m pytest -q` needs no internet access. HTTP behaviour (429 and
Retry-After, 5xx retries, timeouts not being cached, the bootstrap fallback) is
tested against local fake servers on 127.0.0.1. The offline tests replay
fictional `.test` / RFC 5737 fixtures with the network blocked. CI runs on
Python 3.9 and 3.12.

## Responsible use

Only query infrastructure you have a legitimate reason to look at, keep request
volumes low, and respect each service's terms. The data is public, but what you
conclude from it is your own responsibility.

## Licence

MIT. See [LICENSE](LICENSE).
