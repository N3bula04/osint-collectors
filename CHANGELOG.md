# Changelog

## 0.1.0 (2026-09-30)

First release. The collection code comes out of
[osint-pivot-tool](https://github.com/N3bula04/osint-pivot-tool) 0.3.2, so the
pivot tool and Domain Brand Alert can share one implementation.

- `cache`: JSON-file cache with TTL. Uses the same file layout as osint-pivot-tool's `.cache/`.
- `http`: `HttpClient`, which retries timeouts and HTTP 500/502/503/504 with capped exponential
  backoff. Connection errors are not retried. HTTP 429 raises `RateLimited`, carrying the parsed
  Retry-After, and is never retried. `record_backoff` / `backoff_until` store a back-off window
  in the cache.
- `dns`: `dns_query`, which falls back to TCP after a UDP timeout. Resolvers are pluggable.
- `ct`: `crtsh_fetch` and `parse_ct_entries`. crt.sh answers of HTTP 429 now start a stored
  back-off, and calls during that window return `skipped`. (In osint-pivot-tool 0.3.2, a 429
  was retried like a 5xx.)
- `rdap`: `rdap_fetch` tries rdap.org first, then falls back to the IANA bootstrap server.
  It also includes the jCard/entity/event helpers and `load_saved_rdap`. One retry on timeout or 5xx.
- `psl`: registrable-domain helpers based on tldextract's bundled Public Suffix List snapshot.
  These never touch the network. TLDs not on the list follow the PSL `*` rule, and there is a
  built-in fallback list if tldextract is missing.
- `offline`: `FixtureResolver`, `network_blocked()` and `offline_session()` for reproducible
  replays with the network blocked.
- Only successful answers (`ok`, `empty`, `nxdomain`) are cached. Timeouts, errors and skips
  are not.
- Tests use local fake HTTP servers and never touch the internet. CI runs on Python 3.9 and 3.12.
