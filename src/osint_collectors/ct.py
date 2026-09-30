"""Certificate transparency via crt.sh: fetch (cached, retried, 429-aware) and parse."""

import re
from typing import Dict, Optional, Set, Tuple

from . import CACHEABLE_STATUSES, clock
from .cache import Cache
from .http import RETRY_STATUSES, HttpClient, RateLimited, backoff_until, record_backoff

CRTSH_URL = "https://crt.sh/"
CRTSH_PAUSE_SECONDS = 2.0  # polite gap between consecutive crt.sh requests (callers apply it)
CRTSH_ATTEMPTS = 3         # crt.sh returns 502/503 fairly often; retry with backoff

# Names CDNs put on their own shared certificates; they are not customer domains.
CDN_PLACEHOLDERS = ("cloudflaressl.com", "sni.cloudflaressl.com", "fastly.net", "akamaized.net",
                    "cloudfront.net", "azureedge.net", "incapdns.net", "sucuri.net")


def crtsh_fetch(cache: Cache, query: str, timeout: float = 60.0, client: Optional[HttpClient] = None,
                base_url: str = CRTSH_URL, attempts: int = CRTSH_ATTEMPTS) -> Tuple[str, list, str]:
    """Fetch crt.sh JSON for one identity query. Returns (status, entries, detail).

    status: ok / empty / timeout / error / skipped (a previous 429 back-off is
    still running). On HTTP 429 the Retry-After window is stored in the cache.
    """
    cached = cache.get("crtsh", query)
    if cached is not None:
        return cached["status"], cached["entries"], f"cached ({cached['fetched_at']})"
    until = backoff_until(cache, "crtsh")
    if until is not None:
        return "skipped", [], f"skipped: crt.sh rate-limited earlier; backing off until {until.isoformat()}"

    client = client or HttpClient()
    try:
        out = client.get(base_url, params={"q": query, "output": "json"},
                         headers={"Accept": "application/json"}, timeout=timeout, attempts=attempts)
    except RateLimited as e:
        until = record_backoff(cache, "crtsh", e.retry_after)
        return "error", [], f"crt.sh {e.detail}; backing off until {until.isoformat()}"

    if out.kind == "timeout":
        status, entries, detail = "timeout", [], f"crt.sh did not answer within {timeout:.0f}s (attempt {out.attempts})"
    elif out.kind == "error":
        status, entries, detail = "error", [], out.detail
    elif out.response.status_code == 200:
        try:
            entries = out.response.json()
        except ValueError:
            return "error", [], "crt.sh returned HTTP 200 but the body was not JSON"
        if not isinstance(entries, list):
            entries = []
        status = "ok" if entries else "empty"
        detail = f"{len(entries)} certificate entries" if entries else "no certificates found"
    else:
        code = out.response.status_code
        status, entries = "error", []
        retryable = code in RETRY_STATUSES
        detail = f"crt.sh HTTP {code}" + (f" (attempt {out.attempts})" if retryable else "")

    if status in CACHEABLE_STATUSES:
        cache.put("crtsh", query, {"status": status, "entries": entries})
    return status, entries, detail


def cert_names(entry: dict) -> Set[str]:
    """All DNS names on a crt.sh entry, lower-cased, wildcards stripped, emails dropped."""
    raw = set((entry.get("name_value") or "").split("\n"))
    raw.add(entry.get("common_name") or "")
    names = set()
    for n in raw:
        n = n.strip().lower().rstrip(".")
        if not n or "@" in n or " " in n:
            continue
        if n.startswith("*."):
            n = n[2:]
        names.add(n)
    return names


def is_cdn_placeholder(name: str) -> bool:
    return any(name == p or name.endswith("." + p) for p in CDN_PLACEHOLDERS)


def issuer_short(issuer: str) -> str:
    m = re.search(r"CN=([^,]+)", issuer or "")
    return m.group(1).strip() if m else (issuer or "unknown issuer")[:60]


def parse_ct_entries(entries: list, seed: str = "") -> Dict[int, dict]:
    """Collapse raw crt.sh rows into one record per certificate id."""
    certs: Dict[int, dict] = {}
    for e in entries:
        try:
            cid = int(e.get("id"))
        except (TypeError, ValueError, AttributeError):
            continue
        if cid in certs:
            certs[cid]["names"] |= cert_names(e)
            continue
        certs[cid] = {
            "id": cid,
            "issuer": issuer_short(e.get("issuer_name", "")),
            "not_before": (e.get("not_before") or "")[:10],
            "not_after": (e.get("not_after") or "")[:10],
            "names": cert_names(e),
        }
    return certs


def is_expired(cert: dict) -> bool:
    return bool(cert.get("not_after")) and cert["not_after"] < clock.today().isoformat()
