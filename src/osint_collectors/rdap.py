"""RDAP: rdap.org first, IANA bootstrap fallback; cached, retried on 5xx, 429-aware."""

import ipaddress
import json
import pathlib
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from . import CACHEABLE_STATUSES
from .cache import Cache
from .http import HttpClient, RateLimited, backoff_until, host_of, record_backoff

RDAP_REDIRECTOR = "https://rdap.org/"
IANA_BOOTSTRAP = {"domain": "https://data.iana.org/rdap/dns.json",
                  "ipv4": "https://data.iana.org/rdap/ipv4.json",
                  "ipv6": "https://data.iana.org/rdap/ipv6.json"}
RDAP_ATTEMPTS = 2  # one retry on timeouts / 5xx
_ACCEPT = {"Accept": "application/rdap+json, application/json"}

__all__ = ["RateLimited", "rdap_get", "rdap_fetch", "bootstrap_server", "rdap_backoff_until",
           "rdap_record_backoff", "vcard", "entities_by_role", "events", "ip_block", "load_saved_rdap"]


def rdap_get(client: HttpClient, url: str, timeout: float) -> Tuple[str, Optional[dict], str]:
    """One RDAP GET. Returns (status, json_or_None, detail). Raises RateLimited on 429."""
    out = client.get(url, headers=_ACCEPT, timeout=timeout, attempts=RDAP_ATTEMPTS)
    if out.kind != "response":
        return out.kind, None, out.detail
    resp = out.response
    if resp.status_code == 200:
        try:
            return "ok", resp.json(), f"HTTP 200 from {host_of(resp.url)}"
        except ValueError:
            return "error", None, "HTTP 200 but body was not JSON"
    if resp.status_code == 404:
        return "empty", None, "HTTP 404: no RDAP record (unregistered, or registry has no RDAP)"
    return "error", None, f"HTTP {resp.status_code} from {host_of(resp.url)}"


def bootstrap_server(cache: Cache, kind: str, target: str, timeout: float, client: HttpClient,
                     bootstrap_urls: Dict[str, str] = IANA_BOOTSTRAP) -> Optional[str]:
    """Look up the authoritative RDAP base URL from IANA's bootstrap files (kind: domain/ipv4/ipv6)."""
    cached = cache.get("rdap", f"bootstrap:{kind}")
    data = cached["data"] if cached else None
    if data is None:
        status, data, _ = rdap_get(client, bootstrap_urls[kind], timeout)
        if status != "ok" or not isinstance(data, dict):
            return None
        cache.put("rdap", f"bootstrap:{kind}", {"status": "ok", "data": data})
    try:
        for entry in data.get("services", []):
            keys, urls = entry[0], entry[1]
            if kind == "domain":
                if target.rsplit(".", 1)[-1].lower() in [k.lower() for k in keys]:
                    return urls[0]
            else:
                addr = ipaddress.ip_address(target)
                if any(addr in ipaddress.ip_network(k, strict=False) for k in keys):
                    return urls[0]
    except (ValueError, IndexError, TypeError):
        return None
    return None


def rdap_fetch(cache: Cache, kind: str, target: str, timeout: float = 30.0, client: Optional[HttpClient] = None,
               redirector: str = RDAP_REDIRECTOR,
               bootstrap_urls: Dict[str, str] = IANA_BOOTSTRAP) -> Tuple[str, Optional[dict], str]:
    """Fetch an RDAP object (kind 'domain' or 'ip'). Tries rdap.org, then the IANA bootstrap server.

    Raises RateLimited on HTTP 429 so the caller can stop all further RDAP
    requests for the run (see rdap_record_backoff); never raises anything else.
    """
    key = f"{kind}:{target}"
    cached = cache.get("rdap", key)
    if cached is not None:
        return cached["status"], cached.get("data"), f"cached ({cached['fetched_at']})"

    client = client or HttpClient()
    status, data, detail = rdap_get(client, f"{redirector}{kind}/{target}", timeout)
    if status not in ("ok", "empty"):
        bkind = "domain" if kind == "domain" else ("ipv6" if ":" in target else "ipv4")
        base = bootstrap_server(cache, bkind, target, timeout, client, bootstrap_urls)
        if base:
            status2, data2, detail2 = rdap_get(client, f"{base.rstrip('/')}/{kind}/{target}", timeout)
            detail = f"rdap.org failed ({detail}); bootstrap server: {detail2}"
            status, data = status2, data2
        else:
            detail = f"rdap.org failed ({detail}); IANA bootstrap lookup also unavailable"
    if status in CACHEABLE_STATUSES:
        cache.put("rdap", key, {"status": status, "data": data})
    return status, data, detail


def rdap_backoff_until(cache: Cache):
    return backoff_until(cache, "rdap")


def rdap_record_backoff(cache: Cache, seconds: int):
    return record_backoff(cache, "rdap", seconds)


# --- RDAP JSON helpers (defensive: registries differ a lot) -----------------

def vcard(entity: dict) -> Dict[str, str]:
    """Flatten a jCard into {fn, org, email, country}."""
    out: Dict[str, str] = {}
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            name, _, _, value = item[0], item[1], item[2], item[3]
            if name in ("fn", "org", "email") and isinstance(value, str) and value.strip():
                out.setdefault(name, value.strip())
            elif name == "adr":
                if isinstance(value, list) and len(value) >= 7 and value[6]:
                    out.setdefault("country", str(value[6]))
                label = item[1].get("cc") if isinstance(item[1], dict) else None
                if label:
                    out.setdefault("country", label)
    except (IndexError, TypeError, AttributeError):
        pass
    return out


def entities_by_role(obj: dict) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = defaultdict(list)
    for ent in obj.get("entities", []) or []:
        for role in ent.get("roles", []) or []:
            out[role].append(ent)
        for sub in ent.get("entities", []) or []:     # nested (registrar -> abuse contact etc.)
            for role in sub.get("roles", []) or []:
                out[role].append(sub)
    return out


def events(obj: dict) -> Dict[str, str]:
    return {e.get("eventAction", ""): (e.get("eventDate") or "")[:10] for e in obj.get("events", []) or []}


def ip_block(obj: dict) -> str:
    """Best-effort CIDR (or start-end) for an ip network object."""
    parts = []
    for c in obj.get("cidr0_cidrs") or []:
        pfx = c.get("v4prefix") or c.get("v6prefix")
        if pfx and "length" in c:
            parts.append(f"{pfx}/{c['length']}")
    if parts:
        return ", ".join(parts)
    return f"{obj.get('startAddress', '?')}-{obj.get('endAddress', '?')}"


def load_saved_rdap(rdap_dir: pathlib.Path, kind: str, target: str) -> Tuple[str, Optional[dict], str]:
    """Read DIR/<kind>_<target>.json (colons in IPv6 replaced by '-', since Windows forbids them)."""
    p = pathlib.Path(rdap_dir) / f"{kind}_{target.replace(':', '-')}.json"
    if not p.exists():
        return "empty", None, f"no saved file {p.name} in offline mode"
    try:
        return "ok", json.loads(p.read_text(encoding="utf-8")), f"loaded from {p.name} (no network)"
    except (OSError, ValueError) as e:
        return "error", None, f"could not read {p.name}: {e}"
