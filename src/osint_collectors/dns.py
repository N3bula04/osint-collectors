"""DNS lookups through a recursive resolver (dnspython), with caching and a TCP retry."""

from typing import List, Optional, Tuple

import dns.exception
import dns.resolver

from . import CACHEABLE_STATUSES
from .cache import Cache

_RESOLVER_FACTORY = None


def set_resolver_factory(factory) -> None:
    """Replace the resolver: factory(nameserver, timeout) -> object with .resolve(). None restores dnspython."""
    global _RESOLVER_FACTORY
    _RESOLVER_FACTORY = factory


def make_resolver(nameserver: Optional[str] = None, timeout: float = 5.0):
    if _RESOLVER_FACTORY is not None:
        return _RESOLVER_FACTORY(nameserver, timeout)
    r = dns.resolver.Resolver()
    if nameserver:
        r.nameservers = [nameserver]
    r.timeout = timeout          # per-attempt
    r.lifetime = timeout * 2     # total for the query
    return r


def dns_query(resolver, cache: Cache, name: str, rtype: str) -> Tuple[str, List[str], str]:
    """Return (status, answers, detail). Never raises for DNS/network failures.

    status is one of: ok, empty, nxdomain, timeout, error.
    answers are the raw record strings as dnspython prints them.
    """
    key = f"{name.lower().rstrip('.')}:{rtype}"
    cached = cache.get("dns", key)
    if cached is not None:
        return cached["status"], cached["answers"], f"cached ({cached['fetched_at']})"

    result = None
    for use_tcp in (False, True):  # large TXT answers sometimes only arrive over TCP
        try:
            answer = resolver.resolve(name, rtype, tcp=use_tcp)
            answers = sorted(rr.to_text() for rr in answer)
            result = ("ok", answers, f"{len(answers)} record(s)" + (" (via TCP retry)" if use_tcp else ""))
            break
        except dns.resolver.NoAnswer:
            result = ("empty", [], "name exists but has no records of this type"); break
        except dns.resolver.NXDOMAIN:
            result = ("nxdomain", [], "name does not exist"); break
        except dns.resolver.NoNameservers:
            result = ("error", [], "no nameserver answered (SERVFAIL/REFUSED)"); break
        except dns.resolver.LifetimeTimeout:
            result = ("timeout", [], "query timed out (UDP and TCP)")
            continue
        except dns.exception.DNSException as e:  # catch-all for anything else in dnspython
            result = ("error", [], f"{type(e).__name__}: {e}"); break
        except OSError as e:  # e.g. network unreachable
            result = ("error", [], f"network error: {e}"); break

    status, answers, detail = result
    if status in CACHEABLE_STATUSES:
        cache.put("dns", key, {"status": status, "answers": answers, "rtype": rtype, "name": name})
    return status, answers, detail
