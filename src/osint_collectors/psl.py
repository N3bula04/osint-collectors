"""Registrable-domain helpers on the Public Suffix List (tldextract's bundled snapshot).

No network fetch and no cache writes. TLDs not on the list (.test, .internal)
follow the PSL default rule "*" (one-label suffix). If tldextract is missing,
a small built-in two-level suffix list is used instead.
"""

import ipaddress
from typing import Tuple

try:
    import tldextract as _tldextract
    _PSL = _tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True)
except Exception:  # ImportError, or an unexpected packaging problem
    _PSL = None

# Offline fallback only. Not exhaustive.
FALLBACK_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "co.in", "net.in", "org.in", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx", "com.ar", "com.cn", "com.hk", "com.tr",
    "com.sg", "gov.sg", "edu.sg", "org.sg", "net.sg", "per.sg",
    "co.il", "co.kr", "com.tw", "com.my", "gov.my", "com.ph", "com.pk", "com.ng",
    "org.br", "net.br", "gov.br", "gov.in", "gov.cn", "gov.hk", "gov.za",
}


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def split_registrable(hostname: str) -> Tuple[str, str]:
    """Return (label, suffix) for the registrable part, e.g. ('moh', 'gov.sg').

    Either part may be empty for IPs, bare suffixes or single-label names.
    """
    h = hostname.lower().strip().rstrip(".")
    if not h or is_ip(h):
        return "", ""
    if _PSL is not None:
        r = _PSL(h)
        if r.suffix:
            return r.domain, r.suffix
        # Not on the PSL: the default rule "*" makes the TLD a one-label suffix.
    parts = h.split(".")
    if _PSL is not None:
        return (parts[-2], parts[-1]) if len(parts) >= 2 else ("", "")
    if len(parts) >= 3 and ".".join(parts[-2:]) in FALLBACK_TWO_LEVEL_SUFFIXES:
        return parts[-3], ".".join(parts[-2:])
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return "", ""


def registrable_domain(hostname: str) -> str:
    """mail.example.co.uk -> example.co.uk. IPs, bare suffixes and single labels come back unchanged."""
    h = hostname.lower().strip().rstrip(".")
    label, suffix = split_registrable(h)
    return f"{label}.{suffix}" if label and suffix else h


def registrable_label(hostname: str) -> str:
    """The name part of the registrable domain: 'moh' for www.moh.gov.sg."""
    return split_registrable(hostname)[0]


def same_owner(host_a: str, host_b: str) -> bool:
    return registrable_domain(host_a) == registrable_domain(host_b)


def host_in_domain(hostname: str, domain: str) -> bool:
    """True if hostname is `domain` or a name under it (label-boundary suffix match)."""
    h = hostname.lower().strip().rstrip(".")
    d = domain.lower().strip().rstrip(".")
    return bool(d) and (h == d or h.endswith("." + d))


_is_ip = is_ip                        # back-compat aliases (osint-pivot-tool <= 0.3.2 names)
_split_registrable = split_registrable
