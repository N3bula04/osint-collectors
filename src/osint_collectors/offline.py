"""Offline replay: fixture-backed DNS, a network guard and a pinned clock.

While `offline_session()` is active, every common network entry point
(sockets, name resolution, requests) raises NetworkBlockedError, so an
accidental network call fails loudly instead of leaking traffic.

DNS fixtures: {"name:RTYPE": {"status": "ok"|"empty"|"nxdomain", "answers": [...]}}.
PTR keys use the IP address ("192.0.2.10:PTR"). Unknown names answer NXDOMAIN;
a known name without the requested type answers NoAnswer.
"""

import contextlib
import json
import pathlib
import socket
from typing import Dict, Iterator, List, Optional, Union

import dns.name
import dns.resolver
import dns.reversename
import requests

from . import clock
from . import dns as _dns


class NetworkBlockedError(RuntimeError):
    """Raised when anything tries to use the network during an offline session."""


class _Rdata:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


class FixtureResolver:
    """Drop-in for dns.resolver.Resolver.resolve(), backed by a dict."""

    def __init__(self, records: Dict[str, dict]):
        self.records = {k.lower(): v for k, v in records.items()}
        self.names = {k.rsplit(":", 1)[0] for k in self.records}
        self.queries: List[str] = []

    def resolve(self, name, rtype, tcp: bool = False, **_kw):
        name = str(name).lower().rstrip(".")
        if rtype == "PTR" and name.endswith((".in-addr.arpa", ".ip6.arpa")):
            name = str(dns.reversename.to_address(dns.name.from_text(name)))
        key = f"{name}:{rtype}".lower()
        self.queries.append(key)
        entry = self.records.get(key)
        if entry is None:
            if name in self.names:
                raise dns.resolver.NoAnswer()
            raise dns.resolver.NXDOMAIN()
        status = entry.get("status", "ok")
        if status == "nxdomain":
            raise dns.resolver.NXDOMAIN()
        if status == "empty" or not entry.get("answers"):
            raise dns.resolver.NoAnswer()
        return [_Rdata(a) for a in entry["answers"]]


def load_dns_fixtures(path: Union[str, pathlib.Path]) -> Dict[str, dict]:
    """Read dns.json from a directory (or the file itself)."""
    p = pathlib.Path(path)
    if p.is_dir():
        p = p / "dns.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _blocked(*_a, **_kw):
    raise NetworkBlockedError("network access attempted during an offline run")


class _BlockedSocket(socket.socket):
    def __init__(self, *a, **kw):
        _blocked()


@contextlib.contextmanager
def network_blocked() -> Iterator[None]:
    """Make sockets, name resolution and requests raise NetworkBlockedError."""
    saved = (socket.socket, socket.create_connection, socket.getaddrinfo, socket.gethostbyname,
             requests.Session.request, requests.get)
    socket.socket = _BlockedSocket
    socket.create_connection = _blocked
    socket.getaddrinfo = _blocked
    socket.gethostbyname = _blocked
    requests.Session.request = _blocked
    requests.get = _blocked
    try:
        yield
    finally:
        (socket.socket, socket.create_connection, socket.getaddrinfo, socket.gethostbyname,
         requests.Session.request, requests.get) = saved


@contextlib.contextmanager
def offline_session(dns_records: Union[Dict[str, dict], str, pathlib.Path],
                    fixed_time: Optional[str] = None) -> Iterator[FixtureResolver]:
    """Activate fixture DNS, the network guard and (optionally) a pinned clock; restore all on exit.

    dns_records is a dict in dns.json format, or a directory containing dns.json.
    """
    if not isinstance(dns_records, dict):
        dns_records = load_dns_fixtures(dns_records)
    resolver = FixtureResolver(dns_records)
    _dns.set_resolver_factory(lambda nameserver, timeout: resolver)
    if fixed_time:
        clock.set_fixed_time(fixed_time)
    try:
        with network_blocked():
            yield resolver
    finally:
        _dns.set_resolver_factory(None)
        clock.set_fixed_time(None)
