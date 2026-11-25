import dns.resolver
import pytest

from osint_collectors import clock
from osint_collectors.cache import Cache
from osint_collectors.dns import dns_query
from osint_collectors.util import truncate


class Flaky:
    """Resolver that times out on UDP and answers over TCP, or always raises `exc`."""

    def __init__(self, exc=None):
        self.exc = exc
        self.calls = []

    def resolve(self, name, rtype, tcp=False):
        self.calls.append(tcp)
        if self.exc:
            raise self.exc
        if not tcp:
            raise dns.resolver.LifetimeTimeout(timeout=1.0, errors=[])

        class R:
            def to_text(self):
                return "192.0.2.1"
        return [R()]


def test_cache_roundtrip_and_ttl(tmp_path):
    clock.set_fixed_time("2026-09-30T00:00:00+00:00")
    c = Cache(tmp_path, ttl_hours=1)
    assert c.get("ns", "k") is None
    c.put("ns", "k", {"status": "ok", "v": 1})
    got = c.get("ns", "k")
    assert got["v"] == 1 and got["fetched_at"] == "2026-09-30T00:00:00+00:00" and got["query"] == "k"
    assert Cache(tmp_path, refresh=True).get("ns", "k") is None
    clock.set_fixed_time("2026-09-30T02:00:00+00:00")
    assert c.get("ns", "k") is None  # expired


def test_cache_disabled_writes_nothing(tmp_path):
    c = Cache(tmp_path / "off", enabled=False)
    c.put("ns", "k", {"status": "ok"})
    assert c.get("ns", "k") is None and not (tmp_path / "off").exists()


def test_cache_key_is_filesystem_safe(tmp_path):
    p = Cache(tmp_path).path_for("crtsh", "%.example.com/../x?")
    assert p.parent == tmp_path / "crtsh" and "/" not in p.name and p.name.endswith(".json")


@pytest.mark.parametrize("namespace", ["..", "../outside", "nested/path", r"nested\path", "absolute"])
def test_cache_rejects_unsafe_namespace(tmp_path, namespace):
    cache = Cache(tmp_path / "cache")
    if namespace == "absolute":
        namespace = str(tmp_path / "outside")

    with pytest.raises(ValueError, match="invalid cache namespace"):
        cache.put(namespace, "key", {"value": 1})
    with pytest.raises(ValueError, match="invalid cache namespace"):
        cache.get(namespace, "key")

    assert list(tmp_path.iterdir()) == [cache.root]
    assert list(cache.root.iterdir()) == []


@pytest.mark.parametrize("link_file", [False, True])
def test_cache_rejects_symlink_escape(tmp_path, link_file):
    cache = Cache(tmp_path / "cache")
    outside = tmp_path / "outside"
    outside.mkdir()
    if link_file:
        path = cache.path_for("ns", "key")
        path.symlink_to(outside / path.name)
    else:
        (cache.root / "ns").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="outside the cache root"):
        cache.put("ns", "key", {"value": 1})
    with pytest.raises(ValueError, match="outside the cache root"):
        cache.get("ns", "key")

    assert list(outside.iterdir()) == []


def test_dns_tcp_retry_and_caching(tmp_path):
    c = Cache(tmp_path)
    r = Flaky()
    assert dns_query(r, c, "a.test", "A") == ("ok", ["192.0.2.1"], "1 record(s) (via TCP retry)")
    assert r.calls == [False, True]
    assert dns_query(r, c, "A.TEST.", "A")[2].startswith("cached")


def test_dns_timeout_not_cached(tmp_path):
    c = Cache(tmp_path)
    r = Flaky(dns.resolver.LifetimeTimeout(timeout=1.0, errors=[]))
    assert dns_query(r, c, "a.test", "A")[0] == "timeout"
    assert dns_query(r, c, "a.test", "A")[0] == "timeout"
    assert len(r.calls) == 4


def test_dns_nxdomain_cached(tmp_path):
    c = Cache(tmp_path)
    r = Flaky(dns.resolver.NXDOMAIN())
    assert dns_query(r, c, "a.test", "A")[0] == "nxdomain"
    assert dns_query(r, c, "a.test", "A")[2].startswith("cached")


def test_truncate():
    assert truncate("abc", 10) == "abc"
    assert len(truncate("x" * 300)) <= 200
