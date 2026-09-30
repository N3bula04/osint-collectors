import pytest

from osint_collectors import psl


@pytest.mark.parametrize("host,expected", [
    ("mail.example.co.uk", "example.co.uk"),
    ("www.moh.gov.sg", "moh.gov.sg"),
    ("a.b.example.com", "example.com"),
    ("Example.COM.", "example.com"),
    ("foo.github.io", "github.io"),  # ICANN section only, like osint-pivot-tool
    ("ns1.awsdns-00.co.uk", "awsdns-00.co.uk"),
    ("www.example-demo.test", "example-demo.test"),  # not on the PSL: default rule "*"
    ("host.corp.internal", "corp.internal"),
    ("co.uk", "co.uk"),                          # bare suffix unchanged
    ("localhost", "localhost"),                  # single label unchanged
    ("192.0.2.1", "192.0.2.1"),                  # IPs unchanged
    ("2001:db8::1", "2001:db8::1"),
])
def test_registrable_domain(host, expected):
    assert psl.registrable_domain(host) == expected


def test_label_same_owner_host_in_domain():
    assert psl.registrable_label("www.moh.gov.sg") == "moh"
    assert psl.same_owner("a.example.co.uk", "b.example.co.uk")
    assert not psl.same_owner("a.example.co.uk", "a.other.co.uk")
    assert psl.host_in_domain("a.b.example.com", "example.com")
    assert psl.host_in_domain("example.com.", "EXAMPLE.com")
    assert not psl.host_in_domain("notexample.com", "example.com")
    assert not psl.host_in_domain("example.com", "")


def test_no_network_needed_for_psl():
    from osint_collectors.offline import network_blocked
    with network_blocked():
        assert psl.registrable_domain("x.y.example.com.au") == "example.com.au"


def test_fallback_without_tldextract(monkeypatch):
    monkeypatch.setattr(psl, "_PSL", None)
    assert psl.registrable_domain("mail.example.co.uk") == "example.co.uk"
    assert psl.registrable_domain("www.moh.gov.sg") == "moh.gov.sg"
    assert psl.registrable_domain("a.example.com") == "example.com"
    assert psl.registrable_domain("localhost") == "localhost"
