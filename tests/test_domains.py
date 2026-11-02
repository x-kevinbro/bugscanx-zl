import pytest

from bugscanx.utils.domains import main_domain, normalize_host, unique_main_domains


@pytest.mark.parametrize("host,expected", [
    ("m.instagram.com", "instagram.com"),
    ("instagram.com", "instagram.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("www.example.com.au", "example.com.au"),
    ("x.y.example.com.lk", "example.com.lk"),
    ("1.2.3.4", "1.2.3.4"),
    ("localhost", "localhost"),
])
def test_main_domain(host, expected):
    assert main_domain(host) == expected


def test_bare_public_suffix_is_never_a_main_domain():
    assert main_domain("co.uk") is None


def test_unique_main_domains_skips_duplicates_and_suffixes():
    domains, skipped = unique_main_domains(
        ["login.instagram.com", "m.instagram.com", "co.uk", "a.example.co.uk"])
    assert domains == ["instagram.com", "example.co.uk"]
    assert skipped == 2


@pytest.mark.parametrize("line,expected", [
    ("https://M.Instagram.com:443/x?y=1", "m.instagram.com"),
    ("  example.com  ", "example.com"),
    ("# comment", None),
    ("", None),
    ("user@host.example.com", "host.example.com"),
])
def test_normalize_host(line, expected):
    assert normalize_host(line) == expected


def test_psl_private_suffix_when_tldextract_available():
    pytest.importorskip("tldextract")
    # github.io is a private PSL suffix: each user site is its own domain
    assert main_domain("a.me.github.io") == "me.github.io"
    assert main_domain("github.io") is None
    # suffixes missing from the old hard-coded table now work
    assert main_domain("www.example.com.cn") == "example.com.cn"
