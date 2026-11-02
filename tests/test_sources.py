import pytest

from bugscanx.modules.scrapers.subfinder import sources as src
from bugscanx.modules.scrapers.subfinder.utils import DomainValidator, RequestHandler


class FakeResponse:
    def __init__(self, text="", json_data=None, ctype="application/json"):
        self.text = text
        self._json = json_data
        self.headers = {"Content-Type": ctype}
        self.status_code = 200

    def json(self):
        return self._json


def test_normalize_and_filter():
    found = {
        "WWW.Example.COM.", "  api.example.com ", "*.cdn.example.com",
        "admin@mail.example.com", "evil.com", "notexample.com",
        "bad host.example.com", "example.com",
    }
    assert DomainValidator.filter_valid_subdomains(found, "Example.com") == {
        "www.example.com", "api.example.com", "*.cdn.example.com", "example.com",
    }


def test_source_modes():
    thorough = {s.name for s in src.get_sources()}
    fast = {s.name for s in src.get_sources("fast")}
    assert "Wayback" in thorough and "Wayback" not in fast
    assert {"Crt.sh", "RapidDNS", "CertSpotter", "urlscan"} <= fast
    assert all(s.fast for s in src.get_sources("fast"))
    with pytest.raises(ValueError):
        src.get_sources("turbo")


def test_fast_mode_forces_short_timeout(monkeypatch):
    calls = []
    monkeypatch.setattr(RequestHandler, "get",
                        lambda self, url, **kw: calls.append(kw) or None)
    src.CrtshSource(fast=True).fetch("example.com")
    assert calls == [dict(timeout=src.FAST_TIMEOUT, retries=0, backoff=3, headers=None)]


def test_crtsh_gets_long_timeout_and_light_fallback(monkeypatch):
    urls = []

    def fake_get(self, url, **kw):
        urls.append((url, kw["timeout"]))
        if "exclude=expired" not in url:
            return None  # busy / 502
        return FakeResponse(json_data=[{"name_value": "a.example.com\nB.example.com",
                                        "common_name": "c.example.com"}])

    monkeypatch.setattr(RequestHandler, "get", fake_get)
    found = src.CrtshSource().fetch("example.com")
    assert found == {"a.example.com", "B.example.com", "c.example.com"}
    assert urls[0][1][1] >= 60
    assert "exclude=expired" in urls[1][0]


def test_hackertarget_quota_message_is_not_a_result(monkeypatch):
    monkeypatch.setattr(RequestHandler, "get", lambda self, url, **kw: FakeResponse(
        text="API count exceeded - Increase Quota with Membership", ctype="text/plain"))
    s = src.HackertargetSource()
    s.clear_error()
    assert s.fetch("example.com") == set()
    assert s.last_error() == "rate limited"


def test_certspotter_follows_pages(monkeypatch):
    pages = [[{"id": "1", "dns_names": ["a.example.com"]}],
             [{"id": "2", "dns_names": ["b.example.com"]}], []]
    seen = []

    def fake_get(self, url, **kw):
        seen.append(url)
        return FakeResponse(json_data=pages[len(seen) - 1])

    monkeypatch.setattr(RequestHandler, "get", fake_get)
    assert src.CertSpotterSource().fetch("example.com") == {"a.example.com", "b.example.com"}
    assert "after=1" in seen[1] and "after=2" in seen[2]


def test_wayback_extracts_hosts(monkeypatch):
    monkeypatch.setattr(RequestHandler, "get", lambda self, url, **kw: FakeResponse(
        text="http://old.example.com/a\nhttps://API.example.com:8443/x?y\n\nnot a url ::", ctype="text/plain"))
    assert {"old.example.com", "api.example.com"} <= src.WaybackSource().fetch("example.com")
