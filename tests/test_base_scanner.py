import ipaddress

import pytest

from bugscanx.modules.scanners.scanners.base import (
    BaseScanner, count_cidr_hosts, iter_cidr_hosts,
)


class DummyScanner(BaseScanner):
    def generate_tasks(self):
        return iter(())

    def init(self):
        pass

    def task(self, task):
        pass


@pytest.mark.parametrize("port,expected", [
    ("80", "http://example.com"),
    ("443", "https://example.com"),
    ("8443", "https://example.com:8443"),
    ("2053", "https://example.com:2053"),
    ("8080", "http://example.com:8080"),
    (" 443 ", "https://example.com"),
])
def test_auto_scheme(port, expected):
    assert DummyScanner().get_url("example.com", port) == expected


def test_forced_https_on_custom_port():
    s = DummyScanner(scheme="https")
    assert s.get_url("example.com", "8080") == "https://example.com:8080"
    assert s.get_url("example.com", "443") == "https://example.com"
    assert s.get_url("example.com", "80") == "https://example.com:80"


def test_forced_http_on_443():
    s = DummyScanner(scheme="http")
    assert s.get_url("example.com", "443") == "http://example.com:443"
    assert s.get_url("example.com", "80") == "http://example.com"


def test_ipv6_literal_is_bracketed():
    assert DummyScanner().get_url("2001:db8::1", "8080") == "http://[2001:db8::1]:8080"


def test_invalid_scheme_rejected():
    with pytest.raises(ValueError):
        DummyScanner(scheme="ftp")


def test_host_count_matches_generated_hosts(tmp_path):
    f = tmp_path / "hosts.txt"
    # blank lines, comments, wildcards and NO trailing newline
    f.write_text("a.com\n\n# comment\n*.wild.com\n  b.com  \nc.com", encoding="utf-8")
    s = DummyScanner()
    hosts = list(s.generate_hosts_from_file(str(f)))
    assert hosts == ["a.com", "b.com", "c.com"]
    assert s.read_lines_count(str(f)) == 3


def test_host_total_uses_port_and_method_multipliers(tmp_path):
    f = tmp_path / "hosts.txt"
    f.write_text("a.com\nb.com", encoding="utf-8")
    s = DummyScanner()
    s.port_list = ["80", "443"]
    s.method_list = ["GET", "HEAD", "POST"]
    s.set_host_total(str(f))
    assert s._total == 2 * 2 * 3


def test_missing_file_counts_zero(tmp_path):
    assert DummyScanner().read_lines_count(str(tmp_path / "nope.txt")) == 0


@pytest.mark.parametrize("cidr,expected", [
    ("10.0.0.0/24", 254),
    ("10.0.0.0/30", 2),
    ("10.0.0.0/31", 2),
    ("10.0.0.5/32", 1),
    ("2001:db8::/120", 255),
    ("2001:db8::/127", 2),
    ("2001:db8::1/128", 1),
])
def test_cidr_count_matches_generated_hosts(cidr, expected):
    net = ipaddress.ip_network(cidr, strict=False)
    assert count_cidr_hosts(net) == expected
    assert len(list(iter_cidr_hosts(net))) == expected

    s = DummyScanner(is_cidr_input=True)
    assert s.get_total_cidr_hosts([cidr]) == expected
    assert len(list(s.generate_cidr_hosts([cidr]))) == expected


def test_cidr_skips_network_and_broadcast():
    hosts = list(DummyScanner().generate_cidr_hosts(["192.168.1.0/30"]))
    assert hosts == ["192.168.1.1", "192.168.1.2"]


def test_invalid_cidr_ignored():
    s = DummyScanner()
    assert s.get_total_cidr_hosts(["nonsense", "10.0.0.0/32"]) == 1
    assert list(s.generate_cidr_hosts(["nonsense", "10.0.0.0/32"])) == ["10.0.0.0"]
