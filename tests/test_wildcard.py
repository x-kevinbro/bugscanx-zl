from bugscanx.modules.scrapers.subfinder import wildcard


def test_dns_wildcard_bases_are_dropped(monkeypatch):
    def fake_resolve(name, timeout=None):
        if name.endswith(".wild.test"):
            return "10.0.0.1"          # answers for ANY name
        if name in ("www.real.test", "api.real.test"):
            return "10.0.0.2"
        return None

    monkeypatch.setattr(wildcard, "resolve_host", fake_resolve)
    found = wildcard.expand_wildcards(["wild.test", "real.test"], threads=4,
                                      drop_dns_wildcards=True)
    assert found == {"www.real.test", "api.real.test"}

    kept = wildcard.expand_wildcards(["wild.test"], threads=4)
    assert len(kept) == len(wildcard.COMMON_PREFIXES)
