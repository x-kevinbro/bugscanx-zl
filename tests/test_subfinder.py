import pytest

from bugscanx.modules.scrapers.subfinder.subfinder import SubFinderEngine


class FakeSource:
    def __init__(self, name, results=None, error=None):
        self.name = name
        self.results = results or {}
        self.error = error
        self._err = None

    def clear_error(self):
        self._err = None

    def last_error(self):
        return self._err

    def fetch(self, domain):
        if self.error:
            self._err = self.error
            return set()
        return set(self.results.get(domain, ()))


def run(tmp_path, mode, existing=None, sources=None):
    out = tmp_path / "subs.txt"
    if existing is not None:
        out.write_text(existing, encoding="utf-8")
    sources = sources or [FakeSource("A", {"example.com": {"a.example.com", "evil.com"}})]
    engine = SubFinderEngine(["example.com"], sources, str(out), threads=2, mode=mode)
    engine.start()
    return engine, out.read_text(encoding="utf-8")


def test_append_mode_keeps_existing_content(tmp_path):
    _, text = run(tmp_path, "a", existing="old.example.com\n")
    assert "old.example.com" in text
    assert "a.example.com" in text
    assert "evil.com" not in text  # out-of-scope results are filtered


def test_write_mode_starts_fresh(tmp_path):
    _, text = run(tmp_path, "w", existing="old.example.com\n")
    assert "old.example.com" not in text
    assert "a.example.com" in text


def test_invalid_mode_rejected(tmp_path):
    with pytest.raises(ValueError):
        SubFinderEngine(["example.com"], [], str(tmp_path / "x"), mode="x")


def test_source_failures_are_reported(tmp_path):
    engine, _ = run(tmp_path, "w", sources=[
        FakeSource("Good", {"example.com": {"a.example.com"}}),
        FakeSource("Down", error="timeout"),
    ])
    assert "Down: timeout 1" in engine.failure_summary()
