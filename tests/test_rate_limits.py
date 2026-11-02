import time

from bugscanx.modules.scrapers.subfinder import sources as src
from bugscanx.modules.scrapers.subfinder import utils as u
from bugscanx.modules.scrapers.subfinder.subfinder import SubFinderEngine


class Resp:
    def __init__(self, status=200, text="", headers=None, json_data=None):
        self.status_code = status
        self.text = text
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self._json = json_data

    def json(self):
        return self._json

    def iter_content(self, size):
        yield (self.text or "").encode()

    def close(self):
        pass


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def get(self, url, **kw):
        self.calls += 1
        return self.responses.pop(0) if self.responses else Resp(200, json_data=[])


def test_limiter_cooldown_and_disable():
    lim = u.SourceLimiter("X", concurrency=1, interval=0)
    assert lim.acquire() is None
    lim.release()
    lim.penalize(retry_after=120)
    assert lim.acquire() == "rate limited"          # longer than max_wait
    lim.disable("daily limit reached")
    assert lim.acquire() == "daily limit reached"


def test_limiter_spaces_requests():
    lim = u.SourceLimiter("Y", concurrency=4, interval=0.2)
    start = time.monotonic()
    for _ in range(3):
        assert lim.acquire() is None
        lim.release()
    assert time.monotonic() - start >= 0.35


def test_429_sets_cooldown_and_retry_after(monkeypatch):
    session = FakeSession([Resp(429, headers={"Retry-After": "45"})])
    monkeypatch.setattr(u.RequestHandler, "_session", lambda self: session)
    s = src.UrlscanSource()
    s.clear_error()
    assert s.fetch("example.com") == set()
    assert s.last_error() == "rate limited"
    assert session.calls == 1                       # no hammering in place
    assert 40 < u.limiter_for("urlscan").cooldown_left() <= 45


def test_auth_required_disables_source(monkeypatch):
    session = FakeSession([Resp(429, text='{"detail": "Anonymous access to this endpoint is limited. Please authenticate."}')])
    monkeypatch.setattr(u.RequestHandler, "_session", lambda self: session)
    s = src.AlienVaultSource()
    s.clear_error()
    s.fetch("example.com")
    assert s.last_error() == "needs API key"
    assert u.limiter_for("AlienVault").disabled == "needs API key"


def test_alienvault_only_with_key(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    assert "AlienVault" not in {s.name for s in src.get_sources()}
    monkeypatch.setenv("OTX_API_KEY", "k")
    names = {s.name for s in src.get_sources()}
    assert "AlienVault" in names
    assert src.AlienVaultSource().auth_headers() == {"X-OTX-API-KEY": "k"}


class FlakySource:
    """Rate limited for the first `fail` calls, then answers."""

    def __init__(self, name, fail, results):
        self.name, self.fail, self.results = name, fail, results
        self.calls = 0
        self._err = None

    def clear_error(self):
        self._err = None

    def last_error(self):
        return self._err

    def fetch(self, domain):
        self.calls += 1
        if self.calls <= self.fail:
            self._err = "rate limited"
            return set()
        return set(self.results.get(domain, ()))


def test_rate_limited_lookups_are_retried(tmp_path, capsys):
    out = tmp_path / "subs.txt"
    flaky = FlakySource("Flaky", fail=2, results={
        "a.com": {"x.a.com"}, "b.com": {"y.b.com"}})
    engine = SubFinderEngine(["a.com", "b.com"], [flaky], str(out),
                             threads=2, mode="w", retry_rounds=2, retry_wait=1)
    engine.start()
    assert set(out.read_text().split()) == {"x.a.com", "y.b.com"}
    assert engine.failure_summary() == ""          # recovered = not a failure
    assert "Retry round 1" in capsys.readouterr().err


def test_every_domain_is_reported_with_reason(tmp_path, capsys):
    out = tmp_path / "subs.txt"
    never = FlakySource("Never", fail=99, results={})
    engine = SubFinderEngine(["a.com"], [never], str(out),
                             threads=1, mode="w", retry_rounds=1, retry_wait=1)
    engine.start()
    err = capsys.readouterr().err
    assert "a.com: 0 subdomains (no answer: Never rate limited)" in err
    assert never.calls == 2                         # first try + 1 retry round
    assert "Never: rate limited 1" in engine.failure_summary()


def test_certspotter_quota_is_a_cooldown_not_a_ban(monkeypatch):
    body = ('{"code":"rate_limited","message":"You have exceeded your domain search '
            'quota ... Please try again later, or authenticate with an API key"}')
    session = FakeSession([Resp(429, text=body, headers={"Retry-After": "254"})])
    monkeypatch.setattr(u.RequestHandler, "_session", lambda self: session)
    s = src.CertSpotterSource()
    s.clear_error()
    s.fetch("example.com")
    lim = u.limiter_for("CertSpotter")
    assert s.last_error() == "rate limited"
    assert lim.disabled is None and lim.cooldown_left() > 200


def test_busy_source_is_paused_after_repeated_timeouts():
    lim = u.SourceLimiter("Slow", concurrency=1, interval=0)
    assert not any(lim.trouble() for _ in range(lim.TROUBLE_LIMIT - 1))
    assert lim.trouble() is True
    assert lim.acquire() == "busy"          # deferred to the retry round


def test_retry_round_deadline_and_strikes():
    lim = u.SourceLimiter("Z", concurrency=1, interval=0)
    lim.max_wait = 999
    lim.penalize(retry_after=50)
    lim.deadline = time.monotonic() + 10      # cooldown ends after the round
    assert lim.acquire() == "rate limited"
    for _ in range(lim.MAX_STRIKES - 1):
        lim.penalize(retry_after=1)
    assert lim.strikes() >= lim.MAX_STRIKES


def test_trickling_response_is_cut_off(monkeypatch):
    class Slow(Resp):
        def iter_content(self, size):
            while True:
                time.sleep(0.05)
                yield b"x"

    monkeypatch.setattr(u.RequestHandler, "_session",
                        lambda self: FakeSession([Slow(200)]))
    h = u.RequestHandler()
    h.clear_error()
    start = time.monotonic()
    assert h.get("https://x", timeout=(0.1, 0.2)) is None
    assert h.last_error() == "timeout"
    assert time.monotonic() - start < 2
