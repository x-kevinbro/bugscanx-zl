import os
import re
import random
import threading
import time
import requests
from requests.adapters import HTTPAdapter
from bugscanx.utils.http import HEADERS, USER_AGENTS

# Subdomain data comes from third-party APIs (crt.sh, hackertarget, ...), so
# their certificates are verified by default. Set BUGSCANX_INSECURE_SOURCES=1
# only if you are behind an intercepting proxy you trust.
INSECURE_ENV = 'BUGSCANX_INSECURE_SOURCES'


def verify_sources():
    return os.environ.get(INSECURE_ENV, '').strip().lower() not in ('1', 'true', 'yes', 'on')


if not verify_sources():
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning)


STOP = threading.Event()   # set on Ctrl+C so waiting workers exit at once


class SourceLimiter:
    """Per-source politeness: max parallel requests, minimum gap between
    requests and a cooldown after "429 Too Many Requests".

    Free sources (crt.sh, CertSpotter, urlscan ...) block an IP that fires
    dozens of parallel queries - that is why the old engine got results for
    the first few domains only. Requests now queue per source instead.
    """

    BASE_COOLDOWN = 30
    MAX_COOLDOWN = 300

    def __init__(self, name, concurrency=2, interval=1.0):
        self.name = name
        self.concurrency = max(1, int(concurrency))
        self.interval = float(interval)
        self.max_wait = 20.0          # longest cooldown a request waits out
        self.deadline = None          # retry rounds: hard end (monotonic)
        self._slots = threading.BoundedSemaphore(self.concurrency)
        self._lock = threading.Lock()
        self._next = 0.0
        self._cooldown_until = 0.0
        self._strikes = 0
        self._trouble = 0             # timeouts / 5xx in a row
        self._cooldown_reason = 'rate limited'
        self.disabled = None          # reason string once a source is dead

    def cooldown_left(self):
        return max(0.0, self._cooldown_until - time.monotonic())

    def acquire(self):
        """Wait for a slot + pacing. Returns None when the request may go,
        else the reason it was not sent ('rate limited' = try again later)."""
        while True:
            if STOP.is_set():
                return 'stopped'
            if self.disabled:
                return self.disabled
            left = self.cooldown_left()
            now = time.monotonic()
            if left > self.max_wait or (
                    self.deadline is not None and now + left > self.deadline):
                return self._cooldown_reason
            if left > 0:
                STOP.wait(min(left, 1.0))
                continue
            if self.deadline is not None and now > self.deadline:
                return self._cooldown_reason
            if self._slots.acquire(timeout=0.5):
                break
        while True:
            with self._lock:
                now = time.monotonic()
                start = max(now, self._next, self._cooldown_until)
                if start <= now:
                    self._next = now + self.interval
                    return None
                # a cooldown may have started while we waited for the slot
                too_late = (start - now > self.max_wait or (
                    self.deadline is not None and start > self.deadline))
                reason = self._cooldown_reason
            if too_late:
                self._slots.release()
                return reason
            if STOP.wait(min(start - now, 1.0)):
                self._slots.release()
                return 'stopped'

    def release(self):
        try:
            self._slots.release()
        except ValueError:
            pass

    TROUBLE_LIMIT = 4       # this many timeouts / 5xx in a row = source busy
    BUSY_COOLDOWN = 90

    def trouble(self):
        """A request timed out or got a 5xx. After a few in a row the source
        is overloaded: pause it, so the remaining lookups move to the retry
        round instead of each burning minutes on timeouts now."""
        with self._lock:
            self._trouble += 1
            if self._trouble < self.TROUBLE_LIMIT:
                return False
            self._trouble = 0
            self._cooldown_until = max(self._cooldown_until,
                                       time.monotonic() + self.BUSY_COOLDOWN)
            self._cooldown_reason = 'busy'
        return True

    def penalize(self, retry_after=None):
        with self._lock:
            self._cooldown_reason = 'rate limited'
            self._strikes += 1
            wait = retry_after if retry_after else min(
                self.BASE_COOLDOWN * 2 ** (self._strikes - 1), self.MAX_COOLDOWN)
            self._cooldown_until = max(self._cooldown_until,
                                       time.monotonic() + float(wait))
        return wait

    MAX_STRIKES = 3         # 429 three times in one run = stop using it

    def strikes(self):
        return self._strikes

    def ok(self):
        self._strikes = 0
        self._trouble = 0

    def disable(self, reason):
        if not self.disabled:
            self.disabled = reason
            return True
        return False


# requests in flight, minimum seconds between requests - per source
SOURCE_LIMITS = {
    'Crt.sh': (4, 0.5),
    'Hackertarget': (1, 2.0),
    'RapidDNS': (1, 1.5),
    'AlienVault': (1, 2.0),
    'CertSpotter': (1, 1.0),
    'urlscan': (2, 2.1),       # 30 searches / minute per IP without a key
    'Wayback': (2, 1.0),
    'C99': (2, 1.0),
}
_limiters = {}
_limiters_lock = threading.Lock()


def limiter_for(name):
    with _limiters_lock:
        lim = _limiters.get(name)
        if lim is None:
            conc, gap = SOURCE_LIMITS.get(name, (2, 1.0))
            lim = _limiters[name] = SourceLimiter(name, conc, gap)
        return lim


def reset_limiters():
    """Fresh limiter state for a new run."""
    with _limiters_lock:
        _limiters.clear()
    STOP.clear()


def all_limiters():
    with _limiters_lock:
        return list(_limiters.values())


class RequestHandler:
    """
    One shared requests.Session per worker thread (thread-local), so
    hundreds of workers can fetch concurrently without tripping over a
    single shared session, and keep-alive is reused within each thread.

    Every request carries a hard (connect, read) timeout - a hung source
    can occupy a worker for a few seconds at most, never stall the scan.
    """

    DEFAULT_TIMEOUT = (3, 6)
    _tls = threading.local()

    def _session(self):
        session = getattr(self._tls, 'session', None)
        if session is None:
            session = requests.Session()
            session.verify = verify_sources()
            adapter = HTTPAdapter(pool_connections=2, pool_maxsize=4)
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            self._tls.session = session
        return session

    def _get_headers(self):
        headers = HEADERS.copy()
        headers["user-agent"] = random.choice(USER_AGENTS)
        return headers

    # Per-thread "why did the last request fail" slot. A worker runs one
    # (domain, source) task at a time, so the engine can clear it before
    # fetch() and read it afterwards to tell "source failed" from "no subs".
    def clear_error(self):
        self._tls.last_error = None
        self._tls.retry_after = None
        self._tls.error_body = ''

    def error_body(self):
        return getattr(self._tls, 'error_body', '') or ''

    def last_error(self):
        return getattr(self._tls, 'last_error', None)

    def _set_error(self, reason):
        if getattr(self._tls, 'last_error', None) is None:
            self._tls.last_error = reason

    # 429 is NOT retried in place any more: hammering a source that just
    # said "too many requests" only extends the block. The source limiter
    # applies a cooldown instead and the engine retries the domain later.
    RETRY_STATUS = (500, 502, 503, 504)
    MAX_BODY = 64 * 1024 * 1024

    def _fetch_capped(self, url, timeout, headers):
        """GET whose TOTAL duration is capped (connect + read timeout x 2),
        not just the gap between two chunks."""
        read_timeout = timeout[1] if isinstance(timeout, tuple) else timeout
        connect = timeout[0] if isinstance(timeout, tuple) else timeout
        deadline = time.monotonic() + connect + 2 * read_timeout
        response = self._session().get(url, timeout=timeout, headers=headers,
                                       stream=True)
        try:
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                chunks.append(chunk)
                size += len(chunk)
                if time.monotonic() > deadline or size > self.MAX_BODY:
                    raise requests.exceptions.ReadTimeout('response took too long')
            response._content = b''.join(chunks)
        finally:
            response.close()
        return response
    RATE_LIMIT_STATUS = (429,)    # sources may add e.g. 503 ("slow down")

    def retry_after(self):
        return getattr(self._tls, 'retry_after', None)

    def get(self, url, timeout=None, retries=0, backoff=2.0, headers=None):
        """GET with a hard timeout. Retries (if any) only on timeouts,
        connection errors and 429/5xx - the typical "busy" answers of free
        sources such as crt.sh. The last failure reason is kept for
        last_error()."""
        req_headers = self._get_headers()
        if headers:
            req_headers.update(headers)
        for attempt in range(retries + 1):
            reason = None
            try:
                response = self._fetch_capped(url, timeout or self.DEFAULT_TIMEOUT,
                                              req_headers)
                if response.status_code == 200:
                    self._tls.last_error = None
                    return response
                limited = response.status_code in self.RATE_LIMIT_STATUS
                reason = 'rate limited' if limited else f'http {response.status_code}'
                if limited:
                    self._tls.retry_after = _parse_retry_after(
                        response.headers.get('Retry-After'))
                    self._tls.error_body = (response.text or '')[:300]
                retryable = (response.status_code in self.RETRY_STATUS
                             and not limited)
            except requests.exceptions.SSLError:
                reason, retryable = 'tls error', False
            except requests.exceptions.Timeout:
                reason, retryable = 'timeout', True
            except requests.exceptions.ConnectionError:
                reason, retryable = 'connection error', True
            except requests.RequestException:
                reason, retryable = 'request error', False
            self._tls.last_error = reason
            if not retryable or attempt == retries:
                break
            time.sleep(backoff * (attempt + 1))
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        session = getattr(self._tls, 'session', None)
        if session is not None:
            session.close()
            self._tls.session = None


def _parse_retry_after(value):
    if not value:
        return None
    value = str(value).strip()
    if value.isdigit():
        return int(value)
    try:
        from email.utils import parsedate_to_datetime
        import datetime as _dt
        when = parsedate_to_datetime(value)
        return max(0, int((when - _dt.datetime.now(when.tzinfo)).total_seconds()))
    except (TypeError, ValueError, OverflowError):
        return None


class DomainValidator:
    HOST_CHARS = re.compile(r'^[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9])?$')
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
    )

    @classmethod
    def is_valid_domain(cls, domain):
        return bool(
            domain
            and isinstance(domain, str)
            and cls.DOMAIN_REGEX.match(domain)
        )

    @staticmethod
    def normalize(name):
        """'  WWW.Example.COM. ' -> 'www.example.com'. Keeps a leading '*.'
        (wildcard certs are expanded later). Returns None for junk such as
        e-mail addresses, URLs or names with spaces that some sources mix
        into their results."""
        if not isinstance(name, str):
            return None
        name = name.strip().strip('.').lower()
        wildcard = name.startswith('*.')
        core = name[2:] if wildcard else name
        if not core or not DomainValidator.HOST_CHARS.match(core):
            return None
        return name

    @staticmethod
    def filter_valid_subdomains(subdomains, domain):
        if not domain or not isinstance(domain, str):
            return set()

        domain = domain.strip().strip('.').lower()
        domain_suffix = f".{domain}"
        result = set()

        for sub in subdomains:
            sub = DomainValidator.normalize(sub)
            if not sub:
                continue
            if sub == domain or sub.endswith(domain_suffix):
                result.add(sub)

        return result


class CursorManager:
    def __enter__(self):
        print('\033[?25l', end='', flush=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print('\033[?25h', end='', flush=True)
