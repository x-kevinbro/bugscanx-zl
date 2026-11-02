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

    def last_error(self):
        return getattr(self._tls, 'last_error', None)

    def _set_error(self, reason):
        if getattr(self._tls, 'last_error', None) is None:
            self._tls.last_error = reason

    RETRY_STATUS = (429, 500, 502, 503, 504)

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
                response = self._session().get(
                    url,
                    timeout=timeout or self.DEFAULT_TIMEOUT,
                    headers=req_headers,
                )
                if response.status_code == 200:
                    self._tls.last_error = None
                    return response
                reason = ('rate limited' if response.status_code == 429
                          else f'http {response.status_code}')
                retryable = response.status_code in self.RETRY_STATUS
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
