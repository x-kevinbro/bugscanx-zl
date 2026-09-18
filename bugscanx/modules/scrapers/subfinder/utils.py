import re
import random
import threading
import requests
from requests.adapters import HTTPAdapter
from bugscanx.utils.http import HEADERS, USER_AGENTS

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
            session.verify = False
            adapter = HTTPAdapter(pool_connections=2, pool_maxsize=4)
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            self._tls.session = session
        return session

    def _get_headers(self):
        headers = HEADERS.copy()
        headers["user-agent"] = random.choice(USER_AGENTS)
        return headers

    def get(self, url, timeout=None):
        try:
            response = self._session().get(
                url,
                timeout=timeout or self.DEFAULT_TIMEOUT,
                headers=self._get_headers(),
            )
            if response.status_code == 200:
                return response
        except requests.RequestException:
            pass
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        session = getattr(self._tls, 'session', None)
        if session is not None:
            session.close()
            self._tls.session = None


class DomainValidator:
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
    def filter_valid_subdomains(subdomains, domain):
        if not domain or not isinstance(domain, str):
            return set()

        domain_suffix = f".{domain}"
        result = set()

        for sub in subdomains:
            if not isinstance(sub, str):
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
