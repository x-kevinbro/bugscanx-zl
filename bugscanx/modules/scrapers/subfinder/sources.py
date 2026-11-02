import datetime
from abc import ABC, abstractmethod
from urllib.parse import urlsplit
from bs4 import BeautifulSoup
from .utils import RequestHandler


FAST_TIMEOUT = (3, 8)


class SubdomainSource(RequestHandler, ABC):
    """fast=True: short timeouts and no retries (quick, may miss results
    from slow sources). fast=False (thorough): each source gets the time
    it realistically needs."""

    def __init__(self, name, fast=False):
        super().__init__()
        self.name = name
        self.fast = fast

    def get(self, url, timeout=None, retries=0, backoff=2.0, headers=None):
        if self.fast:
            timeout, retries = FAST_TIMEOUT, 0
        return super().get(url, timeout=timeout, retries=retries,
                           backoff=backoff, headers=headers)

    @abstractmethod
    def fetch(self, domain):
        pass


class CrtshSource(SubdomainSource):
    """Certificate Transparency logs - usually the biggest single source.

    crt.sh regularly needs 20-60 s for mid-size domains and answers 502/503
    when busy. The old 6 s read timeout meant it silently returned nothing
    for exactly the domains with the most subdomains, so it now gets a long
    timeout and two retries.
    """
    TIMEOUT = (5, 90)

    def __init__(self, fast=False):
        super().__init__("Crt.sh", fast=fast)

    def fetch(self, domain):
        subdomains = set()
        base = f"https://crt.sh/?q=%25.{domain}&output=json&deduplicate=Y"
        response = self.get(base, timeout=self.TIMEOUT, retries=2, backoff=3)
        if response is None and not self.fast:
            # big domains often hit crt.sh's own query timeout (502);
            # the unexpired-only query is much lighter and usually answers
            response = self.get(base + "&exclude=expired",
                                timeout=self.TIMEOUT, retries=1, backoff=3)
        if response and 'json' in response.headers.get('Content-Type', ''):
            for entry in response.json():
                subdomains.update(entry.get('name_value', '').splitlines())
                common = entry.get('common_name')
                if common:
                    subdomains.add(common)
        return subdomains


class HackertargetSource(SubdomainSource):
    def __init__(self, fast=False):
        super().__init__("Hackertarget", fast=fast)

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                            retries=1)
        if response and 'text' in response.headers.get('Content-Type', ''):
            text = response.text.strip()
            # free tier answers 200 with an error sentence when exhausted
            if text.lower().startswith(('api count exceeded', 'error')):
                self._tls.last_error = 'rate limited'
                return subdomains
            subdomains.update(
                [line.split(",")[0] for line in text.splitlines()]
            )
        return subdomains


class RapidDnsSource(SubdomainSource):
    def __init__(self, fast=False):
        super().__init__("RapidDNS", fast=fast)

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://rapiddns.io/subdomain/{domain}?full=1",
                            timeout=(5, 30), retries=1)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('td'):
                text = link.get_text(strip=True)
                if text.endswith(f".{domain}"):
                    subdomains.add(text)
        return subdomains


class AnubisDbSource(SubdomainSource):
    def __init__(self, fast=False):
        super().__init__("AnubisDB", fast=fast)

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://jldc.me/anubis/subdomains/{domain}")
        if response:
            subdomains.update(response.json())
        return subdomains


class AlienVaultSource(SubdomainSource):
    def __init__(self, fast=False):
        super().__init__("AlienVault", fast=fast)

    def fetch(self, domain):
        subdomains = set()
        response = self.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=(5, 30), retries=1, backoff=5)
        if response:
            for entry in response.json().get("passive_dns", []):
                hostname = entry.get("hostname")
                if hostname:
                    subdomains.add(hostname)
        return subdomains


class CertSpotterSource(SubdomainSource):
    def __init__(self, fast=False):
        super().__init__("CertSpotter", fast=fast)

    MAX_PAGES = 10  # free tier is rate limited - stay well inside it

    def fetch(self, domain):
        subdomains = set()
        base = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
                f"&include_subdomains=true&expand=dns_names")
        after = None
        for _ in range(1 if self.fast else self.MAX_PAGES):
            url = base + (f"&after={after}" if after else "")
            response = self.get(url, timeout=(5, 20))
            if not response:
                break
            page = response.json()
            if not isinstance(page, list) or not page:
                break
            for cert in page:
                subdomains.update(cert.get('dns_names', []))
            after = page[-1].get('id')
            if not after:
                break
        return subdomains


class WaybackSource(SubdomainSource):
    """Internet Archive URL index - finds hosts that never had their own
    certificate (old or internal-looking names). Slow but free."""

    def __init__(self, fast=False):
        super().__init__("Wayback", fast=fast)

    def fetch(self, domain):
        subdomains = set()
        response = self.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
            f"&output=txt&fl=original&collapse=urlkey&limit=50000",
            timeout=(5, 90), retries=1)
        if response:
            for line in response.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    host = urlsplit(line if '://' in line else f'http://{line}').hostname
                except ValueError:
                    continue
                if host:
                    subdomains.add(host)
        return subdomains


class UrlscanSource(SubdomainSource):
    def __init__(self, fast=False):
        super().__init__("urlscan", fast=fast)

    def fetch(self, domain):
        subdomains = set()
        response = self.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000",
            timeout=(5, 30), retries=1, backoff=5)
        if response:
            for result in response.json().get('results', []):
                for key in ('page', 'task'):
                    host = (result.get(key) or {}).get('domain')
                    if host:
                        subdomains.add(host)
        return subdomains


class C99Source(SubdomainSource):
    def __init__(self, fast=False):
        super().__init__("C99", fast=fast)

    def fetch(self, domain):
        subdomains = set()
        dates = [(datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d')
                for i in range(7)]

        for date in dates:
            url = f"https://subdomainfinder.c99.nl/scans/{date}/{domain}"
            response = self.get(url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.select('td a.link.sd'):
                    text = link.get_text(strip=True)
                    if text.endswith(f".{domain}"):
                        subdomains.add(text)
                if subdomains:
                    break
        return subdomains


SOURCE_MODES = ("thorough", "fast")


def get_sources(mode="thorough"):
    """thorough: every working source with realistic timeouts (most
    subdomains, slower). fast: short timeouts, skips the slow Wayback index
    (much quicker for big lists, may miss names only crt.sh/Wayback know)."""
    if mode not in SOURCE_MODES:
        raise ValueError(f"mode must be one of {SOURCE_MODES}")
    fast = mode == "fast"
    sources = [
        CrtshSource(fast),
        HackertargetSource(fast),
        RapidDnsSource(fast),
        AlienVaultSource(fast),
        CertSpotterSource(fast),
        UrlscanSource(fast),
    ]
    if not fast:
        sources.append(WaybackSource())
    # Not used: AnubisDbSource (jldc.me now redirects to a 403 page,
    # Nov 2026) and C99Source (HTML scraping of daily scans, rarely useful).
    return sources
