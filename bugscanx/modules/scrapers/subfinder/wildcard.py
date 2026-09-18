"""
Wildcard expansion for BugScanX (continuation patch).

Certificate-transparency sources often return wildcard names such as
*.api.example.com. A literal '*' host can never be scanned, so for every
wildcard base we DNS-probe a list of common prefixes - whatever resolves
is a real host the scanner can use.

Runs on the same MultiThread engine as everything else: live progress,
hard per-host DNS timeout, instant Ctrl+C (partial results are kept).
"""

import secrets

from bugscanx.modules.scanners.scanners.multithread import MultiThread
from bugscanx.utils.domains import resolve_host

DEFAULT_THREADS = 150
DNS_TIMEOUT = 3.0

# High-value prefixes probed under every wildcard base.
COMMON_PREFIXES = (
    "www", "api", "app", "m", "mobile", "web", "www2", "api2",
    "dev", "test", "staging", "stage", "beta", "alpha", "demo", "sandbox",
    "qa", "uat", "preprod", "prod", "old", "new", "backup",
    "admin", "panel", "dashboard", "portal", "login", "signin", "auth",
    "oauth", "sso", "account", "accounts", "my", "secure",
    "vpn", "remote", "gateway", "gw", "proxy", "edge", "lb",
    "cdn", "static", "assets", "img", "images", "media", "files",
    "download", "downloads", "upload", "video", "stream",
    "mail", "webmail", "email", "smtp", "imap", "pop", "mx",
    "ns1", "ns2", "ftp", "sftp", "ssh",
    "db", "data", "cache", "search", "ws", "wss", "chat",
    "support", "help", "docs", "status", "blog", "news",
    "shop", "store", "pay", "payments", "billing", "checkout",
    "git", "monitor", "crm", "cloud", "id", "connect", "go",
)

def _random_label():
    """Un-guessable label used to detect DNS wildcards: if a random name
    resolves, the base answers for ANY name."""
    return 'zqx' + secrets.token_hex(4)

class WildcardExpander(MultiThread):
    """Probe (wildcard base x common prefix) candidates over DNS."""

    def __init__(self, bases, prefixes=COMMON_PREFIXES, threads=DEFAULT_THREADS,
                 timeout=DNS_TIMEOUT):
        super().__init__(threads=threads)
        self.bases = list(bases)
        self.timeout = timeout
        self._dns_wildcards = set()
        self._tasks = []
        for base in self.bases:
            # one random-label probe per base detects "everything resolves"
            self._tasks.append(('probe', base, f"{_random_label()}.{base}"))
            for prefix in prefixes:
                self._tasks.append(('scan', base, f"{prefix}.{base}"))
        self.set_total(len(self._tasks))

    def init(self):
        pass

    def generate_tasks(self):
        yield from self._tasks

    def task(self, payload):
        kind, base, name = payload
        self.progress(name)
        if not resolve_host(name, timeout=self.timeout):
            return
        if kind == 'probe':
            with self._lock:
                self._dns_wildcards.add(base)
        else:
            self.success(name)

    def render_progress(self):
        super().render_progress(
            extra_parts=[f"{len(self.bases)} wildcard base(s)"])

    def complete(self):
        super().complete()
        self.logger.log(self.logger.colorize(
            f"Wildcards: {len(self.get_success())} host(s) resolved from "
            f"{len(self.bases)} base(s)", 'GREEN'))
        for base in sorted(self._dns_wildcards):
            self.logger.log(self.logger.colorize(
                f"  note: {base} answers for ANY name (DNS wildcard)", 'YELLOW'))

def expand_wildcards(wildcards, prefixes=COMMON_PREFIXES, threads=DEFAULT_THREADS):
    """Expand '*.example.com'-style wildcards into real, resolvable hosts.
    Accepts names with or without the leading '*.'; returns a set."""
    bases = sorted({w[2:] if w.startswith('*.') else w for w in wildcards if w})
    if not bases:
        return set()
    engine = WildcardExpander(bases, prefixes=prefixes, threads=threads)
    engine.start()
    return set(engine.get_success())
