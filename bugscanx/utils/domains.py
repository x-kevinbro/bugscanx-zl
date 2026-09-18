"""
Domain helpers for BugScanX (continuation patch).

- normalize_host():       'https://m.instagram.com:443/x' -> 'm.instagram.com'
- main_domain():          'm.instagram.com' -> 'instagram.com'
                          'a.b.example.co.uk' -> 'example.co.uk'  (suffix-aware)
- unique_main_domains():  each main domain only once, first-seen order
- read_hosts_file():      normalized, de-duplicated host list from a txt file
- resolve_host():         DNS resolution with a hard timeout - the scanner
                          can never get stuck on a dead resolver again
"""

import re
import socket
import threading

MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "co.lk", "com.lk", "org.lk", "gov.lk", "ac.lk",
    "com.br", "net.br", "org.br", "com.mx", "co.jp", "or.jp",
    "com.sg", "com.my", "co.id", "com.ph", "com.pk", "com.bd",
    "co.nz", "com.tr", "com.ng", "com.np", "com.mm", "com.kh",
    "co.za", "com.co", "com.ar", "com.pe", "com.ve", "co.th",
    "com.vn", "com.sa", "com.ae", "co.ke", "com.gh", "com.eg",
}

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def normalize_host(line):
    """Turn a messy txt line into a bare hostname. Returns None if unusable."""
    h = (line or "").strip()
    if not h or h.startswith("#"):
        return None
    h = _SCHEME_RE.sub("", h)          # strip scheme
    h = h.split("/")[0]                # strip path
    h = h.split("?")[0]                # strip query
    h = h.rsplit("@", 1)[-1]           # strip userinfo
    if h.startswith("["):              # ipv6 literal
        h = h.split("]")[0].strip("[]")
    else:
        h = h.split(":")[0]           # strip port
    h = h.strip().strip(".").lower()
    if not h or " " in h or ".." in h:
        return None
    return h


def is_ip(host):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            continue
    return False


def main_domain(host):
    """Registrable (main) domain of a host. IPs and dotless names pass through."""
    if is_ip(host) or "." not in host:
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def read_hosts_file(path):
    """Read a hosts txt file -> clean, unique host list (original order)."""
    hosts = []
    seen = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            h = normalize_host(line)
            if h and h not in seen:
                seen.add(h)
                hosts.append(h)
    return hosts


def unique_main_domains(hosts):
    """
    Collapse hosts to their main domains, each listed once (first-seen order).
    Returns (domains, skipped_count) - skipped_count is how many lines pointed
    at a domain that was already covered (e.g. m.instagram.com after
    login.instagram.com).
    """
    domains = []
    seen = set()
    skipped = 0
    for h in hosts:
        d = main_domain(h)
        if d in seen:
            skipped += 1
            continue
        seen.add(d)
        domains.append(d)
    return domains, skipped


def resolve_host(host, timeout=4.0):
    """
    socket.gethostbyname() with a hard timeout.
    A dead/hung DNS resolver used to freeze worker threads forever - now the
    worst case is `timeout` seconds and the scan moves on. Returns None when
    the host does not resolve.
    """
    box = {}

    def _worker():
        try:
            box["ip"] = socket.gethostbyname(host)
        except Exception:
            pass

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    return box.get("ip")
