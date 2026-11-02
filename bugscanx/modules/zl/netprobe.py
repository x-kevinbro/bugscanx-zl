"""Low-level helpers shared by the ZL scanner suite (menu 10).

Everything here uses plain sockets with hard timeouts - no `requests`
session, no connection pool - so a dead or throttled network can never
hang a worker for longer than the configured timeout.
"""
import ipaddress
import re
import socket
import ssl
import time

MAX_HEAD = 32 * 1024

_HOST_RE = re.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$')


# ---------------------------------------------------------------- parsing

def is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip().strip('[]'))
        return True
    except ValueError:
        return False


def clean_host(value):
    """'https://Www.Example.com:443/path' -> 'www.example.com' (None if junk)."""
    if value is None:
        return None
    value = str(value).strip().lower()
    if not value or value.startswith('#'):
        return None
    value = re.sub(r'^[a-z][a-z0-9+.-]*://', '', value)
    value = value.split('/', 1)[0].split('?', 1)[0]
    if value.startswith('['):           # [v6]:port
        inner = value[1:].split(']', 1)[0]
        return inner if is_ip(inner) else None
    if value.count(':') == 1:
        value = value.split(':', 1)[0]
    value = value.strip('.')
    if is_ip(value):
        return value
    if value.startswith('*.'):
        return None
    return value if _HOST_RE.match(value) else None


def parse_host_ip(line):
    """Parse one line of a "hostname : ip" file.

    Accepts 'host : ip', 'host:ip', 'host ip', 'host,ip', 'host<TAB>ip',
    'ip host' (hosts-file order) and a bare hostname (ip=None).
    Returns (host, ip) or None for blank / comment / unusable lines.
    """
    line = (line or '').strip()
    if not line or line.startswith('#'):
        return None
    parts = [p for p in re.split(r'\s*[,;|\t ]\s*|\s+:\s+', line) if p]
    if len(parts) == 1:
        token = parts[0]
        # 'host:1.2.3.4' (single colon, right side is IPv4)
        if token.count(':') == 1:
            left, right = token.split(':', 1)
            if is_ip(right) and not is_ip(left):
                host = clean_host(left)
                return (host, right) if host else None
        host = clean_host(token)
        if not host:
            return None
        return (host, host) if is_ip(host) else (host, None)
    ips = [p.strip('[]') for p in parts if is_ip(p)]
    names = [clean_host(p) for p in parts if not is_ip(p)]
    names = [n for n in names if n]
    if names and ips:
        return names[0], ips[0]
    if names:
        return names[0], None
    if ips:
        return ips[0], ips[0]
    return None


def parse_proxy(line, default_port=8080):
    """'1.2.3.4:80', 'http://host:3128', '[::1]:8080', 'host' -> (host, port)."""
    line = (line or '').strip()
    if not line or line.startswith('#'):
        return None
    line = re.sub(r'^[a-z][a-z0-9+.-]*://', '', line, flags=re.I)
    line = line.split('/', 1)[0]
    if '@' in line:                      # user:pass@host:port - auth dropped
        line = line.rsplit('@', 1)[1]
    host, port = line, None
    if line.startswith('['):
        host, _, rest = line[1:].partition(']')
        port = rest.lstrip(':') or None
    elif line.count(':') == 1:
        host, port = line.split(':', 1)
    elif line.count(':') > 1 and is_ip(line):
        host = line                      # bare IPv6, no port
    elif ' ' in line:
        host, port = line.split()[:2]
    host = clean_host(host)
    if not host:
        return None
    try:
        port = int(port) if port else int(default_port)
    except ValueError:
        return None
    if not 0 < port < 65536:
        return None
    return host, port


def read_lines(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                yield line


def count_lines(path):
    return sum(1 for _ in read_lines(path))


# ---------------------------------------------------------------- network

def resolve_all(host, timeout=4.0, family=socket.AF_INET):
    """All addresses of `host` (IPv4 by default), with a hard timeout."""
    if is_ip(host):
        return [host]
    import threading
    out = []

    def _work():
        try:
            infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
            seen = []
            for info in infos:
                ip = info[4][0]
                if ip not in seen:
                    seen.append(ip)
            out.extend(seen)
        except (OSError, UnicodeError):
            pass

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout)
    return list(out)


_UNVERIFIED = ssl.create_default_context()
_UNVERIFIED.check_hostname = False
_UNVERIFIED.verify_mode = ssl.CERT_NONE


def tls_context(verify=False):
    if verify:
        return ssl.create_default_context()
    return _UNVERIFIED


def read_head(sock, limit=MAX_HEAD):
    """Read until the blank line ending the response headers."""
    data = b''
    while b'\r\n\r\n' not in data and len(data) < limit:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def parse_head(data):
    """Raw response bytes -> dict(status, reason, server, location, headers)."""
    text = data.decode('latin-1', errors='ignore').split('\r\n\r\n', 1)[0]
    lines = [l for l in text.split('\r\n') if l.strip()]
    if not lines or not lines[0].upper().startswith('HTTP/'):
        return None
    first = lines[0].split(' ', 2)
    try:
        status = int(first[1])
    except (IndexError, ValueError):
        return None
    headers = {}
    for l in lines[1:]:
        if ':' in l:
            k, v = l.split(':', 1)
            headers.setdefault(k.strip().lower(), v.strip())
    return {
        'status': status,
        'reason': first[2] if len(first) > 2 else '',
        'server': headers.get('server', ''),
        'location': headers.get('location', ''),
        'headers': headers,
    }


def http_probe(connect_ip, port, host_header, use_tls=False, sni=None,
               method='HEAD', path='/', timeout=5.0, verify=False):
    """Connect to connect_ip:port, optionally TLS (SNI = sni or host_header),
    send one request with Host: host_header and parse the response head.

    Returns dict(status, server, location, tls, elapsed) or raises OSError.
    """
    start = time.monotonic()
    sock = socket.create_connection((connect_ip, int(port)), timeout=timeout)
    try:
        sock.settimeout(timeout)
        tls_version = None
        if use_tls:
            server_name = sni or host_header
            sock = tls_context(verify).wrap_socket(
                sock, server_hostname=None if is_ip(server_name) else server_name)
            tls_version = sock.version()
        default_port = 443 if use_tls else 80
        host_value = host_header if int(port) == default_port else f"{host_header}:{port}"
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host_value}\r\n"
            "User-Agent: Mozilla/5.0 (Linux; Android 13) BugScanX-ZL\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode('ascii', errors='ignore'))
        head = parse_head(read_head(sock))
        if head is None:
            raise ConnectionError('no HTTP response')
        head['tls'] = tls_version
        head['elapsed'] = time.monotonic() - start
        return head
    finally:
        try:
            sock.close()
        except OSError:
            pass


def tls_probe(connect_ip, port, sni, timeout=4.0, verify=False):
    """TLS handshake only. Returns (tls_version, cert_subject_cn) or raises."""
    with socket.create_connection((connect_ip, int(port)), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with tls_context(verify).wrap_socket(
                raw, server_hostname=None if is_ip(sni) else sni) as s:
            cn = ''
            try:
                cert = s.getpeercert() if verify else None
                if cert:
                    for rdn in cert.get('subject', ()):
                        for k, v in rdn:
                            if k == 'commonName':
                                cn = v
            except (ValueError, ssl.SSLError):
                pass
            return s.version(), cn


def proxy_http_probe(proxy_host, proxy_port, target_host, target_port=80,
                     path='/', timeout=6.0):
    """Absolute-URI GET through an HTTP proxy. Returns parsed head or raises."""
    start = time.monotonic()
    with socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout) as s:
        s.settimeout(timeout)
        hp = target_host if int(target_port) == 80 else f"{target_host}:{target_port}"
        s.sendall((
            f"GET http://{hp}{path} HTTP/1.1\r\n"
            f"Host: {hp}\r\n"
            "User-Agent: Mozilla/5.0 BugScanX-ZL\r\n"
            "Proxy-Connection: close\r\nConnection: close\r\n\r\n"
        ).encode())
        head = parse_head(read_head(s))
    if head is None:
        raise ConnectionError('no HTTP response')
    head['elapsed'] = time.monotonic() - start
    return head


def proxy_connect_probe(proxy_host, proxy_port, target_host, target_port=443,
                        timeout=6.0):
    """HTTP CONNECT tunnel test (what SSH / HTTP-Custom style apps use).
    Returns parsed head of the proxy's reply or raises."""
    start = time.monotonic()
    with socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            "User-Agent: Mozilla/5.0 BugScanX-ZL\r\n"
            "Proxy-Connection: keep-alive\r\n\r\n"
        ).encode())
        head = parse_head(read_head(s))
    if head is None:
        raise ConnectionError('no HTTP response')
    head['elapsed'] = time.monotonic() - start
    return head


def tcp_alive(ip, port, timeout=3.0):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except OSError:
        return False
