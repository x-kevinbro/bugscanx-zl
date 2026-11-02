import socket
import threading
import http.server
import socketserver

import pytest

from bugscanx.modules.zl import netprobe
from bugscanx.modules.zl import scanners as zs


# ----------------------------------------------------------------- parsing

@pytest.mark.parametrize("line,expected", [
    ("example.com : 1.2.3.4", ("example.com", "1.2.3.4")),
    ("example.com:1.2.3.4", ("example.com", "1.2.3.4")),
    ("example.com 1.2.3.4", ("example.com", "1.2.3.4")),
    ("example.com,1.2.3.4", ("example.com", "1.2.3.4")),
    ("example.com\t1.2.3.4", ("example.com", "1.2.3.4")),
    ("1.2.3.4 example.com", ("example.com", "1.2.3.4")),
    ("https://WWW.Example.com/path", ("www.example.com", None)),
    ("example.com", ("example.com", None)),
    ("10.0.0.1", ("10.0.0.1", "10.0.0.1")),
    ("  # comment", None),
    ("", None),
    ("*.example.com", None),
])
def test_parse_host_ip(line, expected):
    assert netprobe.parse_host_ip(line) == expected


@pytest.mark.parametrize("line,expected", [
    ("172.22.2.38:80", ("172.22.2.38", 80)),
    ("http://proxy.example.com:3128", ("proxy.example.com", 3128)),
    ("user:pass@10.0.0.1:8080", ("10.0.0.1", 8080)),
    ("[::1]:8080", ("::1", 8080)),
    ("10.0.0.1", ("10.0.0.1", 8080)),
    ("10.0.0.1 3128", ("10.0.0.1", 3128)),
    ("10.0.0.1:99999", None),
    ("10.0.0.1:abc", None),
    ("# nope", None),
])
def test_parse_proxy(line, expected):
    assert netprobe.parse_proxy(line) == expected


def test_parse_head():
    head = netprobe.parse_head(b"HTTP/1.1 301 Moved\r\nServer: cloudflare\r\n"
                               b"Location: https://x/\r\n\r\nbody")
    assert head['status'] == 301 and head['server'] == 'cloudflare'
    assert head['location'] == 'https://x/'
    assert netprobe.parse_head(b"garbage") is None


# ------------------------------------------------------------ local servers

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Server', 'zltest')
        self.send_header('X-Host', self.headers.get('Host', ''))
        self.end_headers()

    do_GET = do_HEAD

    def log_message(self, *a):
        pass


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    """Fake proxy: answers absolute-URI GET with 200 and CONNECT with 200."""

    def do_GET(self):
        code = 200 if self.path.startswith('http://') else 400
        self.send_response(code)
        self.send_header('Server', 'fakeproxy')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_CONNECT(self):
        self.send_response(200, 'Connection established')
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def proxy():
    srv = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _ProxyHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def _closed_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_http_probe_sends_host_header(server):
    head = netprobe.http_probe('127.0.0.1', server, 'bug.example.com', timeout=3)
    assert head['status'] == 200
    assert head['headers']['x-host'] == f'bug.example.com:{server}'


def test_raw_domain_scanner(tmp_path, server):
    hosts = tmp_path / 'hosts.txt'
    hosts.write_text(f"a.example.com : 127.0.0.1\nb.example.com:127.0.0.1\n# c\n")
    out = tmp_path / 'out.txt'
    sc = zs.RawDomainScanner(input_file=str(hosts), port_list=[server],
                             timeout=3, output_file=str(out), threads=4)
    sc.start()
    assert sc._success_count == 2
    text = out.read_text()
    assert 'a.example.com' in text and 'b.example.com' in text


def test_proxy_scanner(tmp_path, proxy):
    dead = _closed_port()
    plist = tmp_path / 'proxies.txt'
    plist.write_text(f"127.0.0.1:{proxy}\n127.0.0.1:{dead}\njunk:::\n")
    out = tmp_path / 'working.txt'
    sc = zs.ProxyListScanner(input_file=str(plist), target='example.com',
                             mode='both', timeout=3, output_file=str(out), threads=4)
    sc.start()
    assert sc.get_success() == [f"127.0.0.1:{proxy}"]
    assert 'HTTP+CONNECT' in out.read_text()
    assert f":{dead}" not in out.read_text()


def test_hostip_creator(tmp_path):
    src = tmp_path / 'domains.txt'
    src.write_text("localhost\nlocalhost\nno-such-host.invalid\n")
    out = tmp_path / 'hostip.txt'
    sc = zs.HostIPCreator(input_file=str(src), output_file=str(out), timeout=3, threads=2)
    sc.start()
    lines = [l for l in out.read_text().splitlines() if l.strip()]
    assert lines == ['localhost : 127.0.0.1']
    assert netprobe.parse_host_ip(lines[0]) == ('localhost', '127.0.0.1')


def test_unlimited_scanner_hits(tmp_path, server):
    src = tmp_path / 'pairs.txt'
    src.write_text("x.example.com : 127.0.0.1\ny.example.com : 127.0.0.1\n")
    out = tmp_path / 'u.txt'
    sc = zs.UnlimitedScanner(input_file=str(src), port_list=[server], timeout=3,
                             output_file=str(out), threads=2)
    sc.start()
    assert sc._success_count == 2


def test_unlimited_freeze_is_retried(tmp_path, server, monkeypatch):
    """Simulate a freeze: the first N probes fail, the network 'comes
    back', and every probe lost during the freeze is re-tested."""
    src = tmp_path / 'pairs.txt'
    src.write_text(''.join(f"h{i}.example.com : 127.0.0.1\n" for i in range(12)))
    out = tmp_path / 'u.txt'
    sc = zs.UnlimitedScanner(input_file=str(src), port_list=[server], timeout=2,
                             output_file=str(out), threads=3, freeze_streak=4)
    sc.WATCH_INTERVAL = 0.1
    real = netprobe.http_probe
    state = {'down': True, 'calls': 0}
    lock = threading.Lock()

    def flaky(*a, **kw):
        with lock:
            state['calls'] += 1
            down = state['down']
        if down:
            raise socket.timeout('frozen')
        return real(*a, **kw)

    checks = {'n': 0}

    def network_up():
        checks['n'] += 1
        if checks['n'] == 1:
            return False           # first check: really frozen
        state['down'] = False      # network comes back
        return True

    monkeypatch.setattr(zs.netprobe, 'http_probe', flaky)
    monkeypatch.setattr(sc, '_network_up', network_up)
    sc.start()
    assert sc._freezes == 1
    assert sc._success_count == 12          # nothing lost


def test_unlimited_false_alarm_raises_threshold(tmp_path):
    dead = _closed_port()
    src = tmp_path / 'pairs.txt'
    src.write_text(''.join(f"d{i}.example.com : 127.0.0.1\n" for i in range(6)))
    sc = zs.UnlimitedScanner(input_file=str(src), port_list=[dead], timeout=1,
                             output_file=str(tmp_path / 'o.txt'), threads=1,
                             freeze_streak=3)
    sc._network_up = lambda: True
    sc.start()
    assert sc._freezes == 0
    assert sc.freeze_streak >= 6
    assert sc._success_count == 0


def test_tls_scanner_failure_is_counted(tmp_path, server):
    # plain-HTTP server -> TLS handshake must fail cleanly (no hit, no crash)
    src = tmp_path / 'hosts.txt'
    src.write_text("a.example.com : 127.0.0.1\n")
    sc = zs.PairTLSScanner(input_file=str(src), port=server, timeout=2,
                           output_file=str(tmp_path / 't.txt'), threads=1)
    sc.start()
    assert sc._success_count == 0
    assert sc.failure_summary()


def test_menu_has_nine_options():
    from bugscanx.modules.zl import menu
    assert sorted(menu.HANDLERS) == [str(i) for i in range(1, 10)]
    assert menu.parse_cidr_text("1.2.3.4, 104.18.0.0/16, bad") == ['1.2.3.4/32', '104.18.0.0/16']


def test_main_menu_has_zl_entry():
    from bugscanx import main, handler
    assert '10' in main.MENU_OPTIONS
    assert callable(getattr(handler, 'run_10'))
