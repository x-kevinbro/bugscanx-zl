"""Response checker must report status + server from the headers without
waiting for (possibly huge or trickling) bodies."""
import socket
import threading
import time

from bugscanx.modules.scanners.scanners.direct import HostDirectScanner


def _serve(kind):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)

    def handle(c):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = c.recv(4096)
                if not chunk:
                    return
                data += chunk
            if kind == "trickle":
                c.sendall(b"HTTP/1.1 200 OK\r\nServer: trickle\r\nContent-Length: 50\r\n\r\n")
                for _ in range(50):
                    c.sendall(b"x")
                    time.sleep(0.2)
            elif kind == "excluded":
                c.sendall(b"HTTP/1.1 302 Found\r\nLocation: https://jio.com/BalanceExhaust\r\n"
                          b"Content-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


def _scan(tmp_path, port):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("127.0.0.1\n")
    s = HostDirectScanner(method_list=["GET", "HEAD"], input_file=str(hosts),
                          port_list=[str(port)], timeout=3)
    s.threads = 4
    t0 = time.monotonic()
    s.start()
    return s, time.monotonic() - t0


def test_slow_body_does_not_slow_the_scan(tmp_path):
    srv, port = _serve("trickle")
    try:
        s, elapsed = _scan(tmp_path, port)
    finally:
        srv.close()
    assert elapsed < 3          # body would take 10 s to download
    hits = s.get_success()
    assert {h["method"] for h in hits} == {"GET", "HEAD"}
    assert all(h["status_code"] == 200 and h["server"] == "trickle" for h in hits)


def test_excluded_redirect_is_not_a_hit(tmp_path):
    srv, port = _serve("excluded")
    try:
        s, _ = _scan(tmp_path, port)
    finally:
        srv.close()
    assert s.get_success() == []


def test_dns_resolved_once_per_host(tmp_path, monkeypatch):
    from bugscanx.modules.scanners.scanners import direct
    calls = []
    monkeypatch.setattr(direct, "resolve_host",
                        lambda h, timeout=None: calls.append(h) or None)
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("a.invalid\n")
    s = HostDirectScanner(method_list=["GET", "HEAD"], input_file=str(hosts),
                          port_list=["80", "443", "8080"], timeout=1)
    s.threads = 1
    s.start()
    assert calls == ["a.invalid"]
