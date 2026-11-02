import socket

from bugscanx.modules.scanners.scanners.proxy_check import ProxyScannerBase


class FakeConn:
    """Sends a 101 response, then keeps the socket open (like websockets)."""

    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, n):
        if self.chunks:
            return self.chunks.pop(0)
        raise socket.timeout("still open")


def test_101_kept_when_connection_stays_open():
    conn = FakeConn([b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"])
    data = ProxyScannerBase._read_response_head(conn)
    assert data.startswith(b"HTTP/1.1 101")


def test_partial_headers_kept_on_timeout():
    conn = FakeConn([b"HTTP/1.1 200 OK\r\n", b"Server: x\r\n"])
    data = ProxyScannerBase._read_response_head(conn)
    assert b"200 OK" in data and b"Server: x" in data


def test_stops_at_end_of_headers():
    conn = FakeConn([b"HTTP/1.1 101 OK\r\n\r\n", b"BODY-SHOULD-NOT-BE-READ"])
    ProxyScannerBase._read_response_head(conn)
    assert conn.chunks == [b"BODY-SHOULD-NOT-BE-READ"]
