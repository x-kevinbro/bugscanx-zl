import ipaddress
import socket
import ssl
import threading
from datetime import datetime

from .multithread import MultiThread


# Ports that normally speak TLS. With scheme="auto" these are probed over
# HTTPS; every other port is probed over plain HTTP.
HTTPS_PORTS = frozenset({'443', '2053', '2083', '2087', '2096', '8443', '9443'})
SCHEMES = ('auto', 'http', 'https')


def is_scannable_host_line(line):
    """Single source of truth for which host-file lines are scanned, so the
    progress total always matches the number of hosts actually yielded."""
    host = line.strip()
    return bool(host) and not host.startswith(('#', '*'))


def iter_cidr_hosts(network):
    """Usable host addresses of a network, identical on every Python version.

    - IPv4 /31 and /32 (RFC 3021 point-to-point / single host) and
      IPv6 /127 and /128: every address is usable.
    - Other IPv4 networks: skip the network and broadcast addresses.
    - Other IPv6 networks: skip only the subnet-router anycast address.
    """
    max_len = network.max_prefixlen
    if network.prefixlen >= max_len - 1:
        yield from network
        return
    first = int(network.network_address) + 1
    last = int(network.broadcast_address)
    if network.version == 4:
        last -= 1
    addr_cls = type(network.network_address)
    for value in range(first, last + 1):
        yield addr_cls(value)


def count_cidr_hosts(network):
    max_len = network.max_prefixlen
    if network.prefixlen >= max_len - 1:
        return network.num_addresses
    return network.num_addresses - (2 if network.version == 4 else 1)


def classify_error(exc):
    """Short, stable failure reason used in the end-of-scan summary."""
    name = type(exc).__name__
    try:
        import requests
        if isinstance(exc, requests.exceptions.ProxyError):
            return 'proxy error'
        if isinstance(exc, requests.exceptions.SSLError):
            return 'tls error'
        if isinstance(exc, (requests.exceptions.ConnectTimeout,
                            requests.exceptions.ReadTimeout,
                            requests.exceptions.Timeout)):
            return 'timeout'
        if isinstance(exc, requests.exceptions.ConnectionError):
            return 'connection error'
        if isinstance(exc, requests.exceptions.RequestException):
            return 'request error'
    except ImportError:  # pragma: no cover - requests is a hard dependency
        pass
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return 'timeout'
    if isinstance(exc, socket.gaierror):
        return 'dns error'
    if isinstance(exc, ssl.SSLError):
        return 'tls error'
    if isinstance(exc, ConnectionRefusedError):
        return 'refused'
    if isinstance(exc, OSError):
        return 'connection error'
    return name


class BaseScanner(MultiThread):
    def __init__(self, is_cidr_input=False, cidr_ranges=None, output_file=None,
                 scheme='auto', **kwargs):
        super().__init__(**kwargs)
        scheme = (scheme or 'auto').lower()
        if scheme not in SCHEMES:
            raise ValueError(f"scheme must be one of {SCHEMES}, got {scheme!r}")
        self.scheme = scheme
        self.is_cidr_input = is_cidr_input
        self.cidr_ranges = cidr_ranges or []
        self.output_file = output_file
        self._metadata_written = False
        self._file_lock = threading.Lock()

    def write_to_file(self, message):
        if self.output_file:
            with self._file_lock:
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    f.write(message + '\n')

    def write_scan_metadata(self, filepath=None):
        if self.output_file and not self._metadata_written:
            with self._file_lock:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    f.write(f"\nScan Time: {timestamp}\n")
                    if filepath:
                        f.write(f"File Scanned: {filepath}\n\n")
                    elif self.cidr_ranges:
                        f.write(f"CIDR Ranges: {', '.join(self.cidr_ranges)}\n\n")
                self._metadata_written = True

    def get_scheme(self, port):
        port = str(port).strip()
        if self.scheme != 'auto':
            return self.scheme
        return 'https' if port in HTTPS_PORTS else 'http'

    def convert_host_port(self, host, port, scheme=None):
        port = str(port).strip()
        scheme = scheme or self.get_scheme(port)
        default_port = '443' if scheme == 'https' else '80'
        if ':' in host and not host.startswith('['):
            host = f'[{host}]'  # bare IPv6 literal
        return host + ('' if port == default_port else f':{port}')

    def get_url(self, host, port):
        scheme = self.get_scheme(port)
        return f'{scheme}://{self.convert_host_port(host, port, scheme)}'

    def generate_cidr_hosts(self, cidr_ranges):
        for cidr in cidr_ranges:
            try:
                network = ipaddress.ip_network(cidr.strip(), strict=False)
            except ValueError:
                continue
            for ip in iter_cidr_hosts(network):
                yield str(ip)

    def get_total_cidr_hosts(self, cidr_ranges):
        total = 0
        for cidr in cidr_ranges:
            try:
                network = ipaddress.ip_network(cidr.strip(), strict=False)
            except ValueError:
                continue
            total += count_cidr_hosts(network)
        return total

    def set_cidr_total(self, cidr_ranges):
        if self.is_cidr_input and cidr_ranges:
            total_hosts = self.get_total_cidr_hosts(cidr_ranges)
            port_multiplier = len(getattr(self, 'port_list', [1]))
            method_multiplier = len(getattr(self, 'method_list', [1]))
            self.set_total(total_hosts * port_multiplier * method_multiplier)

    def read_lines_count(self, filepath):
        """Number of hosts generate_hosts_from_file() will actually yield
        (blank, comment and wildcard lines excluded; a missing trailing
        newline no longer drops the last host)."""
        count = 0
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    if is_scannable_host_line(line):
                        count += 1
        except (FileNotFoundError, IOError, UnicodeDecodeError):
            return 0
        return count

    def set_host_total(self, host_filepath):
        if host_filepath:
            total_hosts = self.read_lines_count(host_filepath)
            port_multiplier = len(getattr(self, 'port_list', [1]))
            method_multiplier = len(getattr(self, 'method_list', [1]))
            self.set_total(total_hosts * port_multiplier * method_multiplier)

    def generate_hosts_from_file(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                for line in file:
                    if is_scannable_host_line(line):
                        yield line.strip()
        except (FileNotFoundError, IOError, UnicodeDecodeError):
            return
