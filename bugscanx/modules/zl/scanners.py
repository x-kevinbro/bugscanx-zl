"""Scanner engines for the ZL scanner suite (menu 10).

All engines reuse MultiThread/BaseScanner, so they get the same live
progress line, instant Ctrl+C, failure summary and output-file handling
as the main host scanner.
"""
import socket
import ssl
import threading
import time

from bugscanx.modules.scanners.scanners.base import BaseScanner, classify_error
from bugscanx.utils.config import EXCLUDE_LOCATIONS
from . import netprobe

HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443, 9443}


def _short(text, width):
    text = str(text or '')
    return text[:width - 3] + '...' if len(text) > width else text


class _FileScanner(BaseScanner):
    """Base for scanners that read one item per line from a file."""

    def __init__(self, input_file=None, **kwargs):
        super().__init__(**kwargs)
        self.input_file = input_file

    def log_row(self, *cols):
        colors = ('CYAN', 'GREEN', 'MAGENTA', 'ORANGE', 'BLUE', 'LGRAY')
        widths = (6, 5, 16, 6, 16, 0)
        parts = []
        for i, col in enumerate(cols):
            w = widths[i] if i < len(widths) else 0
            text = f"{str(col):<{w}}" if w else str(col)
            parts.append(self.logger.colorize(text, colors[i % len(colors)]))
        self.logger.log('  '.join(parts))

    def write_row(self, *cols):
        widths = (6, 5, 16, 6, 16, 0)
        out = []
        for i, col in enumerate(cols):
            w = widths[i] if i < len(widths) else 0
            out.append(f"{str(col):<{w}}" if w else str(col))
        self.write_to_file('  '.join(out).rstrip())


# ------------------------------------------------------------------ option 7

class RawDomainScanner(_FileScanner):
    """Option 7 - same goal as the normal domain scanner, different method:
    raw sockets instead of `requests` (no connection pool, no redirects,
    no body download, hard per-host timeout). Useful when the requests
    based scanner gets throttled / stuck on a network."""

    def __init__(self, port_list=None, method='HEAD', timeout=4,
                 skip_302=False, **kwargs):
        super().__init__(**kwargs)
        self.port_list = [int(p) for p in (port_list or [80])]
        self.method = method
        self.timeout = float(timeout)
        self.skip_302 = skip_302
        self._dns = {}
        self._dns_lock = threading.Lock()
        if self.input_file:
            self.set_total(netprobe.count_lines(self.input_file) * len(self.port_list))

    def resolve(self, host):
        with self._dns_lock:
            if host in self._dns:
                return self._dns[host]
        ips = netprobe.resolve_all(host, timeout=max(2.0, self.timeout))
        ip = ips[0] if ips else None
        with self._dns_lock:
            self._dns[host] = ip
        return ip

    def generate_tasks(self):
        for line in netprobe.read_lines(self.input_file):
            pair = netprobe.parse_host_ip(line)
            for port in self.port_list:
                yield (pair, port, line)

    def init(self):
        self.write_scan_metadata(self.input_file)
        self.log_row('Method', 'Code', 'Server', 'Port', 'IP', 'Host')
        self.log_row('------', '----', '------', '----', '--', '----')

    def task(self, payload):
        pair, port, line = payload
        if not pair:
            self.record_failure('invalid line', line)
            return
        host, ip = pair
        self.progress(host)
        ip = ip or self.resolve(host)
        if not ip:
            self.record_failure('dns error', host)
            return
        try:
            head = netprobe.http_probe(ip, port, host, use_tls=port in HTTPS_PORTS,
                                       method=self.method, timeout=self.timeout)
        except (OSError, ssl.SSLError, ValueError) as exc:
            self.record_failure(classify_error(exc), f"{host}:{port}: {exc}")
            return
        if self.skip_302 and head['status'] == 302:
            return
        if head['location'] and head['location'] in EXCLUDE_LOCATIONS:
            return
        self.success((host, port, head['status']))
        server = _short(head['server'], 15)
        self.log_row(self.method, head['status'], server, port, ip, host)
        self.write_row(self.method, head['status'], server, port, ip, host)


# ------------------------------------------------------------------ option 5

class ProxyListScanner(_FileScanner):
    """Option 5 - test a list of proxies (ip:port per line).

    mode 'http'    : GET http://target/ through the proxy
    mode 'connect' : CONNECT target:443 (tunnel - what SSH / VPN apps use)
    mode 'both'    : both tests, a proxy is "working" if either passes
    """

    def __init__(self, target='www.google.com', mode='both', timeout=6,
                 show_all=False, default_port=8080, **kwargs):
        super().__init__(**kwargs)
        self.target = netprobe.clean_host(target) or 'www.google.com'
        self.mode = mode
        self.timeout = float(timeout)
        self.show_all = show_all
        self.default_port = default_port
        if self.input_file:
            self.set_total(netprobe.count_lines(self.input_file))

    def generate_tasks(self):
        for line in netprobe.read_lines(self.input_file):
            yield line

    def init(self):
        self.write_scan_metadata(self.input_file)
        self.logger.log(self.logger.colorize(
            f"Target: {self.target}  |  test: {self.mode.upper()}  |  "
            f"timeout {self.timeout:g}s", 'GRAY'))
        self.log_row('Result', 'Code', 'Test', 'ms', 'Server', 'Proxy')
        self.log_row('------', '----', '----', '--', '------', '-----')

    @staticmethod
    def works(test, status):
        if test == 'CONNECT':
            return status == 200
        return 200 <= status < 400

    def task(self, line):
        parsed = netprobe.parse_proxy(line, self.default_port)
        if not parsed:
            self.record_failure('invalid line', line)
            return
        host, port = parsed
        proxy = f"[{host}]:{port}" if ':' in host else f"{host}:{port}"
        self.progress(proxy)
        results = []
        tests = (['HTTP', 'CONNECT'] if self.mode == 'both'
                 else ['CONNECT'] if self.mode == 'connect' else ['HTTP'])
        for test in tests:
            try:
                if test == 'HTTP':
                    head = netprobe.proxy_http_probe(host, port, self.target, 80,
                                                     timeout=self.timeout)
                else:
                    head = netprobe.proxy_connect_probe(host, port, self.target, 443,
                                                        timeout=self.timeout)
                results.append((test, head))
            except (OSError, ValueError) as exc:
                self.record_failure(f"{test.lower()} {classify_error(exc)}",
                                    f"{proxy}: {exc}")
        good = [(t, h) for t, h in results if self.works(t, h['status'])]
        if good:
            self.success(proxy)
        if not good and not (self.show_all and results):
            return
        test, head = (good or results)[0]
        label = 'WORKS' if good else 'FAIL'
        tests_ok = '+'.join(t for t, _ in good) if good else test
        ms = int(head['elapsed'] * 1000)
        server = _short(head['server'], 16)
        self.log_row(label, head['status'], tests_ok, ms, server, proxy)
        if good:
            self.write_row(label, head['status'], tests_ok, ms, server, proxy)


# ------------------------------------------------------------------ option 8

class HostIPCreator(_FileScanner):
    """Option 8 - resolve every domain and write a 'hostname : ip' list
    (ready for the unlimited scanner, which then never needs DNS)."""

    def __init__(self, all_ips=False, timeout=4, **kwargs):
        super().__init__(**kwargs)
        self.all_ips = all_ips
        self.timeout = float(timeout)
        self._seen = set()
        self._seen_lock = threading.Lock()
        if self.input_file:
            self.set_total(netprobe.count_lines(self.input_file))

    def generate_tasks(self):
        for line in netprobe.read_lines(self.input_file):
            yield line

    def init(self):
        self.logger.log(self.logger.colorize(
            "Resolving hosts -> 'hostname : ip' (unresolvable hosts are skipped)", 'GRAY'))

    def task(self, line):
        pair = netprobe.parse_host_ip(line)
        if not pair:
            self.record_failure('invalid line', line)
            return
        host, ip = pair
        self.progress(host)
        ips = [ip] if ip else netprobe.resolve_all(host, timeout=self.timeout)
        if not ips:
            self.record_failure('dns error', host)
            return
        for addr in (ips if self.all_ips else ips[:1]):
            key = (host, addr)
            with self._seen_lock:
                if key in self._seen:
                    continue
                self._seen.add(key)
            self.success(key)
            self.logger.log(f"{self.logger.colorize(f'{host}', 'LGRAY')} : "
                            f"{self.logger.colorize(addr, 'BLUE')}")
            self.write_to_file(f"{host} : {addr}")


# ------------------------------------------------------------------ option 9

class PairTLSScanner(_FileScanner):
    """Option 9 - TLS/SNI handshake on port 443 (no extra setup).

    Accepts plain hostnames or 'hostname : ip' lines; with an IP the
    handshake goes straight to that IP using the hostname as SNI."""

    def __init__(self, port=443, timeout=4, verify_tls=False, **kwargs):
        super().__init__(**kwargs)
        self.port = int(port)
        self.timeout = float(timeout)
        self.verify_tls = verify_tls
        if self.input_file:
            self.set_total(netprobe.count_lines(self.input_file))

    def generate_tasks(self):
        for line in netprobe.read_lines(self.input_file):
            yield line

    def init(self):
        self.write_scan_metadata(self.input_file)
        if not self.verify_tls:
            self.logger.log(self.logger.colorize(
                "Certificates NOT verified - a hit means the SNI handshake works "
                "on this network.", 'GRAY'))
        self.log_row('TLS', 'Port', 'ms', '', 'IP', 'SNI')
        self.log_row('---', '----', '--', '', '--', '---')

    def task(self, line):
        pair = netprobe.parse_host_ip(line)
        if not pair:
            self.record_failure('invalid line', line)
            return
        host, ip = pair
        self.progress(host)
        if not ip:
            ips = netprobe.resolve_all(host, timeout=self.timeout)
            if not ips:
                self.record_failure('dns error', host)
                return
            ip = ips[0]
        start = time.monotonic()
        try:
            version, _ = netprobe.tls_probe(ip, self.port, host,
                                            timeout=self.timeout, verify=self.verify_tls)
        except (OSError, ssl.SSLError, ValueError) as exc:
            self.record_failure(classify_error(exc), f"{host}: {exc}")
            return
        ms = int((time.monotonic() - start) * 1000)
        self.success((host, ip))
        self.log_row(version, self.port, ms, '', ip, host)
        self.write_row(version, self.port, ms, '', ip, host)


# ------------------------------------------------------------------ option 6

class UnlimitedScanner(_FileScanner):
    """Option 6 - for ISPs that freeze while scanning.

    * Reads 'hostname : ip' lines (option 8) and connects straight to the
      IP, so the scan never depends on DNS (the usual thing that freezes).
    * Low default concurrency + hard timeouts.
    * Freeze guard: when many probes in a row fail, all workers pause and
      a watchdog waits until the network answers again; every probe that
      failed during the freeze is re-tested afterwards, so a freeze no
      longer silently loses hosts.
    """

    FREEZE_STREAK = 25          # consecutive failures that count as a freeze
    WATCH_INTERVAL = 3.0
    MAX_FREEZE_WAIT = 300       # give up waiting after 5 minutes
    FALLBACK_PROBES = (('1.1.1.1', 443), ('8.8.8.8', 443), ('1.0.0.1', 80))

    def __init__(self, port_list=None, timeout=5, method='HEAD',
                 freeze_streak=None, retry_rounds=2, delay=0.0, **kwargs):
        super().__init__(**kwargs)
        self.port_list = [int(p) for p in (port_list or [80])]
        self.timeout = float(timeout)
        self.method = method
        self.freeze_streak = int(freeze_streak or self.FREEZE_STREAK)
        self.retry_rounds = int(retry_rounds)
        self.delay = float(delay)

        self._net_lock = threading.Lock()
        self._frozen = threading.Event()
        self._streak = []           # tasks failing in the current streak
        self._pending = []          # failures waiting for the watchdog verdict
        self._retry = []            # tasks to re-test after a freeze
        self._retry_keys = set()
        self._last_good = []        # recent (ip, port) endpoints that answered
        self._freezes = 0
        self._watchdog = None
        self._dns = {}
        if self.input_file:
            self.set_total(netprobe.count_lines(self.input_file) * len(self.port_list))

    # ---------------------------------------------------- freeze handling

    def _on_success(self, ip, port):
        with self._net_lock:
            self._streak.clear()
            if (ip, port) not in self._last_good:
                self._last_good = ([(ip, port)] + self._last_good)[:5]

    def _on_failure(self, task):
        with self._net_lock:
            if self._frozen.is_set():
                self._pending.append(task)
                return
            self._streak.append(task)
            if len(self._streak) < self.freeze_streak:
                return
            self._pending = list(self._streak)
            self._streak.clear()
            self._frozen.set()
        self._start_watchdog()

    def _queue_retry(self, task):
        key = task[:2]
        if key not in self._retry_keys:
            self._retry_keys.add(key)
            self._retry.append(task)

    def _start_watchdog(self):
        if self._watchdog and self._watchdog.is_alive():
            return
        self._watchdog = threading.Thread(target=self._watch, daemon=True)
        self._watchdog.start()

    def _network_up(self):
        # hosts that already answered on THIS network come first: on
        # zero-balance / bug-host setups public resolvers may be blocked
        # even when the network itself is fine
        probes = list(self._last_good) + list(self.FALLBACK_PROBES)
        return any(netprobe.tcp_alive(ip, port, timeout=3) for ip, port in probes)

    def _resume(self, real_freeze):
        with self._net_lock:
            pending, self._pending = self._pending, []
            if real_freeze:
                for t in pending:
                    self._queue_retry(t)
            else:
                # the network answered straight away: those hosts are just
                # dead. Raise the threshold so dead-heavy lists don't keep
                # tripping the guard.
                self.freeze_streak = min(self.freeze_streak * 2, 400)
            self._frozen.clear()

    def _watch(self):
        # false alarm check: a run of dead hosts is not a frozen network
        if self._network_up():
            self._resume(real_freeze=False)
            return
        self._freezes += 1
        self.logger.log(self.logger.colorize(
            "Network freeze detected - pausing, will resume automatically "
            "when the connection is back...", 'YELLOW'))
        started = time.monotonic()
        while not self._stop.is_set():
            for _ in self.sleep(self.WATCH_INTERVAL):
                pass
            if self._stop.is_set():
                break
            if self._network_up():
                self.logger.log(self.logger.colorize(
                    f"Connection is back after {time.monotonic() - started:.0f}s "
                    f"- resuming scan.", 'GREEN'))
                break
            if time.monotonic() - started > self.MAX_FREEZE_WAIT:
                self.logger.log(self.logger.colorize(
                    "Network still down after 5 min - continuing anyway "
                    "(failed hosts will be retried at the end).", 'RED'))
                break
        self._resume(real_freeze=True)

    def _wait_if_frozen(self):
        while self._frozen.is_set() and not self._stop.is_set():
            time.sleep(0.2)

    # ------------------------------------------------------------- tasks

    def _wait_queue_empty(self):
        while self._queue.unfinished_tasks and not self._stop.is_set():
            time.sleep(0.2)

    def generate_tasks(self):
        for line in netprobe.read_lines(self.input_file):
            pair = netprobe.parse_host_ip(line)
            for port in self.port_list:
                yield (pair, port, line, 0)
        # retry rounds: everything that failed during a freeze
        for round_no in range(1, self.retry_rounds + 1):
            self._wait_queue_empty()
            while self._frozen.is_set() and not self._stop.is_set():
                time.sleep(0.3)
            with self._net_lock:
                batch, self._retry = self._retry, []
                self._retry_keys.clear()
            if not batch or self._stop.is_set():
                return
            self.logger.log(self.logger.colorize(
                f"Retry round {round_no}: re-testing {len(batch)} probe(s) "
                f"that failed during a network freeze", 'CYAN'))
            with self._lock:
                self._total += len(batch)
            for pair, port, line, _ in batch:
                yield (pair, port, line, round_no)

    def init(self):
        self.write_scan_metadata(self.input_file)
        self.logger.log(self.logger.colorize(
            f"Freeze guard ON - pause after {self.freeze_streak} failures in a row, "
            f"{self.retry_rounds} retry round(s)", 'GRAY'))
        self.log_row('Method', 'Code', 'Server', 'Port', 'IP', 'Host')
        self.log_row('------', '----', '------', '----', '--', '----')

    def resolve(self, host):
        if host in self._dns:
            return self._dns[host]
        ips = netprobe.resolve_all(host, timeout=self.timeout)
        self._dns[host] = ips[0] if ips else None
        return self._dns[host]

    def task(self, task):
        pair, port, line, round_no = task
        if not pair:
            self.record_failure('invalid line', line)
            return
        self._wait_if_frozen()
        if self._stop.is_set():
            return
        host, ip = pair
        self.progress(host)
        ip = ip or self.resolve(host)
        if not ip:
            self.record_failure('dns error', host)
            return
        if self.delay:
            for _ in self.sleep(self.delay):
                pass
        try:
            head = netprobe.http_probe(ip, port, host, use_tls=port in HTTPS_PORTS,
                                       method=self.method, timeout=self.timeout)
        except (OSError, ssl.SSLError, ValueError) as exc:
            reason = classify_error(exc)
            if reason in ('timeout', 'connection error', 'refused'):
                self._on_failure(task)
            self.record_failure(reason, f"{host}:{port}: {exc}")
            return
        self._on_success(ip, port)
        if head['location'] and head['location'] in EXCLUDE_LOCATIONS:
            return
        self.success((host, port))
        server = _short(head['server'], 15)
        self.log_row(self.method, head['status'], server, port, ip, host)
        self.write_row(self.method, head['status'], server, port, ip, host)

    def complete(self):
        super().complete()
        if self._freezes:
            self.logger.log(self.logger.colorize(
                f"Network froze {self._freezes} time(s) during the scan - "
                f"failed probes were re-tested automatically.", 'GRAY'))
