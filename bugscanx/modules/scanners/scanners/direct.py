import threading

import requests
import urllib3
from requests.adapters import HTTPAdapter

from bugscanx.utils.domains import resolve_host
from .base import BaseScanner
from bugscanx.utils.config import EXCLUDE_LOCATIONS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DirectScannerBase(BaseScanner):
    DEFAULT_TIMEOUT = 3
    DEFAULT_RETRY = 2

    def __init__(
        self,
        method_list=None,
        port_list=None,
        no302=False,
        timeout=None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.method_list = method_list or []
        self.port_list = port_list or []
        self.no302 = no302
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self._tls = threading.local()

    def _session(self):
        """One keep-alive session per worker thread (never shared across
        threads, so hundreds of workers can run without session races)."""
        session = getattr(self._tls, 'session', None)
        if session is None:
            session = requests.Session()
            session.verify = False
            adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8)
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            self._tls.session = session
        return session

    def request(self, method, url, **kwargs):
        method = method.upper()
        kwargs['timeout'] = self.timeout
        self.progress(method, url)
        try:
            return self._session().request(method, url, **kwargs)
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
            requests.exceptions.Timeout,
            requests.exceptions.RequestException
        ):
            return None

    def task(self, payload):
        method = payload['method']
        host = payload['host']
        port = payload['port']

        ip = resolve_host(host, timeout=max(2.0, float(self.timeout)))
        if not ip:
            return

        response = self.request(method, self.get_url(host, port), verify=False, allow_redirects=False)

        if response is None:
            return

        if self.no302 and response.status_code == 302:
            return

        if not self.no302:
            location = response.headers.get('location', '')
            if location and location in EXCLUDE_LOCATIONS:
                return

        data = {
            'method': method,
            'host': host,
            'port': port,
            'status_code': response.status_code,
            'server': response.headers.get('server', ''),
            'ip': ip
        }

        if not self.no302:
            data['location'] = response.headers.get('location', '')

        self._handle_success(data)


class HostDirectScanner(DirectScannerBase):
    def __init__(
        self,
        method_list=None,
        input_file=None,
        port_list=None,
        no302=False,
        threads=50,
        output_file=None,
        timeout=None,
        **kwargs
    ):
        super().__init__(
            method_list=method_list,
            port_list=port_list,
            no302=no302,
            threads=threads,
            is_cidr_input=False,
            output_file=output_file,
            timeout=timeout,
            **kwargs
        )
        self.input_file = input_file

        if self.input_file:
            self.set_host_total(self.input_file)

    def log_info(self, **kwargs):
        server = kwargs.get('server', '')
        kwargs['server'] = ((server[:12] + "...") if len(server) > 12
                          else f"{server:<12}")

        messages = [
            self.logger.colorize(f"{{method:<6}}", "CYAN"),
            self.logger.colorize(f"{{status_code:<4}}", "GREEN"),
            self.logger.colorize(f"{{server:<15}}", "MAGENTA"),
            self.logger.colorize(f"{{port:<4}}", "ORANGE"),
            self.logger.colorize(f"{{ip:<16}}", "BLUE"),
            self.logger.colorize(f"{{host}}", "LGRAY")
        ]

        formatted_message = '  '.join(messages).format(**kwargs)
        self.logger.log(formatted_message)

        if self.output_file and 'method' in kwargs and kwargs['method']:
            plain_message = f"{kwargs['method']:<6}  {kwargs['status_code']:<4}  {kwargs['server']:<15}  {kwargs['port']:<4}  {kwargs['ip']:<16}  {kwargs['host']}"
            self.write_to_file(plain_message)

    def generate_tasks(self):
        for method in self.method_list:
            for host in self.generate_hosts_from_file(self.input_file):
                for port in self.port_list:
                    yield {
                        'method': method.upper(),
                        'host': host,
                        'port': port,
                    }

    def init(self):
        self.write_scan_metadata(self.input_file)
        self.log_info(method='Method', status_code='Code', server='Server', port='Port', ip='IP', host='Host')
        self.log_info(method='------', status_code='----', server='------', port='----', ip='--', host='----')

    def _handle_success(self, data):
        self.success(data)
        self.log_info(**data)


class CIDRDirectScanner(DirectScannerBase):
    def __init__(
        self,
        method_list=None,
        cidr_ranges=None,
        port_list=None,
        no302=False,
        threads=50,
        output_file=None,
        timeout=None,
        **kwargs
    ):
        super().__init__(
            method_list=method_list,
            port_list=port_list,
            no302=no302,
            threads=threads,
            is_cidr_input=True,
            cidr_ranges=cidr_ranges,
            output_file=output_file,
            timeout=timeout,
            **kwargs
        )
        self.cidr_ranges = cidr_ranges or []

        if self.cidr_ranges:
            self.set_cidr_total(self.cidr_ranges)

    def log_info(self, **kwargs):
        server = kwargs.get('server', '')
        kwargs['server'] = ((server[:12] + "...") if len(server) > 12
                          else f"{server:<12}")

        messages = [
            self.logger.colorize(f"{{method:<6}}", "CYAN"),
            self.logger.colorize(f"{{status_code:<4}}", "GREEN"),
            self.logger.colorize(f"{{server:<15}}", "MAGENTA"),
            self.logger.colorize(f"{{port:<4}}", "ORANGE"),
            self.logger.colorize(f"{{host}}", "LGRAY")
        ]

        formatted_message = '  '.join(messages).format(**kwargs)
        self.logger.log(formatted_message)

        if self.output_file and 'method' in kwargs and kwargs['method']:
            plain_message = f"{kwargs['method']:<6}  {kwargs['status_code']:<4}  {kwargs['server']:<15}  {kwargs['port']:<4}  {kwargs['host']}"
            self.write_to_file(plain_message)

    def generate_tasks(self):
        for method in self.method_list:
            for host in self.generate_cidr_hosts(self.cidr_ranges):
                for port in self.port_list:
                    yield {
                        'method': method.upper(),
                        'host': host,
                        'port': port,
                    }

    def init(self):
        self.write_scan_metadata()
        self.log_info(method='Method', status_code='Code', server='Server', port='Port', host='Host')
        self.log_info(method='------', status_code='----', server='------', port='----', host='----')

    def _handle_success(self, data):
        self.success(data)
        self.log_info(**data)
