import socket

from .base import BaseScanner, classify_error


class PingScannerBase(BaseScanner):
    def __init__(
        self,
        port_list=None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.port_list = port_list or []

    def resolve_ip(self, host):
        try:
            return socket.gethostbyname(host)
        except Exception:
            return "Unknown"

    def task(self, payload):
        host = payload['host']
        port = payload['port']

        if not host:
            return

        try:
            # create_connection() handles IPv4 and IPv6 and raises on
            # refused/timeout, so each failure reason is reported
            with socket.create_connection((host, int(port)), timeout=2):
                pass
        except (OSError, ValueError) as exc:
            self.record_failure(classify_error(exc), f"{host}:{port}: {exc}")
        else:
            self._handle_success({'host': host, 'port': port})

        self.progress(f"{host}:{port}")


class HostPingScanner(PingScannerBase):
    def __init__(
        self,
        input_file=None,
        port_list=None,
        threads=50,
        output_file=None,
        **kwargs
    ):
        super().__init__(port_list=port_list, threads=threads, is_cidr_input=False, output_file=output_file, **kwargs)
        self.input_file = input_file

        if self.input_file:
            self.set_host_total(self.input_file)

    def init(self):
        self.write_scan_metadata(self.input_file)
        self.log_info(port='Port', ip='IP', host='Host')
        self.log_info(port='----', ip='--', host='----')

    def log_info(self, **kwargs):
        log_parts = [
            self.logger.colorize('{port:<6}', 'CYAN'),
            self.logger.colorize('{ip:<15}', 'YELLOW'),
            self.logger.colorize('{host}', 'LGRAY'),
        ]

        formatted_message = '  '.join(log_parts).format(**kwargs)
        self.logger.log(formatted_message)

        if self.output_file and 'port' in kwargs and kwargs['port']:
            plain_message = f"{kwargs['port']:<6}  {kwargs['ip']:<15}  {kwargs['host']}"
            self.write_to_file(plain_message)

    def _handle_success(self, data):
        ip = self.resolve_ip(data['host'])
        data['ip'] = ip
        self.success(data)
        self.log_info(**data)

    def generate_tasks(self):
        for host in self.generate_hosts_from_file(self.input_file):
            for port in self.port_list:
                yield {
                    'host': host,
                    'port': port,
                }


class CIDRPingScanner(PingScannerBase):
    def __init__(
        self,
        cidr_ranges=None,
        port_list=None,
        threads=50,
        output_file=None,
        **kwargs
    ):
        super().__init__(port_list=port_list, threads=threads, is_cidr_input=True, cidr_ranges=cidr_ranges, output_file=output_file, **kwargs)
        self.cidr_ranges = cidr_ranges or []

        if self.cidr_ranges:
            self.set_cidr_total(self.cidr_ranges)

    def log_info(self, **kwargs):
        log_parts = [
            self.logger.colorize('{port:<6}', 'CYAN'),
            self.logger.colorize('{host}', 'LGRAY'),
        ]

        formatted_message = '  '.join(log_parts).format(**kwargs)
        self.logger.log(formatted_message)

        # Write plain text version to file
        if self.output_file and 'port' in kwargs and kwargs['port']:
            plain_message = f"{kwargs['port']:<6}  {kwargs['host']}"
            self.write_to_file(plain_message)

    def _handle_success(self, data):
        self.success(data)
        self.log_info(**data)

    def generate_tasks(self):
        for host in self.generate_cidr_hosts(self.cidr_ranges):
            for port in self.port_list:
                yield {
                    'host': host,
                    'port': port,
                }

    def init(self):
        self.write_scan_metadata()
        self.log_info(port='Port', host='Host')
        self.log_info(port='----', host='----')
