import socket
import ssl

from bugscanx.utils.domains import resolve_host
from .base import BaseScanner, classify_error


TLS_UNVERIFIED_NOTE = (
    "Note: certificates are NOT verified in this mode - a successful "
    "handshake means the SNI is reachable, not that its certificate is trusted."
)


class SSLScannerBase(BaseScanner):
    def __init__(
        self,
        verify_tls=False,
        port=443,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.verify_tls = bool(verify_tls)
        self.port = int(port)
        if self.verify_tls:
            # full chain + hostname validation: only trusted certs are hits
            self.tls_context = ssl.create_default_context()
        else:
            # probing mode: any certificate is accepted so that SNI hosts
            # with self-signed / mismatched certs are still discovered
            self.tls_context = ssl.create_default_context()
            self.tls_context.check_hostname = False
            self.tls_context.verify_mode = ssl.CERT_NONE

    def log_tls_mode(self):
        if self.verify_tls:
            self.logger.log(self.logger.colorize(
                "Certificate verification ON - only trusted certificates are reported.",
                'GRAY'))
        else:
            self.logger.log(self.logger.colorize(TLS_UNVERIFIED_NOTE, 'GRAY'))

    def resolve_ip(self, host):
        return resolve_host(host, timeout=4.0) or "Unknown"

    def task(self, payload):
        sni = payload['host']

        if not sni:
            return

        try:
            with socket.create_connection((sni, self.port), timeout=2) as socket_client:
                with self.tls_context.wrap_socket(
                    socket_client,
                    server_hostname=sni,
                    do_handshake_on_connect=True,
                ) as ssl_socket:

                    data = {
                        'sni': sni,
                        'tls_version': ssl_socket.version()
                    }

                    self._handle_success(data)
        except (OSError, ssl.SSLError) as exc:
            self.record_failure(classify_error(exc), f"{sni}: {exc}")

        self.progress(sni)


class HostSSLScanner(SSLScannerBase):
    def __init__(
        self,
        input_file=None,
        threads=50,
        output_file=None,
        **kwargs
    ):
        super().__init__(threads=threads, is_cidr_input=False, output_file=output_file, **kwargs)
        self.input_file = input_file

        if self.input_file:
            self.set_host_total(self.input_file)

    def log_info(self, **kwargs):
        messages = [
            self.logger.colorize('{tls_version:<8}', 'CYAN'),
            self.logger.colorize('{ip:<15}', 'YELLOW'),
            self.logger.colorize('{sni}', 'LGRAY'),
        ]
        formatted_message = '  '.join(messages).format(**kwargs)
        self.logger.log(formatted_message)

        if self.output_file and 'tls_version' in kwargs and kwargs['tls_version']:
            plain_message = f"{kwargs['tls_version']:<8}  {kwargs['ip']:<15}  {kwargs['sni']}"
            self.write_to_file(plain_message)

    def generate_tasks(self):
        for host in self.generate_hosts_from_file(self.input_file):
            yield {
                'host': host,
            }

    def init(self):
        self.write_scan_metadata(self.input_file)
        self.log_info(tls_version='TLS', ip='IP', sni='SNI')
        self.log_info(tls_version='---', ip='--', sni='---')
        self.log_tls_mode()

    def _handle_success(self, data):
        data['ip'] = self.resolve_ip(data['sni'])
        self.success(data)
        self.log_info(**data)


class CIDRSSLScanner(SSLScannerBase):
    def __init__(
        self,
        cidr_ranges=None,
        threads=50,
        output_file=None,
        **kwargs
    ):
        super().__init__(threads=threads, is_cidr_input=True, cidr_ranges=cidr_ranges, output_file=output_file, **kwargs)
        self.cidr_ranges = cidr_ranges or []

        if self.cidr_ranges:
            self.set_cidr_total(self.cidr_ranges)

    def log_info(self, **kwargs):
        messages = [
            self.logger.colorize('{tls_version:<8}', 'CYAN'),
            self.logger.colorize('{sni}', 'LGRAY'),
        ]
        formatted_message = '  '.join(messages).format(**kwargs)
        self.logger.log(formatted_message)

        if self.output_file and 'tls_version' in kwargs and kwargs['tls_version']:
            plain_message = f"{kwargs['tls_version']:<8}  {kwargs['sni']}"
            self.write_to_file(plain_message)

    def generate_tasks(self):
        for host in self.generate_cidr_hosts(self.cidr_ranges):
            yield {
                'host': host,
            }

    def init(self):
        self.write_scan_metadata()
        self.log_info(tls_version='TLS', sni='SNI')
        self.log_info(tls_version='---', sni='---')
        self.log_tls_mode()

    def _handle_success(self, data):
        self.success(data)
        self.log_info(**data)
