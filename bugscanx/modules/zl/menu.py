"""ZL SCANNER - menu 10: nine focused scanners in one place.

 1 IP scanner            IP / CIDR / file of CIDRs
 2 Reverse IP            IP -> hostnames on that IP
 3 Subdomain scanner     file of domains -> subdomains
 4 Normal domain scanner file of domains -> HTTP results (requests engine)
 5 Proxy scanner         file of ip:port proxies -> which ones work
 6 Unlimited scanner     for ISPs that freeze while scanning
 7 Normal domain (alt)   same goal as 4, raw-socket engine
 8 Hostname : IP creator domains -> 'hostname : ip' file (for option 6)
 9 TLS scanner           SNI handshake on 443 (works for SSH/SSL setups)
"""
import ipaddress
import os

from rich import print

from bugscanx.utils.files import check_output_path, resolve_output_mode
from bugscanx.utils.prompts import get_input, get_confirm

ZL_OPTIONS = {
    '1': ("IP SCANNER", "IP / CIDR (eg 104.18.0.0/16) or a file of CIDRs"),
    '2': ("REVERSE IP", "IP address -> hostnames linked to it"),
    '3': ("SUBDOMAIN SCANNER", "file with domains -> subdomains"),
    '4': ("NORMAL DOMAIN SCANNER", "file with domains -> scan result per domain"),
    '5': ("PROXY SCANNER", "file with proxies (ip:port) -> working proxies"),
    '6': ("UNLIMITED SCANNER", "for ISPs that freeze while scanning"),
    '7': ("DOMAIN SCANNER (ALT)", "same as 4, different (raw socket) method"),
    '8': ("HOSTNAME : IP CREATOR", "build a 'hostname : ip' list for option 6"),
    '9': ("TLS SCANNER", "TLS/SNI handshake on port 443"),
    '0': ("BACK", ""),
}


# ------------------------------------------------------------------ helpers

def ask_output(default, input_file=None):
    """Ask for an output file; returns path or None (cancelled).
    Existing files: Append / Overwrite / Cancel."""
    while True:
        output = get_input("Enter output filename", default=default)
        error = check_output_path(output, input_files=[input_file])
        if error:
            print(f"[bold red] {error}[/bold red]")
            continue
        mode = resolve_output_mode(output, input_files=[input_file])
        if mode is None:
            print("[yellow] Cancelled - nothing was written.[/yellow]")
            return None
        if mode == 'w':
            open(output, 'w', encoding='utf-8').close()
        return output


def ask_threads(default):
    return int(get_input("Enter threads", validators="number", default=str(default)))


def ask_timeout(default):
    return int(get_input("Enter timeout", validators="number", default=str(default),
                         instruction="(seconds)"))


def ask_ports(default):
    from bugscanx.modules.scanners.host_scanner import parse_ports
    ports = []
    for p in parse_ports(get_input("Enter port(s)", validators="number", default=default)):
        if p.isdigit() and 0 < int(p) < 65536:
            ports.append(p)
    return ports or [default]


def ask_file(message="Enter path to file.txt"):
    return get_input(message, input_type="file", validators="file")


def default_out(input_file, suffix):
    base = os.path.splitext(os.path.basename(input_file or 'results'))[0]
    folder = os.path.dirname(input_file or '')
    return os.path.join(folder, f"{base}_{suffix}.txt")


def parse_cidr_text(text):
    """'1.2.3.4, 104.18.0.0/16' -> valid networks as strings."""
    out = []
    for part in str(text).replace(';', ',').split(','):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError:
            print(f"[yellow] skipped invalid CIDR/IP: {part}[/yellow]")
    return out


def read_cidr_file(path):
    out = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            try:
                out.append(str(ipaddress.ip_network(line, strict=False)))
            except ValueError:
                pass
    return out


def run_scanner(scanner, threads):
    scanner.threads = threads
    scanner.start()
    if scanner.output_file:
        print(f"[bold green] Results saved to {scanner.output_file}[/bold green]")


# ------------------------------------------------------------------ options

def opt_ip_scanner():
    target = get_input("Enter IP / CIDR or path to file.txt",
                       validators="required", instruction="(eg 104.18.0.0/16)")
    if os.path.isfile(target):
        cidrs = read_cidr_file(target)
        source = target
    else:
        cidrs = parse_cidr_text(target)
        source = None
    if not cidrs:
        print("[bold red] No valid IP / CIDR found.[/bold red]")
        return
    from bugscanx.modules.scanners.scanners.base import count_cidr_hosts
    total = sum(count_cidr_hosts(ipaddress.ip_network(c)) for c in cidrs)
    print(f"[cyan] {len(cidrs)} range(s), {total:,} IP(s) to scan[/cyan]")
    ports = ask_ports("80")
    timeout = ask_timeout(3)
    method = get_input("Select HTTP method", input_type="choice",
                       choices=["HEAD", "GET"])
    output = ask_output(default_out(source, 'ipscan') if source else 'ipscan_results.txt',
                        source)
    if not output:
        return
    threads = ask_threads(100)
    from bugscanx.modules.scanners.scanners.direct import CIDRDirectScanner
    scanner = CIDRDirectScanner(method_list=[method], cidr_ranges=cidrs,
                                port_list=ports, timeout=timeout,
                                output_file=output, scheme='auto')
    run_scanner(scanner, threads)


def opt_reverse_ip():
    target = get_input("Enter IP address (or path to file.txt with IPs)",
                       validators="required")
    from bugscanx.modules.scrapers.iplookup.iplookup import IPLookup
    from bugscanx.modules.scrapers.iplookup.utils import process_file, process_input
    if os.path.isfile(target):
        ips = process_file(target)
        default = default_out(target, 'hostnames')
        source = target
    else:
        ips = []
        for part in target.split(','):
            part = part.strip()
            if not part:
                continue
            try:
                ipaddress.ip_network(part, strict=False)
            except ValueError:
                print(f"[yellow] skipped invalid IP: {part}[/yellow]")
                continue
            ips.extend(process_input(part))
        default = f"{target.split(',')[0].strip().replace('/', '-')}_hostnames.txt"
        source = None
    if not ips:
        print("[bold red] No valid IP found.[/bold red]")
        return
    if len(ips) > 256 and not get_confirm(
            f" {len(ips)} IPs - reverse lookups are slow (rate limited). Continue?",
            default=False):
        return
    output = ask_output(default, source)
    if not output:
        return
    print()
    found = IPLookup().run(ips, output) or set()
    for host in sorted(found)[:50]:
        print(f"   {host}")
    if len(found) > 50:
        print(f"   [dim]... and {len(found) - 50} more in {output}[/dim]")


def opt_subdomain_scanner():
    path = ask_file("Enter path to file.txt with domains")
    from bugscanx.utils.domains import read_hosts_file, unique_main_domains
    from bugscanx.modules.scrapers.subfinder.subfinder import (
        SubFinder, DEFAULT_THREADS, ask_source_mode)
    from bugscanx.modules.scrapers.subfinder.sources import get_sources
    hosts = [h.lstrip('*.') for h in read_hosts_file(path)]
    domains, skipped = unique_main_domains(hosts)
    if not domains:
        print("[bold red] No valid domains in that file.[/bold red]")
        return
    print(f"[cyan] {len(domains)} domain(s) to enumerate"
          + (f" [dim]({skipped} duplicate / covered line(s) skipped)[/dim]" if skipped else "")
          + "[/cyan]")
    while True:
        output = get_input("Enter output filename", default=default_out(path, 'subdomains'))
        error = check_output_path(output, input_files=[path])
        if not error:
            break
        print(f"[bold red] {error}[/bold red]")
    mode = resolve_output_mode(output, input_files=[path])
    if mode is None:
        print("[yellow] Cancelled - nothing was written.[/yellow]")
        return
    sources = get_sources(ask_source_mode())
    print()
    found = SubFinder().run(domains, output, sources,
                            threads=DEFAULT_THREADS, mode=mode) or set()
    found = sorted(s for s in found if not s.startswith('*.'))
    for sub in found[:40]:
        print(f"   {sub}")
    if len(found) > 40:
        print(f"   [dim]... and {len(found) - 40} more in {output}[/dim]")


def _domain_scan_inputs(suffix):
    path = ask_file("Enter path to file.txt with domains")
    ports = ask_ports("80")
    timeout = ask_timeout(3)
    method = get_input("Select HTTP method", input_type="choice",
                       choices=["HEAD", "GET"])
    skip_302 = get_confirm(" Hide 302 redirects?", default=False)
    output = ask_output(default_out(path, suffix), path)
    if not output:
        return None
    threads = ask_threads(100)
    return path, ports, timeout, method, skip_302, output, threads


def opt_domain_scanner():
    inputs = _domain_scan_inputs('scan')
    if not inputs:
        return
    path, ports, timeout, method, skip_302, output, threads = inputs
    from bugscanx.modules.scanners.scanners.direct import HostDirectScanner
    scanner = HostDirectScanner(method_list=[method], input_file=path,
                                port_list=ports, no302=skip_302,
                                timeout=timeout, output_file=output, scheme='auto')
    run_scanner(scanner, threads)


def opt_domain_scanner_alt():
    inputs = _domain_scan_inputs('scan_alt')
    if not inputs:
        return
    path, ports, timeout, method, skip_302, output, threads = inputs
    from .scanners import RawDomainScanner
    scanner = RawDomainScanner(input_file=path, port_list=ports, method=method,
                               timeout=timeout, skip_302=skip_302, output_file=output)
    run_scanner(scanner, threads)


def opt_proxy_scanner():
    print("[dim] One proxy per line, eg 172.22.2.38:80 - use your own ISP proxy.[/dim]")
    path = ask_file("Enter path to file.txt with proxies")
    test = get_input("Select test", input_type="choice", choices=[
        "Both (HTTP GET + CONNECT tunnel)",
        "HTTP GET only",
        "CONNECT only (SSH / tunnel apps)",
    ])
    mode = 'both' if test.startswith('Both') else 'http' if test.startswith('HTTP') else 'connect'
    target = get_input("Enter test host", default="www.google.com", validators="required")
    timeout = ask_timeout(6)
    show_all = get_confirm(" Also show proxies that answered but failed?", default=False)
    output = ask_output(default_out(path, 'working'), path)
    if not output:
        return
    threads = ask_threads(50)
    from .scanners import ProxyListScanner
    scanner = ProxyListScanner(input_file=path, target=target, mode=mode,
                               timeout=timeout, show_all=show_all, output_file=output)
    run_scanner(scanner, threads)


def opt_unlimited_scanner():
    print("[dim] Best input: a 'hostname : ip' file from option 8 (no DNS needed "
          "while scanning). Plain domain lists work too.[/dim]")
    path = ask_file("Enter path to file.txt")
    ports = ask_ports("80")
    timeout = ask_timeout(5)
    method = get_input("Select HTTP method", input_type="choice", choices=["HEAD", "GET"])
    delay_txt = get_input("Delay per request", default="0", validators="number",
                          instruction="(ms, slows the scan for very strict ISPs)")
    output = ask_output(default_out(path, 'unlimited'), path)
    if not output:
        return
    threads = ask_threads(20)
    from .scanners import UnlimitedScanner
    scanner = UnlimitedScanner(input_file=path, port_list=ports, timeout=timeout,
                               method=method, delay=int(delay_txt) / 1000.0,
                               output_file=output)
    run_scanner(scanner, threads)


def opt_hostip_creator():
    path = ask_file("Enter path to file.txt with domains")
    all_ips = get_confirm(" Write every IP of a host (not just the first)?", default=False)
    output = ask_output(default_out(path, 'hostip'), path)
    if not output:
        return
    threads = ask_threads(50)
    from .scanners import HostIPCreator
    scanner = HostIPCreator(input_file=path, all_ips=all_ips, output_file=output)
    run_scanner(scanner, threads)
    print("[cyan] Use this file with option 6 (Unlimited scanner).[/cyan]")


def opt_tls_scanner():
    print("[dim] Input: hosts found by the scanner (plain or 'hostname : ip').[/dim]")
    path = ask_file("Enter path to file.txt with hosts")
    port = ask_ports("443")[0]
    timeout = ask_timeout(4)
    verify = get_confirm(" Only report hosts with a trusted, matching certificate?",
                         default=False)
    output = ask_output(default_out(path, 'tls'), path)
    if not output:
        return
    threads = ask_threads(50)
    from .scanners import PairTLSScanner
    scanner = PairTLSScanner(input_file=path, port=int(port), timeout=timeout,
                             verify_tls=verify, output_file=output)
    run_scanner(scanner, threads)


HANDLERS = {
    '1': opt_ip_scanner,
    '2': opt_reverse_ip,
    '3': opt_subdomain_scanner,
    '4': opt_domain_scanner,
    '5': opt_proxy_scanner,
    '6': opt_unlimited_scanner,
    '7': opt_domain_scanner_alt,
    '8': opt_hostip_creator,
    '9': opt_tls_scanner,
}


def main():
    print("[bold cyan] ZL SCANNER - pick an option[/bold cyan]\n")
    for key, (name, desc) in ZL_OPTIONS.items():
        color = "bold red" if key == '0' else "bold cyan" if int(key) % 2 else "bold magenta"
        print(f"[{color}] [{key}] {name:<22}[/{color}] [dim]{desc}[/dim]")
    choice = input("\n \033[36m[-]  Option (1-9): \033[0m").strip()
    if choice == '0' or choice not in HANDLERS:
        return
    print(f"\n[bold cyan] >> {ZL_OPTIONS[choice][0]}[/bold cyan]\n")
    HANDLERS[choice]()
