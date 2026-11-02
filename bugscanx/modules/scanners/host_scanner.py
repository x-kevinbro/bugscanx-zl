import ipaddress
from rich import print
from bugscanx.utils.files import check_output_path, resolve_output_mode
from bugscanx.utils.prompts import get_input, get_confirm

SCOPE_PREVIEW = 15


def read_cidrs_from_file(filepath):
    valid_cidrs = []
    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    ipaddress.ip_network(line, strict=False)
                    valid_cidrs.append(line)
                except ValueError:
                    pass
            
        return valid_cidrs
    except Exception as e:
        print(f"[bold red]Error reading file: {e}[/bold red]")
        return []


def get_cidr_ranges_from_input(cidr_input):
    return [c.strip() for c in cidr_input.split(',')]


def parse_ports(text):
    """'80, 443,,8080' -> ['80', '443', '8080'] (spaces / empty items dropped)."""
    return [p.strip() for p in str(text).split(',') if p.strip()]


def get_scheme():
    choice = get_input(
        "Select protocol",
        input_type="choice",
        choices=[
            "Auto (HTTPS on 443/8443/2053/2083/2087/2096/9443, HTTP elsewhere)",
            "HTTP",
            "HTTPS",
        ],
    )
    return 'auto' if choice.startswith('Auto') else choice.lower()


def get_common_inputs(input_file=None):
    default_filename = "results.txt"
    while True:
        output = get_input(
            "Enter output filename",
            default=default_filename
        )
        error = check_output_path(output, input_files=[input_file])
        if not error:
            break
        print(f"[bold red] {error}[/bold red]")
    threads = get_input(
        "Enter threads",
        validators="number",
        default="100"
    )
    return output, threads


def expand_hosts_file(filename):
    """Find subdomains of every unique main domain in the file - each domain
    is enumerated ONCE, no matter how many of its subdomains are in the file.
    Wildcard cert finds (*.example.com) and literal wildcard lines are turned
    into real hosts by DNS-probing common prefixes under each wildcard base."""
    from bugscanx.utils.domains import read_hosts_file, unique_main_domains

    hosts = read_hosts_file(filename)
    if not hosts:
        return filename

    # literal '*.example.com' lines can't be scanned - bases expanded below
    wildcards = {h[2:] for h in hosts if h.startswith('*.')}
    hosts = [h for h in hosts if not h.startswith('*.')]

    domains, skipped = unique_main_domains(hosts)
    print(f"[bold cyan][*][/bold cyan] {len(hosts)} host(s) -> "
          f"[bold]{len(domains)}[/bold] unique main domain(s)"
          + (f" [dim](skipped {skipped} already-covered / public-suffix line(s))[/dim]" if skipped else ""))

    # Show exactly which domains would be enumerated so the user can confirm
    # they are all inside the scope they are authorised to test.
    if domains:
        print("[bold cyan][*][/bold cyan] Domains that will be enumerated:")
        for d in domains[:SCOPE_PREVIEW]:
            print(f"      {d}")
        if len(domains) > SCOPE_PREVIEW:
            print(f"      [dim]... and {len(domains) - SCOPE_PREVIEW} more[/dim]")

    if not get_confirm("  Find subdomains of these domains first (only scan targets you are authorised to test)?", default=True):
        return filename

    from bugscanx.modules.scrapers.subfinder.subfinder import SubFinder, DEFAULT_THREADS
    from bugscanx.modules.scrapers.subfinder.sources import get_sources

    base = filename.rsplit('.', 1)[0]
    expanded_file = f"{base}_expanded.txt"
    mode = resolve_output_mode(expanded_file, input_files=[filename])
    if mode is None:
        print("[yellow] Subdomain expansion skipped - scanning the original file.[/yellow]")
        return filename
    previous = set()
    if mode == 'a':
        from bugscanx.utils.domains import read_hosts_file as _read
        previous = set(_read(expanded_file))

    # single output file: subfinder streams new subs into expanded_file,
    # then the original hosts are merged in below (no separate _subdomains.txt)
    found = set()
    if domains:
        subfinder = SubFinder()
        found = subfinder.run(domains, expanded_file, get_sources(),
                              threads=DEFAULT_THREADS, mode=mode) or set()

    # wildcard certs (*.api.example.com) can't be scanned directly - probe
    # common prefixes under each wildcard base and keep whatever resolves
    wildcards |= {s[2:] for s in found if s.startswith('*.')}
    subs = {s for s in found if not s.startswith('*.')}
    wildcard_hosts = set()
    if wildcards:
        from bugscanx.modules.scrapers.subfinder.wildcard import expand_wildcards
        print(f"[bold cyan][*][/bold cyan] {len(wildcards)} wildcard base(s) - "
              f"DNS-probing common prefixes...")
        wildcard_hosts = expand_wildcards(wildcards)
        subs |= wildcard_hosts

    new_hosts = set(subs) - set(hosts)
    merged = sorted(set(hosts) | set(subs) | previous)
    with open(expanded_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(merged) + '\n')
    print(f"[bold green][+][/bold green] one file: "
          f"[bold]{len(hosts)}[/bold] original + [bold]{len(new_hosts)}[/bold] new"
          + (f" [dim]({len(wildcard_hosts)} from wildcards)[/dim]" if wildcard_hosts else "")
          + f" = [bold]{len(merged)}[/bold] hosts -> {expanded_file}")
    return expanded_file


def get_host_input():
    filename = get_input("Enter filename", input_type="file", validators="file", mandatory=False)
    if not filename:
        cidr = get_input("Enter CIDR range(s)", validators="cidr", mandatory=False)
        if not cidr:
            cidr_file = get_input(
                "Enter CIDR file", input_type="file", validators="file")
            cidr = read_cidrs_from_file(cidr_file) if cidr_file else None
        return None, cidr
    return expand_hosts_file(filename), None


def get_input_direct(no302=False):
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None
        
    port_list = parse_ports(get_input("Enter port(s)", validators="number", default="80"))
    scheme = get_scheme()
    timeout = get_input("Enter timeout", validators="number", default="3", instruction="(seconds)")
    output, threads = get_common_inputs(filename)
    method_list = get_input(
        "Select HTTP method(s)",
        input_type="choice",
        multiselect=True, 
        choices=[
            "GET", "HEAD", "POST", "PUT",
            "DELETE", "OPTIONS", "TRACE", "PATCH"
        ],
        transformer=lambda result: ', '.join(result) if isinstance(result, list) else result
    )
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.direct import CIDRDirectScanner        
        scanner = CIDRDirectScanner(
            method_list=method_list,
            cidr_ranges=cidr_ranges,
            port_list=port_list,
            no302=no302,
            timeout=int(timeout),
            output_file=output,
            scheme=scheme
        )
    else:
        from .scanners.direct import HostDirectScanner
        scanner = HostDirectScanner(
            method_list=method_list,
            input_file=filename,
            port_list=port_list,
            no302=no302,
            timeout=int(timeout),
            output_file=output,
            scheme=scheme
        )
    
    return scanner, threads


def get_input_proxy():
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None
        
    target_url = get_input("Enter target url", default="in1.wstunnel.site", validators="required")
    default_payload = (
        "GET / HTTP/1.1[crlf]"
        "Host: [host][crlf]"
        "Connection: Upgrade[crlf]"
        "Upgrade: websocket[crlf][crlf]"
    )
    payload = get_input("Enter payload", default=default_payload, validators="required")
    port_list = parse_ports(get_input("Enter port(s)", validators="number", default="80"))
    output, threads = get_common_inputs(filename)
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.proxy_check import CIDRProxyScanner
        scanner = CIDRProxyScanner(
            cidr_ranges=cidr_ranges,
            port_list=port_list,
            target=target_url,
            payload=payload,
            output_file=output
        )
    else:
        from .scanners.proxy_check import HostProxyScanner
        scanner = HostProxyScanner(
            input_file=filename,
            port_list=port_list,
            target=target_url,
            payload=payload,
            output_file=output
        )
    
    return scanner, threads


def get_input_proxy2():
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None
        
    port_list = parse_ports(get_input("Enter port(s)", validators="number", default="80"))
    output, threads = get_common_inputs(filename)
    method_list = get_input(
        "Select HTTP method(s)",
        input_type="choice",
        multiselect=True, 
        choices=[
            "GET", "HEAD", "POST", "PUT",
            "DELETE", "OPTIONS", "TRACE", "PATCH"
        ],
        transformer=lambda result: ', '.join(result) if isinstance(result, list) else result
    )
    
    scheme = get_scheme()
    proxy = get_input("Enter proxy", instruction="(proxy:port)", validators="required")
    
    use_auth = get_confirm(" Use proxy authentication?")
    proxy_username = None
    proxy_password = None
    
    if use_auth:
        proxy_username = get_input("Enter proxy username", validators="required")
        proxy_password = get_input("Enter proxy password", validators="required")
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.proxy_request import CIDRProxy2Scanner
        scanner = CIDRProxy2Scanner(
            method_list=method_list,
            cidr_ranges=cidr_ranges,
            port_list=port_list,
            output_file=output,
            scheme=scheme
        ).set_proxy(proxy, proxy_username, proxy_password)
    else:
        from .scanners.proxy_request import HostProxy2Scanner
        scanner = HostProxy2Scanner(
            method_list=method_list,
            input_file=filename,
            port_list=port_list,
            output_file=output,
            scheme=scheme
        ).set_proxy(proxy, proxy_username, proxy_password)

    return scanner, threads


def get_input_ssl():
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None
        
    verify_tls = get_confirm(
        " Only report hosts with a trusted, matching certificate?", default=False)
    output, threads = get_common_inputs(filename)
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.ssl import CIDRSSLScanner
        scanner = CIDRSSLScanner(
            cidr_ranges=cidr_ranges,
            output_file=output,
            verify_tls=verify_tls
        )
    else:
        from .scanners.ssl import HostSSLScanner
        scanner = HostSSLScanner(
            input_file=filename,
            output_file=output,
            verify_tls=verify_tls
        )
    
    return scanner, threads


def get_input_ping():
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None
        
    port_list = parse_ports(get_input("Enter port(s)", validators="number", default="443"))
    output, threads = get_common_inputs(filename)
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.ping import CIDRPingScanner
        scanner = CIDRPingScanner(
            port_list=port_list,
            cidr_ranges=cidr_ranges,
            output_file=output
        )
    else:
        from .scanners.ping import HostPingScanner
        scanner = HostPingScanner(
            input_file=filename,
            port_list=port_list,
            output_file=output
        )
    
    return scanner, threads


def get_user_input():
    mode = get_input(
        "Select scanning mode",
        "choice", 
        choices=[
            "Direct", "DirectNon302", "ProxyTest",
            "ProxyRoute", "Ping", "SSL"
        ]
    )
    
    input_handlers = {
        'Direct': lambda: get_input_direct(no302=False),
        'DirectNon302': lambda: get_input_direct(no302=True),
        'ProxyTest': get_input_proxy,
        'ProxyRoute': get_input_proxy2,
        'Ping': get_input_ping,
        'SSL': get_input_ssl
    }
    
    scanner, threads = input_handlers[mode]()
    return scanner, threads


def main():
    scanner, threads = get_user_input()
    if scanner is None:
        print("[yellow] No input provided - nothing to scan.[/yellow]")
        return
    scanner.threads = int(threads)
    scanner.start()
