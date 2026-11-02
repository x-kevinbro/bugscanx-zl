import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
)
from bugscanx.utils.prompts import get_input

console = Console()

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 8888
]


# range() excludes its stop value, so 65536 is needed to include port 65535
MIN_PORT = 1
MAX_PORT = 65535
ALL_PORTS = range(MIN_PORT, MAX_PORT + 1)


def get_ports(scan_type):
    return COMMON_PORTS if scan_type == "Common ports" else ALL_PORTS


def scan_port(ip, port, timeout=1):
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return port if sock.connect_ex((ip, port)) == 0 else None
    except OSError:
        return None


def main():
    target = get_input("Enter target", validators="required")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        console.print(
            "\n[bold red] Failed to resolve hostname",
            "\n[bold red] Please check your target and try again.",
        )
        return

    scan_type = get_input(
        "Select scan type",
        input_type="choice",
        choices=["Common ports", "All ports (1-65535)"]
    )
    ports = get_ports(scan_type)

    console.print(
        f"\n[bold green] Target Info:[/]\n"
        f" • Host: {target}\n"
        f" • IP: {ip}\n"
    )
    console.print(f"[bold blue] Starting scan...[/]\n")

    open_ports = []
    with Progress(
        TextColumn("[bold blue]│[/] {task.description}"),
        BarColumn(complete_style="green"),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(" Scanning ports", total=len(ports))

        executor = ThreadPoolExecutor(max_workers=100)
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        try:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    progress.console.print(f" [green]✓[/] Port {result} is open")
                progress.advance(task)
        except KeyboardInterrupt:
            # drop every queued port instead of waiting for all of them
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False)
            console.print("\n[yellow] Scan stopped by user (Ctrl+C) - showing ports found so far.[/]")
        else:
            executor.shutdown(wait=True)

    if not open_ports:
        console.print("\n[yellow] No open ports found.[/]\n")
