"""portscan - a simple TCP port scanner for learning and authorized testing."""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if the TCP port is open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            return result == 0
        except (socket.gaierror, socket.timeout, OSError):
            return False


def scan_range(host: str, ports: list[int], timeout: float = 1.0) -> dict[int, bool]:
    """Scan multiple ports concurrently. Returns {port: is_open}."""
    results: dict[int, bool] = {}
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {
            executor.submit(scan_port, host, p, timeout): p for p in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                results[port] = future.result()
            except Exception:
                results[port] = False
    return results


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or a mix like '22,80,8000-8100'."""
    ports: list[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(chunk))
    return sorted(set(p for p in ports if 1 <= p <= 65535))


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: portscan <host> <ports>")
        print("  Examples:")
        print("    portscan scanme.nmap.org 22,80,443")
        print("    portscan scanme.nmap.org 1-1024")
        print("    portscan scanme.nmap.org common")
        sys.exit(1)

    host = sys.argv[1]
    spec = sys.argv[2]

    if spec == "common":
        ports = sorted(COMMON_PORTS.keys())
    else:
        ports = parse_ports(spec)

    print(f"Scanning {host} — {len(ports)} ports")
    print("-" * 40)

    results = scan_range(host, ports)
    open_ports = sorted(p for p, is_open in results.items() if is_open)

    if not open_ports:
        print("No open ports found.")
        return

    for port in open_ports:
        service = COMMON_PORTS.get(port, "unknown")
        print(f"  {port:5d}/tcp  OPEN   {service}")

    print("-" * 40)
    print(f"{len(open_ports)} open port(s) out of {len(ports)} scanned.")


if __name__ == "__main__":
    main()
