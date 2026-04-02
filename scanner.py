#!/usr/bin/env python3

"""
Network Scanner
- Scans target host for open TCP ports and attempts basic service
identification via banner grabbing.
"""

import socket
from typing import Iterable, Tuple, List

### ----------- Socket Utils ----------- ###

def create_socket(sock_type=socket.SOCK_STREAM, timeout: float = 1.0) -> socket.socket:
    """
    Create and configure a socket.

    Args:
        sock_type: Socket type (TCP or UDP).
        timeout: Timeout in seconds.

    Returns:
        Configured socket instance.
    """
    sock = socket.socket(socket.AF_INET, sock_type)
    sock.settimeout(timeout)

    return sock

def get_local_ip() -> str:
    """
    Determine the local IP address of the machine.

    Returns:
        Local IP address as a string, or 127.0.0.1 if fail.
    """
    try:
        sock = create_socket(socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"

### ----------- Scan Modes ----------- ###

def mode_common() -> Tuple[Iterable[int], str]:
    """Scan well-known ports (1–1023)."""
    return range(1, 1024), "Common ports (1-1023)"

def mode_extended() -> Tuple[Iterable[int], str]:
    """Scan extended range (1–10000)."""
    return range(1, 10001), "Extended ports (1-10000)"

def mode_all() -> Tuple[Iterable[int], str]:
    """Scan all valid TCP ports."""
    return range(1, 65536), "All ports (1-65535)"

def mode_custom_range() -> Tuple[Iterable[int], str]:
    """Prompt user for a custom port range."""
    start = int(input("Start port: "))
    end = int(input("End port: "))
    return range(start, end + 1), f"Custom range ({start}-{end})"

def mode_specific_ports() -> Tuple[Iterable[int], str]:
    """Prompt user for a list of specific ports."""
    ports_input = input("Enter ports (e.g., 22,80,443): ")
    ports = [int(p.strip()) for p in ports_input.split(",")]
    return ports, f"Specific ports: {ports}"

SCAN_MODES = {
    "1": ("Common ports (1-1023)", mode_common),
    "2": ("Extended (1-10000)", mode_extended),
    "3": ("All ports (1-65535)", mode_all),
    "4": ("Custom range", mode_custom_range),
    "5": ("Specific ports", mode_specific_ports),
}

def get_scan_mode() -> str:
    """
    Display scan mode options and return user choice.

    Returns:
        Selected mode key as a string.
    """
    print("Port range options:")
    for key, (name, _) in SCAN_MODES.items():
        print(f"  {key}. {name}")

    return input("Choose option (1-5, default: 1): ").strip() or "1"

def resolve_scan_mode(choice: str) -> Tuple[Iterable[int], str]:
    """
    Resolve a scan mode into a port iterable and description.

    Args:
        choice: Mode key selected by the user.

    Returns:
        Tuple of (ports iterable, human-readable name).
    """
    name, resolver = SCAN_MODES.get(choice, SCAN_MODES["1"])
    ports, _ = resolver()
    return ports, name

def scan_port(ip: str, port: int) -> bool:
    """
    Check if a TCP port is open.

    Args:
        ip: Target IP address.
        port: Port number.

    Returns:
        True if open, otherwise False.
    """
    sock = create_socket()
    result = sock.connect_ex((ip, port))

    sock.close()
    
    return result == 0

def grab_banner(ip: str, port: int) -> str:
    """
    Attempt to retrieve a service banner.

    Args:
        ip: Target IP address.
        port: Port number.

    Returns:
        Banner string or status message.
    """
    try:
        sock = create_socket(timeout=2)
        sock.connect((ip, port))

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()

        if not banner and port in {80, 443, 8000, 8080, 8443}: # TODO: Add more ports, reafctor to extract
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()

        sock.close()

        return banner.split("\n")[0][:80] if banner else "Unknown"
    except socket.timeout:
        return "Timeout"
    except Exception as e:
        return f"Error: {type(e).__name__}"

def scan_target(target: str, ports: Iterable[int], label: str) -> List[dict]:
    """
    Scan a target for open ports.

    Args:
        target: Target IP or hostname.
        ports: Iterable of ports to scan.
        label: Description of scan mode.

    Returns:
        List of dictionaries containing open port data.
    """
    print(f"Scanning {target} - {label}")
    results = []

    for port in ports:
        if scan_port(target, port):
            banner = grab_banner(target, port)
            print(f"Port {port:5d} OPEN | {banner}")
            results.append({"port": port, "banner": banner})

    return results

### ---------- Main ---------- ###

def main():
    """ Entry point """
    print("Network Scanner")

    my_ip = get_local_ip()
    print(f"Your IP: {my_ip}")

    target = input(f"Enter IP to scan (default: {my_ip}): ").strip() or my_ip

    choice = get_scan_mode()
    ports, label = resolve_scan_mode(choice)

    results = scan_target(target, ports, label)

    print(
        f"Scan COMPLETE. Found {len(results)} open port(s)"
        if results else
        "Scan COMPLETE. No open ports found"
    )

if __name__ == "__main__":
    main()