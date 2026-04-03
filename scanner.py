#!/usr/bin/env python3

"""
Network Scanner
- Scans target host for open TCP ports and attempts basic service
identification via banner grabbing.
"""

import socket
from typing import Iterable, Tuple, List

WEB_PORTS = {
    80,
    443,
    8000,
    8080,
    8443,
    8888,
    3000,
    5000,
    9000,
    7000,
    81,
    591,
    593,
    7070,
}

MIN_PORT = 1
MAX_PORT = 65535

MAX_INPUT_RETRIES = 3

### ----------- Common Utils ----------- ###

def validate_int(value: str, min_val: int = None, max_val: int = None, field_name: str = "Value") -> int:
    """
    Convert a string to an integer with optional range validation.
    
    Args:
        value: String to convert.
        min_val: Minimum value (inclusive).
        max_val: Maximum value (inclusive).
        field_name: Name of field.
    
    Returns:
        Validated integer.

    Raises:
        ValueError: If conversion fails, or out of range.
    """
    try:
        num = int(value)
    except:
        raise ValueError(f"{field_name} must be a valid integer, got: '{value}'.")
    
    if min_val is not None and num < min_val:
        raise ValueError(f"{field_name} must be >= {min_val}, got: {num}.")
    
    if max_val is not None and num > max_val:
        raise ValueError(f"{field_name} must be <= {max_val}, got: {num}.")
    
    return num

def validate_ip(ip: str) -> str:
    """
    Validate IP address format.
    
    Args:
        ip: IP string.
    
    Returns:
        Validated IP.
    
    Raises:
        ValueError: If IP format is invalid.
    """
    try:
        socket.inet_aton(ip)
        return ip
    except socket.error:
        raise ValueError(f"Invalid IP address format: '{ip}'.")

def parse_port_list(ports_str: str) -> List[int]:
    """
    Parse comma-separated port list with validation.
    
    Args:
        ports_str: Comma-separated port numbers.
    
    Returns:
        List of valid port numbers.
    
    Raises:
        ValueError: If any port is invalid.
    """
    if not ports_str.strip():
        raise ValueError("Port list cannot be empty.")
    
    ports = []
    for item in ports_str.split(","):
        item = item.strip()
        if not item:
            continue
        port = validate_int(item, MIN_PORT, MAX_PORT, "Port")
        ports.append(port)
    
    if not ports:
        raise ValueError("No valid ports provided.")
    
    return ports

def print_progress(current: int, total: int) -> None:
    """
    Print progress.

    Args:
        current: Current iteration.
        total: Total iterations.
    """
    if total <= 0:
        return

    progress_bar_length = 30

    fraction = current / total
    filled_length = int(progress_bar_length * fraction)

    bar = "#" * filled_length + "-" * (progress_bar_length - filled_length)
    percent = int(fraction * 100)

    print(f"\r[{bar}] {percent:3d}% ({current}/{total})", end="", flush=True)

def clear_line() -> None:
    """Clear the current terminal line."""
    print("\r" + " " * 80 + "\r", end="")

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
    for attempt in range(MAX_INPUT_RETRIES):
        try:
            start_str = input("Start port: ").strip()
            end_str = input("End port: ").strip()
            
            start = validate_int(start_str, MIN_PORT, MAX_PORT, "Start port")
            end = validate_int(end_str, MIN_PORT, MAX_PORT, "End port")
            
            if start > end:
                print(f"Error: Start port ({start}) cannot be greater than end port ({end}).")
                continue
            
            return range(start, end + 1), f"Custom range ({start}-{end})."
        except ValueError as e:
            print(f"Error: {e}.")

            if attempt < MAX_INPUT_RETRIES - 1:
                print("Please try again.")

    print("Max retries exceeded. Using default (1-1023).")
    return range(1, 1024), "Fallback: Common ports (1-1023)"

def mode_specific_ports() -> Tuple[Iterable[int], str]:
    """Prompt user for a list of specific ports."""
    for attempt in range(MAX_INPUT_RETRIES):
        try:
            ports_input = input("Enter ports (e.g., 22,80,443): ").strip()
            ports = parse_port_list(ports_input)
            return ports, f"Specific ports: {ports}."
        except Exception as e:
            print(f"Error: {e}.")

            if attempt < MAX_INPUT_RETRIES - 1:
                print("Please try again.")

    print("Max retries exceeded. Using default (1-1023).")
    return range(1, 1024), "Fallback: Common ports (1-1023)"

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

    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose option (1-5, default: 1): ").strip() or "1"

        if choice in SCAN_MODES:
            return choice

        print(f"Error: Invalid choice '{choice}'.")

        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (1).")

    return "1"

def resolve_scan_mode(choice: str) -> Tuple[Iterable[int], str]:
    """
    Resolve a scan mode into a port iterable and description.

    Args:
        choice: Mode key selected by the user.

    Returns:
        Tuple of (ports iterable, human-readable name).
    """
    name, resolver = SCAN_MODES.get(choice, SCAN_MODES["1"])
    ports, description = resolver()
    return ports, description

### ----------- Port Scanning ----------- ###

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

        if not banner and port in WEB_PORTS:
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

    for index, port in enumerate(ports, 1):
        if scan_port(target, port):
            banner = grab_banner(target, port)
            clear_line()
            print(f"Port {port:5d} OPEN | {banner}")
            results.append({"port": port, "banner": banner})

        print_progress(index, len(ports))

    return results

### ---------- Main ---------- ###

def main():
    """Entry point"""
    print("=" * 50)
    print("Network Scanner")
    print("=" * 50)

    my_ip = get_local_ip()
    print(f"Your IP: {my_ip}")

    target = my_ip

    for attempt in range(MAX_INPUT_RETRIES):
        try:
            target = validate_ip(input(f"Enter IP to scan (default: {my_ip}): ").strip() or my_ip)
            break
        except ValueError as e:
            print(f"Error: {e}.")

            if attempt < MAX_INPUT_RETRIES - 1:
                print("Please try again.")
            else:
                print("Max retries exceeded. Using default IP.")

    choice = get_scan_mode()
    ports, label = resolve_scan_mode(choice)

    results = scan_target(target, ports, label)

    print("\n" + "=" * 50)
    if results:
        print(f"Scan COMPLETE. Found {len(results)} open port(s).")
    else:
        print("Scan COMPLETE. No open ports found.")
    print("=" * 50)

if __name__ == "__main__":
    main()