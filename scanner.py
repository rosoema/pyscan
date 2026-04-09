#!/usr/bin/env python3

"""
Network Scanner
- Scans target host for open TCP and UDP ports and attempts basic service
identification via banner grabbing.
"""

import os
import socket
import sys

from typing import Iterable, Tuple, Callable, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

### ----------- Constants ----------- ###

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

MAX_WORKERS = 200

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

### ----------- Progress & Threading Utils ----------- ###

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

def get_max_workers(
    num_tasks: int,
    requested_workers: int | None = None,
    threads_per_cpu: int = 5,
) -> int:
    """
    Get optimal number of workers.

    Priority:
    1. User-defined (capped)
    2. Adaptive based on CPU
    3. Always bounded by MAX_WORKERS

    Args:
        task_count: Total number of tasks.
        requested_workers: User-provided worker count.
        threads_per_cpu: How many threads each core should handle.

    Returns:
        Safe number of workers.
    """
    cpu_count = os.cpu_count() or 1

    auto_thread_count = cpu_count * threads_per_cpu

    workers = max(1, min(auto_thread_count, MAX_WORKERS, num_tasks))

    if requested_workers is not None:
        workers = max(1, min(requested_workers, MAX_WORKERS, num_tasks))

    return workers

def run_tasks_concurrently(
    func: Callable[..., Any],
    items: Iterable,
    max_workers: int | None = None,
    show_progress: bool = False,
) -> List[Any]:
    """
    Run tasks concurrently.

    Each item in `items` is passed to `func`. If an item is a tuple, it is unpacked as arguments.

    Args:
        func: Callable to run on each item.
        items: Iterable of inputs.
        max_workers: Maximum number of threads (default None).
        show_progress: If True, displays a live progress bar.

    Returns:
        List of results (excluding None), according to completion.
    """
    results: List[Any] = []
    items = list(items)
    total = len(items)
    completed = 0

    workers = get_max_workers(total, max_workers)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(func, *item) if isinstance(item, tuple) else executor.submit(func, item)
            for item in items
        ]

        try:
            for future in as_completed(futures):
                result = future.result()
                completed += 1

                if result is not None:
                    results.append(result)

                if show_progress:
                    print_progress(completed, total)
        except KeyboardInterrupt:
            print("\nCancelling remaining tasks...")
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False)
            raise

    return results

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

### ----------- Port Mode Helpers ----------- ###

def port_common(protocol: str) -> Tuple[Iterable[int], str]:
    """Scan well-known ports (TCP: 1–1023, UDP: common list)."""
    if protocol == "tcp":
        return range(1, 1024), "Common TCP ports (1-1023)"
    elif protocol == "udp":
        udp_ports = [53, 67, 68, 123, 161, 500, 514]
        return udp_ports, "Common UDP ports"
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

def port_extended(protocol: str) -> Tuple[Iterable[int], str]:
    """Scan extended port range (1–10000)."""
    return range(1, 10001), f"Extended {protocol.upper()} ports (1-10000)"

def port_all(protocol: str) -> Tuple[Iterable[int], str]:
    """Scan all valid ports."""
    return range(1, 65536), f"All {protocol.upper()} ports (1-65535)"

def port_custom_range(protocol: str) -> Tuple[Iterable[int], str]:
    """Prompt user for a custom port range."""
    proto_upper = protocol.upper()
    for attempt in range(MAX_INPUT_RETRIES):
        try:
            start_str = input(f"Start {proto_upper} port: ").strip()
            end_str = input(f"End {proto_upper} port: ").strip()
            
            start = validate_int(start_str, MIN_PORT, MAX_PORT, f"Start {proto_upper} port")
            end = validate_int(end_str, MIN_PORT, MAX_PORT, f"End {proto_upper} port")
            
            if start > end:
                print(f"Error: Start port ({start}) cannot be greater than end port ({end}).")
                continue
            
            return range(start, end + 1), f"Custom {proto_upper} range ({start}-{end})."
        except ValueError as e:
            print(f"Error: {e}.")

            if attempt < MAX_INPUT_RETRIES - 1:
                print("Please try again.")
    
    if protocol == "tcp":
        print("Max retries exceeded. Using default (1-1023).")
        return range(1, 1024), "Fallback: Common TCP ports (1-1023)"
    else:
        print("Max retries exceeded. Using default (common UDP ports).")
        return port_common("udp")

def port_specific_ports(protocol: str) -> Tuple[Iterable[int], str]:
    """Prompt user for a list of specific ports."""
    proto_upper = protocol.upper()
    example = "22,80,443" if protocol == "tcp" else "53,67,123"
    for attempt in range(MAX_INPUT_RETRIES):
        try:
            ports_input = input(f"Enter {proto_upper} ports (e.g., {example}): ").strip()
            ports = parse_port_list(ports_input)
            return ports, f"Specific {proto_upper} ports: {ports}."
        except Exception as e:
            print(f"Error: {e}.")

            if attempt < MAX_INPUT_RETRIES - 1:
                print("Please try again.")
    
    if protocol == "tcp":
        print("Max retries exceeded. Using default (1-1023).")
        return range(1, 1024), "Fallback: Common TCP ports (1-1023)"
    else:
        print("Max retries exceeded. Using default (common UDP ports).")
        return port_common("udp")

# Protocol-specific wrappers
def port_tcp_common() -> Tuple[Iterable[int], str]:
    return port_common("tcp")

def port_tcp_extended() -> Tuple[Iterable[int], str]:
    return port_extended("tcp")

def port_tcp_all() -> Tuple[Iterable[int], str]:
    return port_all("tcp")

def port_tcp_custom_range() -> Tuple[Iterable[int], str]:
    return port_custom_range("tcp")

def port_tcp_specific_ports() -> Tuple[Iterable[int], str]:
    return port_specific_ports("tcp")

def port_udp_common() -> Tuple[Iterable[int], str]:
    return port_common("udp")

def port_udp_extended() -> Tuple[Iterable[int], str]:
    return port_extended("udp")

def port_udp_all() -> Tuple[Iterable[int], str]:
    return port_all("udp")

def port_udp_custom_range() -> Tuple[Iterable[int], str]:
    return port_custom_range("udp")

def port_udp_specific_ports() -> Tuple[Iterable[int], str]:
    return port_specific_ports("udp")

SCAN_PROTOCOLS = {
    "tcp": "TCP",
    "udp": "UDP",
}

PORT_SCAN_MODES = {
    "1": ("Common TCP ports (1-1023)", port_tcp_common),
    "2": ("Extended TCP (1-10000)", port_tcp_extended),
    "3": ("All TCP ports (1-65535)", port_tcp_all),
    "4": ("Custom TCP range", port_tcp_custom_range),
    "5": ("Specific TCP ports", port_tcp_specific_ports),
    "6": ("Common UDP ports", port_udp_common),
    "7": ("Extended UDP (1-10000)", port_udp_extended),
    "8": ("All UDP ports (1-65535)", port_udp_all),
    "9": ("Custom UDP range", port_udp_custom_range),
    "10": ("Specific UDP ports", port_udp_specific_ports),
}

### ----------- User Input & Menu Helpers ----------- ###

def get_scan_type() -> str:
    """
    Display scan type options and return user choice.

    Returns:
        Selected scan type key as a string.
    """
    SCAN_TYPES = {
        "1": ("Port Scan", None),
    }
    
    print("Scan type options:")
    for key, (name, _) in SCAN_TYPES.items():
        print(f"  {key}. {name}")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose scan type (1, default: 1): ").strip() or "1"
        
        if choice in SCAN_TYPES:
            return choice
        
        print(f"Error: Invalid choice '{choice}'.")
        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (1).")
    
    return "1"

def get_protocol() -> str:
    """
    Display protocol options and return user choice.

    Returns:
        Selected protocol as a string ("tcp" or "udp").
    """
    print("Protocol options:")
    print("  1. TCP")
    print("  2. UDP")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose protocol (1-2, default: 1): ").strip() or "1"
        
        if choice == "1":
            return "tcp"
        elif choice == "2":
            return "udp"
        
        print(f"Error: Invalid choice '{choice}'.")
        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (TCP).")
    
    return "tcp"

def get_port_mode(protocol: str) -> str:
    """
    Display port mode options for the given protocol and return user choice.

    Args:
        protocol: "tcp" or "udp".

    Returns:
        Selected mode key as a string.
    """
    PORT_MODES = {
        "1": ("Common ports", port_common),
        "2": ("Extended range (1-10000)", port_extended),
        "3": ("All ports (1-65535)", port_all),
        "4": ("Custom range", port_custom_range),
        "5": ("Specific ports", port_specific_ports),
    }
    
    proto_upper = protocol.upper()
    print(f"{proto_upper} port range options:")
    for key, (name, _) in PORT_MODES.items():
        print(f"  {key}. {name}")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose option (1-5, default: 1): ").strip() or "1"
        
        if choice in PORT_MODES:
            return choice
        
        print(f"Error: Invalid choice '{choice}'.")
        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (1).")
    
    return "1"

def resolve_port_mode(protocol: str, mode_choice: str) -> Tuple[Iterable[int], str]:
    """
    Resolve a port mode into a port iterable and description.

    Args:
        protocol: "tcp" or "udp".
        mode_choice: Mode key selected by the user.

    Returns:
        Tuple of (ports iterable, human-readable name).
    """
    PORT_MODES = {
        "1": ("Common ports", port_common),
        "2": ("Extended range (1-10000)", port_extended),
        "3": ("All ports (1-65535)", port_all),
        "4": ("Custom range", port_custom_range),
        "5": ("Specific ports", port_specific_ports),
    }
    
    name, resolver = PORT_MODES.get(mode_choice, PORT_MODES["1"])
    ports, description = resolver(protocol)
    return ports, description

def get_port_scan_mode() -> str:
    """
    Display scan mode options and return user choice.

    Returns:
        Selected mode key as a string.
    """
    print("Port range options:")
    for key, (name, _) in PORT_SCAN_MODES.items():
        print(f"  {key}. {name}")

    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose option (1-10, default: 1): ").strip() or "1"

        if choice in PORT_SCAN_MODES:
            return choice

        print(f"Error: Invalid choice '{choice}'.")

        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (1).")

    return "1"

def resolve_port_scan_mode(choice: str) -> Tuple[Iterable[int], str]:
    """
    Resolve a scan mode into a port iterable and description.

    Args:
        choice: Mode key selected by the user.

    Returns:
        Tuple of (ports iterable, human-readable name).
    """
    name, resolver = PORT_SCAN_MODES.get(choice, PORT_SCAN_MODES["1"])
    ports, description = resolver()
    return ports, description

### ----------- Port Scanning ----------- ###

def is_tcp_port_open(ip: str, port: int) -> bool:
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

def get_tcp_service_banner(ip: str, port: int) -> str:
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
    
def is_udp_port_open(ip: str, port: int) -> bool:
    """
    Check if a UDP port is open by sending a probe and waiting for a response.
    
    Args:
        ip: Target IP address.
        port: Port number.
    
    Returns:
        True if a response is received (indicating open), otherwise False.
    """
    try:
        sock = create_socket(socket.SOCK_DGRAM, timeout=1.0)
        sock.sendto(b"", (ip, port))
        data, _ = sock.recvfrom(1024)
        sock.close()
        return True
    except socket.timeout:
        return False
    except Exception:
        return False

def get_udp_service_banner(ip: str, port: int) -> str:
    """
    Attempt to retrieve a UDP service banner (basic probe).
    
    Args:
        ip: Target IP address.
        port: Port number.
    
    Returns:
        Banner string or status message.
    """
    try:
        sock = create_socket(socket.SOCK_DGRAM, timeout=2.0)
        probe = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        sock.sendto(probe, (ip, port))
        data, _ = sock.recvfrom(1024)
        banner = data.decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:80] if banner else "Unknown"
    except socket.timeout:
        return "Timeout"
    except Exception as e:
        return f"Error: {type(e).__name__}"

def scan_single_port(target: str, port: int, protocol: str) -> Dict[str, str] | None:
    """
    Scan a single port and get banner if open/responsive.

    Args:
        target: Target IP or hostname.
        port: Port to scan.
        protocol: "tcp" or "udp".

    Returns:
        dict: If open/responsive, else None.
    """
    if protocol == "tcp":
        if is_tcp_port_open(target, port):
            banner = get_tcp_service_banner(target, port)
            return {"port": port, "banner": banner}
    elif protocol == "udp":
        if is_udp_port_open(target, port):
            banner = get_udp_service_banner(target, port)
            return {"port": port, "banner": banner}
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")
    return None

def scan_ports(target: str, ports: Iterable[int], label: str, protocol: str = "tcp") -> List[dict]:
    """
    Scan a target for open ports.

    Args:
        target: Target IP or hostname.
        ports: Iterable of ports to scan.
        label: Description of scan mode.
        protocol: "tcp" or "udp".
    
    Returns:
        List of dictionaries containing open port data.
    """
    print(f"Scanning {target} - {label} ({protocol.upper()})")
    
    tasks = [(target, port, protocol) for port in ports]
    
    results = run_tasks_concurrently(
        func=scan_single_port,
        items=tasks,
        show_progress=True
    )
    
    return results

### ---------- Main ---------- ###

def main():
    """Entry point"""
    try:
        print("=" * 30)
        print("Network Scanner")
        print("=" * 30)

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
            except KeyboardInterrupt:
                print("\nInput interrupted. Exiting.")
                return

        scan_type = get_scan_type()
        
        if scan_type == "1":
            protocol = get_protocol()
            mode_choice = get_port_mode(protocol)
            ports, label = resolve_port_mode(protocol, mode_choice)
            
            results = scan_ports(target, ports, label, protocol)
            
            print("\n" + "=" * 30)
            if results:
                headers = f"{'Port':>5} | Banner"
                lines = "\n".join(f"{r['port']:5d} | {r['banner']}" for r in results)
                print(f"Scan COMPLETE. Found {len(results)} open {protocol.upper()} port(s):")
                print(headers)
                print("-" * len(headers))
                print(lines)
            else:
                print(f"Scan COMPLETE. No open {protocol.upper()} ports found.")
            print("=" * 30)
        else:
            print("Unsupported scan type.")
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting gracefully.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()