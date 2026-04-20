#!/usr/bin/env python3

"""
PyScan - A lightweight Python network scanner

Features:
- Host discovery (ARP, ICMP, TCP SYN)
- TCP / UDP scanning
- Service detection
- OS fingerprinting (basic)
"""

import os
import socket
import sys
import subprocess
import re

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

COMMON_UDP_PORTS = {
    53,
    67,
    68,
    69,
    123,
    161,
    500,
    514,
    1194,
    5060,
    5061,
    1812,
    1813
}

SERVICE_PROBES = {
    21: b"", 
    22: b"",
    23: b"", 
    25: b"EHLO pyscan\r\n", 
    80: b"GET / HTTP/1.0\r\n\r\n",
    110: b"",  
    143: b"",  
    443: b"GET / HTTP/1.0\r\n\r\n",  
    3306: b"",  
    5432: b"", 
    6379: b"PING\r\n",
    8080: b"GET / HTTP/1.0\r\n\r\n", 
}

COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "microsoft-ds", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb", 5000: "upnp", 8000: "http-alt",
}

MIN_PORT = 1
MAX_PORT = 65535

MAX_INPUT_RETRIES = 3

MAX_WORKERS = 100

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

    bar = "█" * filled_length + "░" * (progress_bar_length - filled_length)
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
        num_tasks: Total number of tasks.
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

def get_network_prefix(ip: str) -> str:
    """
    Extract network prefix from IP address.
    
    Args:
        ip: IP address string.
    
    Returns:
        Network prefix (e.g., "192.168.1" from "192.168.1.10").
    """
    return ".".join(ip.split(".")[:3])

### ----------- Socket Utils ----------- ###

def create_socket(sock_type=socket.SOCK_STREAM, timeout: int = 1) -> socket.socket:
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

def get_local_info() -> Tuple[str, str]:
    """
    Determine the local IP address and hostname of the machine.

    Returns:
        Tuple of (hostname, local IP address), or ("N/A", "127.0.0.1") if fail.
    """
    try:
        sock = create_socket(socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))

        hostname = socket.gethostname()
        ip = sock.getsockname()[0]

        sock.close()

        return hostname, ip
    except Exception as e:
        print(f"Error: {e}.")
        return "N/A", "127.0.0.1"

### ----------- Port Mode Helpers ----------- ###

def port_common(protocol: str) -> Tuple[Iterable[int], str]:
    """Scan well-known ports (TCP: 1–1023, UDP: common list)."""
    if protocol == "tcp":
        return range(1, 1024), "Common TCP ports (1-1023)"
    elif protocol == "udp":
        return COMMON_UDP_PORTS, "Common UDP ports"
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

### ----------- User Input & Menu Helpers ----------- ###

def get_scan_type() -> str:
    """
    Display scan type options and return user choice.

    Returns:
        Selected scan type key as a string.
    """
    SCAN_TYPES = {
        "1": ("Host Discovery", None),
        "2": ("Port Scan", None),
    }
    
    print("\nScan type options:")
    for key, (name, _) in SCAN_TYPES.items():
        print(f"  {key}. {name}")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose scan type (1-2, default: 1): ").strip() or "1"
        
        if choice in SCAN_TYPES:
            return choice
        
        print(f"Error: Invalid choice '{choice}'.")
        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (1).")
    
    return "1"

def get_target_ip(default_ip: str) -> str:
    """
    Prompt user for target IP address with validation and retry logic.
    
    Args:
        default_ip: Default IP to use if user presses Enter.
    
    Returns:
        Validated IP address string.
    """
    for attempt in range(MAX_INPUT_RETRIES):
        try:
            target = input(f"\nEnter IP to scan (default: {default_ip}): ").strip() or default_ip
            return validate_ip(target)
        except ValueError as e:
            print(f"Error: {e}.")
            if attempt < MAX_INPUT_RETRIES - 1:
                print("Please try again.")
            else:
                print("Max retries exceeded. Using default IP.")
                return default_ip
        except KeyboardInterrupt:
            print("\nInput interrupted. Exiting.")
            sys.exit(0)
    
    return default_ip

def get_protocol() -> str:
    """
    Display protocol options and return user choice.

    Returns:
        Selected protocol as a string ("tcp" or "udp").
    """
    PROTOCOLS = {
        "1": ("tcp", None),
        "2": ("udp", None),
    }
    
    print("\nProtocol options:")
    for key, (name, _) in PROTOCOLS.items():
        print(f"  {key}. {name.upper()}")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose protocol (1-2, default: 1): ").strip() or "1"
        
        if choice in PROTOCOLS:
            return PROTOCOLS[choice][0]
        
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
    print(f"\n{proto_upper} port range options:")
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

### ----------- Enhanced Host Discovery ----------- ###

def tcp_ping(ip: str, ports: List[int] = [80, 443, 22]) -> bool:
    """
    Perform TCP ping by attempting SYN connection to common ports.
    Useful if ICMP is blocked.
    
    Args:
        ip: Target IP address.
        ports: List of ports to try (default: web and SSH).
    
    Returns:
        True if any port responds, False otherwise.
    """
    for port in ports:
        try:
            sock = create_socket(timeout=1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0 or result == 111:  # 0=open, 111=connection refused (but host is up)
                return True
        except:
            pass
    return False

def is_host_alive(ip: str, timeout: int = 3, use_tcp_fallback: bool = True) -> Tuple[bool, str]:
    """
    Check if a host is alive using ICMP ping, with optional TCP fallback.
    
    Args:
        ip: Target IP address.
        timeout: Ping timeout in seconds.
        use_tcp_fallback: If True, try TCP ping if ICMP fails.
    
    Returns:
        Tuple of (is_alive, detection_method).
    """
    try:
        response = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True,
            text=True
        )
        
        if response.returncode == 0:
            return True, "ICMP"
    except (subprocess.TimeoutExpired, Exception):
        pass
    
    # Try TCP ping as fallback if ICMP failed
    if use_tcp_fallback:
        if tcp_ping(ip):
            return True, "TCP"
    
    return False, "down"

def resolve_hostname(ip: str, provided_hostname: str = None, timeout: int = 1) -> str:
    """
    Enhanced hostname resolution using multiple methods.
    
    Args:
        ip: IP address to resolve.
        timeout: Timeout for DNS lookup.
    
    Returns:
        Hostname or "N/A" if resolution fails.
    """
    if provided_hostname and provided_hostname != "?":
        return provided_hostname

    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except:
        pass

    try:
        hostname = socket.getfqdn(ip)
        if hostname != ip:
            return hostname
    except:
        pass

    return "N/A"

def get_arp_table() -> List[Dict[str, str]]:
    """
    Perform ARP scan and parse results into structured data.
    More reliable than ICMP for local network discovery.
    
    Returns:
        List of dictionaries with 'ip', 'mac', and 'hostname' keys.
    """
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True
        )

        hosts = []

        arp_regex = re.compile(
            r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?:\(incomplete\)|([0-9a-fA-F:]+))\s+on\s+(\S+)\s+([^[]+?)\s*\[(\w+)\]"
        )
        
        for line in result.stdout.splitlines():
            match = arp_regex.search(line)
            if not match:
                continue
            
            raw_hostname = match.group(1)
            ip = match.group(2)
            mac = match.group(3)
            interface = match.group(4) 
            flags = match.group(5) 
            link_type = match.group(6)
            
            if ip.endswith(".255") or ip.startswith("224."):
                continue

            if mac is None and (raw_hostname is None or raw_hostname == "?"):
                continue
            
            raw_hostname = raw_hostname.strip() if raw_hostname and raw_hostname != "?" else None
            hostname = resolve_hostname(ip, provided_hostname=raw_hostname)
            
            state = "offline" if mac is None else "online"
            
            hosts.append({
                "ip": ip,
                "mac": mac if mac else "N/A",
                "hostname": hostname,
                "interface": interface,
                "flags": flags.strip() if flags else "",
                "link_type": link_type if link_type else "",
                "state": state,
                "method": "ARP"
            })
        return hosts

    except Exception as e:
        print(f"ARP scan error: {e}")
        return []

def perform_ping_sweep(network_prefix: str, use_tcp_fallback: bool = True) -> List[Dict[str, str]]:
    """
    Perform ping sweep on a network with TCP fallback for firewall evasion.
    
    Args:
        network_prefix: Network prefix (e.g., "192.168.1").
        use_tcp_fallback: Whether to use TCP ping if ICMP fails.
    
    Returns:
        List of alive hosts with their details.
    """
    def check_host(host_num: int) -> Dict[str, str] | None:
        ip = f"{network_prefix}.{host_num}"
        is_alive, method = is_host_alive(ip, use_tcp_fallback=use_tcp_fallback)
        
        if is_alive:
            hostname = resolve_hostname(ip)
            mac = "N/A"
            
            return {
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "method": method
            }
        return None
    
    print(f"Scanning network {network_prefix}.0/24...")
    
    tasks = range(1, 255)
    results = run_tasks_concurrently(
        func=check_host,
        items=tasks,
        show_progress=True
    )
    
    return results

def get_discovery_mode() -> str:
    """
    Display host discovery mode options and return user choice.
    
    Returns:
        Selected mode: 'arp', 'ping', or 'both'.
    """
    DISCOVERY_MODES = {
        "1": ("arp", "ARP scan (fastest, local network only)"),
        "2": ("ping", "Ping sweep (ICMP + TCP fallback)"),
        "3": ("both", "Both (most comprehensive)")
    }

    print("\nHost discovery method:")
    for key, (_, title) in DISCOVERY_MODES.items():
        print(f"  {key}. {title}")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose method (1-3, default: 3): ").strip() or "3"
        
        if choice in DISCOVERY_MODES:
            return DISCOVERY_MODES[choice][0]
        
        print(f"Error: Invalid choice '{choice}'.")
        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (Both).")
    
    return "both"

def perform_host_discovery(local_ip: str, mode: str = "both") -> List[Dict[str, str]]:
    """
    Perform host discovery using selected methods.

    Args:
        local_ip: Local IP address to determine network.
        mode: Discovery mode ('arp', 'ping', or 'both').

    Returns:
        List of discovered hosts with their details.
    """
    print(f"\nPerforming host discovery...")
    
    all_hosts = {}
    
    if mode in ["ping", "both"]:
        network_prefix = get_network_prefix(local_ip)
        step_num = 2 if mode == "both" else 1
        print(f"\n[{step_num}/2] Running ping sweep on {network_prefix}.0/24...")
        ping_hosts = perform_ping_sweep(network_prefix, use_tcp_fallback=True)
        
        for host in ping_hosts:
            all_hosts[host["ip"]] = host
        
        print(f"\nFound {len(ping_hosts)} hosts via ping")
    
    if mode in ["arp", "both"]:
        print("\n[1/2] Running ARP scan...")
        arp_hosts = get_arp_table()
        
        for host in arp_hosts:
            ip = host["ip"]
            
            if ip in all_hosts:
                existing = all_hosts[ip]
                
                if host.get("mac") and host["mac"] != "N/A" and existing.get("mac") in ["N/A", "N/A", None]:
                    existing["mac"] = host["mac"]
                
                if host.get("hostname") and host["hostname"] != "N/A" and existing.get("hostname") in ["N/A", None]:
                    existing["hostname"] = host["hostname"]
                
                existing["interface"] = host.get("interface", "N/A")
                existing["flags"] = host.get("flags", "N/A")
                existing["link_type"] = host.get("link_type", "N/A")
                existing["state"] = host.get("state", "N/A")
                
                ping_method = existing.get("method", "")
                existing["method"] = f"{ping_method} + ARP"
            else:
                all_hosts[ip] = host
        
        print(f"Found {len(arp_hosts)} hosts via ARP")
    
    return list(all_hosts.values())

def display_discovery_results(hosts: List[Dict[str, str]]) -> None:
    """
    Display host discovery results in a formatted table.
    
    Args:
        hosts: List of discovered host dictionaries.
    """
    print("\n" + "=" * 30)
    print("HOST DISCOVERY RESULTS".center(30))
    print("=" * 30)

    if not hosts:
        print("No hosts discovered.")
        print("=" * 30)
        return

    print(f"{'IP':<15} | {'Hostname':<25} | {'MAC':<20} | {'Method':<12} | "
          f"{'Interface':<10} | {'Flags':<17} | {'Link Type':<11} | {'State':<8}")
    
    print("-" * 30)

    hosts_sorted = sorted(hosts, key=lambda x: tuple(map(int, x["ip"].split("."))))

    for host in hosts_sorted:
        ip = host.get("ip", "N/A")
        hostname = host.get("hostname", "N/A")[:25]
        mac = host.get("mac", "N/A")
        method = host.get("method", "N/A")
        interface = host.get("interface", "N/A")
        flags = host.get("flags", "N/A")
        link_type = host.get("link_type", "N/A")
        state = host.get("state", "N/A")

        print(f"{ip:<15} | {hostname:<25} | {mac:<20} | {method:<12} | "
              f"{interface:<10} | {flags:<17} | {link_type:<11} | {state:<8}")

    print("-" * 30)
    print(f"Total hosts discovered: {len(hosts)}")
    print("=" * 30)

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
    sock = create_socket(timeout=1)
    result = sock.connect_ex((ip, port))

    sock.close()

    return result == 0

def get_tcp_service_banner(ip: str, port: int) -> str:
    """
    Service banner grabbing with protocol-specific probes.

    Args:
        ip: Target IP address.
        port: Port number.

    Returns:
        Banner string or status message.
    """
    try:
        sock = create_socket(timeout=2)
        sock.connect((ip, port))

        probe = SERVICE_PROBES.get(port, b"")
        if probe:
            sock.send(probe)
        
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        
        if not banner and port in WEB_PORTS:
            try:
                sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except:
                pass

        sock.close()

        if banner:
            lines = banner.split("\n")
            for line in lines:
                line = line.strip()
                if line:
                    return line[:80]
        
        if port in COMMON_SERVICES:
            return f"{COMMON_SERVICES[port]} (no banner)"
        
        return "Open (no banner)"
    except socket.timeout:
        return "Timeout"
    except Exception as e:
        return f"Error: {type(e).__name__}"

def is_udp_port_open(ip: str, port: int) -> bool:
    """
    Enhanced UDP port detection using protocol-specific probes.
    
    Args:
        ip: Target IP address.
        port: Port number.
    
    Returns:
        True if a response is received (indicating open), otherwise False.
    """
    try:
        sock = create_socket(socket.SOCK_DGRAM, timeout=1)
        
        probes = {
            53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
            123: b"\x1b" + b"\x00" * 47, 
            161: b"\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63", 
        }
        
        probe = probes.get(port, b"\x00\x01\x00\x00")
        sock.sendto(probe, (ip, port))
        
        data, _ = sock.recvfrom(1024)
        sock.close()
        return True
    except socket.timeout:
        return False
    except Exception:
        return False

def get_udp_service_banner(ip: str, port: int) -> str:
    """
    Attempt to retrieve a UDP service banner with protocol-specific probes.
    
    Args:
        ip: Target IP address.
        port: Port number.
    
    Returns:
        Banner string or status message.
    """
    try:
        sock = create_socket(socket.SOCK_DGRAM, timeout=2)
        
        probes = {
            53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
            123: b"\x1b" + b"\x00" * 47,
            161: b"\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63",
        }
        
        probe = probes.get(port, b"\x00\x01\x00\x00\x00\x00\x00\x00")
        sock.sendto(probe, (ip, port))
        
        data, _ = sock.recvfrom(1024)
        banner = data.decode("utf-8", errors="ignore").strip()
        sock.close()
        
        if banner:
            return banner[:80]
        
        if port in COMMON_SERVICES:
            return f"{COMMON_SERVICES[port]} (open)"
        
        return "Open (no banner)"
    except socket.timeout:
        return "Timeout"
    except Exception as e:
        return f"Error: {type(e).__name__}"

def scan_single_port(target: str, port: int, protocol: str) -> Dict[str, Any] | None:
    """
    Scan a single port and get banner if open/responsive.

    Args:
        target: Target IP or hostname.
        port: Port to scan.
        protocol: "tcp" or "udp".

    Returns:
        dict: If open/responsive with port, banner, and service info, else None.
    """
    if protocol == "tcp":
        if is_tcp_port_open(target, port):
            banner = get_tcp_service_banner(target, port)
            service = COMMON_SERVICES.get(port, "N/A")
            return {
                "port": port,
                "banner": banner,
                "service": service
            }
    elif protocol == "udp":
        if is_udp_port_open(target, port):
            banner = get_udp_service_banner(target, port)
            service = COMMON_SERVICES.get(port, "N/A")
            return {
                "port": port,
                "banner": banner,
                "service": service
            }
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
    print(f"\nScanning {target} - {label} ({protocol.upper()})")
    
    tasks = [(target, port, protocol) for port in ports]
    
    results = run_tasks_concurrently(
        func=scan_single_port,
        items=tasks,
        show_progress=True
    )
    
    return results

def display_port_scan_results(results: List[dict], protocol: str) -> None:
    """
    Display port scan results in a formatted table with service information.
    
    Args:
        results: List of scan result dictionaries.
        protocol: Protocol used ("tcp" or "udp").
    """
    if not results:
        print(f"\nScan COMPLETE. No open {protocol.upper()} ports found.\n")
        return

    print("\n" + "=" * 100)
    if results:
        results_sorted = sorted(results, key=lambda x: x['port'])
        
        headers = f"{'Port':>5} | {'Service':<15} | Banner"
        print(f"Scan COMPLETE. Found {len(results)} open {protocol.upper()} port(s):")
        print(headers)
        print("-" * 100)
        
        for r in results_sorted:
            port = r['port']
            service = r.get('service', 'N/A')[:15]
            banner = r.get('banner', 'N/A')
            print(f"{port:5d} | {service:<15} | {banner}")
    else:
        print(f"Scan COMPLETE. No open {protocol.upper()} ports found.")
    print("=" * 100)

### ---------- Main ---------- ###

def main():
    """Entry point"""
    try:
        print("\n" + "=" * 30)
        print("Welcome to PyScan!".center(30))
        print("=" * 30 + "\n")

        hostname, local_ip = get_local_info()

        print(f"Hostname: {hostname}")
        print(f"Your IP: {local_ip}")

        target = get_target_ip(local_ip)

        scan_type = get_scan_type()
        
        if scan_type == "1":
            # Host discovery
            discovery_mode = get_discovery_mode()
            hosts = perform_host_discovery(local_ip, discovery_mode)
            display_discovery_results(hosts)

        elif scan_type == "2":
            # Port scanning
            protocol = get_protocol()
            mode_choice = get_port_mode(protocol)
            ports, label = resolve_port_mode(protocol, mode_choice)
            
            results = scan_ports(target, ports, label, protocol)
            display_port_scan_results(results, protocol)
        else:
            print("Unsupported scan type.")    
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()