#!/usr/bin/env python3

"""
PyScan - A lightweight Python network scanner

> ⚠️ Active development

Features:
- Host discovery (ARP, ICMP)
- TCP / UDP scanning
- Service detection
"""

import socket
import sys
import subprocess
import re
import ipaddress

from typing import Tuple, Dict

from config import MAX_INPUT_RETRIES, NETWORK_HOST_RANGE

from models import Host

from utils.socket import create_socket
from utils.validation import validate_ip
from utils.concurrency import run_tasks_concurrently

from ports.scanner import scan_ports
from ports.modes import get_port_mode, resolve_port_mode

### ----------- Network & System Information ----------- ###

def get_network_prefix(ip: str) -> str:
    """
    Extract network prefix from IP address.
    
    Args:
        ip: IP address string.
    
    Returns:
        Network prefix (e.g., "192.168.1" from "192.168.1.10").
    """
    return ".".join(ip.split(".")[:3])

def get_active_interface() -> str:
    """
    Get the active network interface (the one with the default route).
    
    Returns:
        Interface name (e.g., 'en0', 'en1') or 'en0' as fallback.
    """
    try:
        result = subprocess.run(
            ['route', '-n', 'get', 'default'],
            capture_output=True,
            text=True,
            check=True
        )
        match = re.search(r'interface: (\S+)', result.stdout)
        return match.group(1) if match else "en0"
    except Exception:
        return "en0"


def get_network_info(interface: str = None) -> Tuple[str, str, str, str, int, ipaddress.IPv4Network]:
    """
    Get network information for the specified interface.
    If no interface is provided, automatically detects the active interface.
    
    Returns:
        Tuple of (hostname, ip, netmask_hex, broadcast, cidr, network)
        or ("N/A", "127.0.0.1", "0xffffff00", "127.0.0.255", 24, network_obj) on failure.
    """
    try:
        if interface is None:
            interface = get_active_interface()
        
        hostname = socket.gethostname()
        
        result = subprocess.run(
            ['ifconfig', interface], 
            capture_output=True, 
            text=True,
            check=True
        )
        
        match = re.search(
            r'inet (\S+) netmask (0x[0-9a-f]+) broadcast (\S+)', 
            result.stdout
        )
        
        if not match:
            raise ValueError(f"Could not parse network info from {interface}")
        
        ip = match.group(1)
        netmask_hex = match.group(2)
        broadcast = match.group(3)
        
        netmask_int = int(netmask_hex, 16)
        cidr = bin(netmask_int).count('1')
        network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
        
        return hostname, ip, netmask_hex, broadcast, cidr, network
    except subprocess.CalledProcessError:
        print(f"\nError: Interface {interface} not found.")
        print("\nReturning fallback values.")
        fallback_network = ipaddress.IPv4Network("127.0.0.1/24", strict=False)
        return "N/A", "127.0.0.1", "0xffffff00", "127.0.0.255", 24, fallback_network
    except Exception as e:
        print(f"\nError getting network info: {e}.")
        print("\nReturning fallback values.")
        fallback_network = ipaddress.IPv4Network("127.0.0.1/24", strict=False)
        return "N/A", "127.0.0.1", "0xffffff00", "127.0.0.255", 24, fallback_network

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

### ----------- Host Discovery ----------- ###

def tcp_ping(ip: str, ports: list[int] | None = None) -> bool:
    """
    Perform TCP ping by attempting SYN connection to common ports.
    Useful if ICMP is blocked.
    
    Args:
        ip: Target IP address.
        ports: List of ports to try (default: web and SSH).
    
    Returns:
        True if any port responds, False otherwise.
    """
    if ports is None:
        ports = [80, 443, 22]

    for port in ports:
        try:
            sock = create_socket(ip=ip)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0 or result == 111:  # 0=open, 111=connection refused (but host is up)
                return True
        except:
            pass
    return False

def is_host_alive(ip: str, timeout: int = 2, use_tcp_fallback: bool = True) -> Tuple[bool, str]:
    """
    Check if a host is alive using ICMP ping, with optional TCP fallback.
    
    Args:
        ip: Target IP address.
        timeout: Ping timeout in seconds.
        use_tcp_fallback: If True, try TCP ping if ICMP fails.
    
    Returns:
        Tuple of (is_alive, detection_method).
    """
    cmd = ["ping", "-c", "1", "-i", str(timeout), ip]
    
    try:
        response = subprocess.run(
            cmd,
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

def get_arp_table() -> list[Host]:
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

        hosts: list[Host] = []

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
            
            hosts.append(
                Host(
                    ip=ip,
                    mac=mac if mac else "N/A",
                    hostname=hostname,
                    interface=interface,
                    flags=flags.strip() if flags else "N/A",
                    link_type=link_type if link_type else "N/A",
                    state=state,
                    method="ARP",
                )
            )

        return hosts

    except Exception as e:
        print(f"ARP scan error: {e}")
        return []

def perform_ping_sweep(
        network_prefix: str, 
        usable_ips: int = 
        NETWORK_HOST_RANGE, 
        use_tcp_fallback: bool = True) -> list[Host]:
    """
    Perform ping sweep on a network with TCP fallback for firewall evasion.
    
    Args:
        network_prefix: Network prefix (e.g., "192.168.1").
        use_tcp_fallback: Whether to use TCP ping if ICMP fails.
    
    Returns:
        List of alive hosts with their details.
    """
    def check_host(host_num: int) -> Host | None:
        ip = f"{network_prefix}.{host_num}"
        is_alive, method = is_host_alive(ip, use_tcp_fallback=use_tcp_fallback)

        if not is_alive:
            return None

        return Host(
            ip=ip,
            hostname=resolve_hostname(ip),
            method=method,
        )
    
    tasks = range(1, usable_ips + 1)
    results = run_tasks_concurrently(
        check_host,
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

def perform_host_discovery(local_ip: str, cidr: int, usable_ips: int, mode: str = "both") -> list[Host]:
    """
    Perform host discovery using selected methods.

    Args:
        local_ip: Local IP address to determine network.
        mode: Discovery mode ('arp', 'ping', or 'both').

    Returns:
        List of discovered hosts with their details.
    """
    print(f"\nPerforming host discovery...")
    
    all_hosts: Dict[str, Host] = {}
    
    if mode in ["ping", "both"]:
        network_prefix = get_network_prefix(local_ip)
        print(f"\nRunning ping sweep on {network_prefix}.0/{cidr}...")
        ping_hosts = perform_ping_sweep(network_prefix, usable_ips, use_tcp_fallback=True)
        
        for host in ping_hosts:
            all_hosts[host.ip] = host
        
        print(f"\nFound {len(ping_hosts)} hosts via ping")
    
    if mode in ["arp", "both"]:
        print("\nRunning ARP scan...")
        arp_hosts = get_arp_table()
        
        for arp_host in arp_hosts:
            ip = arp_host.ip

            if ip in all_hosts:
                existing = all_hosts[ip]

                if arp_host.mac != "N/A" and existing.mac in ("N/A", None):
                    existing.mac = arp_host.mac

                if arp_host.hostname != "N/A" and existing.hostname in ("N/A", None):
                    existing.hostname = arp_host.hostname

                if arp_host.interface != "N/A":
                    existing.interface = arp_host.interface

                if arp_host.flags != "N/A":
                    existing.flags = arp_host.flags

                if arp_host.link_type != "N/A":
                    existing.link_type = arp_host.link_type

                if arp_host.state != "N/A":
                    existing.state = arp_host.state

                existing.method = (
                    f"{existing.method} + ARP"
                    if existing.method
                    else "ARP"
                )

            else:
                all_hosts[ip] = arp_host
        
        print(f"Found {len(arp_hosts)} hosts via ARP")
    
    return list(all_hosts.values())

def display_discovery_results(hosts: list[Host]) -> None:
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

    hosts_sorted = sorted(
        hosts, 
        key=lambda x: ipaddress.ip_address(x.ip)
    )

    for host in hosts_sorted:
        ip = getattr(host, "ip", "N/A")
        hostname = getattr(host, "hostname", "N/A")[:25]
        mac = getattr(host, "mac", "N/A")
        method = getattr(host, "method", "N/A")
        interface = getattr(host, "interface", "N/A")
        flags = getattr(host, "flags", "N/A")
        link_type = getattr(host, "link_type", "N/A")
        state = getattr(host, "state", "N/A")

        print(f"{ip:<15} | {hostname:<25} | {mac:<20} | {method:<12} | "
              f"{interface:<10} | {flags:<17} | {link_type:<11} | {state:<8}")

    print("-" * 30)
    print(f"Total hosts discovered: {len(hosts)}")
    print("=" * 30)

### ----------- Port Scanning ----------- ###

def display_port_scan_results(results: list[dict], protocol: str) -> None:
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
        results_sorted = sorted(results, key=lambda x: x.port)
        
        headers = f"{'Port':>5} | {'Service':<15} | Banner"
        print(f"Scan COMPLETE. Found {len(results)} open {protocol.upper()} port(s):")
        print(headers)
        print("-" * 100)
        
        for r in results_sorted:
            port = r.port
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

        hostname, local_ip, netmask_hex, broadcast, cidr, network = get_network_info()

        usable_ips = network.num_addresses - 2

        print(f"\nHostname: {hostname}")
        print(f"Your IP: {local_ip}")
        print(f"Network: {network}")
        print(f"Broadcast: {broadcast}")
        print(f"Netmask: {netmask_hex}")
        print(f"CIDR: {cidr}")
        print(f"Usable IPs: {usable_ips}")

        target = get_target_ip(local_ip)

        scan_type = get_scan_type()
        
        if scan_type == "1":
            # Host discovery
            discovery_mode = get_discovery_mode()
            hosts = perform_host_discovery(target, cidr, usable_ips, discovery_mode)
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