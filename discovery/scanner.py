# pyscan/discovery/scanner.py

import subprocess

from typing import Tuple, Dict

from config import NETWORK_HOST_RANGE

from models import Host

from utils.socket import create_socket
from utils.concurrency import run_tasks_concurrently


from network.interface import get_network_prefix
from network.hostname import resolve_hostname
from network.arp import get_arp_table


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