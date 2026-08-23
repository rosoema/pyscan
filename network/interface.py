# pyscan/network/interface.py

import socket
import subprocess
import re
import ipaddress

from typing import Tuple


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

def get_network_prefix(ip: str) -> str:
    """
    Extract network prefix from IP address.
    
    Args:
        ip: IP address string.
    
    Returns:
        Network prefix (e.g., "192.168.1" from "192.168.1.10").
    """
    return ".".join(ip.split(".")[:3])