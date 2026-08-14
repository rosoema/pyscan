# pyscan/ports/udp.py

import socket

from config import COMMON_SERVICES

from utils.socket import create_socket


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
        sock = create_socket(ip=ip, sock_type=socket.SOCK_DGRAM)
        
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
        sock = create_socket(ip=ip, sock_type=socket.SOCK_DGRAM, timeout=2)
        
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