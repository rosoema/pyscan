# pyscan/ports/tcp.py

import socket

from config import SERVICE_PROBES, RECV_BUFFER_SIZE, WEB_PORTS, COMMON_SERVICES

from utils.socket import create_socket


def is_tcp_port_open(ip: str, port: int) -> bool:
    """
    Check if a TCP port is open.

    Args:
        ip: Target IP address.
        port: Port number.

    Returns:
        True if open, otherwise False.
    """
    sock = create_socket(ip=ip)
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
        sock = create_socket(ip=ip, timeout=3)
        sock.connect((ip, port))

        probe = SERVICE_PROBES.get(port, b"")
        if probe:
            sock.send(probe)
        
        banner = sock.recv(RECV_BUFFER_SIZE).decode("utf-8", errors="ignore").strip()
        
        if not banner and port in WEB_PORTS:
            try:
                sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                banner = sock.recv(RECV_BUFFER_SIZE).decode("utf-8", errors="ignore").strip()
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