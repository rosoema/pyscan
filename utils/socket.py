# pyscan/utils/socket.py

import socket


def create_socket(ip: str = None, sock_type=socket.SOCK_STREAM, timeout: int = 1) -> socket.socket:
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