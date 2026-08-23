# pyscan/network/hostname.py

import socket


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