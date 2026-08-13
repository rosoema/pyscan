# pyscan/utils/validation.py

import ipaddress

from config import MIN_PORT, MAX_PORT


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
    except ValueError as Exception:
        raise ValueError(
            f"{field_name} must be a valid integer, got: '{value}'."
        ) from Exception
    
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
        address = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc

    return str(address)

def parse_port_list(ports_str: str) -> list[int]:
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

        port = validate_int(
            item, 
            MIN_PORT, 
            MAX_PORT, 
            "Port",
        )

        ports.append(port)
    
    if not ports:
        raise ValueError("No valid ports provided.")
    
    return ports