# pyscan/ports/modes.py

from typing import Iterable, Tuple

from config import MIN_PORT, MAX_PORT, MAX_INPUT_RETRIES, COMMON_UDP_PORTS

from utils.validation import validate_int, parse_port_list


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