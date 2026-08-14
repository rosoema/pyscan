# pyscan/ports/scanner.py

from typing import Iterable

from config import COMMON_SERVICES

from models import PortResult

from utils.concurrency import run_tasks_concurrently

from ports.tcp import is_tcp_port_open, get_tcp_service_banner
from ports.udp import is_udp_port_open, get_udp_service_banner


def scan_single_port(target: str, port: int, protocol: str) -> PortResult | None:
    """
    Scan a single port and get banner if open/responsive.

    Args:
        target: Target IP or hostname.
        port: Port to scan.
        protocol: "tcp" or "udp".

    Returns:
        dict: If open/responsive with port, banner, and service info, else None.
    """

    banner = None

    if protocol == "tcp":
        if is_tcp_port_open(target, port):
            banner = get_tcp_service_banner(target, port)
    elif protocol == "udp":
        if is_udp_port_open(target, port):
            banner = get_udp_service_banner(target, port)
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    if not banner:
        return None

    return PortResult(
        port=port,
        service=COMMON_SERVICES.get(port, "N/A"),
        banner=banner,
    )

def scan_ports(target: str, ports: Iterable[int], label: str, protocol: str = "tcp") -> list[dict]:
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