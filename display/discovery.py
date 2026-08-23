# pyscan/display/discovery.py

import ipaddress

from models import Host


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