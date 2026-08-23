#!/usr/bin/env python3

"""
PyScan - A lightweight Python network scanner

> ⚠️ Active development

Features:
- Host discovery (ARP, ICMP)
- TCP / UDP scanning
- Service detection
"""

import sys

from cli import get_discovery_mode, get_port_mode, get_protocol, get_scan_type, get_target_ip

from ports.scanner import scan_ports
from ports.modes import resolve_port_mode

from network.interface import get_network_info

from discovery.scanner import perform_host_discovery

from display.discovery import display_discovery_results
from display.ports import display_port_scan_results


### ---------- Main ---------- ###

def main():
    """Entry point"""
    try:
        print("\n" + "=" * 30)
        print("Welcome to PyScan!".center(30))
        print("=" * 30 + "\n")

        hostname, local_ip, netmask_hex, broadcast, cidr, network = get_network_info()

        usable_ips = network.num_addresses - 2

        print(f"\nHostname: {hostname}")
        print(f"Your IP: {local_ip}")
        print(f"Network: {network}")
        print(f"Broadcast: {broadcast}")
        print(f"Netmask: {netmask_hex}")
        print(f"CIDR: {cidr}")
        print(f"Usable IPs: {usable_ips}")

        target = get_target_ip(local_ip)

        scan_type = get_scan_type()
        
        if scan_type == "1":
            # Host discovery
            discovery_mode = get_discovery_mode()
            hosts = perform_host_discovery(target, cidr, usable_ips, discovery_mode)
            display_discovery_results(hosts)

        elif scan_type == "2":
            # Port scanning
            protocol = get_protocol()
            mode_choice = get_port_mode(protocol)
            ports, label = resolve_port_mode(protocol, mode_choice)
            
            results = scan_ports(target, ports, label, protocol)
            display_port_scan_results(results, protocol)
        else:
            print("Unsupported scan type.")    
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()