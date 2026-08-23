# pyscan/network/arp.py

import subprocess
import re

from models import Host

from network.hostname import resolve_hostname


def get_arp_table() -> list[Host]:
    """
    Perform ARP scan and parse results into structured data.
    More reliable than ICMP for local network discovery.
    
    Returns:
        List of dictionaries with 'ip', 'mac', and 'hostname' keys.
    """
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True
        )

        hosts: list[Host] = []

        arp_regex = re.compile(
            r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?:\(incomplete\)|([0-9a-fA-F:]+))\s+on\s+(\S+)\s+([^[]+?)\s*\[(\w+)\]"
        )
        
        for line in result.stdout.splitlines():
            match = arp_regex.search(line)
            if not match:
                continue
            
            raw_hostname = match.group(1)
            ip = match.group(2)
            mac = match.group(3)
            interface = match.group(4) 
            flags = match.group(5) 
            link_type = match.group(6)
            
            if ip.endswith(".255") or ip.startswith("224."):
                continue

            if mac is None and (raw_hostname is None or raw_hostname == "?"):
                continue
            
            raw_hostname = raw_hostname.strip() if raw_hostname and raw_hostname != "?" else None
            hostname = resolve_hostname(ip, provided_hostname=raw_hostname)
            
            state = "offline" if mac is None else "online"
            
            hosts.append(
                Host(
                    ip=ip,
                    mac=mac if mac else "N/A",
                    hostname=hostname,
                    interface=interface,
                    flags=flags.strip() if flags else "N/A",
                    link_type=link_type if link_type else "N/A",
                    state=state,
                    method="ARP",
                )
            )

        return hosts

    except Exception as e:
        print(f"ARP scan error: {e}")
        return []