# pyscan/display/ports.py


def display_port_scan_results(results: list[dict], protocol: str) -> None:
    """
    Display port scan results in a formatted table with service information.
    
    Args:
        results: List of scan result dictionaries.
        protocol: Protocol used ("tcp" or "udp").
    """
    if not results:
        print(f"\nScan COMPLETE. No open {protocol.upper()} ports found.\n")
        return

    print("\n" + "=" * 100)
    if results:
        results_sorted = sorted(results, key=lambda x: x.port)
        
        headers = f"{'Port':>5} | {'Service':<15} | Banner"
        print(f"Scan COMPLETE. Found {len(results)} open {protocol.upper()} port(s):")
        print(headers)
        print("-" * 100)
        
        for r in results_sorted:
            port = r.port
            service = r.get('service', 'N/A')[:15]
            banner = r.get('banner', 'N/A')
            print(f"{port:5d} | {service:<15} | {banner}")
    else:
        print(f"Scan COMPLETE. No open {protocol.upper()} ports found.")
    print("=" * 100)