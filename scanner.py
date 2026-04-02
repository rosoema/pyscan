#!/usr/bin/env python3

"""
Network Scanner
"""

import socket


def create_socket(sock_type=socket.SOCK_STREAM, timeout=1):
    """Create a socket with timeout
    
    Args:
        sock_type: socket.SOCK_STREAM (TCP) or socket.SOCK_DGRAM (UDP)
        timeout: timeout in seconds
    """
    sock = socket.socket(socket.AF_INET, sock_type)
    sock.settimeout(timeout)

    return sock

def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        sock = create_socket(socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))

        local_ip = sock.getsockname()[0]

        sock.close()

        return local_ip
    except:
        return "127.0.0.1"

def scan_port(ip, port):
    """Check if a port is open"""
    sock = create_socket()
    result = sock.connect_ex((ip, port))

    sock.close()
    
    return result == 0  # True if open

if __name__ == "__main__":
    my_ip = get_local_ip()
    print(f"Your IP: {my_ip}")
    
    target = input(f"Enter IP to scan (default: {my_ip}): ").strip() or my_ip
    
    print("\nPort range options:")
    print("1. Common ports (1-1023)")
    print("2. Extended range (1-10000)")
    print("3. All ports (1-65535)")
    print("4. Custom range")
    print("5. Specific ports (comma-separated)")

    choice = input("Choose option (1-5, default: 1): ").strip() or "1"
    port_range = range(1, 1024)

    if choice == "1":
        port_range = range(1, 1024)
        print(f"\nScanning {target} - Common ports (1-1023)...")
    elif choice == "2":
        port_range = range(1, 10001)
        print(f"\nScanning {target} - Extended range (1-10000)...")
    elif choice == "3":
        port_range = range(1, 65536)
        print(f"\nScanning {target} - All ports (1-65535)...")
    elif choice == "4":
        start = int(input("Start port: "))
        end = int(input("End port: "))
        port_range = range(start, end + 1)
        print(f"\nScanning {target} - Custom range ({start}-{end})...")
    elif choice == "5":
        ports_input = input("Enter ports (e.g., 22,80,443,8080): ")
        port_range = [int(p.strip()) for p in ports_input.split(",")]
        print(f"\nScanning {target} - Specific ports: {port_range}...")
    else:
        print(f"\nScanning {target} - Common ports (1-1023)...")
    
    for port in port_range:
        if scan_port(target, port):
            print(f"Port {port} is OPEN")