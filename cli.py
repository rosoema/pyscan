# pyscan/cli.py

from config import MAX_INPUT_RETRIES

from utils.validation import validate_ip

from ports.modes import port_all, port_common, port_custom_range, port_extended, port_specific_ports


def get_scan_type() -> str:
    """
    Display scan type options and return user choice.

    Returns:
        Selected scan type key as a string.
    """
    SCAN_TYPES = {
        "1": ("Host Discovery", None),
        "2": ("Port Scan", None),
    }
    
    print("\nScan type options:")
    for key, (name, _) in SCAN_TYPES.items():
        print(f"  {key}. {name}")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose scan type (1-2, default: 1): ").strip() or "1"
        
        if choice in SCAN_TYPES:
            return choice
        
        print(f"Error: Invalid choice '{choice}'.")
        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (1).")
    
    return "1"

def get_target_ip(default_ip: str) -> str:
    """
    Prompt user for target IP address with validation and retry logic.
    
    Args:
        default_ip: Default IP to use if user presses Enter.
    
    Returns:
        Validated IP address string.
    """
    for attempt in range(MAX_INPUT_RETRIES):
        try:
            target = input(f"\nEnter IP to scan (default: {default_ip}): ").strip() or default_ip
            return validate_ip(target)
        except ValueError as e:
            print(f"Error: {e}.")
            if attempt < MAX_INPUT_RETRIES - 1:
                print("Please try again.")
            else:
                print("Max retries exceeded. Using default IP.")
                return default_ip
        except KeyboardInterrupt:
            print("\nInput interrupted. Exiting.")
            sys.exit(0)
    
    return default_ip

def get_protocol() -> str:
    """
    Display protocol options and return user choice.

    Returns:
        Selected protocol as a string ("tcp" or "udp").
    """
    PROTOCOLS = {
        "1": ("tcp", None),
        "2": ("udp", None),
    }
    
    print("\nProtocol options:")
    for key, (name, _) in PROTOCOLS.items():
        print(f"  {key}. {name.upper()}")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose protocol (1-2, default: 1): ").strip() or "1"
        
        if choice in PROTOCOLS:
            return PROTOCOLS[choice][0]
        
        print(f"Error: Invalid choice '{choice}'.")
        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (TCP).")
    
    return "tcp"

def get_port_mode(protocol: str) -> str:
    """
    Display port mode options for the given protocol and return user choice.

    Args:
        protocol: "tcp" or "udp".

    Returns:
        Selected mode key as a string.
    """
    PORT_MODES = {
        "1": ("Common ports", port_common),
        "2": ("Extended range (1-10000)", port_extended),
        "3": ("All ports (1-65535)", port_all),
        "4": ("Custom range", port_custom_range),
        "5": ("Specific ports", port_specific_ports),
    }
    
    proto_upper = protocol.upper()
    print(f"\n{proto_upper} port range options:")
    for key, (name, _) in PORT_MODES.items():
        print(f"  {key}. {name}")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose option (1-5, default: 1): ").strip() or "1"
        
        if choice in PORT_MODES:
            return choice
        
        print(f"Error: Invalid choice '{choice}'.")
        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (1).")
    
    return "1"

def get_discovery_mode() -> str:
    """
    Display host discovery mode options and return user choice.
    
    Returns:
        Selected mode: 'arp', 'ping', or 'both'.
    """
    DISCOVERY_MODES = {
        "1": ("arp", "ARP scan (fastest, local network only)"),
        "2": ("ping", "Ping sweep (ICMP + TCP fallback)"),
        "3": ("both", "Both (most comprehensive)")
    }

    print("\nHost discovery method:")
    for key, (_, title) in DISCOVERY_MODES.items():
        print(f"  {key}. {title}")
    
    for attempt in range(MAX_INPUT_RETRIES):
        choice = input("Choose method (1-3, default: 3): ").strip() or "3"
        
        if choice in DISCOVERY_MODES:
            return DISCOVERY_MODES[choice][0]
        
        print(f"Error: Invalid choice '{choice}'.")
        if attempt < MAX_INPUT_RETRIES - 1:
            print("Please try again.")
        else:
            print("Max retries exceeded. Using default (Both).")
    
    return "both"