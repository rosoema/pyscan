# pyscan/config.py


MIN_PORT = 1
MAX_PORT = 65535

MAX_INPUT_RETRIES = 3

MAX_WORKERS = 100

RECV_BUFFER_SIZE = 4096
NETWORK_HOST_RANGE = 255

WEB_PORTS = {
    80,
    443,
    8000,
    8080,
    8443,
    8888,
    3000,
    5000,
    9000,
    7000,
    81,
    591,
    593,
    7070,
}

COMMON_UDP_PORTS = {
    53,
    67,
    68,
    69,
    123,
    161,
    500,
    514,
    1194,
    5060,
    5061,
    1812,
    1813
}

SERVICE_PROBES = {
    21: b"", 
    22: b"",
    23: b"", 
    25: b"EHLO pyscan\r\n", 
    80: b"GET / HTTP/1.0\r\n\r\n",
    110: b"",  
    143: b"",  
    443: b"GET / HTTP/1.0\r\n\r\n",  
    3306: b"",  
    5432: b"", 
    6379: b"PING\r\n",
    8080: b"GET / HTTP/1.0\r\n\r\n", 
}

COMMON_SERVICES = {
    20: "ftp-data", 
    21: "ftp", 
    22: "ssh", 
    23: "telnet", 
    25: "smtp",
    53: "dns", 
    80: "http", 
    110: "pop3", 
    143: "imap", 
    443: "https",
    445: "microsoft-ds", 
    3306: "mysql", 
    3389: "rdp", 
    5432: "postgresql",
    5900: "vnc", 
    6379: "redis", 
    8080: "http-proxy", 
    8443: "https-alt",
    27017: "mongodb", 
    5000: "upnp", 
    8000: "http-alt",
}