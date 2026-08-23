# PyScan
![Status](https://img.shields.io/badge/status-active_development-yellow)
![Python](https://img.shields.io/badge/python-3.x-blue)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)

> ⚠️ Active development — expect changes and experimental features

A lightweight network scanner.

## Features
**Network Information**
- Auto-detect active network interface
- Display full network configuration (IP, netmask, CIDR, broadcast)
- Support for any subnet size

**Host Discovery**
- ARP scanning for fast local network discovery
- Ping sweep with ICMP and TCP fallback
- MAC address and hostname resolution

**Port Scanning**
- TCP and UDP port scanning
- Service detection via banner grabbing
- Multiple scan modes: common, extended, all ports, custom range, specific ports

**Performance**
- Multi-threaded concurrent scanning
- Real-time progress indicator

## Requirements
- Python 3.x
- macOS

### Installation
```bash
# Clone the repository
git clone https://github.com/rosoema/pyscan.git

# Navigate to directory
cd pyscan
 
# Create virtual environment
python3 -m venv venv
source venv/bin/activate
 
# Install dependencies
pip install -r requirements.txt
```

### Usage
```bash
# Activate virtual environment
source venv/bin/activate
 
# Run
python3 main.py
 
# End
deactivate
```
Follow the interactive prompts to configure your scan.

## Status
This project is public while under active development.
Expect changes, incomplete and experimental features.
