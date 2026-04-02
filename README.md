# Scanner

Lightweight network scanner in Python with minimum dependencies.

### Features
- Auto-detect your IP
- Port scanning
- Multiple modes:
  - Common (1-1023)
  - Extended (1-10000)
  - All (1-65535)
  - Custom range 
  - Specific ports (comma-separated)

### Requirements
- Python 3.x

### Installation
 
```bash
# Clone the repository
git clone https://github.com/rosoema/scanner.git
 
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
python3 scanner.py
 
# End
deactivate
```

