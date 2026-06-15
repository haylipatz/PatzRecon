# PatzRecon
PatzRecon: Educational Reconnaissance Framework<br>
PatzRecon is a Python-based, modular reconnaissance tool designed to assist security practitioners in identifying potential vulnerability classes within controlled, authorized environments. It is not an exploitation framework; it performs structured probing to reduce manual enumeration time during penetration testing engagements or CTF challenges.

# Core Philosophy:
Authorization First: The tool requires explicit target definition (URL/IP) and assumes the user has legal authority to test the target.
<br>No False Positives (Best Effort): Probes are designed to be deterministic where possible (e.g., checking for specific headers, status codes, or known file paths) rather than relying on heuristic guesses that often lead to false positives.
<br>Modularity: Each of the 31 PortSwigger Web Security Academy topics is handled by an independent module, allowing for easy updates and maintenance.

# How It Works
PatzRecon operates as a "Lab-Scope Recon Aide." Instead of blindly attacking a target, it systematically fingerprints the application structure and behavior.
<br>1. Input: The user provides a target URL (e.g., https://example.net/) and optional credentials or session cookies.
<br>2. Orchestration: The main engine (PatzRecon.py) loads all 31 vulnerability modules.
<br>3. Probing: Each module executes a series of non-destructive checks:
<br>Passive Analysis: Inspects HTML source, HTTP headers, and JavaScript files for clues (e.g., X-Powered-By, CSRF tokens, CORS headers).
<br>Active Fingerprinting: Sends specific, safe requests to detect behaviors (e.g., sending a malformed JSON body to check for deserialization errors, or requesting /admin to check for access control responses).
<br>4. Reporting: Results are aggregated into a structured report indicating which vulnerability classes are likely present based on observed indicators.
<br><br>Example Scenario:
<br>Target: A PortSwigger Lab ID acme123.
<br>Action: PatzRecon sends a request to the homepage.
<br>Module: SQL Injection: Checks if input parameters reflect in error messages or if specific SQL keywords trigger database errors.
<br>Module: CORS: Checks if the Access-Control-Allow-Origin header is set to * or reflects the Origin header improperly.
<br>Output: "Potential SQL Injection detected in 'productId' parameter. CORS misconfiguration identified."
<br>
# Architecture: Modular Plugin System
The project is split into a main orchestrator and independent vulnerability modules. This follows the Strategy Pattern and Plugin Architecture.
Directory Structure

PatzRecon/
<br>├── core/
<br>│   ├── __init__.py
<br>│   ├── engine.py          # Main orchestrator
<br>│   ├── http_client.py      # Async HTTP handler
<br>│   ├── cache.py           # SQLite deduplication
<br>│   ├── matcher.py         # Fuzzy detection logic
<br>│   └── reporter.py        # Output formatting
<br>├── modules/               # 31 vulnerability modules
<br>│   ├── sqli/
<br>│   ├── xss/
<br>│   ├── csrf/
<br>│   ├── cors/
<br>│   ├── idor/
<br>│   └── ... (31 topics)
<br>├── payloads/              # YAML payload database
<br>│   ├── sqli.yaml
<br>│   ├── xss.yaml
<br>│   └── ...
<br>├── utils/
<br>│   ├── lab_parser.py      # PortSwigger URL parser
<br>│   ├── auth_handler.py    # Session management
<br>│   └── validators.py      # Input validation
<br>├── reports/               # Output directory
<br>├── patzrecon.py           # CLI entry point
<br>└── requirements.txt

## Installation Guide
<br>Step 1: Prerequisites

```
# Python 3.8+ required
python3 --version

# Install pip if needed
sudo apt-get install python3-pip  # Debian/Ubuntu
brew install python3              # macOS
```
<br>Step 2: Install PatzRecon
```
# Clone or extract archive
cd PatzRecon

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

<br>Step 3: Verify Installation 
```
python patzrecon.py --help
```

<br>Step 4: Configure (Optional)
<br>Create config.yaml in the PatzRecon directory:
```
max_concurrent: 10
timeout: 30
rate_limit_delay: [1, 3]
user_agent: "PatzRecon/1.0"
min_confidence: low
```
##Usage Example
<br>Beginner Usage
```
# Basic scan of a lab
python patzrecon.py -u "https://abc123.web-security-academy.net"

# Scan with session (logged-in testing)
python patzrecon.py -u "https://target.com" --cookie "session=xyz789"

# Output to file
python patzrecon.py -u "https://target.com" -o results.json --format json
```

<br>Professional Usage 
```
# BSCP Exam mode - all relevant modules
python patzrecon.py -u "https://exam-id.web-security-academy.net" \
    --bscp-mode \
    --proxy http://127.0.0.1:8080 \
    -o bscp_report.html \
    --format html \
    -v

# Specific modules with authentication
python patzRecon.py -u "https://app.com/admin" \
    -m sqli,idor,access_control,jwt \
    --auth-header "Bearer eyJ0eXAiOiJKV1Qi..." \
    --cookie "admin=true; session=abc" \
    --scope "https://app.com/api,https://app.com/admin" \
    -o findings.json

# HTB/CTF Mode
python patzrecon.py -u "http://10.10.10.10" \
    -m file_upload,lfi,ssti,cmd_injection \
    --threads 20 \
    --timeout 60 \
    -o htb_results.json
```
<br>How Main Flow Works 
```
1. CLI Parsing
   ↓
2. Lab URL Analysis (detect PortSwigger patterns)
   ↓
3. Target Configuration (cookies, auth, scope)
   ↓
4. Engine Initialization
   ├── Load async session
   ├── Initialize SQLite cache
   └── Dynamically load 31 modules
   ↓
5. Module Execution (async with rate limiting)
   ├── Each module probes independently
   ├── Confidence scoring per finding
   └── Deduplication via hash caching
   ↓
6. Result Aggregation
   ↓
7. Report Generation (JSON/CSV/HTML)
```
<br>Lab Integration Example: 
```
# BSCP Exam workflow
target_url = "https://0a7b00xx.yy"
engine = PatzReconEngine()
await engine.initialize()

# Auto-detect lab type from URL
lab = PortSwiggerLabParser().parse(target_url)
# Returns: {'lab_id': '0a7b00xx', 'lab_type': 'sqli_union', ...'}

# BSCP Mode optimizes module order based on exam syllabus
findings = await engine.scan(target, selected_modules=bscp_priority_modules)

# Output mapped to PortSwigger categories
{
  "vulnerability": "SQL Injection (Union-based)",
  "portswigger_topic": "SQL injection UNION attacks",
  "tryhackme_module": "SQL Injection"
}
```
##False Positive Prevention
<br>PatzRecon eliminates false positives through:

<br>1. Multi-Confirmation: Requires multiple indicators
<br>2. Context Awareness: Validates HTML/JS context
<br>3. Response Analysis: Differential comparison
<br>4. Confidence Thresholding: Dismisses low-confidence results
<br>5. Pattern Validation: Regex with strict boundaries

##Kali Linux Installation Guide

<br>Method 1: Direct Installation (Recommended) 
```
# Step 1: Update system packages
sudo apt update && sudo apt upgrade -y

# Step 2: Install system dependencies
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    libssl-dev \
    libffi-dev \
    build-essential

# Step 3: Create installation directory
sudo mkdir -p /opt/patzrecon
sudo chown $(whoami):$(whoami) /opt/patzrecon
cd /opt/patzrecon

# Step 4: Clone repository (or extract archive)
# git clone https://github.com/yourrepo/patzrecon.git .
# OR if you have the archive:
# tar -xzf patzrecon.tar.gz -C /opt/patzrecon

# Step 5: Create Python virtual environment
python3 -m venv venv

# Step 6: Activate virtual environment
source venv/bin/activate

# Step 7: Upgrade pip and install dependencies
pip install --upgrade pip wheel
pip install -r requirements.txt

# Step 8: Make executable globally
chmod +x patzrecon.py
sudo ln -sf /opt/patzrecon/patzrecon.py /usr/local/bin/patzrecon

# Step 9: Verify installation
patzrecon --help
```

<br>Method 2: Kali-Specific Package Installation 
```
# Install Kali's pre-packaged Python tools
sudo apt install -y \
    python3-aiohttp \
    python3-bs4 \
    python3-yaml \
    python3-colorama \
    python3-tqdm

# Then install remaining dependencies via pip
pip install fuzzywuzzy python-Levenshtein
```
<br>Method 3: Docker Install (Optional)
<br>Create Dockerfile
```
FROM kalilinux/kali-rolling

# Install dependencies
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source
COPY . /app/

# Install Python dependencies
RUN python3 -m venv venv && \
    . venv/bin/activate && \
    pip install --upgrade pip && \
    pip install -r requirements.txt

# Entry point
ENTRYPOINT ["venv/bin/python", "patzrecon.py"]
```
<br>Build and run:
```
# Build image
sudo docker build -t patzrecon .

# Run (interact mode)
sudo docker run -it --rm \
    --network host \
    -v $(pwd)/reports:/app/reports \
    patzrecon -u https://target.com

# Run with Burp proxy
sudo docker run -it --rm \
    --network host \
    -e HTTP_PROXY=http://127.0.0.1:8080 \
    patzrecon -u https://target.com --proxy http://127.0.0.1:8080
```
<br>Method 4: Quick Install Script
<br>Save as install_kali.sh
```
#!/bin/bash
# PatzRecon Kali Linux Installer

set -e

echo "[*] Installing PatzRecon on Kali Linux..."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo -e "${RED}[!] Do not run as root${NC}"
   exit 1
fi

# Update system
echo "[*] Updating package lists..."
sudo apt update

# Install dependencies
echo "[*] Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-venv git

# Create directory
INSTALL_DIR="$HOME/tools/patzrecon"
echo "[*] Creating directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Create virtual environment
echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Create requirements.txt if not exists
cat > requirements.txt << 'EOF'
aiohttp>=3.8.0
beautifulsoup4>=4.11.0
pyyaml>=6.0
colorama>=0.4.0
tqdm>=4.64.0
requests>=2.28.0
fuzzywuzzy>=0.18.0
python-Levenshtein>=0.12.0
EOF

# Install Python packages
echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create main script (minimal version for testing)
cat > patzrecon.py << 'EOF'
#!/usr/bin/env python3
"""PatzRecon - Placeholder until full source download"""
print("PatzRecon installed successfully!")
print("Replace this with actual source files.")
EOF

chmod +x patzrecon.py

# Add to PATH
echo "[*] Adding to PATH..."
if ! grep -q "patzrecon" "$HOME/.zshrc"; then
    echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$HOME/.zshrc"
    echo "alias patzrecon='cd $INSTALL_DIR && source venv/bin/activate && python patzrecon.py'" >> "$HOME/.zshrc"
fi

echo -e "${GREEN}[+] Installation complete!${NC}"
echo "[*] Usage: patzrecon -u <target_url>"
echo "[*] Reload terminal or run: source ~/.zshrc"
```
<br>Run
```
chmod +x install_kali.sh
./install_kali.sh
```
<br>Requirements File (requirements.txt)
```
# Core async HTTP
aiohttp>=3.8.4
aiofiles>=23.0.0

# HTML parsing
beautifulsoup4>=4.12.0
lxml>=4.9.0

# Data handling
pyyaml>=6.0

# Async utilities
asyncio-throttle>=1.0.2

# Fuzzy matching (for FP elimination)
fuzzywuzzy>=0.18.0
python-Levenshtein>=0.12.0

# Progress bars
tqdm>=4.65.0

# Output formatting
colorama>=0.4.6
tabulate>=0.9.0

# Optional: For Windows compatibility on WSL
dnspython>=2.3.0
```
##Kali Linux Integration
<br>Burp Suite Pro Integration
<br>Step 3: 
```

```
<br>Step 3: 
```

```
<br>Step 3: 
```

```
<br>Step 3: 
```

```
<br>Step 3: 
```

```
<br>Step 3: 
```

```




