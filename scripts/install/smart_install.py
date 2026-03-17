#!/usr/bin/env python3
"""
Enterprise NGFW v2.0 - Advanced AI-Driven Installer for Linux
Replaces the legacy install.sh with an intelligent, self-healing deployment script.

Features:
- Autonomous error resolution using Gemini AI.
- Full context awareness of the Enterprise NGFW ecosystem.
- Creates shortcuts, systemd services, Python venvs, and installs system deps.
"""

import os
import sys
import shutil
import subprocess
import json
import urllib.request
import urllib.error
import time

# ================= Configuration =================
TARGET_DIR = "/opt/enterprise_ngfw"
BIN_CMD = "/usr/local/bin/ngfw-start"
SERVICE_FILE = "/etc/systemd/system/ngfw.service"
VENV_DIR = os.path.join(TARGET_DIR, "venv")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# 🧠 Comprehensive System Context for the AI
SYSTEM_CONTEXT = """
Enterprise Next-Generation Firewall (NGFW) v2.0 Architecture & Requirements Context:

1. Core Technologies:
   - Language: Python 3.9+ 
   - Framework: FastAPI (API/REST), SQLAlchemy (Database), Uvicorn (Server)
   - Network capabilities: eBPF/XDP for acceleration (requires bcc-tools, python3-bpfcc, linux-headers).
   - Packet Processing: Scapy, nfqueue.

2. Inspection Modules (The 15 Subsystems):
   - WAF (Web Application Firewall): NLP and ML (PyTorch, Scikit-learn), Rate Limiting.
   - DLP (Data Loss Prevention): Regex matchers and deep file parsers.
   - SSL Inspection: Needs OpenSSL, cryptography module, CA Certificate generation.
   - Malware AV: Uses YARA (yara-python) for static analysis.
   - Web Filter: Categorizes domains, enforces Safe Search.
   - IDS/IPS: Parses Snort/Suricata rules.
   - DNS Security: Detects DGA (entropy analysis) and DNS Tunneling.
   - HTTP Inspection: Deep L7 analysis.
   - QoS: Token bucket algorithms.
   - Email Security: NLP phishing detection, SMTP protocol parsers.
   - UBA (User Behavior Analytics) & Predictive AI: Requires ML pipelines.

3. Typical Linux Package Dependencies (Debian/Ubuntu):
   - build-essential, python3-dev, python3-pip, python3-venv
   - libssl-dev, libffi-dev, libpcap-dev (for Scapy/packet sniffing)
   - clang, llvm, libbpf-dev, linux-headers-$(uname -r) (for eBPF)

4. Operating Environment:
   - Target install directory: /opt/enterprise_ngfw
   - Main execution point: python api/rest/main.py
   - Configuration file: system/config/base.yaml (Controls dynamic Plugin loading via ModuleManager)

If the user encounters an installation error, YOU (the AI) must provide a ONE-LINE terminal command to fix it. Do NOT output markdown formatting like ```bash, just the raw command string ready for execution.
"""

def print_banner():
    print("\033[0;36m" + "="*70 + "\033[0m")
    print("\033[1;36m    🛡️  Enterprise NGFW v2.0 - Smart AI-Installer 🧠  \033[0m")
    print("\033[0;36m" + "="*70 + "\033[0m")

def print_step(msg):
    print(f"\n\033[1;33m[+]\033[0m {msg}...")

def print_success(msg):
    print(f"  \033[1;32m✅ {msg}\033[0m")

def print_error(msg):
    print(f"  \033[1;31m❌ {msg}\033[0m")
    
def print_ai_action(msg):
    print(f"  \033[1;35m🧠 [AI Agent]: {msg}\033[0m")

def check_root():
    if os.geteuid() != 0:
        print_error("This installer requires root privileges. Please run with sudo.")
        sys.exit(1)

def ask_for_api_key():
    global GEMINI_API_KEY
    if not GEMINI_API_KEY:
        print("\n\033[1;34m[ℹ]\033[0m The Smart Installer can use Google Gemini AI to automatically fix any Linux dependency or Python installation errors.")
        print("\033[1;34m[ℹ]\033[0m Highly recommended to provide an API Key.")
        key = input("Enter your Gemini API Key (or press Enter to skip AI auto-fix): ").strip()
        if key:
            GEMINI_API_KEY = key
            os.environ["GEMINI_API_KEY"] = key

def call_ai_for_fix(failed_command: str, error_output: str) -> str:
    """ Queries Gemini to get a bash command to fix the installation error. """
    if not GEMINI_API_KEY:
        return ""
        
    prompt = f"""
{SYSTEM_CONTEXT}

You are an expert DevOps engineer and Linux Admin fixing an installation script failure.
I ran this bash command: `{failed_command}`
It failed with this error:
```
{error_output[-2000:]} 
```
Provide ONLY a valid one-line bash command to fix this exact error.
For example, if a python c-extension fails to build, provide the `apt-get install -y <missing-lib>` command.
If pip fails, maybe upgrade pip or install a system package.
Output exactly ONE line. Do NOT output markdown, explanations, or quotes. Just the command.
"""
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    data = {"contents": [{"parts": [{"text": prompt}]}]}
    
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers)
    
    try:
        response = urllib.request.urlopen(req)
        res_body = response.read().decode('utf-8')
        res_json = json.loads(res_body)
        
        candidates = res_json.get("candidates", [])
        if candidates:
            fix_cmd = candidates[0]["content"]["parts"][0]["text"].strip()
            # Clean up potential markdown code blocks returned by AI
            if fix_cmd.startswith("```bash"):
                fix_cmd = fix_cmd[7:]
            elif fix_cmd.startswith("```"):
                fix_cmd = fix_cmd[3:]
            if fix_cmd.endswith("```"):
                fix_cmd = fix_cmd[:-3]
            return fix_cmd.strip()
            
    except Exception as e:
        print_error(f"Failed to communicate with AI API: {e}")
        
    return ""

def run_cmd_smart(cmd: str, max_retries: int = 2) -> bool:
    """ Runs a bash command. If it fails and AI is available, asks AI for a fix and retries. """
    for attempt in range(max_retries + 1):
        try:
            result = subprocess.run(
                ["bash", "-c", cmd], 
                capture_output=True, 
                text=True, 
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            if attempt == max_retries:
                print_error(f"Command failed after {max_retries} retries: {cmd}")
                print_error(f"Output: {e.stderr.strip()[-500:]}")
                return False
                
            print_error(f"Command failed (Attempt {attempt+1}/{max_retries+1})")
            
            if GEMINI_API_KEY:
                print_ai_action("Analyzing error log and fetching a fix...")
                fix_cmd = call_ai_for_fix(cmd, e.stderr)
                if fix_cmd:
                    print_ai_action(f"Applying AI proposed fix: {fix_cmd}")
                    try:
                        subprocess.run(["bash", "-c", fix_cmd], capture_output=True, check=True)
                        print_ai_action("Fix applied successfully! Retrying original command...")
                        time.sleep(1)
                    except subprocess.CalledProcessError as fix_e:
                        print_error(f"The AI fix also failed: {fix_cmd}")
                else:
                    print_error("AI could not provide a valid fix format.")
            else:
                print_error(f"Error output: {e.stderr.strip()[-500:]}")
                print_error("No AI key provided. Manual intervention required. Aborting.")
                return False
    return False

def setup_target_dir():
    print_step(f"Copying System to Deploy Directory: {TARGET_DIR}")
    
    # We are in scripts/install, the root repo is two levels up
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    
    if os.path.exists(TARGET_DIR):
        print_step(f"Directory {TARGET_DIR} already exists. Updating files...")
        os.system(f"cp -r {repo_root}/* {TARGET_DIR}/")
    else:
        shutil.copytree(repo_root, TARGET_DIR)
        
    print_success(f"System successfully copied to {TARGET_DIR}")

def install_system_dependencies():
    print_step("Installing base system dependencies")
    # Base dependencies that might be needed to compile python libraries
    cmds = [
        "apt-get update -y || echo 'Skipping apt update on non-debian'",
        "apt-get install -y build-essential python3-dev python3-pip python3-venv libssl-dev libffi-dev libpcap-dev || yum install -y gcc python3-devel libpcap-devel"
    ]
    for c in cmds:
        if "apt-get update" in c: 
            # We don't care if apt fails on RedHat
            subprocess.run(["bash", "-c", c], capture_output=True)
        else:
            if not run_cmd_smart(c):
                print_error("Failed to install critical system requirements.")
                sys.exit(1)
    print_success("Base Linux dependencies installed.")

def setup_python_env():
    print_step("Setting up Python Virtual Environment & Requirements")
    os.chdir(TARGET_DIR)
    
    if not os.path.exists(VENV_DIR):
        if not run_cmd_smart(f"python3 -m venv {VENV_DIR}"):
            sys.exit(1)
            
    activate = f"source {VENV_DIR}/bin/activate"
    
    # Upgrade pip and install requirements
    req_file = os.path.join(TARGET_DIR, "requirements.txt")
    if os.path.exists(req_file):
        pip_cmd = f"{activate} && pip install --upgrade pip && pip install -r {req_file}"
        if not run_cmd_smart(pip_cmd, max_retries=3): 
            sys.exit(1)
            
    print_success("Python environment setup complete.")

def create_system_shortcut():
    print_step(f"Creating global executable shortcut at {BIN_CMD}")
    
    script_content = f"""#!/bin/bash
# Enterprise NGFW Startup wrapper
cd {TARGET_DIR}
source {VENV_DIR}/bin/activate
export PYTHONPATH="{TARGET_DIR}:$PYTHONPATH"
export NGFW_ENV="production"
export NGFW_CONFIG="{TARGET_DIR}/system/config/base.yaml"

# Start the main API which dynamically loads all modules
python api/rest/main.py "$@"
"""
    try:
        with open(BIN_CMD, 'w', encoding='utf-8') as f:
            f.write(script_content)
        os.chmod(BIN_CMD, 0o755)
        print_success(f"Shortcut created! You can now run the system anywhere using: ngfw-start")
    except Exception as e:
        print_error(f"Failed to create shortcut: {e}")

def create_systemd_service():
    print_step("Creating Systemd Service for Autostart")
    
    service_content = f"""[Unit]
Description=Enterprise Next-Gen Firewall (NGFW) v2.0
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={TARGET_DIR}
ExecStart={BIN_CMD}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    try:
        with open(SERVICE_FILE, 'w', encoding='utf-8') as f:
            f.write(service_content)
        
        if shutil.which("systemctl"):
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", "ngfw"], check=True)
            print_success(f"Systemd service created ({SERVICE_FILE}). Start with: systemctl start ngfw")
        else:
            print_success(f"Systemd service file created at {SERVICE_FILE}")
            
    except Exception as e:
        print_error(f"Failed to create systemd service: {e}")

def main():
    print_banner()
    check_root()
    ask_for_api_key()
    
    setup_target_dir()
    install_system_dependencies()
    setup_python_env()
    create_system_shortcut()
    create_systemd_service()
    
    print("\n\033[0;32m" + "="*70 + "\033[0m")
    print("\033[1;32m✨ Installation Completed Successfully! ✨\033[0m")
    print("\033[0;32m" + "="*70 + "\033[0m")
    print("To start the system right now, run:")
    print("   \033[1;33mngfw-start\033[0m")
    print("\nOr to run it as a background service:")
    print("   \033[1;33msystemctl start ngfw\033[0m")
    print("   \033[1;33msystemctl status ngfw\033[0m")
    print("\nThe API and Dashboard will start on \033[1mhttp://0.0.0.0:8000\033[0m")
    print("======================================================================")

if __name__ == "__main__":
    main()
