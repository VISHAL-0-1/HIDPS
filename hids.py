import hashlib
import json
import time
import os
import psutil
import logging
import smtplib
from email.mime.text import MIMEText
import subprocess
import requests
import threading
import re
import sys
import shutil
import ipaddress
from datetime import datetime, timedelta

# GUI imports (required for this version)
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("❌ GUI libraries not available. Please install tkinter.")
    sys.exit(1)

# --- Load Configuration ---
def load_config(config_file="config.json"):
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file '{config_file}' not found!")
        print(f"Error: Configuration file '{config_file}' not found!")
        print("Please create a config.json file with your settings.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing configuration file: {e}")
        print(f"Error: Invalid JSON in configuration file: {e}")
        sys.exit(1)

# Load configuration
config = load_config()

# --- Email Configuration ---
SENDER_EMAIL = config["email"]["sender_email"]
EMAIL_PASSWORD = config["email"]["password"]
RECEIVER_EMAIL = config["email"]["receiver_email"]
SEND_EMAIL_ALERTS = config["email"]["send_alerts"]

# --- Threat Intelligence Integration ---
VT_API_KEY = config["threat_intelligence"]["virustotal_api_key"]

# --- Intrusion Prevention Configuration ---
IPS_ENABLED = config["intrusion_prevention"]["enabled"]
AUTO_BLOCK_IPS = config["intrusion_prevention"]["auto_block_malicious_ips"]
AUTO_KILL_PROCESSES = config["intrusion_prevention"]["auto_kill_suspicious_processes"]
QUARANTINE_FILES = config["intrusion_prevention"]["quarantine_modified_files"]
WHITELIST_IPS = config["intrusion_prevention"]["whitelist_ips"]
PROTECTED_PROCESSES = config["intrusion_prevention"]["protected_processes"]
QUARANTINE_DIR = config["intrusion_prevention"]["quarantine_directory"]
BLOCK_DURATION = config["intrusion_prevention"]["block_duration_minutes"]

# --- State Management ---
blocked_ips = set()
quarantined_files = []
incident_log = []

# --- API Rate Limiting ---
vt_api_cache = {}
last_vt_request = 0
VT_REQUEST_INTERVAL = 15  # Minimum 15 seconds between requests (free tier: 4 requests/minute)

def check_malicious_ip(ip_address):
    global last_vt_request
    
    if not VT_API_KEY:
        logging.error("VirusTotal API key is not set.")
        return False
    
    # Check cache first
    if ip_address in vt_api_cache:
        cache_entry = vt_api_cache[ip_address]
        # Cache valid for 1 hour
        if time.time() - cache_entry['timestamp'] < 3600:
            return cache_entry['is_malicious']
    
    # Rate limiting - ensure minimum interval between requests
    current_time = time.time()
    time_since_last_request = current_time - last_vt_request
    
    if time_since_last_request < VT_REQUEST_INTERVAL:
        wait_time = VT_REQUEST_INTERVAL - time_since_last_request
        logging.info(f"Rate limiting VirusTotal API. Waiting {wait_time:.1f} seconds for IP {ip_address}")
        return False  # Skip this check to avoid rate limiting
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    
    try:
        last_vt_request = current_time
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            is_malicious = malicious_count > 0
            
            # Cache the result
            vt_api_cache[ip_address] = {
                'is_malicious': is_malicious,
                'timestamp': current_time,
                'malicious_count': malicious_count
            }
            
            if is_malicious:
                logging.warning(f"Malicious IP detected: {ip_address} with {malicious_count} malicious hits.")
                return True
            else:
                return False
        elif response.status_code == 429:
            logging.warning(f"VirusTotal API rate limit exceeded. Skipping check for {ip_address}")
            return False
        elif response.status_code == 404:
            # IP not found in VirusTotal - cache as clean
            vt_api_cache[ip_address] = {
                'is_malicious': False,
                'timestamp': current_time,
                'malicious_count': 0
            }
            return False
        else:
            logging.error(f"VirusTotal API request failed with status code: {response.status_code}")
            return False
    except requests.exceptions.Timeout:
        logging.error(f"VirusTotal API timeout for IP: {ip_address}")
        return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking IP with VirusTotal: {e}")
        return False

# --- UTILITY FUNCTIONS ---
def print_banner():
    """Print startup banner"""
    print("\n" + "="*60)
    print("🛡️  HIDS/IPS - Host Intrusion Detection & Prevention System")
    print("="*60)
    print(f"📍 Version: 2.0 | IPS: {'ENABLED' if IPS_ENABLED else 'DISABLED'}")
    print(f"🕒 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

def generate_report():
    """Generate and save system status report"""
    try:
        uname_info = os.uname()
        report = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "system_info": {
                "hostname": uname_info.nodename,
                "platform": uname_info.sysname,
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent
            },
            "security_status": get_ips_status(),
            "blocked_ips": list(blocked_ips),
            "quarantined_files": len(quarantined_files),
            "total_incidents": len(incident_log)
        }
        
        with open('hids_report.json', 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"📊 System report generated: hids_report.json")
        
    except Exception as e:
        print(f"❌ Error generating report: {e}")

# --- CLEANUP FUNCTIONS ---
def is_ip_whitelisted(ip_address):
    """Check if IP is in whitelist"""
    try:
        ip = ipaddress.ip_address(ip_address)
        for whitelist_entry in WHITELIST_IPS:
            if '/' in whitelist_entry:  # CIDR notation
                if ip in ipaddress.ip_network(whitelist_entry):
                    return True
            else:  # Single IP
                if ip == ipaddress.ip_address(whitelist_entry):
                    return True
        return False
    except ValueError:
        return False

def block_malicious_ip(ip_address, reason="Malicious activity detected"):
    """Block malicious IP using iptables"""
    if not IPS_ENABLED or not AUTO_BLOCK_IPS:
        return False
        
    if is_ip_whitelisted(ip_address):
        log_alert("IPS", f"IP {ip_address} is whitelisted, not blocking", ip_address)
        return False
        
    if ip_address in blocked_ips:
        return False  # Already blocked
    
    try:
        # Add iptables rule to block the IP
        subprocess.run([
            'sudo', 'iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP'
        ], check=True, capture_output=True)
        
        blocked_ips.add(ip_address)
        incident = {
            "timestamp": datetime.now().isoformat(),
            "action": "IP_BLOCKED",
            "target": ip_address,
            "reason": reason
        }
        incident_log.append(incident)
        
        log_alert("IPS", f"BLOCKED malicious IP: {ip_address} - Reason: {reason}", ip_address, is_critical=True)
        
        # Schedule unblock after duration
        threading.Timer(BLOCK_DURATION * 60, unblock_ip, args=[ip_address]).start()
        return True
        
    except subprocess.CalledProcessError as e:
        log_alert("IPS", f"Failed to block IP {ip_address}: {e}", ip_address)
        return False
    except Exception as e:
        log_alert("IPS", f"Error blocking IP {ip_address}: {e}", ip_address)
        return False

def unblock_ip(ip_address):
    """Remove IP block after timeout"""
    try:
        subprocess.run([
            'sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'
        ], check=True, capture_output=True)
        
        blocked_ips.discard(ip_address)
        log_alert("IPS", f"UNBLOCKED IP: {ip_address} (timeout expired)", ip_address)
        
    except subprocess.CalledProcessError:
        # Rule might not exist, ignore
        pass
    except Exception as e:
        log_alert("IPS", f"Error unblocking IP {ip_address}: {e}", ip_address)

def terminate_suspicious_process(process):
    """Terminate suspicious process"""
    if not IPS_ENABLED or not AUTO_KILL_PROCESSES:
        return False
        
    try:
        process_name = process.name().lower()
        if any(protected in process_name for protected in PROTECTED_PROCESSES):
            log_alert("IPS", f"Process {process.name()} (PID: {process.pid}) is protected, not terminating", process.pid)
            return False
            
        process.terminate()
        # Wait for graceful termination
        process.wait(timeout=5)
        
        incident = {
            "timestamp": datetime.now().isoformat(),
            "action": "PROCESS_TERMINATED",
            "target": f"{process.name()} (PID: {process.pid})",
            "reason": "Suspicious process activity"
        }
        incident_log.append(incident)
        
        log_alert("IPS", f"TERMINATED suspicious process: {process.name()} (PID: {process.pid})", process.pid, is_critical=True)
        return True
        
    except psutil.NoSuchProcess:
        return False  # Process already gone
    except psutil.TimeoutExpired:
        try:
            process.kill()  # Force kill if terminate fails
            log_alert("IPS", f"FORCE KILLED suspicious process: {process.name()} (PID: {process.pid})", process.pid, is_critical=True)
            return True
        except psutil.NoSuchProcess:
            return False
    except Exception as e:
        log_alert("IPS", f"Error terminating process {process.pid}: {e}", process.pid)
        return False

def quarantine_file(file_path, reason="File modification detected"):
    """Quarantine modified critical file"""
    if not IPS_ENABLED or not QUARANTINE_FILES:
        return False
        
    try:
        # Create quarantine directory if it doesn't exist
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        
        # Generate quarantine filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{filename}_{timestamp}")
        
        # Copy file to quarantine (preserve original for investigation)
        if os.path.exists(file_path):
            shutil.copy2(file_path, quarantine_path)
            
            quarantine_info = {
                "original_path": file_path,
                "quarantine_path": quarantine_path,
                "timestamp": datetime.now().isoformat(),
                "reason": reason
            }
            quarantined_files.append(quarantine_info)
            
            incident = {
                "timestamp": datetime.now().isoformat(),
                "action": "FILE_QUARANTINED",
                "target": file_path,
                "quarantine_location": quarantine_path,
                "reason": reason
            }
            incident_log.append(incident)
            
            log_alert("IPS", f"QUARANTINED file: {file_path} -> {quarantine_path} - Reason: {reason}", file_path, is_critical=True)
            return True
            
    except Exception as e:
        log_alert("IPS", f"Error quarantining file {file_path}: {e}", file_path)
        return False
    
    return False

# --- Central Logging Setup ---
log_file_path = "hids.log"
logging.basicConfig(
    filename=log_file_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(message)s'))
logging.getLogger().addHandler(console_handler)

# --- State Management for Alerts ---
sent_alerts = set()

def send_email(subject, body):
    if not SEND_EMAIL_ALERTS:
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, EMAIL_PASSWORD)
            smtp.send_message(msg)
        logging.info("Email alert sent successfully!")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def log_alert(module, message, unique_id, is_critical=False):
    alert_message = f"MODULE: {module} | {message}"
    logging.info(alert_message)
    
    if is_critical and unique_id not in sent_alerts:
        sent_alerts.add(unique_id)
        subject = f"HIDS ALERT: {module} Detection"
        send_email(subject, alert_message)

# --- FILE INTEGRITY MONITORING (FIM) ---
def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        log_alert("FIM", f"Error accessing file {file_path}: {e}", file_path)
        return None

def check_file_integrity(baseline_file):
    try:
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)
    except FileNotFoundError:
        log_alert("FIM", f"Baseline file '{baseline_file}' not found.", baseline_file)
        return

    for file_path, stored_hash in baseline.items():
        current_hash = calculate_sha256(file_path)
        
        if current_hash is None:
            log_alert("FIM", f"File deleted: {file_path}", file_path, is_critical=True)
        elif current_hash != stored_hash:
            log_alert("FIM", f"File modified: {file_path}", file_path, is_critical=True)
            # IPS: Quarantine the modified file
            quarantine_file(file_path, f"Critical file modification detected")

# --- LOG ANALYSIS ---
def start_log_monitor(log_file):
    suspicious_patterns = ["authentication failure", "invalid user", "Failed password"]
    try:
        process = subprocess.Popen(
            ['tail', '-n', '0', '-f', log_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        for line in iter(process.stdout.readline, ''):
            for pattern in suspicious_patterns:
                if pattern in line:
                    log_alert("Log Analyzer", f"Suspicious activity detected! Log entry: {line.strip()}", line, is_critical=True)
    except FileNotFoundError:
        log_alert("Log Analyzer", f"Log file not found at {log_file}", log_file)
    except Exception as e:
        log_alert("Log Analyzer", f"Error in log monitor: {e}", log_file)

# --- PROCESS MONITORING & THREAT INTEL SCANNER ---
def start_network_scanner():
    scan_count = 0
    while True:
        try:
            # Use netstat to get all established connections
            netstat_output = subprocess.run(['netstat', '-ant'], capture_output=True, text=True, check=True)
            unique_ips = set()
            
            for line in netstat_output.stdout.splitlines():
                if "ESTABLISHED" in line:
                    match = re.search(r"\S+\s+\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\s+ESTABLISHED", line)
                    if match:
                        remote_ip = match.group(2)
                        unique_ips.add(remote_ip)
                        continue

                if "CLOSE_WAIT" in line:
                    match = re.search(r"\S+\s+\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\s+CLOSE_WAIT", line)
                    if match:
                        remote_ip = match.group(2)
                        unique_ips.add(remote_ip)
                        continue
            
            # Only check a few IPs per scan to avoid rate limiting
            ips_to_check = list(unique_ips)[:3]  # Limit to 3 IPs per scan
            
            for remote_ip in ips_to_check:
                # Skip private/local IPs
                if remote_ip.startswith(('127.', '192.168.', '10.', '172.')):
                    continue
                    
                if check_malicious_ip(remote_ip):
                    log_alert("Threat Intel", f"Connection to malicious IP {remote_ip} detected.", remote_ip, is_critical=True)
                    # IPS: Block the malicious IP
                    block_malicious_ip(remote_ip, "VirusTotal threat intelligence match")
                
                # Small delay between IP checks
                time.sleep(2)

        except subprocess.CalledProcessError as e:
            log_alert("Threat Intel", f"Error running netstat: {e}", "netstat_error")
        except Exception as e:
            log_alert("Threat Intel", f"Error in network scanner: {e}", "network_scan_error")
        
        scan_count += 1
        # Longer sleep between network scans to reduce API usage
        time.sleep(30)  # Scan every 30 seconds instead of 10

def monitor_processes():
    suspicious_directories = ["/tmp", "/var/tmp"]
    for proc in psutil.process_iter(['name', 'exe', 'cmdline']):
        try:
            cmdline = " ".join(proc.cmdline())
            is_suspicious_path = any(susp_dir in proc.exe() for susp_dir in suspicious_directories) if proc.exe() else False
            is_suspicious_cmdline = any(susp_dir in cmdline for susp_dir in suspicious_directories) if cmdline else False

            if is_suspicious_path or is_suspicious_cmdline:
                message = f"Suspicious process running! Name: {proc.name()} | PID: {proc.pid} | Command Line: {cmdline}"
                log_alert("Process Monitor", message, proc.pid, is_critical=True)
                # IPS: Terminate suspicious process
                terminate_suspicious_process(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

# --- INCIDENT RESPONSE AND REPORTING ---
def save_incident_report():
    """Save incident log to file"""
    try:
        report_file = f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                "report_generated": datetime.now().isoformat(),
                "total_incidents": len(incident_log),
                "blocked_ips": list(blocked_ips),
                "quarantined_files": quarantined_files,
                "incidents": incident_log
            }, f, indent=4)
        log_alert("IPS", f"Incident report saved to {report_file}", "incident_report")
        return report_file
    except Exception as e:
        log_alert("IPS", f"Error saving incident report: {e}", "incident_report_error")
        return None

def cleanup_expired_blocks():
    """Clean up any remaining iptables rules (in case of unexpected shutdown)"""
    try:
        # This is a safety cleanup - normally handled by timers
        result = subprocess.run(['sudo', 'iptables', '-L', 'INPUT', '-n'], 
                              capture_output=True, text=True, check=True)
        
        # Look for our DROP rules and clean them up if needed
        for line in result.stdout.split('\n'):
            if 'DROP' in line and any(ip in line for ip in blocked_ips):
                # Rules exist, they'll be handled by the timer system
                pass
                
    except Exception as e:
        log_alert("IPS", f"Error during cleanup check: {e}", "cleanup_error")

def get_ips_status():
    """Get current IPS status"""
    return {
        "ips_enabled": IPS_ENABLED,
        "blocked_ips_count": len(blocked_ips),
        "quarantined_files_count": len(quarantined_files),
        "total_incidents": len(incident_log),
        "auto_block_enabled": AUTO_BLOCK_IPS,
        "auto_kill_enabled": AUTO_KILL_PROCESSES,
        "quarantine_enabled": QUARANTINE_FILES
    }

# --- GUI CLASS ---
class HIDSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HIDS/IPS Control Center")
        self.root.geometry("1200x800")

        # Theme & palette
        self.setup_theme()
        
        # HIDS control
        self.hids_thread = None
        self.hids_running = False
        self.config_data = config  # Reference to global config
        
        self.create_widgets()
        self.update_display()

        # Auto-start HIDS monitoring on GUI launch
        # Delay slightly to ensure UI is fully realized before threads start
        self.root.after(100, self.start_hids)
        
        # Start periodic updates
        self.root.after(3000, self.periodic_update)
    
    def create_widgets(self):
        """Create comprehensive GUI with tabs"""
        # Main title / app bar
        title_frame = ttk.Frame(self.root, padding=(10, 12))
        title_frame.pack(fill=tk.X)
        ttk.Label(title_frame, text="HIDS/IPS Control Center", style='Header.TLabel').pack(side=tk.LEFT)
        # subtle right-side subtitle
        ttk.Label(title_frame, text="Modern UI • All features intact", style='Subtle.TLabel').pack(side=tk.RIGHT)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create tabs
        self.create_status_tab()
        self.create_config_tab()
        self.create_logs_tab()
        self.create_ip_management_tab()
        self.create_quarantine_tab()

    def setup_theme(self):
        """Configure a modern dark theme for ttk widgets"""
        # Professional light palette by default
        self.colors = {
            'bg': '#f5f6fa',        # app background
            'panel': '#ffffff',     # cards/panels
            'surface': '#ffffff',   # inputs/text areas
            'text': '#2b2d42',      # primary text
            'subtext': '#6c757d',   # secondary text
            'primary': '#2b8cff',   # primary button/tab highlight
            'primary_active': '#1e7aff',
            'success': '#20c997',   # success button
            'warning': '#f0ad4e',   # warning button
            'danger': '#dc3545',    # danger button
            'accent': '#6f42c1',    # secondary-accent
            'select': '#e9f2ff',    # selection bg
            'border': '#dfe3e8'     # borders/dividers
        }

        try:
            self.style = ttk.Style()
            # Use a theme that respects colors
            try:
                self.style.theme_use('clam')
            except tk.TclError:
                pass
            # Root background
            self.root.configure(bg=self.colors['bg'])

            # Base styles
            self.style.configure('.', background=self.colors['bg'], foreground=self.colors['text'])
            self.style.configure('TFrame', background=self.colors['panel'])
            self.style.configure('TLabel', background=self.colors['panel'], foreground=self.colors['text'], font=("Segoe UI", 11))
            self.style.configure('Subtle.TLabel', background=self.colors['bg'], foreground=self.colors['subtext'], font=("Segoe UI", 10))
            self.style.configure('Header.TLabel', background=self.colors['bg'], foreground=self.colors['text'], font=("Segoe UI", 20, 'bold'))
            self.style.configure('Card.TLabelframe', background=self.colors['panel'], foreground=self.colors['text'], padding=10, bordercolor=self.colors['border'])
            self.style.configure('Card.TLabelframe.Label', background=self.colors['panel'], foreground=self.colors['subtext'], font=("Segoe UI", 12, 'bold'))

            # Buttons
            self.style.configure('Accent.TButton', background=self.colors['primary'], foreground='#0b0b0f', padding=8, font=("Segoe UI", 11, 'bold'))
            self.style.map('Accent.TButton', background=[('active', self.colors['primary_active']), ('disabled', '#2b2f40')])
            self.style.configure('Success.TButton', background=self.colors['success'], foreground='#0b0b0f', padding=8, font=("Segoe UI", 11, 'bold'))
            self.style.configure('Danger.TButton', background=self.colors['danger'], foreground='#0b0b0f', padding=8, font=("Segoe UI", 11, 'bold'))
            self.style.configure('Warning.TButton', background=self.colors['warning'], foreground='#0b0b0f', padding=8, font=("Segoe UI", 11, 'bold'))
            self.style.configure('Secondary.TButton', background=self.colors['surface'], foreground=self.colors['text'], padding=8, font=("Segoe UI", 11, 'bold'))
            self.style.map('Secondary.TButton', background=[('active', '#3b3f55')])

            # Notebook (tabs)
            self.style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
            self.style.configure('TNotebook.Tab', background='#f8f9fb', foreground=self.colors['subtext'], padding=(16, 8), font=("Segoe UI", 11, 'bold'))
            self.style.map('TNotebook.Tab', background=[('selected', '#ffffff')], foreground=[('selected', self.colors['text'])])

            # Entry / Checkbox
            self.style.configure('TEntry', fieldbackground=self.colors['surface'], background=self.colors['surface'], foreground=self.colors['text'])
            self.style.configure('TCheckbutton', background=self.colors['panel'], foreground=self.colors['text'])

            # Treeview
            self.style.configure('Treeview', background=self.colors['surface'], fieldbackground=self.colors['surface'], foreground=self.colors['text'], borderwidth=0, rowheight=28, font=("Segoe UI", 10))
            self.style.configure('Treeview.Heading', background='#f8f9fb', foreground=self.colors['subtext'], font=("Segoe UI", 10, 'bold'))
            self.style.map('Treeview', background=[('selected', self.colors['select'])], foreground=[('selected', self.colors['text'])])

            # Status badges
            self.style.configure('Good.Badge.TLabel', background=self.colors['success'], foreground='#0b0b0f', padding=(10, 4), font=("Segoe UI", 11, 'bold'))
            self.style.configure('Bad.Badge.TLabel', background=self.colors['danger'], foreground='#0b0b0f', padding=(10, 4), font=("Segoe UI", 11, 'bold'))
            self.style.configure('Neutral.Badge.TLabel', background='#8c8fa1', foreground='#0b0b0f', padding=(10, 4), font=("Segoe UI", 11, 'bold'))

        except Exception:
            # If styling fails for any reason, fall back silently
            pass
    
    def create_status_tab(self):
        """Create system status and control tab"""
        status_frame = ttk.Frame(self.notebook)
        self.notebook.add(status_frame, text="System Status")
        
        # System Status Section
        status_group = ttk.LabelFrame(status_frame, text="System Status", padding=10, style='Card.TLabelframe')
        status_group.pack(fill=tk.X, padx=10, pady=5)
        
        # Status indicators
        self.status_indicators = ttk.Frame(status_group)
        self.status_indicators.pack(fill=tk.X, pady=5)
        
        # Control buttons
        control_frame = ttk.LabelFrame(status_frame, text="System Controls", padding=10, style='Card.TLabelframe')
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        button_frame = ttk.Frame(control_frame)
        button_frame.pack()
        
        self.start_btn = ttk.Button(button_frame, text="Start HIDS", command=self.start_hids, style='Success.TButton')
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop HIDS", command=self.stop_hids, style='Danger.TButton')
        self.stop_btn.state(['disabled'])
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Refresh", command=self.update_display, style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        
        # Add demo data button for testing
        ttk.Button(button_frame, text="Add Test Data", command=self.add_demo_data, style='Secondary.TButton').pack(side=tk.LEFT, padx=5)
        
        # System Information Display
        info_frame = ttk.LabelFrame(status_frame, text="System Information", padding=10, style='Card.TLabelframe')
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.info_text = scrolledtext.ScrolledText(info_frame, height=20, width=100, font=('Courier', 10))
        try:
            self.info_text.configure(bg=self.colors['surface'], fg=self.colors['text'], insertbackground=self.colors['text'], highlightthickness=0, bd=0)
        except Exception:
            pass
        self.info_text.pack(fill=tk.BOTH, expand=True)
    
    def create_config_tab(self):
        """Create configuration management tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")
        
        # Create scrollable frame
        canvas = tk.Canvas(config_frame, background=self.colors['panel'], highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(config_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Email Configuration
        email_group = ttk.LabelFrame(scrollable_frame, text="📧 Email Settings", padding=10, style='Card.TLabelframe')
        email_group.pack(fill=tk.X, padx=10, pady=5)
        
        self.email_vars = {}
        email_fields = [
            ("sender_email", "Sender Email:"),
            ("password", "App Password:"),
            ("receiver_email", "Receiver Email:")
        ]
        
        for field, label in email_fields:
            frame = ttk.Frame(email_group)
            frame.pack(fill=tk.X, pady=2)
            ttk.Label(frame, text=label, width=20, anchor='w').pack(side=tk.LEFT)
            var = tk.StringVar(value=self.config_data.get('email', {}).get(field, ''))
            self.email_vars[field] = var
            entry = ttk.Entry(frame, textvariable=var, width=40, show='*' if 'password' in field else None)
            entry.pack(side=tk.LEFT, padx=5)
        
        self.email_alerts_var = tk.BooleanVar(value=self.config_data.get('email', {}).get('send_alerts', True))
        ttk.Checkbutton(email_group, text="Enable Email Alerts", variable=self.email_alerts_var).pack(anchor='w')
        
        # Test email button
        test_email_frame = ttk.Frame(email_group)
        test_email_frame.pack(fill=tk.X, pady=5)
        ttk.Button(test_email_frame, text="Send Test Email", command=self.send_test_email, style='Secondary.TButton').pack(side=tk.LEFT)
        
        # IPS Configuration
        ips_group = ttk.LabelFrame(scrollable_frame, text="🛡️ Intrusion Prevention Settings", padding=10, style='Card.TLabelframe')
        ips_group.pack(fill=tk.X, padx=10, pady=5)
        
        self.ips_vars = {}
        ips_checks = [
            ("enabled", "Enable IPS"),
            ("auto_block_malicious_ips", "Auto Block Malicious IPs"),
            ("auto_kill_suspicious_processes", "Auto Kill Suspicious Processes"),
            ("quarantine_modified_files", "Quarantine Modified Files")
        ]
        
        for field, label in ips_checks:
            var = tk.BooleanVar(value=self.config_data.get('intrusion_prevention', {}).get(field, True))
            self.ips_vars[field] = var
            ttk.Checkbutton(ips_group, text=label, variable=var).pack(anchor='w')
        
        # Block duration
        duration_frame = ttk.Frame(ips_group)
        duration_frame.pack(fill=tk.X, pady=5)
        ttk.Label(duration_frame, text="Block Duration (minutes):").pack(side=tk.LEFT)
        self.block_duration_var = tk.StringVar(value=str(self.config_data.get('intrusion_prevention', {}).get('block_duration_minutes', 60)))
        ttk.Entry(duration_frame, textvariable=self.block_duration_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # Monitoring Settings
        monitor_group = ttk.LabelFrame(scrollable_frame, text="🔍 Monitoring Settings", padding=10, style='Card.TLabelframe')
        monitor_group.pack(fill=tk.X, padx=10, pady=5)
        
        monitor_fields = [
            ("scan_interval", "Scan Interval (seconds):"),
            ("fim_check_interval", "FIM Check Interval (seconds):"),
            ("log_file", "Log File Path:")
        ]
        
        self.monitor_vars = {}
        for field, label in monitor_fields:
            frame = ttk.Frame(monitor_group)
            frame.pack(fill=tk.X, pady=2)
            ttk.Label(frame, text=label, width=25, anchor='w').pack(side=tk.LEFT)
            var = tk.StringVar(value=str(self.config_data.get('monitoring', {}).get(field, '')))
            self.monitor_vars[field] = var
            ttk.Entry(frame, textvariable=var, width=40).pack(side=tk.LEFT, padx=5)
        
        # API Settings
        api_group = ttk.LabelFrame(scrollable_frame, text="🌐 API Settings", padding=10, style='Card.TLabelframe')
        api_group.pack(fill=tk.X, padx=10, pady=5)
        
        api_frame = ttk.Frame(api_group)
        api_frame.pack(fill=tk.X, pady=2)
        ttk.Label(api_frame, text="VirusTotal API Key:", width=25, anchor='w').pack(side=tk.LEFT)
        self.vt_api_var = tk.StringVar(value=self.config_data.get('threat_intelligence', {}).get('virustotal_api_key', ''))
        ttk.Entry(api_frame, textvariable=self.vt_api_var, width=40, show='*').pack(side=tk.LEFT, padx=5)
        
        # Save button
        save_frame = ttk.Frame(scrollable_frame)
        save_frame.pack(fill=tk.X, padx=10, pady=20)
        ttk.Button(save_frame, text="💾 Save Configuration", command=self.save_configuration, style='Accent.TButton').pack()
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def create_logs_tab(self):
        """Create logs and alerts tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs & Alerts")
        
        # Log viewer
        log_group = ttk.LabelFrame(logs_frame, text="System Logs", padding=10, style='Card.TLabelframe')
        log_group.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Control buttons for logs
        log_controls = ttk.Frame(log_group)
        log_controls.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(log_controls, text="Refresh Logs", command=self.refresh_logs, style='Accent.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(log_controls, text="Clear Logs", command=self.clear_logs, style='Danger.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(log_controls, text="Export Logs", command=self.export_logs, style='Success.TButton').pack(side=tk.LEFT, padx=2)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(log_group, height=25, width=100, font=('Courier', 9))
        try:
            self.log_text.configure(bg=self.colors['surface'], fg=self.colors['text'], insertbackground=self.colors['text'], highlightthickness=0, bd=0)
        except Exception:
            pass
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Auto-refresh checkbox
        auto_refresh_frame = ttk.Frame(log_group)
        auto_refresh_frame.pack(fill=tk.X, pady=5)
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(auto_refresh_frame, text="Auto-refresh logs every 5 seconds", variable=self.auto_refresh_var).pack(anchor='w')
    
    def create_ip_management_tab(self):
        """Create IP management tab"""
        ip_frame = ttk.Frame(self.notebook)
        self.notebook.add(ip_frame, text="IP Management")
        
        # Blocked IPs section
        blocked_group = ttk.LabelFrame(ip_frame, text="Blocked IP Addresses", padding=10, style='Card.TLabelframe')
        blocked_group.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # IP control buttons
        ip_controls = ttk.Frame(blocked_group)
        ip_controls.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(ip_controls, text="Refresh List", command=self.refresh_blocked_ips, style='Accent.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(ip_controls, text="VT Status", command=self.show_virustotal_status, style='Secondary.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(ip_controls, text="Unblock Selected", command=self.unblock_selected_ip, style='Warning.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(ip_controls, text="Clear All Blocks", command=self.clear_all_blocks, style='Danger.TButton').pack(side=tk.LEFT, padx=2)
        
        # IP list
        list_frame = ttk.Frame(blocked_group)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.ip_listbox = tk.Listbox(list_frame, height=15, font=('Courier', 10))
        scrollbar_ip = ttk.Scrollbar(list_frame, orient="vertical")
        self.ip_listbox.config(yscrollcommand=scrollbar_ip.set)
        scrollbar_ip.config(command=self.ip_listbox.yview)
        
        self.ip_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_ip.pack(side=tk.RIGHT, fill=tk.Y)
        try:
            self.ip_listbox.configure(bg=self.colors['surface'], fg=self.colors['text'], selectbackground=self.colors['select'], selectforeground=self.colors['text'], highlightthickness=0, bd=0)
        except Exception:
            pass
        
        # Manual IP blocking
        manual_group = ttk.LabelFrame(ip_frame, text="Manual IP Blocking", padding=10, style='Card.TLabelframe')
        manual_group.pack(fill=tk.X, padx=10, pady=5)
        
        manual_frame = ttk.Frame(manual_group)
        manual_frame.pack(fill=tk.X)
        
        ttk.Label(manual_frame, text="IP Address:").pack(side=tk.LEFT)
        self.manual_ip_var = tk.StringVar()
        ttk.Entry(manual_frame, textvariable=self.manual_ip_var, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(manual_frame, text="Block IP", command=self.manual_block_ip, style='Danger.TButton').pack(side=tk.LEFT, padx=5)
    
    def create_quarantine_tab(self):
        """Create quarantine management tab"""
        quarantine_frame = ttk.Frame(self.notebook)
        self.notebook.add(quarantine_frame, text="Quarantine")
        
        # Quarantined files section
        files_group = ttk.LabelFrame(quarantine_frame, text="Quarantined Files", padding=10, style='Card.TLabelframe')
        files_group.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Quarantine controls
        q_controls = ttk.Frame(files_group)
        q_controls.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(q_controls, text="Refresh List", command=self.refresh_quarantine, style='Accent.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(q_controls, text="View Details", command=self.view_quarantine_file, style='Success.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(q_controls, text="Delete Selected", command=self.delete_quarantine_file, style='Danger.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(q_controls, text="Clear All", command=self.clear_quarantine, style='Danger.TButton').pack(side=tk.LEFT, padx=2)
        
        # File list with details
        tree_frame = ttk.Frame(files_group)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('Filename', 'Original Path', 'Date', 'Size')
        self.quarantine_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.quarantine_tree.heading(col, text=col)
            self.quarantine_tree.column(col, width=250)
        
        q_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=q_scrollbar.set)
        
        self.quarantine_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        q_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def start_hids(self):
        """Start HIDS monitoring in background thread"""
        if not self.hids_running:
            self.hids_running = True
            self.hids_thread = threading.Thread(target=self.run_hids_monitoring, daemon=True)
            self.hids_thread.start()
            
            self.update_status_indicators()
            self.log_message("🚀 HIDS started from GUI")
    
    def stop_hids(self):
        """Stop HIDS monitoring"""
        if self.hids_running:
            self.hids_running = False
            self.update_status_indicators()
            self.log_message("⏹️ HIDS stopped from GUI")
    
    def update_status_indicators(self):
        """Update status indicator display"""
        # Clear previous indicators
        for widget in self.status_indicators.winfo_children():
            widget.destroy()
        
        # HIDS Status
        status_color = '#27ae60' if self.hids_running else '#e74c3c'
        status_text = 'RUNNING' if self.hids_running else 'STOPPED'
        
        tk.Label(self.status_indicators, text=f"HIDS: {status_text}", 
                bg=status_color, fg='white', font=('Arial', 12, 'bold'), 
                padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        # IPS Status
        ips_enabled = IPS_ENABLED
        ips_color = '#27ae60' if ips_enabled else '#95a5a6'
        ips_text = 'ENABLED' if ips_enabled else 'DISABLED'
        
        tk.Label(self.status_indicators, text=f"IPS: {ips_text}", 
                bg=ips_color, fg='white', font=('Arial', 12, 'bold'), 
                padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Update buttons
        if self.hids_running:
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
        else:
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
    
    def save_configuration(self):
        """Save GUI configuration changes"""
        try:
            # Update email settings
            if 'email' not in self.config_data:
                self.config_data['email'] = {}
            
            for field, var in self.email_vars.items():
                self.config_data['email'][field] = var.get()
            
            self.config_data['email']['send_alerts'] = self.email_alerts_var.get()
            
            # Update IPS settings
            if 'intrusion_prevention' not in self.config_data:
                self.config_data['intrusion_prevention'] = {}
            
            for field, var in self.ips_vars.items():
                self.config_data['intrusion_prevention'][field] = var.get()
            
            self.config_data['intrusion_prevention']['block_duration_minutes'] = int(self.block_duration_var.get())
            
            # Update monitoring settings
            for field, var in self.monitor_vars.items():
                if field in ['scan_interval', 'fim_check_interval']:
                    self.config_data['monitoring'][field] = int(var.get())
                else:
                    self.config_data['monitoring'][field] = var.get()
            
            # Update API settings
            if 'threat_intelligence' not in self.config_data:
                self.config_data['threat_intelligence'] = {}
            self.config_data['threat_intelligence']['virustotal_api_key'] = self.vt_api_var.get()
            
            # Save to file
            with open('config.json', 'w') as f:
                json.dump(self.config_data, f, indent=4)
            
            messagebox.showinfo("Success", "Configuration saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
    
    def send_test_email(self):
        """Send a test email to verify email configuration"""
        try:
            if not self.config_data.get('email', {}).get('send_alerts', False):
                messagebox.showwarning("Email Disabled", "Email alerts are currently disabled. Enable them first to send test email.")
                return
            
            sender = self.config_data.get('email', {}).get('sender_email', '')
            if not sender:
                messagebox.showerror("Email Error", "No sender email configured. Please configure email settings first.")
                return
            
            # Send test email using the existing send_email function
            test_subject = "HIDS/IPS Test Email"
            test_body = f"""This is a test email from your HIDS/IPS system.

System Information:
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Hostname: {os.uname().nodename}
- HIDS Status: {'RUNNING' if self.hids_running else 'STOPPED'}
- IPS Status: {'ENABLED' if IPS_ENABLED else 'DISABLED'}

Email Configuration:
- Sender: {sender}
- Receiver: {self.config_data.get('email', {}).get('receiver_email', '')}

If you received this email, your HIDS email alerts are working correctly!
"""
            
            send_email(test_subject, test_body)
            messagebox.showinfo("Test Email", "Test email sent successfully! Check your inbox to confirm delivery.")
            self.log_message("Test email sent successfully")
            
        except Exception as e:
            messagebox.showerror("Email Error", f"Failed to send test email: {str(e)}")
            self.log_message(f"Test email failed: {str(e)}")
    
    def refresh_logs(self):
        """Refresh log display"""
        self.update_logs()
    
    def clear_logs(self):
        """Clear log files"""
        try:
            if messagebox.askyesno("Confirm", "Clear all log files? This action cannot be undone."):
                if os.path.exists('hids.log'):
                    os.remove('hids.log')
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, "Log files cleared.\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear logs: {e}")
    
    def export_logs(self):
        """Export logs to file"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {e}")
    
    def refresh_blocked_ips(self):
        """Refresh blocked IP list"""
        self.ip_listbox.delete(0, tk.END)
        if blocked_ips:
            self.ip_listbox.insert(tk.END, f"🔒 Currently Blocked IPs ({len(blocked_ips)} total):")
            self.ip_listbox.insert(tk.END, "")
            for ip in blocked_ips:
                # Check if this IP has VirusTotal data
                vt_info = ""
                if ip in vt_api_cache:
                    cache_entry = vt_api_cache[ip]
                    if cache_entry['is_malicious']:
                        vt_info = f" [VT: {cache_entry['malicious_count']} threats]"
                    else:
                        vt_info = " [VT: Clean]"
                else:
                    vt_info = " [VT: Not checked]"
                
                display_text = f"🚫 {ip}{vt_info}"
                self.ip_listbox.insert(tk.END, display_text)
        else:
            self.ip_listbox.insert(tk.END, "ℹ️  No IPs currently blocked")
            self.ip_listbox.insert(tk.END, "")
            self.ip_listbox.insert(tk.END, "💡 IPs will be blocked when:")
            self.ip_listbox.insert(tk.END, "   • VirusTotal flags them as malicious")
            self.ip_listbox.insert(tk.END, "   • Manual blocking is performed")
            self.ip_listbox.insert(tk.END, "   • Network threats are detected")
            self.ip_listbox.insert(tk.END, "")
            # Show VirusTotal detection status
            vt_detections = [ip for ip in vt_api_cache.keys() if vt_api_cache[ip]['is_malicious']]
            if vt_detections:
                self.ip_listbox.insert(tk.END, f"🔍 VirusTotal Detected ({len(vt_detections)} IPs):")
                for ip in vt_detections[:5]:  # Show up to 5
                    cache_entry = vt_api_cache[ip]
                    self.ip_listbox.insert(tk.END, f"   ⚠️  {ip} ({cache_entry['malicious_count']} threats)")
                if len(vt_detections) > 5:
                    self.ip_listbox.insert(tk.END, f"   ... and {len(vt_detections) - 5} more")
    
    def unblock_selected_ip(self):
        """Unblock selected IP"""
        try:
            selection = self.ip_listbox.curselection()
            if selection:
                item = self.ip_listbox.get(selection[0])
                if item.startswith("🚫"):
                    ip = item.replace("🚫 ", "")
                    if ip in blocked_ips:
                        unblock_ip(ip)
                        self.refresh_blocked_ips()
                        self.log_message(f"🔓 Unblocked IP: {ip}")
                        messagebox.showinfo("Success", f"IP {ip} has been unblocked")
                else:
                    messagebox.showinfo("Info", "Please select a blocked IP to unblock")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unblock IP: {e}")
    
    def clear_all_blocks(self):
        """Clear all IP blocks"""
        try:
            if not blocked_ips:
                messagebox.showinfo("Info", "No IP addresses are currently blocked")
                return
                
            if messagebox.askyesno("Confirm", f"Remove all {len(blocked_ips)} IP blocks? This action cannot be undone."):
                blocked_count = len(blocked_ips)
                for ip in list(blocked_ips):
                    unblock_ip(ip)
                self.refresh_blocked_ips()
                self.log_message(f"🧹 Cleared {blocked_count} IP blocks")
                messagebox.showinfo("Success", f"All {blocked_count} IP blocks have been cleared")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear blocks: {e}")
    
    def show_virustotal_status(self):
        """Show VirusTotal detection status in a separate window"""
        try:
            # Create status window
            status_window = tk.Toplevel(self.root)
            status_window.title("VirusTotal Status")
            status_window.geometry("600x500")
            status_window.configure(bg=self.colors['bg'])
            status_window.transient(self.root)
            
            # Title
            title_frame = ttk.Frame(status_window, padding=10)
            title_frame.pack(fill=tk.X)
            ttk.Label(title_frame, text="VirusTotal Threat Intelligence Status", style='Header.TLabel').pack()
            
            # Status information
            info_frame = ttk.LabelFrame(status_window, text="System Status", padding=10)
            info_frame.pack(fill=tk.X, padx=10, pady=5)
            
            # Configuration status
            status_text = f"API Key Configured: {'✅ Yes' if VT_API_KEY else '❌ No'}\n"
            status_text += f"IPS Enabled: {'✅ Yes' if IPS_ENABLED else '❌ No'}\n"
            status_text += f"Auto-Block IPs: {'✅ Yes' if AUTO_BLOCK_IPS else '❌ No'}\n"
            status_text += f"Cache Entries: {len(vt_api_cache)}\n"
            status_text += f"Rate Limit: {VT_REQUEST_INTERVAL}s between requests"
            
            ttk.Label(info_frame, text=status_text, style='Subtle.TLabel').pack(anchor='w')
            
            # VirusTotal detections
            detections_frame = ttk.LabelFrame(status_window, text="VirusTotal Detections", padding=5)
            detections_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            # Create text widget with scrollbar
            text_frame = ttk.Frame(detections_frame)
            text_frame.pack(fill=tk.BOTH, expand=True)
            
            vt_text = tk.Text(text_frame, wrap=tk.WORD, font=('Courier', 10))
            vt_scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=vt_text.yview)
            vt_text.configure(yscrollcommand=vt_scrollbar.set)
            
            vt_text.pack(side="left", fill="both", expand=True)
            vt_scrollbar.pack(side="right", fill="y")
            
            # Populate with VirusTotal data
            if not vt_api_cache:
                vt_text.insert(tk.END, "No VirusTotal data available yet.\n")
                vt_text.insert(tk.END, "Start network monitoring to begin collecting threat intelligence.\n")
            else:
                malicious_ips = []
                clean_ips = []
                
                for ip, data in vt_api_cache.items():
                    age = int((time.time() - data['timestamp']) / 60)  # Age in minutes
                    if data['is_malicious']:
                        malicious_ips.append((ip, data['malicious_count'], age))
                    else:
                        clean_ips.append((ip, age))
                
                if malicious_ips:
                    vt_text.insert(tk.END, f"🚨 MALICIOUS IPs ({len(malicious_ips)}):\n")
                    vt_text.insert(tk.END, "-" * 50 + "\n")
                    for ip, threats, age in malicious_ips:
                        blocked_status = "BLOCKED" if ip in blocked_ips else "NOT BLOCKED"
                        vt_text.insert(tk.END, f"IP: {ip}\n")
                        vt_text.insert(tk.END, f"  Threats: {threats}\n")
                        vt_text.insert(tk.END, f"  Status: {blocked_status}\n")
                        vt_text.insert(tk.END, f"  Checked: {age} minutes ago\n\n")
                
                if clean_ips:
                    vt_text.insert(tk.END, f"\n✅ CLEAN IPs ({len(clean_ips)}):\n")
                    vt_text.insert(tk.END, "-" * 50 + "\n")
                    for ip, age in clean_ips[:10]:  # Show first 10
                        vt_text.insert(tk.END, f"{ip} (checked {age}m ago)\n")
                    if len(clean_ips) > 10:
                        vt_text.insert(tk.END, f"... and {len(clean_ips) - 10} more clean IPs\n")
            
            vt_text.config(state=tk.DISABLED)
            
            # Close button
            button_frame = ttk.Frame(status_window, padding=10)
            button_frame.pack(fill=tk.X)
            ttk.Button(button_frame, text="Close", command=status_window.destroy, style='Secondary.TButton').pack(side=tk.RIGHT)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show VirusTotal status: {e}")
    
    def manual_block_ip(self):
        """Manually block an IP"""
        try:
            ip = self.manual_ip_var.get().strip()
            if ip:
                # Basic IP validation
                import ipaddress
                try:
                    ipaddress.ip_address(ip)
                except:
                    messagebox.showerror("Error", "Please enter a valid IP address")
                    return
                
                if ip in blocked_ips:
                    messagebox.showinfo("Info", f"IP {ip} is already blocked")
                    return
                    
                block_malicious_ip(ip, "Manual block from GUI")
                self.refresh_blocked_ips()
                self.manual_ip_var.set("")
                self.log_message(f"🚫 Manually blocked IP: {ip}")
                messagebox.showinfo("Success", f"IP {ip} has been blocked successfully")
            else:
                messagebox.showwarning("Warning", "Please enter an IP address to block")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to block IP: {e}")
    
    def refresh_quarantine(self):
        """Refresh quarantine file list"""
        try:
            # Clear existing items
            for item in self.quarantine_tree.get_children():
                self.quarantine_tree.delete(item)
            
            if quarantined_files:
                # Add quarantined files
                for file_info in quarantined_files:
                    filename = os.path.basename(file_info.get('quarantine_path', ''))
                    original = file_info.get('original_path', 'Unknown')
                    timestamp = file_info.get('timestamp', 'Unknown')
                    
                    try:
                        size = os.path.getsize(file_info.get('quarantine_path', ''))
                        size_str = f"{size} bytes"
                    except:
                        size_str = "Unknown"
                    
                    self.quarantine_tree.insert('', 'end', values=(filename, original, timestamp, size_str))
            else:
                # Show helpful message when empty
                self.quarantine_tree.insert('', 'end', values=(
                    "ℹ️  No quarantined files", "", "", ""
                ))
                self.quarantine_tree.insert('', 'end', values=(
                    "", "", "", ""
                ))
                self.quarantine_tree.insert('', 'end', values=(
                    "💡 Files will be quarantined when:", "", "", ""
                ))
                self.quarantine_tree.insert('', 'end', values=(
                    "   • Critical system files are modified", "", "", ""
                ))
                self.quarantine_tree.insert('', 'end', values=(
                    "   • Unauthorized changes are detected", "", "", ""
                ))
                self.quarantine_tree.insert('', 'end', values=(
                    "   • IPS quarantine protection is enabled", "", "", ""
                ))
        except Exception as e:
            print(f"Error refreshing quarantine list: {e}")
            self.quarantine_tree.insert('', 'end', values=(
                f"Error: {str(e)}", "", "", ""
            ))
    
    def view_quarantine_file(self):
        """View details of selected quarantine file"""
        try:
            selection = self.quarantine_tree.selection()
            if selection:
                item = self.quarantine_tree.item(selection[0])
                values = item['values']
                
                # Check if it's a real file or info message
                if values[0].startswith("ℹ️") or values[0].startswith("💡"):
                    messagebox.showinfo("Info", "No quarantined files to view")
                    return
                
                details = f"Quarantined File Details\n"
                details += f"{'='*40}\n"
                details += f"Filename: {values[0]}\n"
                details += f"Original Path: {values[1]}\n"
                details += f"Quarantine Date: {values[2]}\n"
                details += f"File Size: {values[3]}\n"
                
                # Try to find more details from quarantined_files
                for file_info in quarantined_files:
                    if os.path.basename(file_info.get('quarantine_path', '')) == values[0]:
                        details += f"Reason: {file_info.get('reason', 'Unknown')}\n"
                        details += f"Quarantine Path: {file_info.get('quarantine_path', 'Unknown')}\n"
                        break
                
                messagebox.showinfo("File Details", details)
            else:
                messagebox.showinfo("Info", "Please select a file to view details")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to view file details: {e}")
    
    def delete_quarantine_file(self):
        """Delete selected quarantine file"""
        try:
            selection = self.quarantine_tree.selection()
            if not selection:
                messagebox.showinfo("Info", "Please select a file to delete")
                return
                
            item = self.quarantine_tree.item(selection[0])
            filename = item['values'][0]
            
            # Check if it's a real file or info message
            if filename.startswith("ℹ️") or filename.startswith("💡"):
                messagebox.showinfo("Info", "No quarantined files to delete")
                return
            
            if messagebox.askyesno("Confirm", f"Permanently delete quarantined file '{filename}'?"):
                # Find and remove the file
                for file_info in quarantined_files:
                    if os.path.basename(file_info.get('quarantine_path', '')) == filename:
                        try:
                            quarantine_path = file_info['quarantine_path']
                            if os.path.exists(quarantine_path):
                                os.remove(quarantine_path)
                            quarantined_files.remove(file_info)
                            self.refresh_quarantine()
                            self.log_message(f"🗑️ Deleted quarantined file: {filename}")
                            messagebox.showinfo("Success", f"File '{filename}' has been deleted")
                            return
                        except Exception as e:
                            messagebox.showerror("Error", f"Failed to delete file: {e}")
                            return
                
                messagebox.showwarning("Warning", f"File '{filename}' not found in quarantine")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete file: {e}")
    
    def clear_quarantine(self):
        """Clear all quarantine files"""
        try:
            if not quarantined_files:
                messagebox.showinfo("Info", "No quarantined files to clear")
                return
                
            if messagebox.askyesno("Confirm", f"Delete all {len(quarantined_files)} quarantined files? This action cannot be undone."):
                deleted_count = 0
                for file_info in list(quarantined_files):
                    try:
                        quarantine_path = file_info['quarantine_path']
                        if os.path.exists(quarantine_path):
                            os.remove(quarantine_path)
                        quarantined_files.remove(file_info)
                        deleted_count += 1
                    except Exception as e:
                        print(f"Error deleting {file_info.get('quarantine_path', 'unknown')}: {e}")
                
                self.refresh_quarantine()
                self.log_message(f"🧹 Cleared {deleted_count} quarantine files")
                messagebox.showinfo("Success", f"Deleted {deleted_count} quarantined files")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear quarantine: {e}")
    
    def add_demo_data(self):
        """Show demo data selection dialog with multiple testing scenarios"""
        try:
            # Create demo selection dialog
            demo_window = tk.Toplevel(self.root)
            demo_window.title("Select Demo Data")
            demo_window.geometry("500x400")
            demo_window.configure(bg=self.colors['bg'])
            demo_window.transient(self.root)
            demo_window.grab_set()
            
            # Center the dialog
            demo_window.update_idletasks()
            x = (demo_window.winfo_screenwidth() - demo_window.winfo_width()) // 2
            y = (demo_window.winfo_screenheight() - demo_window.winfo_height()) // 2
            demo_window.geometry(f"+{x}+{y}")
            
            # Title
            title_frame = ttk.Frame(demo_window, padding=10)
            title_frame.pack(fill=tk.X)
            ttk.Label(title_frame, text="Demo Data Generator", style='Header.TLabel').pack()
            ttk.Label(title_frame, text="Select demo scenarios to populate the HIDS interface", style='Subtle.TLabel').pack(pady=(5,0))
            
            # Create scrollable frame for demo options
            canvas_frame = ttk.LabelFrame(demo_window, text="Available Demo Scenarios", padding=5, style='Card.TLabelframe')
            canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            # Canvas and scrollbar for scrolling
            canvas = tk.Canvas(canvas_frame, background=self.colors['panel'], highlightthickness=0, bd=0)
            scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
            options_frame = ttk.Frame(canvas)
            
            options_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=options_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            # Enable mousewheel scrolling
            def _on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            canvas.bind("<MouseWheel>", _on_mousewheel)  # Windows
            canvas.bind("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))  # Linux scroll up
            canvas.bind("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))   # Linux scroll down
            
            # Demo checkboxes
            self.demo_vars = {}
            demo_options = [
                ("blocked_ips", "Blocked Malicious IPs", "Add sample blocked IP addresses (APT groups, botnets)"),
                ("quarantine", "Quarantined Files", "Add sample quarantined system files"),
                ("incidents", "Security Incidents", "Add sample incident log entries"),
                ("network_alerts", "Network Threat Alerts", "Add network-based security alerts"),
                ("fim_alerts", "File Integrity Alerts", "Add file modification alerts"),
                ("process_alerts", "Process Monitoring Alerts", "Add suspicious process alerts"),
                ("clear_all", "Clear All Demo Data", "Remove all demo data and reset to clean state")
            ]
            
            for key, label, description in demo_options:
                var = tk.BooleanVar()
                self.demo_vars[key] = var
                
                frame = ttk.Frame(options_frame)
                frame.pack(fill=tk.X, pady=2)
                
                check = ttk.Checkbutton(frame, text=label, variable=var)
                check.pack(anchor='w')
                
                desc_label = ttk.Label(frame, text=description, style='Subtle.TLabel')
                desc_label.pack(anchor='w', padx=(20, 0))
                
                if key == "clear_all":
                    ttk.Separator(options_frame, orient='horizontal').pack(fill=tk.X, pady=5)
            
            # Pack canvas and scrollbar
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Buttons frame
            buttons_frame = ttk.Frame(demo_window, padding=10)
            buttons_frame.pack(fill=tk.X)
            
            def apply_demos():
                try:
                    added_count = 0
                    
                    # Clear all demo data if requested
                    if self.demo_vars["clear_all"].get():
                        self.clear_demo_data()
                        messagebox.showinfo("Demo Data", "All demo data has been cleared")
                        demo_window.destroy()
                        return
                    
                    # Add blocked IPs
                    if self.demo_vars["blocked_ips"].get():
                        global blocked_ips  # Ensure we're modifying the global variable
                        demo_ips = [
                            "203.159.120.45",   # Fake APT IP
                            "91.203.67.143",    # Fake botnet C&C
                            "185.220.101.42",   # Fake malware distribution
                            "45.138.16.111"     # Fake scanning source
                        ]
                        for ip in demo_ips:
                            if ip not in blocked_ips:
                                blocked_ips.add(ip)
                                added_count += 1
                        self.log_message(f"Added {len(demo_ips)} demo blocked IPs")
                    
                    # Add quarantine files
                    if self.demo_vars["quarantine"].get():
                        global quarantined_files  # Ensure we're modifying the global variable
                        quarantine_demos = [
                            ("suspicious_script.sh", "/tmp/suspicious_script.sh", "Suspicious shell script detected"),
                            ("modified_hosts.bak", "/etc/hosts", "Critical system file modification"),
                            ("malware_sample.bin", "/tmp/malware_sample.bin", "Potential malware detected")
                        ]
                        
                        os.makedirs('/tmp/hids_quarantine', exist_ok=True)
                        for filename, original_path, reason in quarantine_demos:
                            quarantine_path = f'/tmp/hids_quarantine/{filename}_{int(time.time())}'
                            
                            # Create demo file
                            with open(quarantine_path, 'w') as f:
                                f.write(f"Demo quarantined file: {filename}\nOriginal path: {original_path}\nReason: {reason}\n")
                            
                            demo_file = {
                                'original_path': original_path,
                                'quarantine_path': quarantine_path,
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'reason': reason
                            }
                            quarantined_files.append(demo_file)
                            added_count += 1
                        
                        self.log_message(f"Added {len(quarantine_demos)} demo quarantined files")
                    
                    # Add incidents
                    if self.demo_vars["incidents"].get():
                        global incident_log  # Ensure we're modifying the global variable
                        demo_incidents = [
                            {
                                "timestamp": datetime.now().isoformat(),
                                "action": "IP_BLOCKED",
                                "target": "203.159.120.45",
                                "reason": "VirusTotal threat intelligence match"
                            },
                            {
                                "timestamp": (datetime.now() - timedelta(minutes=15)).isoformat(),
                                "action": "PROCESS_TERMINATED",
                                "target": "suspicious_miner (PID: 1337)",
                                "reason": "Cryptocurrency mining detected"
                            },
                            {
                                "timestamp": (datetime.now() - timedelta(minutes=30)).isoformat(),
                                "action": "FILE_QUARANTINED",
                                "target": "/etc/hosts",
                                "reason": "Critical system file modification"
                            }
                        ]
                        
                        for incident in demo_incidents:
                            incident_log.append(incident)
                            added_count += 1
                        
                        self.log_message(f"Added {len(demo_incidents)} demo incidents")
                    
                    # Add network alerts
                    if self.demo_vars["network_alerts"].get():
                        network_alerts = [
                            "Network scan detected from 192.168.1.50",
                            "Suspicious DNS queries to known C&C domains",
                            "Large data transfer to external IP detected",
                            "Connection attempt to Tor exit node blocked"
                        ]
                        
                        for alert in network_alerts:
                            log_alert("Network Monitor", alert, f"network_demo_{added_count}", is_critical=True)
                            added_count += 1
                        
                        self.log_message(f"Added {len(network_alerts)} network alerts")
                    
                    # Add FIM alerts
                    if self.demo_vars["fim_alerts"].get():
                        fim_alerts = [
                            "Critical file modified: /etc/passwd",
                            "System configuration changed: /etc/ssh/sshd_config",
                            "Boot sector file accessed: /boot/grub/grub.cfg",
                            "Kernel module modified: /lib/modules/suspicious.ko"
                        ]
                        
                        for alert in fim_alerts:
                            log_alert("FIM", alert, f"fim_demo_{added_count}", is_critical=True)
                            added_count += 1
                        
                        self.log_message(f"Added {len(fim_alerts)} FIM alerts")
                    
                    # Add process alerts
                    if self.demo_vars["process_alerts"].get():
                        process_alerts = [
                            "Suspicious process running from /tmp: cryptominer",
                            "Process attempting privilege escalation: exploit.py",
                            "Network scanning tool detected: nmap",
                            "Keylogger process identified: keylogger.exe"
                        ]
                        
                        for alert in process_alerts:
                            log_alert("Process Monitor", alert, f"process_demo_{added_count}", is_critical=True)
                            added_count += 1
                        
                        self.log_message(f"Added {len(process_alerts)} process alerts")
                    
                    # Refresh all displays
                    self.refresh_blocked_ips()
                    self.refresh_quarantine()
                    self.update_display()
                    
                    if added_count > 0:
                        messagebox.showinfo("Demo Data", f"Successfully added {added_count} demo items to the HIDS interface")
                        
                        # Send notification if email alerts are enabled
                        if SEND_EMAIL_ALERTS:
                            try:
                                send_email(
                                    "Demo Data Generated - Security Alert", 
                                    f"HIDS Demo System has generated {added_count} security events for testing.\n\n"
                                    "Demo data includes:\n"
                                    + ("• Blocked IPs\n" if self.demo_vars["blocked_ips"].get() else "")
                                    + ("• Quarantined Files\n" if self.demo_vars["quarantine"].get() else "")
                                    + ("• Incident Reports\n" if self.demo_vars["incidents"].get() else "")
                                    + ("• Network Alerts\n" if self.demo_vars["network_alerts"].get() else "")
                                    + ("• FIM Alerts\n" if self.demo_vars["fim_alerts"].get() else "")
                                    + ("• Process Alerts\n" if self.demo_vars["process_alerts"].get() else "")
                                    + f"\nGenerated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                                    "This is a demo notification to test email functionality."
                                )
                                self.log_message("📧 Demo notification email sent successfully")
                            except Exception as e:
                                self.log_message(f"⚠️ Email notification failed: {str(e)}")
                    else:
                        messagebox.showinfo("Demo Data", "No demo options were selected")
                    
                    demo_window.destroy()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to add demo data: {e}")
                    demo_window.destroy()
            
            def select_all():
                for key, var in self.demo_vars.items():
                    if key != "clear_all":
                        var.set(True)
            
            def select_none():
                for var in self.demo_vars.values():
                    var.set(False)
            
            # Button layout
            button_left_frame = ttk.Frame(buttons_frame)
            button_left_frame.pack(side=tk.LEFT)
            ttk.Button(button_left_frame, text="Select All", command=select_all, style='Secondary.TButton').pack(side=tk.LEFT, padx=5)
            ttk.Button(button_left_frame, text="Clear Selection", command=select_none, style='Secondary.TButton').pack(side=tk.LEFT, padx=5)
            
            button_right_frame = ttk.Frame(buttons_frame)
            button_right_frame.pack(side=tk.RIGHT)
            ttk.Button(button_right_frame, text="Cancel", command=demo_window.destroy, style='Secondary.TButton').pack(side=tk.LEFT, padx=5)
            ttk.Button(button_right_frame, text="✓ Generate Demo Data", command=apply_demos, style='Accent.TButton').pack(side=tk.LEFT, padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open demo dialog: {e}")
    
    def clear_demo_data(self):
        """Clear all demo data from the system"""
        try:
            # Clear blocked IPs (only demo ones)
            demo_ips = ["203.159.120.45", "91.203.67.143", "185.220.101.42", "45.138.16.111"]
            for ip in demo_ips:
                if ip in blocked_ips:
                    blocked_ips.discard(ip)
            
            # Clear demo quarantine files
            for file_info in list(quarantined_files):
                if "demo" in file_info.get('quarantine_path', '').lower():
                    try:
                        if os.path.exists(file_info['quarantine_path']):
                            os.remove(file_info['quarantine_path'])
                        quarantined_files.remove(file_info)
                    except:
                        pass
            
            # Clear demo incidents (keep only real ones)
            global incident_log
            incident_log = [inc for inc in incident_log if not any(demo_ip in str(inc) for demo_ip in demo_ips)]
            
            # Refresh displays
            self.refresh_blocked_ips()
            self.refresh_quarantine()
            self.update_display()
            
            self.log_message("Cleared all demo data")
            
        except Exception as e:
            self.log_message(f"Error clearing demo data: {e}")
    
    def run_hids_monitoring(self):
        """Run HIDS monitoring loop"""
        log_alert("GUI", "HIDS monitoring started from GUI interface", "gui_start")
        
        # Ensure FIM baseline exists when launching from GUI
        try:
            fim_baseline = config["monitoring"]["baseline_file"]
            if not os.path.exists(fim_baseline):
                from baseline import create_baseline
                create_baseline()
                log_alert("FIM", f"Baseline created at {fim_baseline}", "fim_baseline_created")
        except Exception as e:
            log_alert("FIM", f"Unable to verify/create baseline: {e}", "fim_baseline_error")
        
        # Start background threads
        log_thread = threading.Thread(target=start_log_monitor, args=(config["monitoring"]["log_file"],))
        log_thread.daemon = True
        log_thread.start()

        network_thread = threading.Thread(target=start_network_scanner)
        network_thread.daemon = True
        network_thread.start()
        
        fim_baseline = config["monitoring"]["baseline_file"]
        fim_check_interval = config["monitoring"]["fim_check_interval"]
        scan_interval = config["monitoring"]["scan_interval"]
        
        last_fim_check = 0
        
        while self.hids_running:
            try:
                current_time = int(time.time())
                
                # File integrity monitoring
                if current_time - last_fim_check >= fim_check_interval:
                    check_file_integrity(fim_baseline)
                    last_fim_check = current_time

                # Process monitoring
                monitor_processes()
                
                # Generate incident report every hour
                if current_time % 3600 == 0 and incident_log:
                    save_incident_report()

            except Exception as e:
                log_alert("GUI", f"Monitoring error: {e}", "gui_error")
            
            time.sleep(scan_interval)
        
        log_alert("GUI", "HIDS monitoring stopped from GUI interface", "gui_stop")
    
    def update_display(self):
        """Update the information display"""
        try:
            self.update_status_indicators()
            
            info = []
            info.append(f"🕒 Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            info.append(f"🛡️ HIDS Status: {'RUNNING' if self.hids_running else 'STOPPED'}")
            info.append(f"🔧 IPS Status: {'ENABLED' if IPS_ENABLED else 'DISABLED'}")
            info.append("")
            
            # System resources
            try:
                info.append("📊 SYSTEM RESOURCES:")
                info.append(f"   CPU Usage: {psutil.cpu_percent():.1f}%")
                info.append(f"   Memory Usage: {psutil.virtual_memory().percent:.1f}%")
                info.append(f"   Disk Usage: {psutil.disk_usage('/').percent:.1f}%")
                
                connections = psutil.net_connections(kind='inet')
                established = [c for c in connections if c.status == 'ESTABLISHED']
                info.append(f"   Network Connections: {len(established)}")
            except:
                info.append("📊 System info unavailable")
            
            info.append("")
            
            # Security status
            info.append("🔒 SECURITY STATUS:")
            info.append(f"   Blocked IPs: {len(blocked_ips)}")
            info.append(f"   Quarantined Files: {len(quarantined_files)}")
            info.append(f"   Total Incidents: {len(incident_log)}")
            
            info.append("")
            
            # Configuration
            info.append("⚙️ CONFIGURATION:")
            info.append(f"   Auto Block IPs: {AUTO_BLOCK_IPS}")
            info.append(f"   Auto Kill Processes: {AUTO_KILL_PROCESSES}")
            info.append(f"   File Quarantine: {QUARANTINE_FILES}")
            info.append(f"   Scan Interval: {config['monitoring']['scan_interval']} seconds")
            info.append(f"   Block Duration: {BLOCK_DURATION} minutes")
            
            info.append("")
            
            # Recent incidents
            if incident_log:
                info.append("🚨 RECENT INCIDENTS:")
                for incident in incident_log[-5:]:  # Last 5 incidents
                    info.append(f"   {incident['timestamp']}: {incident['action']} - {incident['target']}")
            else:
                info.append("✅ NO RECENT INCIDENTS")
            
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, '\n'.join(info))
            
            # Update logs and other tabs
            self.update_logs()
            self.refresh_blocked_ips()
            self.refresh_quarantine()
            
        except Exception as e:
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, f"Error updating display: {e}")
    
    def update_logs(self):
        """Update log display"""
        try:
            if os.path.exists('hids.log'):
                with open('hids.log', 'r') as f:
                    lines = f.readlines()
                    recent_lines = lines[-20:] if len(lines) > 20 else lines
                    
                self.log_text.delete(1.0, tk.END)
                for line in recent_lines:
                    self.log_text.insert(tk.END, line)
                self.log_text.see(tk.END)
            else:
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, "No log file available")
        except Exception as e:
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, f"Error reading logs: {e}")
    
    def log_message(self, message):
        """Add message to log display"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        if hasattr(self, 'log_text'):
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
    
    def periodic_update(self):
        """Periodic update function"""
        if hasattr(self, 'auto_refresh_var') and self.auto_refresh_var.get():
            self.update_logs()
        
        if self.hids_running:
            self.update_display()
        
        # Schedule next update
        self.root.after(5000, self.periodic_update)

# --- MAIN EXECUTION ---
def main():
    """Main function - GUI-only HIDS/IPS System"""
    
    # Show startup banner
    print_banner()
    
    # Check if GUI is available
    if not GUI_AVAILABLE:
        print("❌ GUI libraries not available. This version requires tkinter.")
        sys.exit(1)
    
    # Start HIDS with GUI interface
    try:
        print("🖥️  Starting HIDS with GUI interface...")
        root = tk.Tk()
        app = HIDSGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"❌ GUI failed to start: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()