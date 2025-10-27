# HIDS (Host-based Intrusion Detection System) with IPS

A Python-based Host Intrusion Detection System with **Intrusion Prevention System (IPS)** capabilities including automated threat response, file integrity monitoring, process monitoring, log analysis, and threat intelligence integration.

**🖥️ Modern GUI Interface** - This version features a professional graphical user interface for easy monitoring and management of your security system.

## ✨ Key Features

### 🛡️ Security Monitoring
- **Real-time Threat Detection**: Network monitoring with VirusTotal integration
- **File Integrity Monitoring (FIM)**: Detects unauthorized file modifications
- **Process Monitoring**: Identifies suspicious processes and activities
- **Log Analysis**: Real-time log monitoring and threat pattern detection

### � Intrusion Prevention (IPS)
- **Automated IP Blocking**: Blocks malicious IPs using iptables
- **Process Termination**: Automatically kills suspicious processes
- **File Quarantine**: Quarantines modified critical system files
- **Incident Response**: Comprehensive logging and automated responses

### �️ Professional GUI Interface
- **Modern Design**: Clean, professional interface with light theme
- **Real-time Dashboard**: Live system status and security metrics
- **Interactive Controls**: Easy start/stop monitoring with visual feedback
- **Demo System**: Built-in demo data for testing and training
- **Email Integration**: Test email alerts and notifications
- **VirusTotal Status**: Detailed threat intelligence diagnostics

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
# or
pip install psutil requests tkinter
```

### 2. Configure System
```bash
cp config.example.json config.json
# Edit config.json with your settings
```

### 3. Set VirusTotal API Key
Edit `config.json` and add your VirusTotal API key:
```json
{
    "threat_intelligence": {
        "virustotal_api_key": "your_api_key_here"
    }
}
```

### 4. Create File Baseline
```bash
python baseline.py
```

### 5. Run HIDS
```bash
# Launch GUI (automatic monitoring start)
sudo python hids.py

# Note: sudo required for iptables access in IPS mode
```

## 🖥️ GUI Interface Features

### Modern Professional Interface
- **Auto-Start Monitoring**: System begins monitoring immediately on launch
- **Clean Design**: Professional light theme for easy readability
- **Tabbed Layout**: Organized sections for monitoring, IP management, quarantine, and configuration

### Monitoring Tab
- **System Status**: Real-time HIDS status and resource usage
- **Live Activity Log**: Scrolling display of security events and system activity
- **Demo System**: Generate sample security events for testing and training
- **Control Buttons**: Start/stop monitoring with visual feedback

### IP Management Tab
- **Blocked IP List**: View all currently blocked IP addresses
- **VirusTotal Integration**: See threat intelligence data for each IP
- **VT Status Button**: Detailed VirusTotal diagnostics and detection status
- **Manual Controls**: Block/unblock IPs manually
- **Automatic Blocking**: Real-time blocking of malicious IPs detected by VirusTotal

### Quarantine Tab
- **Quarantined Files**: List of files moved to quarantine for safety
- **File Details**: Original path, quarantine location, and reason for quarantine
- **Restore Options**: Safely restore files from quarantine when appropriate

### Configuration Tab
- **System Settings**: Modify monitoring intervals, thresholds, and behavior
- **Email Configuration**: Set up SMTP alerts and test email functionality
- **IPS Controls**: Enable/disable intrusion prevention features
- **API Settings**: VirusTotal API key configuration

## 🛡️ Security Features

### Threat Detection & Intelligence
- **VirusTotal Integration**: Real-time IP reputation checking
- **Network Monitoring**: Monitors active network connections for threats
- **Pattern Recognition**: Detects suspicious network and process activities
- **Real-time Alerts**: Immediate notification of security events

### Automated Response (IPS)
- **Smart IP Blocking**: Automatically blocks IPs flagged by VirusTotal
- **Process Management**: Terminates suspicious processes in temp directories
- **File Protection**: Quarantines modified critical system files
- **Timed Responses**: Configurable automatic unblocking after set duration

### Configuration & Control
- **Whitelist Protection**: Safeguards legitimate IPs and processes
- **Flexible Settings**: Enable/disable individual response mechanisms
- **Rate Limiting**: Respects VirusTotal API limits (15-second intervals)
- **Incident Logging**: Comprehensive tracking of all security events

## Setup Instructions

### 1. Clone and Setup
```bash
cd /path/to/hbids
python -m venv hids-env
source hids-env/bin/activate  # On Windows: hids-env\Scripts\activate
pip install psutil requests
```

### 2. Configuration
1. Copy the example configuration:
   ```bash
   cp config.example.json config.json
   ```

2. Edit `config.json` with your actual credentials and IPS settings:
   - **Email Settings**: Update with your Gmail credentials (use app-specific password)
   - **VirusTotal API**: Get a free API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
   - **IPS Settings**: Configure automated response behavior
   - **Monitoring Settings**: Adjust file paths and intervals as needed

### 3. System Preparation (for IPS features)
```bash
# Ensure sudo access for iptables (required for IP blocking)
sudo visudo  # Add your user to sudoers if needed

# Create quarantine directory
sudo mkdir -p /tmp/hids_quarantine
sudo chown $USER:$USER /tmp/hids_quarantine
```

### 4. Create File Baseline
```bash
python baseline.py
```

### 5. Run HIDS with IPS
```bash
sudo python hids.py  # Requires sudo for iptables access
```

## � GUI Interface

For easy management, use the graphical interface:

```bash
## ⚙️ Management Commands

Use the included management utility for advanced operations:

```bash
# Show comprehensive system status
python hids_manage.py status

# List currently blocked IPs
python hids_manage.py list-blocked

# Manually unblock an IP
python hids_manage.py unblock 192.168.1.100

# View recent incident reports
python hids_manage.py incidents

# Clear quarantine directory
python hids_manage.py clear-quarantine
```

## 📁 File Structure

```
hids.py              # Main HIDS/IPS system with integrated GUI
config.json          # Configuration file (create from config.example.json)
hids_cli.py          # Command-line interface module
hids_gui.py          # GUI module (launched by main system)
hids_manage.py       # Management utility
baseline.py          # File integrity baseline creation
process_monitor.py   # Process monitoring module
fim_monitor.py       # File integrity monitoring module
log_analyzer.py      # Log analysis module
```
```

### GUI Features:
- 🏠 **System Status**: Real-time monitoring and start/stop controls
- ⚙️ **Configuration**: Edit all HIDS/IPS settings through GUI
- 📋 **Logs & Alerts**: View, export, and clear system logs
- 🚫 **IP Management**: View blocked IPs, manual blocking/unblocking
- 📦 **Quarantine**: Browse and manage quarantined files

## �🎛️ Management Commands

Use the included management utility:

```bash
# Show system status
python hids_manage.py status

# List currently blocked IPs
python hids_manage.py list-blocked

# Manually unblock an IP
python hids_manage.py unblock 192.168.1.100

# View recent incident reports
python hids_manage.py incidents

# Clear quarantine directory
python hids_manage.py clear-quarantine
```

## Features

### Detection (HIDS)
- **File Integrity Monitoring (FIM)**: Detects unauthorized file modifications
- **Process Monitoring**: Identifies suspicious processes running from temp directories
- **Log Analysis**: Monitors system logs for authentication failures and suspicious activities
- **Network Threat Intelligence**: Checks connections against VirusTotal database
- **Email Alerting**: Sends email notifications for critical alerts
- **Centralized Logging**: All alerts logged to `hids.log`

### Prevention (IPS) 
- **Automatic IP Blocking**: Blocks malicious IPs detected by threat intelligence
- **Process Termination**: Automatically kills suspicious processes
- **File Quarantine**: Moves modified critical files to quarantine
- **Incident Response**: Comprehensive logging and reporting of all actions
- **Timed Recovery**: Automatic unblocking and cleanup after configurable timeouts

## Configuration Options

### Email Settings
- `sender_email`: Gmail address for sending alerts
- `password`: Gmail app-specific password
- `receiver_email`: Email to receive alerts
- `send_alerts`: Enable/disable email notifications

### Threat Intelligence
- `virustotal_api_key`: Your VirusTotal API key

### Monitoring Settings
- `log_file`: System log file to monitor (default: `/var/log/auth.log`)
- `baseline_file`: File containing hash baselines
- `scan_interval`: Time between scans in seconds
- `fim_check_interval`: File integrity check interval in seconds

### IPS Settings
- `enabled`: Master enable/disable for all IPS features
- `auto_block_malicious_ips`: Automatically block malicious IPs
- `auto_kill_suspicious_processes`: Automatically terminate suspicious processes
- `quarantine_modified_files`: Quarantine modified critical files
- `max_login_attempts`: Failed login threshold (planned feature)
- `block_duration_minutes`: How long to block IPs (60 minutes default)
- `whitelist_ips`: IPs that should never be blocked (supports CIDR)
- `protected_processes`: Process names that should never be killed
- `quarantine_directory`: Where to store quarantined files

## Security Notes

- **Requires sudo access** for IP blocking functionality
- Never commit `config.json` to version control
- Use app-specific passwords for Gmail
- Keep your VirusTotal API key secure
- Test IPS features in a safe environment first
- Monitor quarantine directory size
- Review incident reports regularly

## Files

- `hids.py`: Main HIDS/IPS application
- `hids_manage.py`: Management utility for IPS operations
- `baseline.py`: Creates file hash baselines  
- `config.json`: Configuration file (not in git)
- `config.example.json`: Template configuration file
- `*.py`: Individual monitoring modules
- `hids.log`: Application log file
- `incident_report_*.json`: Automated incident reports

## Example IPS Actions

When threats are detected:

1. **Malicious IP Connection**:
   - ✅ Detected via VirusTotal API
   - 🚫 Automatically blocked with iptables
   - ⏰ Unblocked after 60 minutes (configurable)
   - 📧 Email alert sent
   - 📝 Incident logged

2. **Suspicious Process**:
   - ✅ Process running from /tmp detected
   - ⚠️ Process terminated (if not protected)
   - 📧 Email alert sent  
   - 📝 Incident logged

3. **File Modification**:
   - ✅ Critical file change detected
   - 📦 File quarantined to safe location
   - 📧 Email alert sent
   - 📝 Incident logged

## Monitoring Recommendations

- Check incident reports daily: `python hids_manage.py incidents`
- Monitor quarantine directory size
- Review blocked IPs weekly: `python hids_manage.py list-blocked`
- Test email alerts periodically
- Keep VirusTotal API usage within limits