# 🔒 Linux Security Hardening Tool

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/security-hardening-green.svg)](https://github.com/yourusername/linux-security-hardening)

A comprehensive, automated tool for hardening Linux systems against security threats using industry best practices. This tool assesses your current security posture and applies targeted hardening measures across multiple security domains.

## 🌟 Features

- **Multi-distribution support**: Works on Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, and SUSE systems
- **Security assessment**: Detailed scoring system with actionable recommendations
- **Comprehensive hardening**:
  - System updates and patch management
  - Firewall configuration (UFW/firewalld)
  - Service hardening and unnecessary service removal
  - SSH security optimization
  - Password policies and user account hardening
  - File permission corrections
  - Kernel parameter tuning
  - SELinux/AppArmor configuration
  - Fail2ban intrusion prevention setup
  - System auditing configuration
  - USB storage control options
  - Boot loader security
- **User-friendly interface**:
  - Interactive mode with confirmation prompts
  - Automatic mode for scripted deployments
  - Detailed logging and change tracking
  - Before/after security scoring

## 🚀 Installation

### Prerequisites
- Python 3.6 or newer
- Root/sudo access to the target system
- Internet connection for package updates (recommended)

### Quick Setup
```bash
git clone https://github.com/yourusername/linux-security-hardening.git
cd linux-security-hardening
chmod +x harden_linux.py
```

🛠️ Usage
Interactive Mode (Recommended)
```bash
sudo ./harden_linux.py
```

Scan Only Mode (No Changes)
```bash
sudo ./harden_linux.py --scan-only
```

Automatic Mode (Non-interactive)
```bash
sudo ./harden_linux.py --auto
```

Help and Options
```bash
sudo ./harden_linux.py --help
```

📊 Sample Assessment Report
```
======================================================================
              Security Assessment Results
======================================================================

Security Score: 75/100
⚠ Moderate security - improvements recommended

Issues Found:
  1. Many packages need updates
  2. No intrusion prevention system active (fail2ban)
```

🔄 Security Improvement Tracking
After hardening, the tool provides a comparison of initial and final security scores:
```
======================================================================
               Security Improvement Summary
======================================================================

Initial Score: 75/100
Final Score:   92/100
Improvement:   +17 points 🎉
```

🔐 Security Considerations
Always test in a non-production environment first
Keep backups of critical configuration files (the tool creates backups automatically)
Review all changes before applying them in production environments
Consider scheduling regular security scans to maintain your security posture

🤝 Contributing
Contributions are welcome! Please see CONTRIBUTING.md for details on how to contribute.

📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

⚠ Disclaimer
This tool makes significant changes to system configuration. While it has been designed with safety in mind:

Always test on non-production systems first
Ensure you have backups and recovery procedures
The authors are not responsible for any damage caused by improper use
Use at your own risk
🙏 Acknowledgements
This tool incorporates security best practices from:

CIS Benchmarks
NIST Security Guidelines
NSA Security Configuration Guides
DISA STIGs
OpenSCAP Security Profiles
Made By arkanzasfeziii
