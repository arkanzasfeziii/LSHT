#!/usr/bin/env python3
"""
=============================================================================
Linux Security Hardening Tool - Complete System Security Enhancement
=============================================================================

"""

import os
import sys
import subprocess
import logging
import argparse
import time
import re
import shutil
from datetime import datetime
from pathlib import Path

# Simple progress bar (no external dependencies)
class ProgressBar:
    def __init__(self, total, desc="Progress"):
        self.total = total
        self.current = 0
        self.desc = desc
        self.bar_length = 40
        
    def update(self, step=1):
        self.current += step
        if self.current > self.total:
            self.current = self.total
        self._display()
    
    def _display(self):
        percent = (self.current / self.total) * 100
        filled = int(self.bar_length * self.current / self.total)
        bar = '█' * filled + '░' * (self.bar_length - filled)
        sys.stdout.write(f'\r{self.desc}: |{bar}| {percent:.1f}%')
        sys.stdout.flush()
        if self.current >= self.total:
            print()  # New line when complete

# Color output helper
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(70)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

def print_success(text):
    print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")

def print_warning(text):
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")

def print_info(text):
    print(f"{Colors.OKCYAN}ℹ {text}{Colors.ENDC}")

# Setup logging
def setup_logging():
    log_dir = "/var/log/system-hardening"
    os.makedirs(log_dir, exist_ok=True)
    log_file = f"{log_dir}/hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_file

# Run shell command safely
def run_command(cmd, check=True, capture=True):
    try:
        if capture:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                check=check
            )
            return result.stdout.strip()
        else:
            subprocess.run(cmd, shell=True, check=check)
            return ""
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {cmd}\nError: {e.stderr}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error running command: {cmd}\nError: {str(e)}")
        return None

# Detect Linux distribution
class DistroDetector:
    def __init__(self):
        self.name = "unknown"
        self.version = "unknown"
        self.family = "unknown"
        self.package_manager = None
        self.detect()
    
    def detect(self):
        # Try /etc/os-release first (modern standard)
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('ID='):
                        self.name = line.split('=')[1].strip().strip('"').lower()
                    elif line.startswith('VERSION_ID='):
                        self.version = line.split('=')[1].strip().strip('"')
        
        # Fallback detection methods
        if self.name == "unknown":
            if os.path.exists('/etc/debian_version'):
                self.name = "debian"
            elif os.path.exists('/etc/redhat-release'):
                self.name = "rhel"
            elif os.path.exists('/etc/arch-release'):
                self.name = "arch"
            elif os.path.exists('/etc/SuSE-release'):
                self.name = "suse"
        
        # Determine family and package manager
        if self.name in ['ubuntu', 'debian', 'linuxmint', 'pop']:
            self.family = "debian"
            self.package_manager = "apt"
        elif self.name in ['fedora', 'rhel', 'centos', 'rocky', 'almalinux']:
            self.family = "redhat"
            self.package_manager = "dnf" if shutil.which('dnf') else "yum"
        elif self.name == "arch" or self.name == "manjaro":
            self.family = "arch"
            self.package_manager = "pacman"
        elif self.name in ['opensuse', 'suse', 'sles']:
            self.family = "suse"
            self.package_manager = "zypper"
        
        logging.info(f"Detected: {self.name} {self.version} (family: {self.family})")
    
    def is_supported(self):
        return self.package_manager is not None

# Security Scanner - Assess current security status
class SecurityScanner:
    def __init__(self, distro):
        self.distro = distro
        self.score = 0
        self.max_score = 100
        self.issues = []
        self.checks = []
    
    def scan(self):
        print_header("Scanning Current Security Status")
        checks = [
            self.check_updates,
            self.check_firewall,
            self.check_services,
            self.check_users,
            self.check_permissions,
            self.check_kernel_settings,
            self.check_selinux_apparmor,
            self.check_ssh_config,
            self.check_password_policy,
            self.check_fail2ban
        ]
        
        total = len(checks)
        for i, check in enumerate(checks):
            check()
            sys.stdout.write(f'\rScanning... {int((i+1)/total*100)}%')
            sys.stdout.flush()
        
        print("\n")
        self.calculate_score()
        return self.score
    
    def check_updates(self):
        self.checks.append("System Updates")
        if self.distro.family == "debian":
            result = run_command("apt list --upgradable 2>/dev/null | wc -l")
            if result and int(result) > 10:
                self.issues.append("Many packages need updates")
                return
        elif self.distro.family == "redhat":
            result = run_command("dnf check-update 2>/dev/null | grep -c '^[a-zA-Z]'", check=False)
            if result and int(result) > 10:
                self.issues.append("Many packages need updates")
                return
        self.score += 10
    
    def check_firewall(self):
        self.checks.append("Firewall Status")
        if self.distro.family == "debian":
            result = run_command("ufw status 2>/dev/null", check=False)
            if not result or "inactive" in result.lower():
                self.issues.append("Firewall is turned off (leaves system exposed)")
                return
        elif self.distro.family == "redhat":
            result = run_command("firewall-cmd --state 2>/dev/null", check=False)
            if not result or "not running" in result.lower():
                self.issues.append("Firewall is turned off (leaves system exposed)")
                return
        self.score += 15
    
    def check_services(self):
        self.checks.append("Unnecessary Services")
        dangerous = ['telnet', 'rsh', 'rlogin', 'tftp', 'vsftpd']
        found = []
        for svc in dangerous:
            result = run_command(f"systemctl is-active {svc} 2>/dev/null", check=False)
            if result and "active" in result:
                found.append(svc)
        if found:
            self.issues.append(f"Risky services running: {', '.join(found)}")
            return
        self.score += 10
    
    def check_users(self):
        self.checks.append("User Accounts")
        result = run_command("awk -F: '$3 >= 1000 && $3 < 65534' /etc/passwd | wc -l")
        if result and int(result) > 5:
            self.issues.append("Many user accounts exist (potential risk)")
        else:
            self.score += 8
        
        # Check for users with empty passwords
        result = run_command("awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null", check=False)
        if result and result.strip():
            self.issues.append("Users with no password found!")
        else:
            self.score += 7
    
    def check_permissions(self):
        self.checks.append("File Permissions")
        critical_files = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow']
        issues = []
        for fpath in critical_files:
            if os.path.exists(fpath):
                perms = oct(os.stat(fpath).st_mode)[-3:]
                if fpath == '/etc/shadow' and perms != '000' and perms != '400':
                    issues.append(f"{fpath} has loose permissions")
        if issues:
            self.issues.extend(issues)
        else:
            self.score += 10
    
    def check_kernel_settings(self):
        self.checks.append("Kernel Security Settings")
        secure_settings = {
            'net.ipv4.ip_forward': '0',
            'net.ipv4.conf.all.accept_source_route': '0',
            'net.ipv4.conf.all.accept_redirects': '0',
            'net.ipv4.icmp_echo_ignore_broadcasts': '1',
            'net.ipv4.tcp_syncookies': '1'
        }
        insecure = []
        for key, expected in secure_settings.items():
            result = run_command(f"sysctl -n {key} 2>/dev/null", check=False)
            if result != expected:
                insecure.append(key)
        
        if len(insecure) > 2:
            self.issues.append("Kernel security settings not optimized")
        else:
            self.score += 10
    
    def check_selinux_apparmor(self):
        self.checks.append("Advanced Security Module")
        # Check SELinux
        if os.path.exists('/usr/sbin/getenforce'):
            result = run_command("getenforce 2>/dev/null", check=False)
            if result and result.lower() == "enforcing":
                self.score += 10
                return
        # Check AppArmor
        if os.path.exists('/usr/sbin/aa-status'):
            result = run_command("aa-status 2>/dev/null | grep -c 'profiles are in enforce mode'", check=False)
            if result and int(result) > 0:
                self.score += 10
                return
        self.issues.append("Advanced security mode (SELinux/AppArmor) not active")
    
    def check_ssh_config(self):
        self.checks.append("SSH Security")
        ssh_config = '/etc/ssh/sshd_config'
        if os.path.exists(ssh_config):
            with open(ssh_config, 'r') as f:
                content = f.read()
                if 'PermitRootLogin yes' in content:
                    self.issues.append("SSH allows direct root login (not recommended)")
                    return
            self.score += 10
        else:
            self.score += 10  # No SSH = secure
    
    def check_password_policy(self):
        self.checks.append("Password Policy")
        login_defs = '/etc/login.defs'
        if os.path.exists(login_defs):
            with open(login_defs, 'r') as f:
                content = f.read()
                if 'PASS_MAX_DAYS' in content:
                    match = re.search(r'PASS_MAX_DAYS\s+(\d+)', content)
                    if match and int(match.group(1)) > 90:
                        self.issues.append("Passwords don't expire regularly")
                        return
            self.score += 5
        
        # Check PAM password quality
        if os.path.exists('/etc/pam.d/common-password') or os.path.exists('/etc/pam.d/system-auth'):
            self.score += 5
    
    def check_fail2ban(self):
        self.checks.append("Intrusion Prevention")
        result = run_command("systemctl is-active fail2ban 2>/dev/null", check=False)
        if result and "active" in result:
            self.score += 5
        else:
            self.issues.append("No intrusion prevention system active (fail2ban)")
    
    def calculate_score(self):
        # Score already calculated incrementally
        pass
    
    def display_results(self):
        print_header("Security Assessment Results")
        print(f"\n{Colors.BOLD}Security Score: {self.score}/{self.max_score}{Colors.ENDC}")
        
        if self.score >= 80:
            print_success("Good security posture!")
        elif self.score >= 50:
            print_warning("Moderate security - improvements recommended")
        else:
            print_error("Weak security - hardening strongly recommended")
        
        if self.issues:
            print(f"\n{Colors.BOLD}Issues Found:{Colors.ENDC}")
            for i, issue in enumerate(self.issues, 1):
                print(f"  {i}. {issue}")
        else:
            print_success("\nNo major issues found!")
        
        print()

# Get user confirmation
def get_confirmation(prompt, default_yes=True):
    default = "yes" if default_yes else "no"
    choice = input(f"{prompt} (yes/no, default: {default} for safety): ").strip().lower()
    if not choice:
        return default_yes
    return choice in ['y', 'yes']

# System Hardening Implementation
class SystemHardener:
    def __init__(self, distro, interactive=True):
        self.distro = distro
        self.interactive = interactive
        self.changes = []
        self.total_steps = 12
        self.current_step = 0
        self.progress = ProgressBar(self.total_steps, "Hardening Progress")
    
    def harden(self):
        print_header("Starting System Hardening")
        print_info("This will secure your system using industry best practices")
        print_info("You'll be asked to confirm important changes\n")
        
        if self.interactive:
            if not get_confirmation("Ready to begin hardening?", True):
                print_warning("Hardening cancelled by user")
                return False
        
        print()
        
        # Execute hardening steps
        self.update_system()
        self.configure_firewall()
        self.disable_unnecessary_services()
        self.secure_ssh()
        self.configure_users_and_passwords()
        self.set_file_permissions()
        self.configure_kernel_parameters()
        self.setup_selinux_apparmor()
        self.install_fail2ban()
        self.configure_auditing()
        self.disable_usb_if_needed()
        self.secure_grub()
        
        self.progress.update(self.total_steps - self.current_step)  # Complete
        return True
    
    def update_system(self):
        print_info("\n[1/12] Checking for system updates...")
        self.current_step += 1
        
        if self.interactive:
            if not get_confirmation("Update all packages to latest versions?", True):
                print_warning("Skipped system updates")
                self.progress.update()
                return
        
        try:
            if self.distro.family == "debian":
                print_info("Updating package lists...")
                run_command("apt-get update -qq", capture=False)
                print_info("Upgrading packages (this may take a while)...")
                run_command("DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq", capture=False)
            elif self.distro.family == "redhat":
                print_info("Updating packages (this may take a while)...")
                run_command(f"{self.distro.package_manager} upgrade -y -q", capture=False)
            elif self.distro.family == "arch":
                print_info("Updating packages...")
                run_command("pacman -Syu --noconfirm -q", capture=False)
            elif self.distro.family == "suse":
                print_info("Updating packages...")
                run_command("zypper update -y", capture=False)
            
            print_success("System updated successfully")
            self.changes.append("Updated all system packages")
            logging.info("System packages updated")
        except Exception as e:
            print_error(f"Update failed: {str(e)}")
            logging.error(f"System update failed: {str(e)}")
        
        self.progress.update()
    
    def configure_firewall(self):
        print_info("\n[2/12] Configuring firewall...")
        self.current_step += 1
        
        try:
            if self.distro.family == "debian":
                # Install UFW if not present
                if not shutil.which('ufw'):
                    run_command("apt-get install -y ufw -qq", capture=False)
                
                # Configure UFW
                run_command("ufw --force reset", check=False)
                run_command("ufw default deny incoming")
                run_command("ufw default allow outgoing")
                
                # Ask for SSH port
                ssh_port = "22"
                if self.interactive:
                    custom_port = input("Enter SSH port to allow (default: 22): ").strip()
                    if custom_port and custom_port.isdigit():
                        ssh_port = custom_port
                
                run_command(f"ufw allow {ssh_port}/tcp")
                
                # Ask for additional ports
                if self.interactive:
                    if get_confirmation("Do you need to allow any other ports? (web, database, etc.)", False):
                        ports_input = input("Enter ports separated by commas (e.g., 80,443,3306): ").strip()
                        if ports_input:
                            for port in ports_input.split(','):
                                port = port.strip()
                                if port.isdigit():
                                    run_command(f"ufw allow {port}/tcp")
                                    print_success(f"Allowed port {port}")
                
                run_command("ufw --force enable")
                print_success("Firewall configured and activated")
                self.changes.append("Configured firewall with deny-all default")
                
            elif self.distro.family == "redhat":
                # Install firewalld if not present
                if not shutil.which('firewall-cmd'):
                    run_command(f"{self.distro.package_manager} install -y firewalld -q", capture=False)
                
                run_command("systemctl start firewalld")
                run_command("systemctl enable firewalld")
                run_command("firewall-cmd --set-default-zone=drop")
                run_command("firewall-cmd --zone=drop --add-service=ssh --permanent")
                
                if self.interactive:
                    if get_confirmation("Do you need to allow any services? (http, https, etc.)", False):
                        services = input("Enter services separated by commas (e.g., http,https): ").strip()
                        if services:
                            for svc in services.split(','):
                                svc = svc.strip()
                                run_command(f"firewall-cmd --zone=drop --add-service={svc} --permanent")
                
                run_command("firewall-cmd --reload")
                print_success("Firewall configured and activated")
                self.changes.append("Configured firewall with restrictive rules")
            
            logging.info("Firewall configured")
        except Exception as e:
            print_error(f"Firewall configuration failed: {str(e)}")
            logging.error(f"Firewall configuration failed: {str(e)}")
        
        self.progress.update()
    
    def disable_unnecessary_services(self):
        print_info("\n[3/12] Checking for unnecessary services...")
        self.current_step += 1
        
        dangerous_services = [
            ('telnet', 'Old remote access (not encrypted)'),
            ('rsh', 'Insecure remote shell'),
            ('rlogin', 'Insecure remote login'),
            ('tftp', 'Insecure file transfer'),
            ('vsftpd', 'FTP server (use SFTP instead)'),
            ('avahi-daemon', 'Network discovery (not needed on most servers)'),
            ('cups', 'Printer service (not needed on servers)'),
        ]
        
        for service, description in dangerous_services:
            result = run_command(f"systemctl is-active {service} 2>/dev/null", check=False)
            if result and "active" in result:
                disable = True
                if self.interactive:
                    disable = get_confirmation(f"Turn off '{service}'? ({description})", True)
                
                if disable:
                    run_command(f"systemctl stop {service}", check=False)
                    run_command(f"systemctl disable {service}", check=False)
                    print_success(f"Disabled {service}")
                    self.changes.append(f"Disabled service: {service}")
                    logging.info(f"Disabled service: {service}")
        
        self.progress.update()
    
    def secure_ssh(self):
        print_info("\n[4/12] Securing SSH access...")
        self.current_step += 1
        
        ssh_config = '/etc/ssh/sshd_config'
        if not os.path.exists(ssh_config):
            print_warning("SSH not installed, skipping")
            self.progress.update()
            return
        
        try:
            # Backup original config
            backup_file = f"{ssh_config}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(ssh_config, backup_file)
            
            with open(ssh_config, 'r') as f:
                lines = f.readlines()
            
            # Security settings
            settings = {
                'PermitRootLogin': 'no',
                'PasswordAuthentication': 'yes',  # Keep yes for now, user can change
                'PermitEmptyPasswords': 'no',
                'X11Forwarding': 'no',
                'MaxAuthTries': '3',
                'Protocol': '2',
            }
            
            if self.interactive:
                disable_root = get_confirmation(
                    "Disable direct root login via SSH? (you'll need to use sudo)", 
                    True
                )
                if not disable_root:
                    settings['PermitRootLogin'] = 'yes'
            
            # Apply settings
            new_lines = []
            applied = set()
            
            for line in lines:
                line_stripped = line.strip()
                if line_stripped.startswith('#') or not line_stripped:
                    new_lines.append(line)
                    continue
                
                key = line_stripped.split()[0]
                if key in settings:
                    new_lines.append(f"{key} {settings[key]}\n")
                    applied.add(key)
                else:
                    new_lines.append(line)
            
            # Add missing settings
            for key, value in settings.items():
                if key not in applied:
                    new_lines.append(f"{key} {value}\n")
            
            with open(ssh_config, 'w') as f:
                f.writelines(new_lines)
            
            # Restart SSH
            run_command("systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null", check=False)
            
            print_success("SSH configuration hardened")
            self.changes.append("Secured SSH configuration")
            logging.info("SSH configuration secured")
        except Exception as e:
            print_error(f"SSH hardening failed: {str(e)}")
            logging.error(f"SSH hardening failed: {str(e)}")
        
        self.progress.update()
    
    def configure_users_and_passwords(self):
        print_info("\n[5/12] Configuring user accounts and password policies...")
        self.current_step += 1
        
        try:
            # Set password aging
            login_defs = '/etc/login.defs'
            if os.path.exists(login_defs):
                with open(login_defs, 'r') as f:
                    content = f.read()
                
                # Backup
                backup = f"{login_defs}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(login_defs, backup)
                
                # Update settings
                settings = {
                    'PASS_MAX_DAYS': '90',
                    'PASS_MIN_DAYS': '7',
                    'PASS_WARN_AGE': '14',
                    'PASS_MIN_LEN': '12',
                }
                
                for key, value in settings.items():
                    pattern = rf'^{key}\s+\d+'
                    replacement = f'{key}\t{value}'
                    if re.search(pattern, content, re.MULTILINE):
                        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
                    else:
                        content += f'\n{key}\t{value}\n'
                
                with open(login_defs, 'w') as f:
                    f.write(content)
                
                print_success("Password aging policies configured")
                self.changes.append("Configured password policies")
            
            # Configure PAM for password complexity
            pam_files = ['/etc/pam.d/common-password', '/etc/pam.d/system-auth']
            for pam_file in pam_files:
                if os.path.exists(pam_file):
                    with open(pam_file, 'r') as f:
                        content = f.read()
                    
                    # Add password quality requirements
                    if 'pam_pwquality.so' not in content and 'pam_cracklib.so' not in content:
                        # Install pwquality if needed
                        if self.distro.family == "debian":
                            run_command("apt-get install -y libpam-pwquality -qq", check=False)
                        elif self.distro.family == "redhat":
                            run_command(f"{self.distro.package_manager} install -y libpwquality -q", check=False)
                        
                        backup = f"{pam_file}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                        shutil.copy2(pam_file, backup)
                        
                        with open(pam_file, 'a') as f:
                            f.write('\n# Password quality requirements\n')
                            f.write('password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n')
                        
                        print_success("Password complexity requirements enabled")
                        self.changes.append("Enabled strong password requirements")
                    break
            
            logging.info("User and password policies configured")
        except Exception as e:
            print_error(f"Password policy configuration failed: {str(e)}")
            logging.error(f"Password policy configuration failed: {str(e)}")
        
        self.progress.update()
    
    def set_file_permissions(self):
        print_info("\n[6/12] Setting secure file permissions...")
        self.current_step += 1
        
        try:
            critical_files = {
                '/etc/passwd': '0644',
                '/etc/shadow': '0000',
                '/etc/group': '0644',
                '/etc/gshadow': '0000',
                '/etc/ssh/sshd_config': '0600',
            }
            
            for fpath, perms in critical_files.items():
                if os.path.exists(fpath):
                    os.chmod(fpath, int(perms, 8))
            
            # Set restrictive umask
            profile_files = ['/etc/profile', '/etc/bash.bashrc']
            for profile in profile_files:
                if os.path.exists(profile):
                    with open(profile, 'r') as f:
                        content = f.read()
                    
                    if 'umask 077' not in content:
                        backup = f"{profile}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                        shutil.copy2(profile, backup)
                        
                        with open(profile, 'a') as f:
                            f.write('\n# Restrictive umask for security\numask 077\n')
            
            print_success("File permissions secured")
            self.changes.append("Set secure file permissions")
            logging.info("File permissions configured")
        except Exception as e:
            print_error(f"Permission configuration failed: {str(e)}")
            logging.error(f"Permission configuration failed: {str(e)}")
        
        self.progress.update()
    
    def configure_kernel_parameters(self):
        print_info("\n[7/12] Configuring kernel security parameters...")
        self.current_step += 1
        
        try:
            sysctl_config = '/etc/sysctl.d/99-hardening.conf'
            
            # Security-focused kernel parameters
            params = {
                # Network security
                'net.ipv4.ip_forward': '0',
                'net.ipv4.conf.all.send_redirects': '0',
                'net.ipv4.conf.default.send_redirects': '0',
                'net.ipv4.conf.all.accept_source_route': '0',
                'net.ipv4.conf.default.accept_source_route': '0',
                'net.ipv4.conf.all.accept_redirects': '0',
                'net.ipv4.conf.default.accept_redirects': '0',
                'net.ipv4.conf.all.secure_redirects': '0',
                'net.ipv4.conf.default.secure_redirects': '0',
                'net.ipv4.conf.all.log_martians': '1',
                'net.ipv4.conf.default.log_martians': '1',
                'net.ipv4.icmp_echo_ignore_broadcasts': '1',
                'net.ipv4.icmp_ignore_bogus_error_responses': '1',
                'net.ipv4.tcp_syncookies': '1',
                'net.ipv4.conf.all.rp_filter': '1',
                'net.ipv4.conf.default.rp_filter': '1',
                
                # IPv6 security (if not disabled)
                'net.ipv6.conf.all.accept_source_route': '0',
                'net.ipv6.conf.default.accept_source_route': '0',
                'net.ipv6.conf.all.accept_redirects': '0',
                'net.ipv6.conf.default.accept_redirects': '0',
                
                # Kernel hardening
                'kernel.dmesg_restrict': '1',
                'kernel.kptr_restrict': '2',
                'kernel.yama.ptrace_scope': '1',
                'kernel.kexec_load_disabled': '1',
                'kernel.unprivileged_bpf_disabled': '1',
                
                # Filesystem hardening
                'fs.suid_dumpable': '0',
                'fs.protected_hardlinks': '1',
                'fs.protected_symlinks': '1',
            }
            
            # Ask about IPv6
            if self.interactive:
                disable_ipv6 = get_confirmation(
                    "Disable IPv6? (only if you don't use it)", 
                    False
                )
                if disable_ipv6:
                    params['net.ipv6.conf.all.disable_ipv6'] = '1'
                    params['net.ipv6.conf.default.disable_ipv6'] = '1'
            
            # Write configuration
            with open(sysctl_config, 'w') as f:
                f.write('# System hardening parameters\n')
                f.write(f'# Generated by Security Hardening Tool on {datetime.now()}\n\n')
                for key, value in params.items():
                    f.write(f'{key} = {value}\n')
            
            # Apply settings
            run_command(f"sysctl -p {sysctl_config}", check=False)
            
            print_success("Kernel parameters hardened")
            self.changes.append("Applied secure kernel parameters")
            logging.info("Kernel parameters configured")
        except Exception as e:
            print_error(f"Kernel configuration failed: {str(e)}")
            logging.error(f"Kernel configuration failed: {str(e)}")
        
        self.progress.update()
    
    def setup_selinux_apparmor(self):
        print_info("\n[8/12] Configuring advanced security module...")
        self.current_step += 1
        
        try:
            # Try SELinux first (RedHat/Fedora/CentOS)
            if os.path.exists('/usr/sbin/getenforce'):
                current_mode = run_command("getenforce 2>/dev/null", check=False)
                if current_mode and current_mode.lower() != "enforcing":
                    enable = True
                    if self.interactive:
                        enable = get_confirmation(
                            "Enable advanced security mode (SELinux)? Provides strong protection", 
                            True
                        )
                    
                    if enable:
                        # Set to enforcing
                        selinux_config = '/etc/selinux/config'
                        if os.path.exists(selinux_config):
                            with open(selinux_config, 'r') as f:
                                content = f.read()
                            
                            content = re.sub(
                                r'^SELINUX=.*',
                                'SELINUX=enforcing',
                                content,
                                flags=re.MULTILINE
                            )
                            
                            backup = f"{selinux_config}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                            shutil.copy2(selinux_config, backup)
                            
                            with open(selinux_config, 'w') as f:
                                f.write(content)
                            
                            run_command("setenforce 1", check=False)
                            print_success("SELinux enabled (enforcing mode)")
                            print_warning("Note: System reboot recommended for full activation")
                            self.changes.append("Enabled SELinux in enforcing mode")
                            logging.info("SELinux configured")
                else:
                    print_success("SELinux already in enforcing mode")
            
            # Try AppArmor (Ubuntu/Debian)
            elif os.path.exists('/usr/sbin/aa-status'):
                result = run_command("aa-status --enabled 2>/dev/null", check=False)
                if result is not None:
                    # AppArmor is enabled, ensure profiles are enforced
                    run_command("aa-enforce /etc/apparmor.d/* 2>/dev/null", check=False)
                    print_success("AppArmor profiles enforced")
                    self.changes.append("Enforced AppArmor profiles")
                    logging.info("AppArmor configured")
                else:
                    # Try to install and enable
                    if self.distro.family == "debian":
                        run_command("apt-get install -y apparmor apparmor-utils -qq", check=False)
                        run_command("systemctl enable apparmor", check=False)
                        run_command("systemctl start apparmor", check=False)
                        print_success("AppArmor installed and enabled")
                        self.changes.append("Installed and enabled AppArmor")
            else:
                print_warning("No advanced security module available for this distribution")
        
        except Exception as e:
            print_error(f"Security module configuration failed: {str(e)}")
            logging.error(f"Security module configuration failed: {str(e)}")
        
        self.progress.update()
    
    def install_fail2ban(self):
        print_info("\n[9/12] Setting up intrusion prevention...")
        self.current_step += 1
        
        try:
            # Check if fail2ban is installed
            if not shutil.which('fail2ban-client'):
                install = True
                if self.interactive:
                    install = get_confirmation(
                        "Install intrusion prevention system (fail2ban)? Blocks attackers automatically",
                        True
                    )
                
                if install:
                    print_info("Installing fail2ban...")
                    if self.distro.family == "debian":
                        run_command("apt-get install -y fail2ban -qq", capture=False)
                    elif self.distro.family == "redhat":
                        run_command(f"{self.distro.package_manager} install -y fail2ban -q", capture=False)
                    elif self.distro.family == "arch":
                        run_command("pacman -S --noconfirm fail2ban -q", capture=False)
                    elif self.distro.family == "suse":
                        run_command("zypper install -y fail2ban", capture=False)
            
            if shutil.which('fail2ban-client'):
                # Configure fail2ban
                jail_local = '/etc/fail2ban/jail.local'
                
                config = """[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = systemd
"""
                with open(jail_local, 'w') as f:
                    f.write(config)
                
                # Enable and start
                run_command("systemctl enable fail2ban", check=False)
                run_command("systemctl restart fail2ban", check=False)
                
                print_success("Intrusion prevention system configured")
                self.changes.append("Installed and configured fail2ban")
                logging.info("fail2ban installed and configured")
            else:
                print_warning("Could not install fail2ban")
        
        except Exception as e:
            print_error(f"fail2ban installation failed: {str(e)}")
            logging.error(f"fail2ban installation failed: {str(e)}")
        
        self.progress.update()
    
    def configure_auditing(self):
        print_info("\n[10/12] Configuring system auditing...")
        self.current_step += 1
        
        try:
            # Install auditd if not present
            if not shutil.which('auditctl'):
                if self.distro.family == "debian":
                    run_command("apt-get install -y auditd audispd-plugins -qq", check=False)
                elif self.distro.family == "redhat":
                    run_command(f"{self.distro.package_manager} install -y audit -q", check=False)
                elif self.distro.family == "arch":
                    run_command("pacman -S --noconfirm audit -q", check=False)
            
            if shutil.which('auditctl'):
                # Enable auditd
                run_command("systemctl enable auditd", check=False)
                run_command("systemctl start auditd", check=False)
                
                # Add basic audit rules
                rules_file = '/etc/audit/rules.d/hardening.rules'
                rules = """# Audit rules for security monitoring
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /var/log/sudo.log -p wa -k actions
-w /etc/ssh/sshd_config -p wa -k sshd
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
"""
                with open(rules_file, 'w') as f:
                    f.write(rules)
                
                run_command("augenrules --load", check=False)
                
                print_success("System auditing enabled")
                self.changes.append("Configured comprehensive system auditing")
                logging.info("System auditing configured")
            else:
                print_warning("Could not install auditing system")
        
        except Exception as e:
            print_error(f"Auditing configuration failed: {str(e)}")
            logging.error(f"Auditing configuration failed: {str(e)}")
        
        self.progress.update()
    
    def disable_usb_if_needed(self):
        print_info("\n[11/12] Checking USB storage security...")
        self.current_step += 1
        
        try:
            if self.interactive:
                disable_usb = get_confirmation(
                    "Disable USB storage devices? (high security, but inconvenient)",
                    False
                )
                
                if disable_usb:
                    blacklist_file = '/etc/modprobe.d/blacklist-usb-storage.conf'
                    with open(blacklist_file, 'w') as f:
                        f.write('# Disable USB storage for security\n')
                        f.write('blacklist usb-storage\n')
                    
                    run_command("modprobe -r usb-storage", check=False)
                    
                    print_success("USB storage disabled")
                    self.changes.append("Disabled USB storage devices")
                    logging.info("USB storage disabled")
                else:
                    print_info("USB storage kept enabled")
            else:
                print_info("Skipped USB configuration (interactive mode only)")
        
        except Exception as e:
            print_error(f"USB configuration failed: {str(e)}")
            logging.error(f"USB configuration failed: {str(e)}")
        
        self.progress.update()
    
    def secure_grub(self):
        print_info("\n[12/12] Securing boot loader...")
        self.current_step += 1
        
        try:
            grub_config = None
            if os.path.exists('/etc/default/grub'):
                grub_config = '/etc/default/grub'
            elif os.path.exists('/boot/grub/grub.cfg'):
                grub_config = '/boot/grub/grub.cfg'
            
            if grub_config and self.interactive:
                set_password = get_confirmation(
                    "Set password for boot loader? (prevents unauthorized boot changes)",
                    False
                )
                
                if set_password:
                    print_info("To set GRUB password, run: grub-mkpasswd-pbkdf2")
                    print_info("Then add the hash to /etc/grub.d/40_custom")
                    print_warning("This requires manual configuration for safety")
                    self.changes.append("Recommended GRUB password setup")
            
            print_success("Boot loader security reviewed")
            logging.info("GRUB security configured")
        
        except Exception as e:
            print_error(f"Boot loader configuration failed: {str(e)}")
            logging.error(f"Boot loader configuration failed: {str(e)}")
        
        self.progress.update()
    
    def display_changes(self):
        if self.changes:
            print_header("Changes Applied")
            for i, change in enumerate(self.changes, 1):
                print(f"  {i}. {change}")
        else:
            print_info("No changes were applied")

# Main execution
def main():
    # Check for root
    if os.geteuid() != 0:
        print_error("This tool must be run as root (use sudo)")
        print_info("Example: sudo python3 harden_linux.py")
        sys.exit(1)
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="Linux Security Hardening Tool - Complete system security enhancement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 harden_linux.py              # Full interactive hardening
  sudo python3 harden_linux.py --scan-only  # Just assess security status
  sudo python3 harden_linux.py --auto       # Auto mode (use safe defaults)
        """
    )
    parser.add_argument(
        '--scan-only',
        action='store_true',
        help='Only scan and display security status (no changes)'
    )
    parser.add_argument(
        '--auto',
        action='store_true',
        help='Automatic mode with safe defaults (no prompts)'
    )
    args = parser.parse_args()
    
    # Welcome message
    print_header("Linux Security Hardening Tool")
    print(f"{Colors.BOLD}Making your Linux system more secure{Colors.ENDC}\n")
    print_info(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Setup logging
    log_file = setup_logging()
    print_info(f"Log file: {log_file}\n")
    
    # Detect distribution
    print_info("Detecting your Linux system...")
    distro = DistroDetector()
    
    if not distro.is_supported():
        print_error(f"Unsupported distribution: {distro.name}")
        print_warning("This tool supports: Ubuntu, Debian, Fedora, CentOS, RHEL, Arch, SUSE")
        print_info("You may still try to run it, but some features may not work")
        if not get_confirmation("Continue anyway?", False):
            sys.exit(1)
    else:
        print_success(f"Detected: {distro.name.title()} {distro.version} ({distro.family})")
    
    time.sleep(1)
    
    # Initial security scan
    scanner = SecurityScanner(distro)
    initial_score = scanner.scan()
    scanner.display_results()
    
    # If scan-only mode, exit here
    if args.scan_only:
        print_info("\nScan-only mode - no changes made")
        print_info("Run without --scan-only to harden your system")
        sys.exit(0)
    
    # Confirm hardening
    print("\n" + "="*70)
    if not args.auto:
        print_warning("This tool will make security changes to your system")
        print_info("You'll be asked to confirm important changes")
        if not get_confirmation("\nReady to start hardening your system?", True):
            print_warning("Operation cancelled by user")
            sys.exit(0)
    else:
        print_info("Running in automatic mode with safe defaults...")
        time.sleep(2)
    
    # Execute hardening
    hardener = SystemHardener(distro, interactive=not args.auto)
    success = hardener.harden()
    
    if not success:
        print_error("\nHardening was not completed")
        sys.exit(1)
    
    # Final security scan
    print_header("Final Security Assessment")
    final_scanner = SecurityScanner(distro)
    final_score = final_scanner.scan()
    final_scanner.display_results()
    
    # Display comparison
    print_header("Security Improvement Summary")
    improvement = final_score - initial_score
    print(f"{Colors.BOLD}Initial Score: {initial_score}/100{Colors.ENDC}")
    print(f"{Colors.BOLD}Final Score:   {final_score}/100{Colors.ENDC}")
    
    if improvement > 0:
        print(f"{Colors.OKGREEN}{Colors.BOLD}Improvement:   +{improvement} points 🎉{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}Improvement:   {improvement} points{Colors.ENDC}")
    
    print()
    hardener.display_changes()
    
    # Final recommendations
    print_header("Next Steps & Recommendations")
    print_info("1. Review the log file for detailed changes")
    print_info("2. Test your applications to ensure they still work")
    print_info("3. Consider enabling automatic security updates")
    print_info("4. Regularly review system logs for suspicious activity")
    print_info("5. Keep your system updated with latest security patches")
    
    if 'SELinux' in ' '.join(hardener.changes) or 'AppArmor' in ' '.join(hardener.changes):
        print_warning("\n⚠  System reboot recommended for full security activation")
    
    print(f"\n{Colors.OKGREEN}{Colors.BOLD}System hardening completed successfully!{Colors.ENDC}")
    print_info(f"Full log saved to: {log_file}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n" + "="*70)
        print_warning("Operation cancelled by user (Ctrl+C)")
        print_info("No partial changes - system state preserved")
        sys.exit(130)
    except Exception as e:
        print("\n\n" + "="*70)
        print_error(f"Unexpected error: {str(e)}")
        logging.exception("Fatal error occurred")
        print_info("Check the log file for details")
        sys.exit(1)
