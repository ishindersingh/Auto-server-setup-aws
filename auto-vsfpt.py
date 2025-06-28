#!/usr/bin/env python3
import os
import subprocess
import sys
import socket
import platform

def print_header(message):
    print(f"\n{'=' * 50}")
    print(f"  {message}")
    print(f"{'=' * 50}")

def print_success(message):
    print(f"\n✅ {message}")

def print_info(message):
    print(f"\nℹ️ {message}")

def print_error(message):
    print(f"\n❌ {message}")

def run(command):
    print(f"Running: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"Error: {stderr.decode()}")
        print("Script stopped due to error.")
        sys.exit(1)
    return stdout.decode().strip()

def run_with_output(command):
    try:
        return subprocess.check_output(command, shell=True).decode('utf-8').strip()
    except Exception as e:
        print(f"Command failed: {command}, Error: {str(e)}")
        return ""

def is_service_active(service_name):
    try:
        result = subprocess.run(["systemctl", "is-active", service_name], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except:
        return False

def check_root():
    if os.geteuid() != 0:
        print_error("This script must be run as root (sudo).")
        sys.exit(1)

def get_server_ip():
    # Try multiple methods to get the public IP
    for command in [
        "curl -s ifconfig.me",
        "curl -s icanhazip.com",
        "curl -s ipinfo.io/ip",
        "curl -s api.ipify.org"
    ]:
        ip = run_with_output(command)
        if ip and len(ip.split('.')) == 4:
            return ip.strip()
    
    # Fallback to local IP if public IP cannot be determined
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))  # Connect to Google DNS
        local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        print_error(f"Could not determine IP address: {e}")
        return "YOUR_SERVER_IP"  # Placeholder
    finally:
        s.close()

def disable_firewalls():
    print_header("Disabling Firewalls")
    
    # Disable UFW if installed
    if os.path.exists("/usr/sbin/ufw"):
        run("ufw disable")
        print_success("UFW firewall disabled")
    
    # Disable firewalld if installed
    if os.path.exists("/usr/sbin/firewalld"):
        run("systemctl stop firewalld")
        run("systemctl disable firewalld")
        print_success("firewalld disabled")
    
    # Check for and disable iptables
    run("iptables -F")
    print_success("iptables rules flushed")
    
    print_info("All firewalls have been disabled. Note that this may reduce server security.")

def setup_vsftpd():
    print_header("Setting up FTP Server")
    
    run("apt install -y vsftpd curl")
    print_success("vsftpd installed")
    
    # Backup original config if it exists
    if os.path.exists("/etc/vsftpd.conf"):
        run("cp /etc/vsftpd.conf /etc/vsftpd.conf.bak")
    
    # Get server IP for passive mode
    server_ip = get_server_ip()
    print_info(f"Using server IP for passive mode: {server_ip}")
    
    # Create a completely new vsftpd.conf file with all necessary settings
    vsftpd_config = f"""# FTP server configuration
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES

# Allow users to access their entire home directory
chroot_local_user=NO

pam_service_name=vsftpd

# Passive mode settings
pasv_enable=YES
pasv_min_port=9000
pasv_max_port=10000
pasv_address={server_ip}
pasv_addr_resolve=NO

# Logging settings
xferlog_std_format=NO
log_ftp_protocol=YES

# User settings
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO

# Disable SSL for easier connection testing
ssl_enable=NO
"""
    
    # Write the new config
    with open("/etc/vsftpd.conf", "w") as f:
        f.write(vsftpd_config)
    
    # Create empty userlist file if it doesn't exist
    run("touch /etc/vsftpd.userlist")
    
    # Make sure the empty directory exists
    run("mkdir -p /var/run/vsftpd/empty")
    
    # Restart and enable the service
    run("systemctl restart vsftpd")
    run("systemctl enable vsftpd")
    print_success("FTP server configured")

def create_ftp_user(username="ishu", password="power"):
    print_header(f"Creating FTP user: {username}")
    
    # Try to remove the user if it exists (to start fresh)
    run(f"userdel -r {username} 2>/dev/null || true")
    
    # Create the user with a proper shell and home directory
    run(f"useradd -m -s /bin/bash {username}")
    
    # Set password
    run(f"echo '{username}:{password}' | chpasswd")
    
    # Set permissions for home directory
    run(f"chown -R {username}:{username} /home/{username}")
    run(f"chmod -R 755 /home/{username}")
    
    # Add user to vsftpd.userlist for FTP access (overwrite the file)
    run(f"echo '{username}' > /etc/vsftpd.userlist")
    
    # Create a test file in the home directory
    run(f"echo 'FTP is working correctly!' > /home/{username}/test.txt")
    run(f"chown {username}:{username} /home/{username}/test.txt")
    
    # Restart FTP server to apply changes
    run("systemctl restart vsftpd")
    print_success(f"FTP user {username} created with password: {password}")

def main():
    # Check if running as root on Linux
    if platform.system() == "Linux":
        check_root()
    
    print_header("FTP Server Setup Script")
    print_info("This script will install and configure vsftpd with a user that has full access to their home directory")
    
    # Disable firewalls
    disable_firewalls()
    
    # Setup VSFTPD
    setup_vsftpd()
    
    # Create FTP user
    create_ftp_user()
    
    # Get server IP for display
    server_ip = get_server_ip()
    
    print_header("Setup Complete!")
    print_info(f"FTP server has been set up on IP: {server_ip}")
    print("\nConnection Details:")
    print(f"  - Host: {server_ip}")
    print("  - Protocol: FTP")
    print("  - Port: 21")
    print("  - Encryption: None")
    print("  - Logon Type: Normal")
    print("  - Username: ishu")
    print("  - Password: power")
    print("  - Home Directory: /home/ishu")
    
    print("\nTo connect with FileZilla:")
    print("1. Open FileZilla")
    print("2. Enter the above connection details in the quickconnect bar")
    print("3. Click Quickconnect")
    
    print("\nFor command-line FTP:")
    print(f"ftp {server_ip}")
    print("Username: ishu")
    print("Password: power")
    
    print_info("All firewalls have been disabled to ensure connectivity")

if __name__ == "__main__":
    main()