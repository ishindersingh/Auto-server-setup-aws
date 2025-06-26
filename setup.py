#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import socket
import platform

def print_header(message):
    print(f"\n{'=' * 50}")
    print(f"  {message}")
    print(f"{'=' * 50}")

def print_success(message):
    print(f"\n {message}")

def print_info(message):
    print(f"\n {message}")

def print_error(message):
    print(f"\n {message}")

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

def setup_lamp_stack():
    print_header("Installing LAMP Stack")
    
    # Update package lists
    run("apt update")
    
    # Install Apache
    run("apt install -y apache2")
    print_success("Apache installed")
    
    # Install MySQL
    run("apt install -y mysql-server")
    print_success("MySQL installed")
    
    # Install PHP and required modules
    run("apt install -y php libapache2-mod-php php-mysql")
    print_success("PHP installed")
    
    # Enable and start services
    if not is_service_active("apache2"):
        run("systemctl enable apache2")
        run("systemctl start apache2")
    
    if not is_service_active("mysql"):
        run("systemctl enable mysql")
        run("systemctl start mysql")

    # Install phpMyAdmin without interaction
    print_header("Setting up phpMyAdmin")
    run("echo 'phpmyadmin phpmyadmin/dbconfig-install boolean true' | debconf-set-selections")
    run("echo 'phpmyadmin phpmyadmin/app-password-confirm password root' | debconf-set-selections")
    run("echo 'phpmyadmin phpmyadmin/mysql/admin-pass password root' | debconf-set-selections")
    run("echo 'phpmyadmin phpmyadmin/mysql/app-pass password root' | debconf-set-selections")
    run("echo 'phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2' | debconf-set-selections")
    run("DEBIAN_FRONTEND=noninteractive apt install -y phpmyadmin")
    
    # Configure MySQL Security
    print_header("Configuring MySQL")
    try:
        run("mysql -u root -e \"ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'root';\"")
        run("mysql -u root -p'root' -e \"DELETE FROM mysql.user WHERE User='';\"")
        run("mysql -u root -p'root' -e \"DROP DATABASE IF EXISTS test;\"")
        run("mysql -u root -p'root' -e \"FLUSH PRIVILEGES;\"")
        print_success("MySQL configured successfully")
    except Exception as e:
        print_info(f"Failed to configure MySQL automatically: {str(e)}")
        print_info("You may need to configure MySQL manually.")
    
    # Create a test PHP file
    print_header("Creating test PHP file")
    php_content = """<?php
    phpinfo();
    ?>"""
    
    with open("/var/www/html/info.php", "w") as f:
        f.write(php_content)
    
    print_success("LAMP stack installation completed")

def setup_ufw():
    print_header("Setting up Firewall")
    # Make sure we explicitly allow required ports
    run("apt install -y ufw")
    run("ufw allow OpenSSH")
    run("ufw allow 20/tcp")  # FTP data
    run("ufw allow 21/tcp")  # FTP control
    run("ufw allow 80/tcp")  # HTTP
    run("ufw allow 443/tcp") # HTTPS
    run("ufw allow 9000:10000/tcp")  # Passive FTP port range
    run("echo 'y' | ufw enable")
    
    # Check if ufw is active
    if not is_service_active("ufw"):
        run("systemctl enable ufw")
        run("systemctl start ufw")
    
    print_success("Firewall configured")

def setup_vsftpd():
    print_header("Setting up FTP Server")
    run("apt install -y vsftpd")
    print_success("vsftpd installed")
    
    # Backup original config
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
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd

# Fixed passive mode settings
pasv_enable=YES
pasv_min_port=9000
pasv_max_port=10000
pasv_address={server_ip}
pasv_addr_resolve=NO

# Logging settings - important for debugging
xferlog_std_format=NO
log_ftp_protocol=YES
debug_ssl=YES

# User settings
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO

# Allow writable home directory
allow_writeable_chroot=YES

# Disable SSL for testing
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
    
    # Create FTP directory and set permissions
    run(f"mkdir -p /home/{username}/ftp")
    run(f"chown -R {username}:{username} /home/{username}")
    run(f"chmod 755 /home/{username}")
    run(f"chmod -R 755 /home/{username}/ftp")
    
    # Add user to vsftpd.userlist for FTP access
    run(f"echo '{username}' > /etc/vsftpd.userlist")
    
    # Create a test file in the FTP directory
    run(f"echo 'FTP is working correctly!' > /home/{username}/ftp/test.txt")
    run(f"chown {username}:{username} /home/{username}/ftp/test.txt")
    
    # Fix passive mode on cloud providers (specifically AWS)
    server_ip = get_server_ip()
    print_info(f"Ensuring iptables rules for FTP passive mode on IP: {server_ip}")
    
    # Add iptables rules for FTP passive mode
    for port in range(9000, 10001):
        run(f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT || true")
    
    # Save iptables rules if possible
    run("iptables-save > /etc/iptables.rules || true")
    
    # Restart FTP server to apply changes
    run("systemctl restart vsftpd")
    print_success(f"FTP user {username} created with password: {password}")
    
    # Verify FTP is accessible
    print_info(f"Verifying FTP configuration on {server_ip}...")
    
    # Output connection details for the user
    print_info(f"FTP Connection Details:")
    print(f"  - Server: {server_ip}")
    print(f"  - Port: 21")
    print(f"  - Username: {username}")
    print(f"  - Password: {password}")
    print(f"  - Home directory: /home/{username}/ftp")

def configure_aws_security_group():
    print_header("AWS Security Group Configuration")
    print_info("If you're running this on AWS EC2, make sure your security group allows:")
    print("1. Port 21 (FTP Control)")
    print("2. Port 20 (FTP Data)")
    print("3. Ports 9000-10000 (Passive FTP)")
    print("4. Port 80 (HTTP)")
    print("5. Port 443 (HTTPS)")

def main():
    # Check if running as root
    if platform.system() == "Linux":
        check_root()
    
    print_header("Automatic Server Setup Script")
    print_info("This script will install and configure LAMP stack and FTP server")
    
    # Update system
    print_header("Updating system packages")
    run("apt update")
    run("apt upgrade -y")
    
    # Install common utilities
    print_header("Installing common utilities")
    run("apt install -y curl wget unzip git python3-pip iptables-persistent")
    
    # Setup components
    setup_lamp_stack()
    setup_ufw()
    setup_vsftpd()
    create_ftp_user()
    
    # Cloud-specific configurations
    configure_aws_security_group()
    
    # Get server IP for display
    server_ip = get_server_ip()
    
    print_header("Setup Complete!")
    print_info(f"Your server has been set up with IP: {server_ip}")
    print("- Apache Web Server")
    print("- MySQL Database Server")
    print("- PHP")
    print(f"- phpMyAdmin (http://{server_ip}/phpmyadmin, user: root, pass: root)")
    print(f"- FTP Server (user: ishu, pass: power)")
    print("\nTo connect with FileZilla:")
    print(f"  - Host: {server_ip}")
    print("  - Protocol: FTP")
    print("  - Encryption: None")
    print("  - Logon Type: Normal")
    print("  - User: ishu")
    print("  - Password: power")
    print("  - Port: 21")
    
    print_info("If FTP directory listing fails, try these solutions:")
    print("1. Ensure EC2 security groups allow ports 9000-10000")
    print("2. Check if your ISP blocks FTP connections")
    print("3. Try connecting in passive mode")
    print("4. Try disabling firewall temporarily: sudo ufw disable")
    
    print("\nRemember to change default passwords in a production environment!")

if __name__ == "__main__":
    main()
