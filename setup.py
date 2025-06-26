import os
import subprocess
import sys
import time

def print_header(message):
    print(f"\n{'=' * 50}")
    print(f"  {message}")
    print(f"{'=' * 50}")

def print_success(message):
    print(f"\n {message}")

def print_info(message):
    print(f"\nℹ️ {message}")

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
    except:
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
        print("This script must be run as root.")
        sys.exit(1)

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
    except:
        print_info("Failed to configure MySQL automatically. You may need to do this manually.")
    
    # Create a test PHP file
    print_header("Creating test PHP file")
    php_content = """<?php
    phpinfo();
    ?>"""
    
    with open("/var/www/html/info.php", "w") as f:
        f.write(php_content)
    
    print_success("LAMP stack installation completed")
    print_info("You can access phpMyAdmin at: http://your-server-ip/phpmyadmin")
    print_info("Username: root, Password: root")
    print_info("You can test PHP at: http://your-server-ip/info.php")

def setup_ufw():
    print_header("Setting up Firewall")
    # Make sure we explicitly allow required ports
    run("ufw allow OpenSSH")
    run("ufw allow 20/tcp")  # FTP data
    run("ufw allow 21/tcp")  # FTP control
    run("ufw allow 80/tcp")  # HTTP
    run("ufw allow 443/tcp") # HTTPS
    run("ufw allow 9000:10000/tcp")  # Passive FTP port range
    run("echo 'y' | ufw enable")
    print_success("Firewall configured")

def setup_vsftpd():
    print_header("Setting up FTP Server")
    run("apt install -y vsftpd")
    print_success("vsftpd installed")
    
    # Backup original config
    run("cp /etc/vsftpd.conf /etc/vsftpd.conf.bak")
    
    # Create a completely new vsftpd.conf file with all necessary settings
    vsftpd_config = """# FTP server configuration
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
pasv_enable=YES
pasv_min_port=9000
pasv_max_port=10000
pasv_address=AUTO_IP_ADDRESS
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO
allow_writeable_chroot=YES
ssl_enable=NO
"""
    
    # Try to get the public IP address
    public_ip = run_with_output("curl -s ifconfig.me || curl -s icanhazip.com || curl -s ipinfo.io/ip || curl -s api.ipify.org")
    if public_ip:
        # Replace AUTO_IP_ADDRESS with the actual IP
        vsftpd_config = vsftpd_config.replace("AUTO_IP_ADDRESS", public_ip.strip())
    else:
        # If we can't get the IP, remove that line
        vsftpd_config = vsftpd_config.replace("pasv_address=AUTO_IP_ADDRESS\n", "")
    
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

def create_ftp_user(username="admin", password="power"):
    print_header(f"Creating FTP user: {username}")
    
    # Check if user exists
    if os.system(f"id {username} >/dev/null 2>&1") != 0:
        # Create user with home directory
        run(f"useradd -m -s /bin/bash {username}")
    
    # Set password
    run(f"echo '{username}:{password}' | chpasswd")
    
    # Create FTP directory structure and set permissions
    run(f"mkdir -p /home/{username}/ftp")
    run(f"chown -R {username}:{username} /home/{username}")
    run(f"chmod -R 755 /home/{username}")
    
    # Add user to vsftpd.userlist to allow access
    run(f"echo '{username}' >> /etc/vsftpd.userlist")
    
    print_success(f"FTP user {username} created with password: {password}")
    print_info(f"FTP server is ready. Connect to your server IP on port 21")

def main():
    check_root()
    print_header("Automatic Server Setup Script")
    print_info("This script will install and configure LAMP stack and FTP server")
    
    # Update system
    print_header("Updating system packages")
    run("apt update && apt upgrade -y")
    
    # Install common utilities
    print_header("Installing common utilities")
    run("apt install -y curl wget unzip git ufw")
    
    # Setup LAMP stack
    setup_lamp_stack()
    
    # Setup Firewall
    setup_ufw()
    
    # Setup FTP
    setup_vsftpd()
    create_ftp_user()
    
    print_header("Setup Complete!")
    print_info("Your server has been set up with:")
    print("- Apache Web Server")
    print("- MySQL Database Server")
    print("- PHP")
    print("- phpMyAdmin (http://your-server-ip/phpmyadmin, user: root, pass: root)")
    print("- FTP Server (user: admin, pass: power)")
    print("\nRemember to change default passwords in a production environment!")

if __name__ == "__main__":
    main()
