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

def setup_lamp_stack():
    print_header("Installing LAMP Stack")
    
    # Update apt repository
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

    # Install phpMyAdmin - with better error handling
    print_header("Setting up phpMyAdmin")
    try:
        # Make sure the universe repository is enabled
        run("apt-add-repository universe -y")
        run("apt update")
        
        # Set up debconf selections for non-interactive install
        run("echo 'phpmyadmin phpmyadmin/dbconfig-install boolean true' | debconf-set-selections")
        run("echo 'phpmyadmin phpmyadmin/app-password-confirm password root' | debconf-set-selections")
        run("echo 'phpmyadmin phpmyadmin/mysql/admin-pass password root' | debconf-set-selections")
        run("echo 'phpmyadmin phpmyadmin/mysql/app-pass password root' | debconf-set-selections")
        run("echo 'phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2' | debconf-set-selections")
        
        # Install phpMyAdmin
        run("DEBIAN_FRONTEND=noninteractive apt install -y phpmyadmin")
        print_success("phpMyAdmin installed")
    except Exception as e:
        print_error(f"Failed to install phpMyAdmin: {str(e)}")
        print_info("Trying alternative installation method...")
        
        # Alternative method: Download and configure manually
        try:
            run("cd /tmp && wget https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz")
            run("mkdir -p /usr/share/phpmyadmin")
            run("tar xvf /tmp/phpMyAdmin-latest-all-languages.tar.gz --strip-components=1 -C /usr/share/phpmyadmin")
            run("cp /usr/share/phpmyadmin/config.sample.inc.php /usr/share/phpmyadmin/config.inc.php")
            
            # Generate blowfish secret
            blowfish_secret = run('openssl rand -base64 32')
            run(f"sed -i \"s/\\$cfg\\['blowfish_secret'\\] = '';/\\$cfg\\['blowfish_secret'\\] = '{blowfish_secret}';/g\" /usr/share/phpmyadmin/config.inc.php")
            
            # Create symbolic link to Apache document root
            run("ln -sf /usr/share/phpmyadmin /var/www/html/phpmyadmin")
            run("systemctl restart apache2")
            print_success("phpMyAdmin installed manually")
        except:
            print_error("Could not install phpMyAdmin. Please install it manually after setup.")
    
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
    print_header("Firewall Setup")
    # Disabling firewall as requested
    if is_service_active("ufw"):
        run("ufw disable")
        print_success("Firewall disabled")
    
    # If firewalld is installed, disable it as well
    if os.path.exists("/usr/sbin/firewalld"):
        run("systemctl stop firewalld")
        run("systemctl disable firewalld")
        print_success("firewalld disabled")
    
    print_info("Firewall has been disabled as requested. Note that this may reduce server security.")


def main():
    # Check if running as root
    if platform.system() == "Linux":
        check_root()
    
    print_header("Automatic Server Setup Script")
    print_info("This script will install and configure LAMP stack")
    
    # Install common utilities
    print_header("Installing common utilities")
    run("apt install -y curl wget unzip git software-properties-common apt-transport-https ca-certificates")
    
    # Setup components
    setup_lamp_stack()
    
    # Disable firewall instead of setting it up
    setup_ufw()  # This now disables firewall instead of configuring it
    
    # Get server IP for display
    server_ip = get_server_ip()
    
    print_header("Setup Complete!")
    print_info(f"Your server has been set up with IP: {server_ip}")
    print("- Apache Web Server")
    print("- MySQL Database Server")
    print("- PHP")
    print(f"- phpMyAdmin (http://{server_ip}/phpmyadmin, user: root, pass: root)")
    print("\nTo connect with FileZilla:")
    print(f"  - Host: {server_ip}")
    print("\nRemember to change default passwords in a production environment!")

if __name__ == "__main__":
    main()