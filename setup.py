import subprocess
import os
import crypt
import shutil
import time
import getpass
import re
import sys

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(msg):
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== {msg} ==={Colors.ENDC}\n")

def print_success(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.ENDC}")

def print_warning(msg):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.ENDC}")

def print_error(msg):
    print(f"{Colors.RED}✗ {msg}{Colors.ENDC}")

def run(cmd, check=True, show_output=True):
    print(f"{Colors.BLUE}Running: {cmd}{Colors.ENDC}")
    spinner = ['|', '/', '-', '\\']
    i = 0
    
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Show a spinner for long-running commands
    while process.poll() is None:
        if show_output:
            sys.stdout.write(f"\r{spinner[i]} Working... ")
            sys.stdout.flush()
            i = (i + 1) % 4
            time.sleep(0.1)
    
    if show_output:
        sys.stdout.write("\r")
    
    stdout, stderr = process.communicate()
    
    if process.returncode != 0:
        print_error(f"Command failed: {stderr.strip()}")
        if check:
            raise SystemExit("Script stopped due to error.")
        return False, stderr
    else:
        if show_output and stdout.strip():
            print_success("Command completed successfully")
            if len(stdout.strip()) > 0:
                print(stdout.strip())
        return True, stdout
    
def is_service_active(service_name):
    result = subprocess.run(f"systemctl is-active {service_name}", shell=True, capture_output=True, text=True)
    return result.stdout.strip() == "active"

def install_lamp_phpmyadmin():
    print_header("Installing LAMP Stack and phpMyAdmin")
    
    run("apt update")
    run("apt install -y apache2")
    print_success("Apache installed")
    
    run("apt install -y mysql-server")
    print_success("MySQL installed")
    
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

    # Enable PHP extensions and restart Apache
    run("phpenmod mysqli")
    run("systemctl restart apache2")

    # Link phpMyAdmin manually if not auto-linked
    if not os.path.exists("/var/www/html/phpmyadmin"):
        run("ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin")
    
    print_success("LAMP stack with phpMyAdmin installed successfully")

def secure_mysql():
    print_header("Securing MySQL")
    
    # Before MySQL 5.7, the root password is empty by default
    # After MySQL 5.7, root uses auth_socket plugin by default
    
    # First, try to run a simple command to check if we can access MySQL without password
    success, _ = run("mysql -e 'SELECT 1'", check=False, show_output=False)
    
    if success:
        # We can access MySQL without password, let's secure it
        print_success("MySQL is accessible without password. Setting up root password and securing...")
        sql = (
            "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'root';"
            "DELETE FROM mysql.user WHERE User='';"
            "DROP DATABASE IF EXISTS test;"
            "FLUSH PRIVILEGES;"
        )
        run(f"mysql -e \"{sql}\"")
    else:
        # We cannot access MySQL without password, let's try to reset the root password
        print_warning("Cannot access MySQL without password. Attempting to reset root password...")
        
        # Stop MySQL service
        run("systemctl stop mysql")
        
        # Start MySQL in safe mode
        print("Starting MySQL in safe mode...")
        safe_process = subprocess.Popen(
            "mysqld_safe --skip-grant-tables --skip-networking &", 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        
        # Wait for MySQL to start in safe mode
        time.sleep(5)
        
        # Reset root password
        reset_sql = (
            "FLUSH PRIVILEGES;"
            "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'root';"
            "FLUSH PRIVILEGES;"
        )
        
        try:
            run("mysql -u root -e \"" + reset_sql + "\"")
        except SystemExit:
            print_warning("Could not reset password in safe mode. Using alternative method...")
            
        # Kill MySQL safe mode and restart normal service
        run("pkill mysqld", check=False)
        time.sleep(2)
        run("systemctl start mysql")
        
        # Try direct password reset
        direct_reset = "UPDATE mysql.user SET authentication_string=PASSWORD('root'), plugin='mysql_native_password' WHERE User='root' AND Host='localhost';"
        run(f"echo \"{direct_reset}FLUSH PRIVILEGES;\" | mysql --defaults-file=/etc/mysql/debian.cnf", check=False)
    
    # Verify we can connect with the new password
    success, _ = run("mysql -u root -proot -e 'SELECT 1'", check=False, show_output=False)
    if success:
        print_success("MySQL secured successfully. Root password set to 'root'")
    else:
        print_warning("Could not verify MySQL password. You may need to secure MySQL manually.")

def install_vsftpd():
    print_header("Installing and configuring vsftpd")
    run("apt install -y vsftpd")
    run("systemctl enable vsftpd")
    run("systemctl start vsftpd")

    vsftpd_conf = "/etc/vsftpd.conf"
    if not os.path.exists(vsftpd_conf + ".bak"):
        shutil.copy(vsftpd_conf, vsftpd_conf + ".bak")
        print_success(f"Configuration backup created: {vsftpd_conf}.bak")

    config_values = {
        "anonymous_enable": "NO",
        "local_enable": "YES",
        "write_enable": "YES",
        "chroot_local_user": "YES",
        "allow_writeable_chroot": "YES",
        "user_sub_token": "$USER",
        "local_root": "/home/$USER/ftp",
        "pasv_min_port": "40000",
        "pasv_max_port": "50000"
    }

    with open(vsftpd_conf, "r") as f:
        lines = f.readlines()

    new_lines = []
    keys_updated = set()
    for line in lines:
        updated = False
        for key, value in config_values.items():
            if line.strip().startswith(key):
                new_lines.append(f"{key}={value}\n")
                keys_updated.add(key)
                updated = True
                break
        if not updated:
            new_lines.append(line)

    for key, value in config_values.items():
        if key not in keys_updated:
            new_lines.append(f"{key}={value}\n")

    with open(vsftpd_conf, "w") as f:
        f.writelines(new_lines)

    run("systemctl restart vsftpd")
    print_success("VSFTPD configured and restarted")

def validate_username(username):
    if not re.match(r'^[a-z][-a-z0-9_]*$', username):
        return False
    return True

def create_ftp_user(username=None, password=None):
    print_header("Creating FTP User")
    
    if username is None:
        while True:
            username = input("Enter FTP username (default: admin): ").strip() or "admin"
            if validate_username(username):
                break
            print_warning("Invalid username. Use only lowercase letters, numbers, hyphens, and underscores.")
    
    if password is None:
        while True:
            password = getpass.getpass(f"Enter password for {username} (default: power): ") or "power"
            if len(password) >= 4:
                break
            print_warning("Password should be at least 4 characters long.")
    
    # Check if user already exists
    result = subprocess.run(f"id -u {username}", shell=True, capture_output=True)
    if result.returncode == 0:
        print_warning(f"User {username} already exists.")
    else:
        # Create group if not exists
        run("getent group ftpusers || groupadd ftpusers")
        encrypted_pwd = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
        run(f"useradd -m -s /usr/sbin/nologin -p '{encrypted_pwd}' -g ftpusers {username}")
        print_success(f"FTP user {username} created")

    ftp_dir = f"/home/{username}/ftp/files"
    os.makedirs(ftp_dir, exist_ok=True)
    run(f"chown -R {username}:{username} /home/{username}/ftp")
    run(f"chmod -R 755 /home/{username}/ftp")
    print_success(f"FTP directory created: {ftp_dir}")

def get_server_ip():
    try:
        result = subprocess.run("hostname -I | awk '{print $1}'", shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "<your-server-ip>"

def main():
    try:
        print_header("AWS Server Setup Script")
        
        # Ask for confirmation
        proceed = input("This script will install and configure LAMP stack, phpMyAdmin, and FTP. Continue? (y/n): ").lower()
        if proceed != 'y':
            print("Setup cancelled.")
            return
            
        # Install components
        install_lamp_phpmyadmin()
        secure_mysql()
        install_vsftpd()
        
        # Ask for FTP details
        create_custom_user = input("Create custom FTP user? (Default credentials will be admin/power) (y/n): ").lower()
        if create_custom_user == 'y':
            create_ftp_user(None, None)  # Will prompt for username and password
        else:
            create_ftp_user("admin", "power")  # Use default

        # Get server IP for the final message
        server_ip = get_server_ip()
            
        print_header("Setup Completed Successfully")
        print(f"{Colors.GREEN}Apache:{Colors.ENDC} http://{server_ip}")
        print(f"{Colors.GREEN}phpMyAdmin:{Colors.ENDC} http://{server_ip}/phpmyadmin")
        print(f"{Colors.GREEN}MySQL root password:{Colors.ENDC} root")
        if create_custom_user == 'y':
            print(f"{Colors.GREEN}FTP credentials:{Colors.ENDC} Custom credentials were set")
        else:
            print(f"{Colors.GREEN}FTP credentials:{Colors.ENDC} Username: admin, Password: power")
        print("\nRemember to change default passwords in a production environment!")
            
    except KeyboardInterrupt:
        print("\nSetup interrupted.")
    except Exception as e:
        print_error(f"An error occurred: {str(e)}")
        return 1

if __name__ == "__main__":
    if os.geteuid() != 0:
        print_error("Please run this script as root (using sudo).")
        sys.exit(1)
    else:
        sys.exit(main() or 0)
