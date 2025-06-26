import subprocess
import os
import crypt
import shutil

def run(cmd, check=True):
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr.strip()}")
        if check:
            raise SystemExit("Script stopped due to error.")
    else:
        print(result.stdout.strip())

def install_lamp_phpmyadmin():
    print("\nInstalling Apache, MySQL, PHP, and phpMyAdmin...")
    run("apt update")
    run("apt install -y apache2 mysql-server php libapache2-mod-php php-mysql")
    run("systemctl enable apache2")
    run("systemctl start apache2")
    run("systemctl enable mysql")
    run("systemctl start mysql")

    # Install phpMyAdmin without interaction
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

def secure_mysql():
    print("\nSecuring MySQL...")
    sql = (
        "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'root';"
        "DELETE FROM mysql.user WHERE User='';"
        "DROP DATABASE IF EXISTS test;"
        "FLUSH PRIVILEGES;"
    )
    run(f"mysql -u root -e \"{sql}\"")

def install_vsftpd():
    print("\nInstalling and configuring vsftpd...")
    run("apt install -y vsftpd")
    run("systemctl enable vsftpd")
    run("systemctl start vsftpd")

    vsftpd_conf = "/etc/vsftpd.conf"
    if not os.path.exists(vsftpd_conf + ".bak"):
        shutil.copy(vsftpd_conf, vsftpd_conf + ".bak")

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

def create_ftp_user(username="admin", password="power"):
    print(f"\nCreating FTP user: {username}")
    result = subprocess.run(f"id -u {username}", shell=True, capture_output=True)
    if result.returncode == 0:
        print(f"User {username} already exists.")
    else:
        # Create group if not exists
        run("getent group ftpusers || groupadd ftpusers")
        encrypted_pwd = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
        run(f"useradd -m -s /usr/sbin/nologin -p '{encrypted_pwd}' -g ftpusers {username}")

    ftp_dir = f"/home/{username}/ftp/files"
    os.makedirs(ftp_dir, exist_ok=True)
    run(f"chown -R {username}:{username} /home/{username}/ftp")
    run(f"chmod -R 755 /home/{username}/ftp")

def main():
    install_lamp_phpmyadmin()
    secure_mysql()
    install_vsftpd()
    create_ftp_user()

    print("\nSetup completed.")
    print("Apache: http://<your-server-ip>")
    print("phpMyAdmin: http://<your-server-ip>/phpmyadmin")
    print("MySQL root password: root")
    print("FTP credentials - Username: admin, Password: power")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root (using sudo).")
    else:
        main()
