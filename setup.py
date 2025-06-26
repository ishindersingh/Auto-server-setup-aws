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

def install_lamp():
    print("\nInstalling LAMP (Apache, MySQL, PHP)...")
    run("apt update")
    run("apt install -y apache2 gedit mysql-server php libapache2-mod-php php-mysql")
    run("systemctl enable apache2")
    run("systemctl start apache2")
    run("systemctl enable mysql")
    run("systemctl start mysql")

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
        encrypted_pwd = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
        run("getent group ftpusers || groupadd ftpusers")
        run(f"useradd -m -s /bin/bash -p '{encrypted_pwd}' -g ftpusers {username}")

    ftp_dir = f"/home/{username}/ftp/files"
    os.makedirs(ftp_dir, exist_ok=True)
    run(f"chown -R {username}:{username} /home/{username}/ftp")
    run(f"chmod -R 755 /home/{username}/ftp")
    run(f"usermod -s /usr/sbin/nologin {username}")


def main():
    install_lamp()
    secure_mysql()
    install_vsftpd()
    create_ftp_user()

    print("\nSetup completed.")
    print("Apache: http://<your-server-ip>")
    print("MySQL root password: root")
    print("FTP credentials - Username: admin, Password: power")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root (using sudo).")
    else:
        main()
