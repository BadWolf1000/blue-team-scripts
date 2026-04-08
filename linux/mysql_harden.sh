#!/bin/bash
# ============================================================
# DreadWatch Blue Team - MySQL Hardening Script
# Target: SilkRoad (Ubuntu 18, 10.x.2.10)
# Scored service: MySQL (port 3306)
#
# WHAT THIS SCRIPT DOES:
#   MySQL ships with several insecure defaults that red team
#   exploits immediately. This script locks it all down while
#   keeping the scored service running and responding.
#   Actions taken:
#     1. Removes anonymous accounts (allow login with no password)
#     2. Drops the 'test' database (world-readable by default)
#     3. Removes remote root login (root should only connect locally)
#     4. Changes root password to something strong
#     5. Audits and lets you change application user passwords
#     6. Optionally binds MySQL to localhost only
#     7. Disables LOAD DATA INFILE (used to read system files)
#     8. Enables query logging so you can see what attackers ran
#
# HOW TO USE:
#   Step 1 - Run ONLY on SilkRoad (the host with MySQL):
#            sudo bash mysql_harden.sh
#
#   Step 2 - The script will ask for the current MySQL root password.
#            At the start of the competition it's likely blank - just press Enter.
#
#   Step 3 - It will ask you to set a new root password.
#            Choose something strong and WRITE IT DOWN.
#            If you lose it you'll be locked out.
#
#   Step 4 - For each application database user found, it will ask
#            if you want to change that password too. Say yes.
#
#   Step 5 - When asked about binding to localhost:
#            Say YES if the web app (SilkRoad) runs on the SAME machine.
#            Say NO if the web app connects to MySQL from a different IP.
#
#   Step 6 - Verify MySQL is still running after hardening:
#            systemctl status mysql
#            mysql -u root -p  (test login with new password)
#
# WARNING: Do NOT run this on any host other than SilkRoad.
# ============================================================
# ============================================================

set -euo pipefail

LOGFILE="/var/log/blueteam_mysql_harden.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "=== MySQL Hardening - $(date) ==="

# ---------- CHECK MYSQL IS RUNNING ----------
if ! systemctl is-active --quiet mysql 2>/dev/null && \
   ! systemctl is-active --quiet mysqld 2>/dev/null; then
    echo "[!] MySQL is not running. Starting..."
    systemctl start mysql 2>/dev/null || systemctl start mysqld 2>/dev/null
fi

# ---------- PROMPT FOR ROOT PASSWORD ----------
echo "[*] Enter current MySQL root password (blank if none):"
read -rs MYSQL_ROOT_PASS
echo ""

if [[ -z "$MYSQL_ROOT_PASS" ]]; then
    MYSQL_CMD="mysql -u root"
else
    MYSQL_CMD="mysql -u root -p${MYSQL_ROOT_PASS}"
fi

# Test connection
if ! $MYSQL_CMD -e "SELECT 1;" &>/dev/null; then
    echo "[!] Cannot connect to MySQL. Check root password."
    echo "[*] Trying with sudo mysql..."
    MYSQL_CMD="sudo mysql"
    if ! $MYSQL_CMD -e "SELECT 1;" &>/dev/null; then
        echo "[!!] Cannot connect to MySQL at all. Exiting."
        exit 1
    fi
fi
echo "[+] MySQL connection successful"

NEW_ROOT_PASS="DreadMysql@2024!"
echo "[*] Set a new MySQL root password (leave blank to use default: $NEW_ROOT_PASS):"
read -rs USER_ROOT_PASS
echo ""
[[ -n "$USER_ROOT_PASS" ]] && NEW_ROOT_PASS="$USER_ROOT_PASS"

# ============================================================
# 1. AUDIT CURRENT USERS BEFORE CHANGES
# ============================================================
echo "[1] Current MySQL users:"
$MYSQL_CMD -e "SELECT user, host, authentication_string != '' AS has_password, account_locked FROM mysql.user;" 2>/dev/null

# ============================================================
# 2. REMOVE ANONYMOUS ACCOUNTS
# ============================================================
echo "[2] Removing anonymous accounts..."
$MYSQL_CMD -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null && \
    echo "[+] Anonymous accounts removed"

# ============================================================
# 3. REMOVE TEST DATABASE
# ============================================================
echo "[3] Removing test database..."
$MYSQL_CMD -e "DROP DATABASE IF EXISTS test;" 2>/dev/null && \
    echo "[+] Test database removed"
$MYSQL_CMD -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null

# ============================================================
# 4. DISABLE REMOTE ROOT LOGIN
# ============================================================
echo "[4] Restricting root to localhost only..."
$MYSQL_CMD -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" 2>/dev/null && \
    echo "[+] Remote root login disabled"

# ============================================================
# 5. CHANGE ROOT PASSWORD
# ============================================================
echo "[5] Changing root password..."
# MySQL 5.7+ / 8.0 syntax
$MYSQL_CMD -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${NEW_ROOT_PASS}';" 2>/dev/null || \
$MYSQL_CMD -e "UPDATE mysql.user SET authentication_string=PASSWORD('${NEW_ROOT_PASS}') WHERE User='root';" 2>/dev/null
echo "[+] Root password changed"
MYSQL_CMD="mysql -u root -p${NEW_ROOT_PASS}"

# ============================================================
# 6. AUDIT AND LOCK APPLICATION USERS
# ============================================================
echo "[6] Auditing application database users..."
$MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE User NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema');" 2>/dev/null | while read -r user host; do
    [[ "$user" == "user" ]] && continue  # skip header
    echo "[*] Found app user: $user@$host"
    echo "[*] Enter new password for $user (blank to skip):"
    read -rs app_pass
    echo ""
    if [[ -n "$app_pass" ]]; then
        $MYSQL_CMD -e "ALTER USER '$user'@'$host' IDENTIFIED BY '${app_pass}';" 2>/dev/null && \
            echo "[+] Password changed for $user"
    fi
    # Show what privileges this user has
    echo "[*] Privileges for $user@$host:"
    $MYSQL_CMD -e "SHOW GRANTS FOR '$user'@'$host';" 2>/dev/null | sed 's/^/    /'
done

# ============================================================
# 7. RESTRICT MYSQL TO LOCALHOST (if remote access not needed)
# ============================================================
echo "[7] Checking MySQL bind address..."
MYSQL_CONF=""
for f in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf /etc/my.cnf; do
    [[ -f "$f" ]] && MYSQL_CONF="$f" && break
done

if [[ -n "$MYSQL_CONF" ]]; then
    cp "$MYSQL_CONF" "${MYSQL_CONF}.bak.$(date +%s)"
    if grep -q "bind-address" "$MYSQL_CONF"; then
        # Check if scoring requires remote access - if MySQL is only accessed locally, bind to 127.0.0.1
        echo "[*] Current bind-address:"
        grep "bind-address" "$MYSQL_CONF"
        echo "[*] Restrict MySQL to localhost only? (say NO if SilkRoad app needs remote DB access) [y/N]:"
        read -r bind_ans
        if [[ "$bind_ans" =~ ^[Yy]$ ]]; then
            sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$MYSQL_CONF"
            echo "[+] MySQL bound to 127.0.0.1"
        fi
    else
        echo "bind-address = 127.0.0.1" >> "$MYSQL_CONF"
        echo "[+] bind-address set to 127.0.0.1"
    fi
fi

# ============================================================
# 8. DISABLE LOAD DATA INFILE (file read exploit)
# ============================================================
echo "[8] Disabling LOAD DATA INFILE..."
if [[ -n "$MYSQL_CONF" ]]; then
    if ! grep -q "local-infile" "$MYSQL_CONF"; then
        echo "" >> "$MYSQL_CONF"
        echo "[mysqld]" >> "$MYSQL_CONF"
        echo "local-infile = 0" >> "$MYSQL_CONF"
        echo "[+] local-infile disabled in config"
    fi
fi
$MYSQL_CMD -e "SET GLOBAL local_infile = 0;" 2>/dev/null && echo "[+] local_infile disabled globally"

# ============================================================
# 9. ENABLE QUERY LOGGING (for IR evidence)
# ============================================================
echo "[9] Enabling general query log for IR evidence..."
$MYSQL_CMD -e "SET GLOBAL general_log = 'ON';" 2>/dev/null
$MYSQL_CMD -e "SET GLOBAL general_log_file = '/var/log/mysql/mysql_queries.log';" 2>/dev/null
echo "[+] Query logging enabled -> /var/log/mysql/mysql_queries.log"

# ============================================================
# 10. FLUSH PRIVILEGES AND VERIFY
# ============================================================
echo "[10] Flushing privileges..."
$MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null

echo ""
echo "=== Final user list ==="
$MYSQL_CMD -e "SELECT user, host FROM mysql.user;" 2>/dev/null

# ============================================================
# 11. RESTART AND VERIFY SERVICE IS STILL UP
# ============================================================
echo "[11] Restarting MySQL..."
systemctl restart mysql 2>/dev/null || systemctl restart mysqld 2>/dev/null
sleep 3
if systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mysqld 2>/dev/null; then
    echo "[+] MySQL is running - scored service intact"
else
    echo "[!!] MySQL failed to restart! Check config."
    systemctl status mysql 2>/dev/null || systemctl status mysqld 2>/dev/null
fi

echo ""
echo "================================================"
echo "[+] MySQL hardening complete"
echo "[!] New root password: $NEW_ROOT_PASS"
echo "[!] WRITE THIS DOWN - you will need it"
echo "Log: $LOGFILE"
echo "================================================"
