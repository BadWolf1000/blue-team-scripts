#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Linux Hardening Script
# Targets: Ubuntu 18/20 (Ballast, SilkRoad), Debian 10 (PoopDeck), Fedora 31 (Courier)
#
# WHAT THIS SCRIPT DOES:
#   1. Changes ALL known competition account passwords
#   2. Locks any user accounts not in the known list
#   3. Hardens SSH config (disables root login, limits auth tries)
#   4. Sets up firewall rules specific to this host's scored services
#   5. Removes suspicious cron jobs
#   6. Lists SUID binaries for manual review
#   7. Audits sudoers file
#   8. Applies kernel-level network hardening (sysctl)
#   9. Disables legacy dangerous services (telnet, rsh, etc.)
#  10. Verifies elastic-agent is still running (don't remove it!)
#
# HOW TO USE:
#   Step 1 - Pull from GitHub (do this first on every Linux box):
#            git clone https://github.com/BadWolf1000/blue-team-scripts.git /opt/bt
#            cd /opt/bt/linux && chmod +x *.sh
#
#   Step 2 - BEFORE running, set your team's password at the top of this file.
#            Open the script and change: NEW_PASS="DreadWatch@2024!"
#            to something your team decides. Write it down!
#
#   Step 3 - Run it:
#            sudo bash harden_linux.sh
#
#   Step 4 - Review the output. Look for any [!] warnings.
#            The script logs everything to $HOME/Desktop/blueteam_logs/harden_<timestamp>.log
#
#   Step 5 - Manually review the SUID file list printed at the end.
#            Remove any SUID binaries that shouldn't be there.
#
#   Step 6 - Run this on EVERY Linux box during the first 30 minutes.
#            Order: Ballast -> SilkRoad -> PoopDeck -> Courier
#
# SAFE TO RE-RUN: Yes. Running it again will re-apply all settings.
#
# HOSTS:
#   Ballast   - Ubuntu 20  - 10.x.2.12 - FTP, SSH, VNC
#   SilkRoad  - Ubuntu 18  - 10.x.2.10 - HTTP, MySQL, SSH
#   PoopDeck  - Debian 10  - 10.x.1.11 - DNS, HTTP-WikiJS, SSH
#   Courier   - Fedora 31  - 10.x.3.12 - HTTP-Roundcube, SMTP, SSH
# ============================================================

set -euo pipefail

# ---------- DETECT OS / PACKAGE MANAGER ----------
if command -v apt-get &>/dev/null; then
    PKG="apt-get"
    DISTRO="debian"
elif command -v dnf &>/dev/null; then
    PKG="dnf"
    DISTRO="fedora"
else
    echo "[!] Unknown package manager. Exiting."; exit 1
fi

echo "[*] Running on $DISTRO-based system"
LOGFILE="$HOME/Desktop/blueteam_logs/harden_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

# ============================================================
# 1. CHANGE ALL KNOWN ACCOUNT PASSWORDS
# ============================================================
echo "[*] Changing all known account passwords..."

NEW_PASS="DreadWatch@2024!"   # Change this before competition!

KNOWN_USERS=(
    "SaltyDog23" "PlunderMate56" "RumRider12" "GoldTooth89"
    "HighTide74" "SeaScourge30" "ParrotJack67" "CannonDeck45"
    "BarnacleBill98" "StormBringer09"
    "AdmiralNelson" "quartermaster" "skulllord" "dreadpirate" "blackflag"
)

for user in "${KNOWN_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        echo "$user:$NEW_PASS" | chpasswd
        echo "[+] Password changed: $user"
    fi
done

# Also change root password
echo "root:$NEW_PASS" | chpasswd
echo "[+] Root password changed"

# ============================================================
# 2. LOCK ACCOUNTS NOT NEEDED ON THIS HOST
# ============================================================
echo "[*] Locking suspicious accounts..."
# Lock any non-system account that isn't in our known list
KNOWN_SET=" ${KNOWN_USERS[*]} root "
while IFS=: read -r uname _ uid _ _ _ shell; do
    # Only check UID 1000+ (regular users) with login shells
    if [[ "$uid" -ge 1000 && "$shell" != "/sbin/nologin" && "$shell" != "/bin/false" ]]; then
        if [[ ! "$KNOWN_SET" =~ " $uname " ]]; then
            usermod -L "$uname" 2>/dev/null && echo "[!] Locked unexpected account: $uname"
        fi
    fi
done < /etc/passwd

# ============================================================
# 3. SSH HARDENING
# ============================================================
echo "[*] Hardening SSH..."
SSHD_CONF="/etc/ssh/sshd_config"

# Backup first
cp "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%s)"

apply_ssh_setting() {
    local key="$1" val="$2"
    if grep -qE "^#?${key}" "$SSHD_CONF"; then
        sed -i "s|^#\?${key}.*|${key} ${val}|" "$SSHD_CONF"
    else
        echo "${key} ${val}" >> "$SSHD_CONF"
    fi
}

apply_ssh_setting "PermitRootLogin"        "no"
apply_ssh_setting "PasswordAuthentication" "yes"    # Keep yes - scoring engine needs it
apply_ssh_setting "MaxAuthTries"           "3"
apply_ssh_setting "LoginGraceTime"         "30"
apply_ssh_setting "X11Forwarding"          "no"
apply_ssh_setting "AllowTcpForwarding"     "no"
apply_ssh_setting "ClientAliveInterval"    "300"
apply_ssh_setting "ClientAliveCountMax"    "2"
apply_ssh_setting "PermitEmptyPasswords"   "no"
apply_ssh_setting "Protocol"               "2"

systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
echo "[+] SSH hardened and restarted"

# ============================================================
# 4. FIREWALL RULES (UFW for Debian/Ubuntu, firewalld for Fedora)
# ============================================================
echo "[*] Configuring firewall..."

# Detect hostname to apply correct port rules
HOSTNAME_LC=$(hostname | tr '[:upper:]' '[:lower:]')

setup_ufw() {
    if ! command -v ufw &>/dev/null; then
        apt-get install -y ufw
    fi
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    # Always allow SSH
    ufw allow 22/tcp comment 'SSH scored'
    # Host-specific rules
    case "$HOSTNAME_LC" in
        *ballast*)
            ufw allow 21/tcp comment 'FTP scored'
            ufw allow 5900/tcp comment 'VNC scored'
            ufw allow 20/tcp comment 'FTP data'
            ;;
        *silkroad*)
            ufw allow 80/tcp comment 'HTTP-SilkRoad scored'
            ufw allow 443/tcp comment 'HTTPS'
            ufw allow 3306/tcp comment 'MySQL scored'
            ;;
        *poopdeck*)
            ufw allow 53/tcp comment 'DNS scored'
            ufw allow 53/udp comment 'DNS UDP'
            ufw allow 80/tcp comment 'HTTP-WikiJS scored'
            ufw allow 443/tcp comment 'HTTPS'
            ;;
        *courier*)
            ufw allow 80/tcp comment 'HTTP-Roundcube scored'
            ufw allow 25/tcp comment 'SMTP scored'
            ufw allow 587/tcp comment 'SMTP submission'
            ufw allow 143/tcp comment 'Dovecot IMAP'
            ufw allow 993/tcp comment 'IMAP SSL'
            ;;
    esac
    ufw --force enable
    echo "[+] UFW configured"
}

setup_firewalld() {
    systemctl enable firewalld
    systemctl start firewalld
    # Set default to drop
    firewall-cmd --set-default-zone=drop
    # SSH
    firewall-cmd --permanent --zone=drop --add-port=22/tcp
    # Courier-specific
    firewall-cmd --permanent --zone=drop --add-port=80/tcp
    firewall-cmd --permanent --zone=drop --add-port=25/tcp
    firewall-cmd --permanent --zone=drop --add-port=587/tcp
    firewall-cmd --permanent --zone=drop --add-port=143/tcp
    firewall-cmd --permanent --zone=drop --add-port=993/tcp
    firewall-cmd --reload
    echo "[+] firewalld configured"
}

if [[ "$DISTRO" == "debian" ]]; then
    setup_ufw
elif [[ "$DISTRO" == "fedora" ]]; then
    setup_firewalld
fi

# ============================================================
# 5. REMOVE UNAUTHORIZED CRON JOBS
# ============================================================
echo "[*] Auditing cron jobs..."
for user in $(cut -d: -f1 /etc/passwd); do
    CRON=$(crontab -l -u "$user" 2>/dev/null || true)
    if [[ -n "$CRON" ]]; then
        echo "[!] Cron found for $user:"
        echo "$CRON"
        # Uncomment next line to auto-clear suspicious users' crons:
        # crontab -r -u "$user" 2>/dev/null
    fi
done

# Check /etc/cron* for unexpected files
echo "[*] /etc/cron.d contents:"
ls -la /etc/cron.d/ 2>/dev/null

# ============================================================
# 6. CHECK FOR SUSPICIOUS SUID/SGID BINARIES
# ============================================================
echo "[*] Checking SUID binaries (review manually)..."
find / -perm /4000 -type f 2>/dev/null | grep -v -E '^/(proc|sys|run)' | tee /tmp/suid_files.txt
echo "[*] SUID list saved to /tmp/suid_files.txt"

# ============================================================
# 7. AUDIT SUDOERS
# ============================================================
echo "[*] Current sudoers:"
cat /etc/sudoers
echo "[*] /etc/sudoers.d:"
ls -la /etc/sudoers.d/ 2>/dev/null

# ============================================================
# 8. SECURE /tmp AND /var/tmp
# ============================================================
echo "[*] Securing temp directories..."
chmod 1777 /tmp /var/tmp

# ============================================================
# 9. DISABLE UNNECESSARY SERVICES
# ============================================================
echo "[*] Disabling risky services..."
DANGEROUS_SERVICES=("telnet" "rsh" "rlogin" "rexec" "finger" "tftp")
for svc in "${DANGEROUS_SERVICES[@]}"; do
    systemctl stop "$svc" 2>/dev/null && systemctl disable "$svc" 2>/dev/null && echo "[+] Disabled: $svc" || true
done

# ============================================================
# 10. KERNEL HARDENING VIA SYSCTL
# ============================================================
echo "[*] Applying kernel hardening..."
cat > /etc/sysctl.d/99-blueteam.conf << 'EOF'
# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
# SYN flood protection
net.ipv4.tcp_syncookies = 1
# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
EOF
sysctl -p /etc/sysctl.d/99-blueteam.conf
echo "[+] Kernel hardening applied"

# ============================================================
# 11. VERIFY elastic-agent IS RUNNING (DO NOT REMOVE)
# ============================================================
echo "[*] Checking elastic-agent..."
if systemctl is-active --quiet elastic-agent 2>/dev/null; then
    echo "[+] elastic-agent is running - leave it alone!"
else
    echo "[!] WARNING: elastic-agent is NOT running"
fi

echo ""
echo "================================================"
echo "[+] Hardening complete. Log: $LOGFILE"
echo "[!] REVIEW CRON JOBS AND SUID FILES MANUALLY"
echo "================================================"
