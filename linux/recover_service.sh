#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Service Recovery "Panic Button"
#
# WHAT THIS SCRIPT DOES:
#   One command that restarts all scored services on this host.
#   Auto-detects which host it's on and knows which services
#   to restart. Also checks config files for corruption before
#   restarting (red team sometimes tampers with configs so the
#   service won't start). If a backup config exists, it restores it.
#
# HOW TO USE:
#   --- PANIC: Red team killed everything, restart it all ---
#   sudo bash recover_service.sh all
#
#   --- Only one service is down ---
#   sudo bash recover_service.sh ssh        # SSH is down
#   sudo bash recover_service.sh web        # Web server is down
#   sudo bash recover_service.sh db         # MySQL is down
#   sudo bash recover_service.sh ftp        # FTP is down (Ballast)
#   sudo bash recover_service.sh dns        # DNS is down (PoopDeck)
#   sudo bash recover_service.sh smtp       # SMTP is down (Courier)
#
#   --- Restart a specific service by name ---
#   sudo bash recover_service.sh nginx
#   sudo bash recover_service.sh vsftpd
#   sudo bash recover_service.sh bind9
#
# AFTER RUNNING:
#   Step 1 - Check services came back up:
#            systemctl status <service_name>
#   Step 2 - Verify from network perspective:
#            bash network_audit.sh <team_number>
#   Step 3 - If a service still won't start, check its logs:
#            journalctl -u <service_name> -n 50
#
# WHEN TO USE:
#   - Service watchdog failed to restart something
#   - Red team wiped a config file
#   - You accidentally broke something during hardening
#
# LOG FILE: /var/log/blueteam_ir/recovery.log
# ============================================================

TARGET="${1:-all}"
LOG="/var/log/blueteam_ir/recovery.log"
mkdir -p "$(dirname "$LOG")"

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] $*" | tee -a "$LOG"; }

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; NC='\033[0m'

HOSTNAME_LC=$(hostname | tr '[:upper:]' '[:lower:]')
log "=== Recovery started on $(hostname) - target: $TARGET ==="

restart_svc() {
    local name="$1" label="${2:-$1}"
    log "[*] Restarting $label..."
    # Try multiple service name variants
    for svc_name in "$name" "${name}d" "apache2" "httpd"; do
        if systemctl list-unit-files "${svc_name}.service" &>/dev/null 2>&1 || \
           systemctl status "$svc_name" &>/dev/null 2>/dev/null; then
            systemctl restart "$svc_name" 2>/dev/null && {
                sleep 2
                if systemctl is-active --quiet "$svc_name" 2>/dev/null; then
                    echo -e "${GRN}[+] $label is UP${NC}" | tee -a "$LOG"
                    return 0
                fi
            }
        fi
    done
    echo -e "${RED}[!!] $label FAILED to restart${NC}" | tee -a "$LOG"
    return 1
}

check_config() {
    # Verify config files haven't been wiped/corrupted
    local conf="$1" service_name="$2"
    if [[ ! -s "$conf" ]]; then
        echo -e "${RED}[!!] Config file is empty/missing: $conf${NC}" | tee -a "$LOG"
        return 1
    fi
    return 0
}

# ============================================================
# SSH RECOVERY (common to all Linux hosts)
# ============================================================
recover_ssh() {
    log "[SSH] Checking SSH..."
    # Make sure config is intact
    if ! sshd -t &>/dev/null; then
        log "[!] SSH config is broken - restoring backup..."
        BACKUP=$(ls /etc/ssh/sshd_config.bak.* 2>/dev/null | sort | tail -1)
        if [[ -n "$BACKUP" ]]; then
            cp "$BACKUP" /etc/ssh/sshd_config
            log "[+] Restored SSH config from $BACKUP"
        else
            log "[!] No backup found - using minimal safe config"
            cat > /etc/ssh/sshd_config << 'SSHEOF'
Port 22
PermitRootLogin no
PasswordAuthentication yes
MaxAuthTries 3
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
SSHEOF
        fi
    fi
    restart_svc "ssh" "SSH" || restart_svc "sshd" "SSH"
}

# ============================================================
# HOST-SPECIFIC RECOVERY FUNCTIONS
# ============================================================

recover_ballast() {
    log "=== Ballast recovery ==="
    recover_ssh

    log "[FTP] Checking vsftpd config..."
    if [[ ! -f /etc/vsftpd.conf ]] || ! check_config /etc/vsftpd.conf "FTP"; then
        cat > /etc/vsftpd.conf << 'FTPEOF'
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
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
FTPEOF
        log "[+] Restored default vsftpd.conf"
    fi
    restart_svc "vsftpd" "FTP"

    log "[VNC] Checking VNC..."
    # Try common VNC services
    for vnc_svc in "vncserver@:1" "x11vnc" "tightvncserver" "tigervnc"; do
        systemctl is-active --quiet "$vnc_svc" 2>/dev/null && break
        systemctl start "$vnc_svc" 2>/dev/null && log "[+] VNC started ($vnc_svc)" && break
    done
}

recover_silkroad() {
    log "=== SilkRoad recovery ==="
    recover_ssh

    log "[WEB] Checking web service..."
    # Try nginx first, then apache
    if systemctl list-unit-files "nginx.service" &>/dev/null; then
        nginx -t &>/dev/null && restart_svc "nginx" "Nginx/HTTP-SilkRoad" || {
            log "[!] Nginx config broken - checking..."
            nginx -t 2>&1 | tee -a "$LOG"
        }
    else
        apache2ctl configtest &>/dev/null && restart_svc "apache2" "Apache/HTTP-SilkRoad" || {
            log "[!] Apache config broken"
            apache2ctl configtest 2>&1 | tee -a "$LOG"
        }
    fi

    log "[DB] Checking MySQL..."
    if ! systemctl is-active --quiet mysql 2>/dev/null; then
        restart_svc "mysql" "MySQL"
        sleep 3
        if ! systemctl is-active --quiet mysql 2>/dev/null; then
            log "[!] MySQL won't start - checking logs..."
            tail -20 /var/log/mysql/error.log 2>/dev/null | tee -a "$LOG"
        fi
    else
        log "[+] MySQL already running"
    fi
}

recover_poopdeck() {
    log "=== PoopDeck recovery ==="
    recover_ssh

    log "[DNS] Checking DNS (bind9/named)..."
    # Check named config
    named-checkconf /etc/bind/named.conf 2>/dev/null || named-checkconf /etc/named.conf 2>/dev/null
    if [[ $? -ne 0 ]]; then
        log "[!] DNS config has errors"
        named-checkconf 2>&1 | tee -a "$LOG"
    else
        restart_svc "bind9" "DNS" || restart_svc "named" "DNS"
    fi

    log "[WEB] Checking WikiJS..."
    restart_svc "wikijs" "WikiJS" || \
    restart_svc "wiki.js" "WikiJS" || \
    restart_svc "nginx" "Nginx" || \
    restart_svc "apache2" "Apache"
}

recover_courier() {
    log "=== Courier recovery ==="
    recover_ssh

    log "[SMTP] Checking Postfix..."
    postfix check &>/dev/null && restart_svc "postfix" "SMTP/Postfix" || {
        log "[!] Postfix config error:"
        postfix check 2>&1 | tee -a "$LOG"
    }

    log "[IMAP] Checking Dovecot..."
    doveconf -n &>/dev/null && restart_svc "dovecot" "Dovecot/IMAP" || {
        log "[!] Dovecot config error"
    }

    log "[WEB] Checking Roundcube..."
    restart_svc "apache2" "Apache/Roundcube" || restart_svc "nginx" "Nginx/Roundcube"
}

# ============================================================
# MAIN DISPATCH
# ============================================================
case "$TARGET" in
    all)
        case "$HOSTNAME_LC" in
            *ballast*)   recover_ballast ;;
            *silkroad*)  recover_silkroad ;;
            *poopdeck*)  recover_poopdeck ;;
            *courier*)   recover_courier ;;
            *)
                log "[!] Unknown host - attempting generic recovery"
                recover_ssh
                for svc in apache2 nginx mysql bind9 named postfix vsftpd; do
                    systemctl is-active --quiet "$svc" 2>/dev/null || \
                        restart_svc "$svc" "$svc" 2>/dev/null
                done
                ;;
        esac
        ;;
    ssh)    recover_ssh ;;
    web)
        restart_svc "nginx" "Nginx" || restart_svc "apache2" "Apache"
        ;;
    db|mysql)
        restart_svc "mysql" "MySQL" || restart_svc "mysqld" "MySQL"
        ;;
    ftp)    restart_svc "vsftpd" "FTP" ;;
    dns)    restart_svc "bind9" "DNS" || restart_svc "named" "DNS" ;;
    smtp)   restart_svc "postfix" "SMTP" ;;
    *)
        restart_svc "$TARGET" "$TARGET"
        ;;
esac

log "=== Recovery complete ==="
echo ""
echo "============================================"
echo "[+] Recovery complete. Check service status:"
echo "    systemctl status <service>"
echo "    bash status_dashboard.sh"
echo "============================================"
