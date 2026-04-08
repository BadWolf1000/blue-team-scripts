#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Service Watchdog
#
# WHAT THIS SCRIPT DOES:
#   Runs as a background loop every 30 seconds. If any scored
#   service goes down (killed by red team or crash), it
#   automatically restarts it and logs the event.
#   This protects your 50% uptime score.
#
# HOW TO USE:
#   Step 1 - Start it in the background immediately after hardening:
#            sudo bash service_watchdog.sh &
#
#   Step 2 - Confirm it's running:
#            ps aux | grep service_watchdog
#
#   Step 3 - Watch its log in another terminal if you want live output:
#            tail -f /var/log/blueteam_watchdog.log
#
#   Step 4 - It auto-detects which host it's on and monitors the
#            correct services. No config needed.
#
#   Step 5 - Leave it running for the entire competition.
#            Do NOT kill it.
#
# OPTIONAL - Override hostname if auto-detect fails:
#   sudo bash service_watchdog.sh ballast
#   sudo bash service_watchdog.sh silkroad
#   sudo bash service_watchdog.sh poopdeck
#   sudo bash service_watchdog.sh courier
#
# LOG FILE: /var/log/blueteam_watchdog.log
# ============================================================

LOGFILE="/var/log/blueteam_watchdog.log"
INTERVAL=30  # seconds between checks

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

# Auto-detect hostname or accept override
HOSTNAME_LC="${1:-$(hostname | tr '[:upper:]' '[:lower:]')}"
log "Watchdog starting for host: $HOSTNAME_LC"

# ---------- SERVICE MAPS ----------
declare -A SERVICE_MAP   # systemd service name -> human label

case "$HOSTNAME_LC" in
    *ballast*)
        SERVICE_MAP=(
            ["vsftpd"]="FTP"
            ["ssh"]="SSH"
            ["sshd"]="SSH"
            ["vncserver@:1"]="VNC"
            ["x11vnc"]="VNC"
        )
        ;;
    *silkroad*)
        SERVICE_MAP=(
            ["apache2"]="HTTP-SilkRoad"
            ["nginx"]="HTTP-SilkRoad"
            ["mysql"]="MySQL"
            ["ssh"]="SSH"
            ["sshd"]="SSH"
        )
        ;;
    *poopdeck*)
        SERVICE_MAP=(
            ["bind9"]="DNS"
            ["named"]="DNS"
            ["ssh"]="SSH"
            ["sshd"]="SSH"
            ["wikijs"]="HTTP-WikiJS"
            ["wiki.js"]="HTTP-WikiJS"
            ["nginx"]="HTTP-WikiJS"
            ["apache2"]="HTTP-WikiJS"
        )
        ;;
    *courier*)
        SERVICE_MAP=(
            ["postfix"]="SMTP"
            ["dovecot"]="Dovecot"
            ["roundcube"]="HTTP-Roundcube"
            ["apache2"]="HTTP-Roundcube"
            ["nginx"]="HTTP-Roundcube"
            ["ssh"]="SSH"
            ["sshd"]="SSH"
        )
        ;;
    *)
        log "[!] Unknown hostname '$HOSTNAME_LC' - monitoring common services"
        SERVICE_MAP=(
            ["ssh"]="SSH"
            ["sshd"]="SSH"
            ["apache2"]="HTTP"
            ["nginx"]="HTTP"
            ["mysql"]="MySQL"
        )
        ;;
esac

check_and_restart() {
    local svc="$1" label="$2"
    # Skip if unit file doesn't exist
    if ! systemctl list-unit-files "${svc}.service" &>/dev/null && \
       ! systemctl status "$svc" &>/dev/null; then
        return
    fi
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        log "[!] $label ($svc) is DOWN - attempting restart..."
        systemctl restart "$svc" 2>&1 | tee -a "$LOGFILE"
        sleep 3
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            log "[+] $label ($svc) restarted successfully"
        else
            log "[!!] $label ($svc) FAILED to restart - check manually!"
        fi
    fi
}

# ---------- PORT HEALTH CHECK ----------
check_port() {
    local port="$1" proto="${2:-tcp}"
    if command -v ss &>/dev/null; then
        ss -lnp "${proto}" | grep -q ":${port} " && return 0
    elif command -v netstat &>/dev/null; then
        netstat -lnp | grep -q ":${port} " && return 0
    fi
    return 1
}

# ---------- MAIN LOOP ----------
while true; do
    for svc in "${!SERVICE_MAP[@]}"; do
        check_and_restart "$svc" "${SERVICE_MAP[$svc]}"
    done

    # Also check elastic-agent - don't restart if stopped, just warn
    if ! systemctl is-active --quiet elastic-agent 2>/dev/null; then
        log "[!!] elastic-agent is not running (do NOT remove it)"
    fi

    sleep "$INTERVAL"
done
