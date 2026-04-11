#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Live Service Status Dashboard
#
# WHAT THIS SCRIPT DOES:
#   Checks all 19 scored services across all 6 hosts and displays
#   a color-coded table: GREEN = up, RED = down.
#   Also shows your estimated uptime score percentage.
#   Does real service checks (not just ping) - tests FTP banners,
#   HTTP responses, SSH banners, DNS queries, etc.
#
# IMPORTANT SETUP - Before using, update the IPs:
#   Open this file and find the SERVICES section (~line 60).
#   Replace the 'x' in all IPs (10.x.2.12, etc.) with your team number.
#   Example: if your team is team 3, change 10.x.2.12 to 10.3.2.12
#
# HOW TO USE:
#   --- One-time check of all services ---
#   bash status_dashboard.sh
#
#   --- Live dashboard that refreshes every 15 seconds ---
#   bash status_dashboard.sh --loop
#   (Press Ctrl+C to exit)
#
#   --- Easier: use network_audit.sh with your team number ---
#   bash network_audit.sh 3    (replace 3 with your team number)
#   This automatically fills in the correct IPs.
#
# WHEN TO USE:
#   - Keep this running in a terminal during the competition
#     so you always know your uptime score status
#   - Run immediately after service_watchdog.sh to confirm
#     all services came up correctly
#   - Run after any red team attack to see what they knocked down
#
# CAN BE RUN FROM: Any Linux machine that has network access to all hosts
# ============================================================

LOOP=false
USE_SSH=false
for arg in "$@"; do
    [[ "$arg" == "--loop" ]] && LOOP=true
    [[ "$arg" == "--ssh"  ]] && USE_SSH=true
done

# ---------- COLORS ----------
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
BLU='\033[1;34m'
CYN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

UP="${GRN}[  UP  ]${NC}"
DOWN="${RED}[ DOWN ]${NC}"
UNKN="${YEL}[  ??  ]${NC}"

# ============================================================
# HOST/SERVICE DEFINITIONS (update x in IPs to match your team)
# ============================================================
# Format: "hostname|ip|port|protocol|service_label|scored"
# scored: Y = scored, N = not scored (still shown)

SERVICES=(
    "Ballast|10.x.2.12|21|tcp|FTP|Y"
    "Ballast|10.x.2.12|22|tcp|SSH|Y"
    "Ballast|10.x.2.12|5900|tcp|VNC|Y"
    "BlackPearl|10.x.1.10|389|tcp|LDAP|Y"
    "BlackPearl|10.x.1.10|3389|tcp|RDP|Y"
    "BlackPearl|10.x.1.10|445|tcp|SMB|Y"
    "BlackPearl|10.x.1.10|5985|tcp|WinRM|Y"
    "Courier|10.x.3.12|80|tcp|HTTP-Roundcube|Y"
    "Courier|10.x.3.12|25|tcp|SMTP|Y"
    "Courier|10.x.3.12|22|tcp|SSH|Y"
    "Courier|10.x.3.12|143|tcp|Dovecot-IMAP|N"
    "JollyRoger|10.x.2.11|3389|tcp|RDP|Y"
    "JollyRoger|10.x.2.11|5985|tcp|WinRM|Y"
    "PoopDeck|10.x.1.11|53|tcp|DNS|Y"
    "PoopDeck|10.x.1.11|80|tcp|HTTP-WikiJS|Y"
    "PoopDeck|10.x.1.11|22|tcp|SSH|Y"
    "SilkRoad|10.x.2.10|80|tcp|HTTP-SilkRoad|Y"
    "SilkRoad|10.x.2.10|3306|tcp|MySQL|Y"
    "SilkRoad|10.x.2.10|22|tcp|SSH|Y"
)

TIMEOUT=2  # seconds per check

check_port() {
    local ip="$1" port="$2"
    timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
    return $?
}

check_http() {
    local ip="$1" port="$2"
    curl -s --connect-timeout "$TIMEOUT" --max-time "$((TIMEOUT+1))" \
        -o /dev/null -w "%{http_code}" "http://$ip:$port/" 2>/dev/null | grep -qE '^[23]'
}

check_ftp() {
    local ip="$1"
    timeout "$TIMEOUT" bash -c "echo QUIT | nc -w$TIMEOUT $ip 21 2>/dev/null | grep -q '220'"
}

check_smtp() {
    local ip="$1"
    timeout "$TIMEOUT" bash -c "echo QUIT | nc -w$TIMEOUT $ip 25 2>/dev/null | grep -q '220'"
}

check_ssh_banner() {
    local ip="$1"
    timeout "$TIMEOUT" bash -c "nc -w$TIMEOUT $ip 22 2>/dev/null | grep -q 'SSH'"
}

check_dns() {
    local ip="$1"
    # Try a DNS query to the server
    if command -v dig &>/dev/null; then
        timeout "$TIMEOUT" dig @"$ip" google.com +time=2 +tries=1 &>/dev/null
    elif command -v nslookup &>/dev/null; then
        timeout "$TIMEOUT" nslookup google.com "$ip" &>/dev/null
    else
        check_port "$ip" 53
    fi
}

check_mysql() {
    local ip="$1"
    timeout "$TIMEOUT" bash -c "echo '' | nc -w$TIMEOUT $ip 3306 2>/dev/null | grep -q 'mysql\|MariaDB\|J'" 2>/dev/null
}

do_check() {
    local hostname="$1" ip="$2" port="$3" proto="$4" label="$5"
    local result=0

    case "$label" in
        HTTP*|HTTP-*)  check_http "$ip" "$port" && result=0 || result=1 ;;
        FTP)           check_ftp "$ip" && result=0 || result=1 ;;
        SMTP)          check_smtp "$ip" && result=0 || result=1 ;;
        SSH)           check_ssh_banner "$ip" && result=0 || result=1 ;;
        DNS)           check_dns "$ip" && result=0 || result=1 ;;
        MySQL)         check_mysql "$ip" && result=0 || result=1 ;;
        *)             check_port "$ip" "$port" && result=0 || result=1 ;;
    esac
    return $result
}

draw_dashboard() {
    clear
    echo -e "${BOLD}${BLU}"
    echo "  ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗"
    echo "  ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║"
    echo "  ██║  ██║██████╔╝█████╗  ███████║██║  ██║██║ █╗ ██║███████║   ██║   ██║     ███████║"
    echo "  ██║  ██║██╔══██╗██╔══╝  ██╔══██║██║  ██║██║███╗██║██╔══██║   ██║   ██║     ██╔══██║"
    echo "  ██████╔╝██║  ██║███████╗██║  ██║██████╔╝╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║"
    echo "  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝  ╚═╝    ╚═════╝╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}DREADWATCH SERVICE STATUS DASHBOARD${NC}    $(date '+%H:%M:%S')    (Ctrl+C to exit)"
    echo ""
    printf "  %-14s %-14s %-6s %-20s %-8s %s\n" "HOST" "IP" "PORT" "SERVICE" "SCORED" "STATUS"
    echo "  ──────────────────────────────────────────────────────────────────────"

    TOTAL_SCORED=0
    TOTAL_UP=0
    CURRENT_HOST=""

    for entry in "${SERVICES[@]}"; do
        IFS='|' read -r hostname ip port proto label scored <<< "$entry"

        # Print host separator
        if [[ "$hostname" != "$CURRENT_HOST" ]]; then
            [[ -n "$CURRENT_HOST" ]] && echo ""
            CURRENT_HOST="$hostname"
        fi

        # Run check
        if do_check "$hostname" "$ip" "$port" "$proto" "$label"; then
            status="$UP"
            [[ "$scored" == "Y" ]] && ((TOTAL_UP++))
        else
            status="$DOWN"
        fi

        [[ "$scored" == "Y" ]] && ((TOTAL_SCORED++))
        scored_label=$([ "$scored" == "Y" ] && echo "${GRN}SCORED${NC}" || echo "${YEL}  --  ${NC}")

        printf "  %-14s %-14s %-6s %-20s " "$hostname" "$ip" "$port" "$label"
        echo -e "$scored_label  $status"
    done

    echo ""
    echo "  ──────────────────────────────────────────────────────────────────────"
    SCORE_PCT=$(( TOTAL_UP * 100 / TOTAL_SCORED ))
    if [[ $SCORE_PCT -ge 80 ]]; then
        SCORE_COLOR=$GRN
    elif [[ $SCORE_PCT -ge 50 ]]; then
        SCORE_COLOR=$YEL
    else
        SCORE_COLOR=$RED
    fi
    echo -e "  ${BOLD}Scored Services Up: ${SCORE_COLOR}${TOTAL_UP}/${TOTAL_SCORED} (${SCORE_PCT}%)${NC}"
    echo ""
    $LOOP && echo -e "  ${CYN}Auto-refreshing every 15s...${NC}" || echo -e "  ${CYN}Run with --loop to auto-refresh${NC}"
}

if $LOOP; then
    while true; do
        draw_dashboard
        sleep 15
    done
else
    draw_dashboard
fi
