#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Network Audit / Service Verifier
#
# WHAT THIS SCRIPT DOES:
#   Simulates exactly what the scoring engine does - connects
#   to every scored service on every host and checks if it
#   responds correctly. Shows PASS/FAIL for all 19 services
#   and calculates your estimated uptime score percentage.
#   This is the closest thing to seeing your actual score
#   BEFORE the scoring engine checks.
#
# HOW TO USE:
#   Step 1 - Find your team number. The IPs in the competition
#            look like 10.x.y.z where x is your team number.
#            Ask White Crew if unsure.
#
#   Step 2 - Run it with your team number:
#            bash network_audit.sh 3      (if your IPs are 10.3.x.x)
#            bash network_audit.sh 5      (if your IPs are 10.5.x.x)
#
#   Step 3 - Review the output:
#            [PASS] = Service is up and responding correctly
#            [FAIL] = Service is DOWN - fix this immediately!
#            [WARN] = Port is open but response is unexpected
#
#   Step 4 - Fix any FAIL services:
#            sudo bash recover_service.sh all    (on the affected host)
#            or restart the specific service:
#            ssh user@10.x.y.z "sudo systemctl restart <service>"
#
#   Step 5 - Re-run network_audit.sh to confirm the fix worked.
#
# WHEN TO RUN:
#   - After initial hardening to confirm nothing broke
#   - After a red team attack to see what's still up
#   - Periodically throughout the competition as a health check
#   - Before the scoring engine does its next check
#
# CAN BE RUN FROM: Any Linux machine on the network
# OUTPUT: /var/log/blueteam_ir/network_audit_<timestamp>.log
# ============================================================

# Set your team's subnet prefix (the 'x' in 10.x)
TEAM_PREFIX="${1:-x}"

if [[ "$TEAM_PREFIX" == "x" ]]; then
    echo "[!] WARNING: Using placeholder IPs (10.x.*)"
    echo "    Run: bash network_audit.sh <team_number>"
    echo "    Example: bash network_audit.sh 3   (for 10.3.*)"
    echo ""
fi

LOGDIR="/var/log/blueteam_ir"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/network_audit_$(date +%Y%m%d_%H%M%S).log"

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

pass() { echo -e "  ${GRN}[PASS]${NC} $*" | tee -a "$LOG"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $*" | tee -a "$LOG"; ((FAIL++)); }
warn() { echo -e "  ${YEL}[WARN]${NC} $*" | tee -a "$LOG"; ((WARN++)); }
hdr()  { echo "" | tee -a "$LOG"; echo -e "${BOLD}=== $* ===${NC}" | tee -a "$LOG"; }

TIMEOUT=3

# Replace 'x' with team prefix in IPs
ip() { echo "$1" | sed "s/\.x\./\.${TEAM_PREFIX}\./g"; }

# ============================================================
# PORT CHECK FUNCTIONS
# ============================================================
check_tcp() {
    local label="$1" host="$2" port="$3"
    if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        pass "$label ($host:$port) - TCP port open"
        return 0
    else
        fail "$label ($host:$port) - TCP port NOT responding"
        return 1
    fi
}

check_http() {
    local label="$1" url="$2"
    local code
    code=$(curl -s --connect-timeout "$TIMEOUT" --max-time $((TIMEOUT+2)) \
        -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    if echo "$code" | grep -qE '^[23]'; then
        pass "$label ($url) - HTTP $code"
        return 0
    else
        fail "$label ($url) - HTTP response: $code (expected 2xx/3xx)"
        return 1
    fi
}

check_ssh() {
    local label="$1" host="$2"
    local banner
    banner=$(timeout "$TIMEOUT" bash -c "nc -w$TIMEOUT $host 22 2>/dev/null" | head -1)
    if echo "$banner" | grep -q "SSH"; then
        pass "$label ($host:22) - SSH banner: $banner"
    else
        fail "$label ($host:22) - No SSH banner received"
    fi
}

check_ftp() {
    local label="$1" host="$2"
    local banner
    banner=$(timeout "$TIMEOUT" bash -c "echo QUIT | nc -w$TIMEOUT $host 21 2>/dev/null" | head -1)
    if echo "$banner" | grep -q "220"; then
        pass "$label ($host:21) - FTP banner: $banner"
    else
        fail "$label ($host:21) - No FTP 220 banner (got: $banner)"
    fi
}

check_smtp() {
    local label="$1" host="$2"
    local banner
    banner=$(timeout "$TIMEOUT" bash -c "echo QUIT | nc -w$TIMEOUT $host 25 2>/dev/null" | head -1)
    if echo "$banner" | grep -q "220"; then
        pass "$label ($host:25) - SMTP banner: $banner"
    else
        fail "$label ($host:25) - No SMTP 220 banner (got: $banner)"
    fi
}

check_dns() {
    local label="$1" host="$2"
    if command -v dig &>/dev/null; then
        result=$(timeout "$TIMEOUT" dig @"$host" google.com A +time=2 +tries=1 2>/dev/null)
        if echo "$result" | grep -q "ANSWER"; then
            pass "$label ($host:53) - DNS resolving correctly"
        else
            # Try just the port
            if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$host/53" 2>/dev/null; then
                warn "$label ($host:53) - Port open but DNS query failed"
            else
                fail "$label ($host:53) - DNS port not responding"
            fi
        fi
    else
        check_tcp "$label" "$host" 53
    fi
}

check_mysql() {
    local label="$1" host="$2"
    local banner
    banner=$(timeout "$TIMEOUT" bash -c "echo '' | nc -w$TIMEOUT $host 3306 2>/dev/null | strings | head -1")
    if echo "$banner" | grep -qiE "mysql|mariadb|[0-9]+\.[0-9]+"; then
        pass "$label ($host:3306) - MySQL banner received"
    else
        if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$host/3306" 2>/dev/null; then
            warn "$label ($host:3306) - Port open, unexpected banner: $banner"
        else
            fail "$label ($host:3306) - MySQL port not responding"
        fi
    fi
}

check_ldap() {
    local label="$1" host="$2"
    if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$host/389" 2>/dev/null; then
        pass "$label ($host:389) - LDAP port open"
    else
        fail "$label ($host:389) - LDAP port NOT responding"
    fi
}

check_winrm() {
    local label="$1" host="$2"
    local code
    code=$(curl -s --connect-timeout "$TIMEOUT" --max-time $((TIMEOUT+1)) \
        -o /dev/null -w "%{http_code}" "http://$host:5985/wsman" 2>/dev/null)
    if [[ "$code" == "405" || "$code" == "200" ]]; then
        pass "$label ($host:5985) - WinRM responding (HTTP $code)"
    elif timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$host/5985" 2>/dev/null; then
        warn "$label ($host:5985) - WinRM port open but unexpected response ($code)"
    else
        fail "$label ($host:5985) - WinRM port NOT responding"
    fi
}

# ============================================================
# RUN ALL CHECKS
# ============================================================
echo "============================================" | tee "$LOG"
echo " Network Audit - $(date)" | tee -a "$LOG"
echo " Team prefix: $TEAM_PREFIX" | tee -a "$LOG"
echo "============================================" | tee -a "$LOG"

# ---------- BALLAST (Ubuntu 20, 10.x.2.12) ----------
hdr "BALLAST - Ubuntu 20 ($(ip 10.x.2.12))"
check_ftp  "FTP [SCORED]"  "$(ip 10.x.2.12)"
check_ssh  "SSH [SCORED]"  "$(ip 10.x.2.12)"
check_tcp  "VNC [SCORED]"  "$(ip 10.x.2.12)" 5900

# ---------- BLACKPEARL (Win Server 2022, 10.x.1.10) ----------
hdr "BLACKPEARL - Windows Server 2022 ($(ip 10.x.1.10))"
check_ldap   "LDAP [SCORED]"   "$(ip 10.x.1.10)"
check_tcp    "RDP [SCORED]"    "$(ip 10.x.1.10)" 3389
check_tcp    "SMB [SCORED]"    "$(ip 10.x.1.10)" 445
check_winrm  "WinRM [SCORED]"  "$(ip 10.x.1.10)"

# ---------- COURIER (Fedora 31, 10.x.3.12) ----------
hdr "COURIER - Fedora 31 ($(ip 10.x.3.12))"
check_http "HTTP-Roundcube [SCORED]" "http://$(ip 10.x.3.12)"
check_smtp "SMTP [SCORED]"           "$(ip 10.x.3.12)"
check_ssh  "SSH [SCORED]"            "$(ip 10.x.3.12)"

# ---------- JOLLYROGER (Win Server 2022, 10.x.2.11) ----------
hdr "JOLLYROGER - Windows Server 2022 ($(ip 10.x.2.11))"
check_tcp    "RDP [SCORED]"    "$(ip 10.x.2.11)" 3389
check_winrm  "WinRM [SCORED]"  "$(ip 10.x.2.11)"

# ---------- POOPDECK (Debian 10, 10.x.1.11) ----------
hdr "POOPDECK - Debian 10 ($(ip 10.x.1.11))"
check_dns  "DNS [SCORED]"          "$(ip 10.x.1.11)"
check_http "HTTP-WikiJS [SCORED]"  "http://$(ip 10.x.1.11)"
check_ssh  "SSH [SCORED]"          "$(ip 10.x.1.11)"

# ---------- SILKROAD (Ubuntu 18, 10.x.2.10) ----------
hdr "SILKROAD - Ubuntu 18 ($(ip 10.x.2.10))"
check_http  "HTTP-SilkRoad [SCORED]" "http://$(ip 10.x.2.10)"
check_mysql "MySQL [SCORED]"         "$(ip 10.x.2.10)"
check_ssh   "SSH [SCORED]"           "$(ip 10.x.2.10)"

# ============================================================
# SUMMARY
# ============================================================
echo "" | tee -a "$LOG"
echo "============================================" | tee -a "$LOG"
TOTAL=$((PASS + FAIL + WARN))
echo -e "${BOLD}RESULTS: ${GRN}${PASS} PASS${NC} | ${RED}${FAIL} FAIL${NC} | ${YEL}${WARN} WARN${NC} | Total: $TOTAL${NC}" | tee -a "$LOG"
SCORE_PCT=0
[[ $TOTAL -gt 0 ]] && SCORE_PCT=$(( PASS * 100 / TOTAL ))
echo -e "Estimated uptime score: ${BOLD}${SCORE_PCT}%${NC}" | tee -a "$LOG"
echo "" | tee -a "$LOG"
[[ $FAIL -gt 0 ]] && echo -e "${RED}[!!] Fix FAILED services before scoring engine checks!${NC}" | tee -a "$LOG"
echo "Full log: $LOG" | tee -a "$LOG"
echo "============================================" | tee -a "$LOG"
