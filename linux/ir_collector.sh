#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Incident Response Evidence Collector
# Captures everything needed for an IR report:
#   - Running processes
#   - Active network connections + IPs
#   - Logged-in users / active sessions
#   - Recent auth failures and successes
#   - Modified files
#   - Suspicious cron/startup entries
#
# Usage: bash ir_collector.sh
# Output: /tmp/IR_EVIDENCE_<timestamp>/
# ============================================================

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="/tmp/IR_EVIDENCE_${TIMESTAMP}"
mkdir -p "$OUTDIR"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$OUTDIR/collection.log"; }

log "=== IR Evidence Collection Started ==="
log "Host: $(hostname)  |  IP: $(hostname -I)"
log "Output: $OUTDIR"

# ============================================================
# 1. ACTIVE SESSIONS (WHO IS ON THE BOX RIGHT NOW)
# ============================================================
log "[1] Active sessions..."
{
    echo "=== who ==="
    who -a
    echo ""
    echo "=== w (what users are doing) ==="
    w
    echo ""
    echo "=== last (recent logins) ==="
    last -20
    echo ""
    echo "=== lastb (failed logins) ==="
    lastb -20 2>/dev/null || echo "lastb not available"
} > "$OUTDIR/sessions.txt"

# ============================================================
# 2. RUNNING PROCESSES
# ============================================================
log "[2] Processes..."
{
    echo "=== All processes (ps auxf) ==="
    ps auxf
    echo ""
    echo "=== Processes by non-system users ==="
    ps aux | awk '$1 != "root" && $1 != "www-data" && $1 != "mysql" && $1 != "postfix" && $1 != "nobody"'
} > "$OUTDIR/processes.txt"

# ============================================================
# 3. NETWORK CONNECTIONS + ATTACKER IPs
# ============================================================
log "[3] Network connections..."
{
    echo "=== ESTABLISHED connections ==="
    ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null
    echo ""
    echo "=== All listening services ==="
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
    echo ""
    echo "=== UDP listeners ==="
    ss -ulnp 2>/dev/null || netstat -ulnp 2>/dev/null
    echo ""
    echo "=== ARP table (hosts on local network) ==="
    arp -n 2>/dev/null || ip neigh 2>/dev/null
} > "$OUTDIR/network.txt"

# Extract unique external IPs from established connections
log "[3b] Extracting connected IPs..."
ss -tnp state established 2>/dev/null | awk 'NR>1{print $5}' | cut -d: -f1 | sort -u \
    > "$OUTDIR/connected_ips.txt"
echo "--- Connected IPs ---"
cat "$OUTDIR/connected_ips.txt"

# ============================================================
# 4. AUTHENTICATION LOGS
# ============================================================
log "[4] Auth logs..."
{
    echo "=== Recent SSH logins ==="
    grep -i "accepted\|failed\|invalid\|disconnect" /var/log/auth.log 2>/dev/null \
        | tail -200 || \
    grep -i "accepted\|failed\|invalid\|disconnect" /var/log/secure 2>/dev/null \
        | tail -200
    echo ""
    echo "=== Sudo usage ==="
    grep -i "sudo" /var/log/auth.log 2>/dev/null | tail -50 || \
    grep -i "sudo" /var/log/secure 2>/dev/null | tail -50
} > "$OUTDIR/auth_log.txt"

# ============================================================
# 5. CRON JOBS (all users)
# ============================================================
log "[5] Cron jobs..."
{
    echo "=== System crontab ==="
    cat /etc/crontab 2>/dev/null
    echo ""
    echo "=== /etc/cron.d/ ==="
    ls -la /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null
    echo ""
    echo "=== Per-user crontabs ==="
    for user in $(cut -d: -f1 /etc/passwd); do
        CRON=$(crontab -l -u "$user" 2>/dev/null)
        if [[ -n "$CRON" ]]; then
            echo "--- $user ---"
            echo "$CRON"
        fi
    done
} > "$OUTDIR/crontabs.txt"

# ============================================================
# 6. RECENTLY MODIFIED FILES (last 2 hours)
# ============================================================
log "[6] Recently modified files..."
find / -mmin -120 -type f \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/run/*' \
    ! -path '/dev/*' ! -path "$OUTDIR/*" \
    2>/dev/null | head -200 > "$OUTDIR/recent_files.txt"
echo "[*] $(wc -l < "$OUTDIR/recent_files.txt") files modified in last 2 hours"

# ============================================================
# 7. STARTUP / PERSISTENCE MECHANISMS
# ============================================================
log "[7] Persistence checks..."
{
    echo "=== Systemd enabled services ==="
    systemctl list-unit-files --state=enabled 2>/dev/null
    echo ""
    echo "=== /etc/rc.local ==="
    cat /etc/rc.local 2>/dev/null
    echo ""
    echo "=== ~/.bashrc / ~/.profile for all users ==="
    for home in /home/* /root; do
        echo "--- $home/.bashrc ---"
        cat "$home/.bashrc" 2>/dev/null
        echo "--- $home/.profile ---"
        cat "$home/.profile" 2>/dev/null
    done
} > "$OUTDIR/persistence.txt"

# ============================================================
# 8. USER ACCOUNT AUDIT
# ============================================================
log "[8] User accounts..."
{
    echo "=== /etc/passwd (non-system users) ==="
    awk -F: '$3 >= 1000 {print}' /etc/passwd
    echo ""
    echo "=== Users with shells ==="
    grep -v '/nologin\|/false' /etc/passwd
    echo ""
    echo "=== Sudoers ==="
    cat /etc/sudoers 2>/dev/null
    ls -la /etc/sudoers.d/ 2>/dev/null
    cat /etc/sudoers.d/* 2>/dev/null
    echo ""
    echo "=== Users with empty passwords ==="
    awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null
} > "$OUTDIR/users.txt"

# ============================================================
# 9. QUICK SUMMARY FOR IR REPORT
# ============================================================
log "[9] Generating IR summary..."
CONNECTED_IPS=$(cat "$OUTDIR/connected_ips.txt" 2>/dev/null | tr '\n' ', ')
ACTIVE_USERS=$(who | awk '{print $1}' | sort -u | tr '\n' ', ')

cat > "$OUTDIR/IR_SUMMARY.txt" << EOF
====================================================
 INCIDENT RESPONSE SUMMARY - $(date)
 Host: $(hostname) | $(hostname -I)
====================================================

ACTIVE USERS ON SYSTEM:
  $ACTIVE_USERS

EXTERNAL IPs CONNECTED:
  $CONNECTED_IPS

RECENT FAILED LOGINS (last 10):
$(lastb -10 2>/dev/null || grep -i "failed" /var/log/auth.log 2>/dev/null | tail -10 || echo "N/A")

PROCESSES RUNNING AS UNEXPECTED USERS:
$(ps aux | awk 'NR==1 || ($1 != "root" && $1 != "www-data" && $1 != "mysql" && $1 != "postfix" && $1 != "nobody" && $1 != "sshd" && $1 != "daemon")' | head -20)

FILES MODIFIED IN LAST 2 HOURS:
$(head -20 "$OUTDIR/recent_files.txt")

====================================================
See full evidence in: $OUTDIR/
Files to include in IR report:
  - sessions.txt      (who was logged in)
  - connected_ips.txt (attacker IPs)
  - processes.txt     (what they ran)
  - auth_log.txt      (login evidence)
  - recent_files.txt  (what they touched)
====================================================
EOF

cat "$OUTDIR/IR_SUMMARY.txt"

# ============================================================
# 10. PACKAGE AS TARBALL
# ============================================================
tar -czf "/tmp/IR_EVIDENCE_${TIMESTAMP}.tar.gz" -C /tmp "IR_EVIDENCE_${TIMESTAMP}/"
log "Evidence packaged: /tmp/IR_EVIDENCE_${TIMESTAMP}.tar.gz"
log "=== Collection Complete ==="
