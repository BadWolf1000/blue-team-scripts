#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Continuous IR Monitor (Linux)
#
# WHAT THIS SCRIPT DOES:
#   Runs silently in the background and records evidence the
#   moment an attacker does something. Everything is tagged
#   and saved to EVIDENCE.log which feeds directly into the
#   IR report generator. Captures:
#     [NEW-CONNECTION]  - Every new external IP that connects
#     [AUTH-SUCCESS]    - Every successful login (user + source IP)
#     [AUTH-FAIL]       - Every failed login attempt
#     [USER-PROCESS]    - Every process run by a non-system user
#     [SUSPICIOUS-PROC] - Processes matching attack patterns
#     [SESSION-CHANGE]  - Any new or ended user session
#     [NEW-LISTENER]    - New ports opened (potential backdoors)
#
# HOW TO USE:
#   Step 1 - Start it immediately at the beginning of the competition:
#            sudo bash ir_monitor.sh &
#
#   Step 2 - Confirm it started:
#            cat /var/run/bt_monitor.pid   (shows the PID)
#
#   Step 3 - Leave it running the entire competition.
#            The longer it runs, the more evidence it collects.
#
#   Step 4 - When you detect an attack, check the evidence log:
#            cat $HOME/blueteam_logs/EVIDENCE.log
#            or search for a specific IP:
#            grep "10.x.x.x" $HOME/blueteam_logs/EVIDENCE.log
#
#   Step 5 - When ready to write an IR report, run:
#            sudo bash generate_ir_report.sh "Describe the attack"
#
#   To stop the monitor:
#            sudo bash ir_monitor.sh stop
#
# LOG FILES (all in $HOME/blueteam_logs/):
#   EVIDENCE.log         <- Main file used for IR reports
#   sessions.log         <- Session change details
#   network_connections.log
#   processes.log
#   auth_events.log
# ============================================================

LOGDIR="$HOME/blueteam_logs"
mkdir -p "$LOGDIR"

PIDFILE="/var/run/bt_monitor.pid"
MAIN_LOG="$LOGDIR/monitor.log"
SESSIONS_LOG="$LOGDIR/sessions.log"
NETWORK_LOG="$LOGDIR/network_connections.log"
PROCESSES_LOG="$LOGDIR/processes.log"
AUTH_LOG="$LOGDIR/auth_events.log"
EVIDENCE_LOG="$LOGDIR/EVIDENCE.log"   # This is the one for the IR report

INTERVAL=10  # seconds between sweeps

# ---------- STOP COMMAND ----------
if [[ "${1:-}" == "stop" ]]; then
    if [[ -f "$PIDFILE" ]]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null && echo "[+] Monitor stopped"
        rm -f "$PIDFILE"
    else
        echo "[!] No monitor running"
    fi
    exit 0
fi

echo $$ > "$PIDFILE"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log_main()     { echo "[$(ts)] $*" | tee -a "$MAIN_LOG"; }
log_evidence() { echo "[$(ts)] $*" | tee -a "$EVIDENCE_LOG"; }

log_main "=== IR Monitor Started (PID $$) on $(hostname) ==="

# ============================================================
# BASELINE - Take snapshot of current state so we can detect CHANGES
# ============================================================
log_main "[*] Taking baseline snapshot..."

# Baseline: connections
ss -tnp state established 2>/dev/null | awk 'NR>1{print $5}' | cut -d: -f1 | sort -u \
    > "$LOGDIR/baseline_ips.txt"

# Baseline: sessions
who > "$LOGDIR/baseline_sessions.txt"

# Baseline: processes (just PIDs)
ps aux --no-headers | awk '{print $2}' | sort -n > "$LOGDIR/baseline_pids.txt"

# Baseline: listening ports
ss -tlnp 2>/dev/null > "$LOGDIR/baseline_ports.txt"

log_main "[+] Baseline taken. Monitoring started (interval: ${INTERVAL}s)"
log_main "[*] Evidence log: $EVIDENCE_LOG"

# ============================================================
# AUTH LOG TAILER - Follow auth.log in background
# ============================================================
AUTH_SOURCE=""
for f in /var/log/auth.log /var/log/secure; do
    [[ -f "$f" ]] && AUTH_SOURCE="$f" && break
done

if [[ -n "$AUTH_SOURCE" ]]; then
    tail -Fn0 "$AUTH_SOURCE" | while IFS= read -r line; do
        echo "[$(ts)] $line" >> "$AUTH_LOG"
        # Flag high-value events to evidence log
        if echo "$line" | grep -qiE "Accepted (password|publickey)|session opened for user"; then
            log_evidence "[AUTH-SUCCESS] $line"
        fi
        if echo "$line" | grep -qiE "Failed password|Invalid user|authentication failure"; then
            log_evidence "[AUTH-FAIL] $line"
        fi
        if echo "$line" | grep -qi "sudo"; then
            log_evidence "[SUDO] $line"
        fi
        if echo "$line" | grep -qiE "new user|useradd|usermod"; then
            log_evidence "[ACCOUNT-CHANGE] $line"
        fi
    done &
    AUTH_TAIL_PID=$!
    log_main "[+] Auth log tailer started (PID $AUTH_TAIL_PID)"
fi

# ============================================================
# MAIN MONITORING LOOP
# ============================================================
while true; do

    # ----------------------------------------------------------
    # A. DETECT NEW NETWORK CONNECTIONS (Attacker IPs)
    # ----------------------------------------------------------
    CURRENT_IPS=$(ss -tnp state established 2>/dev/null | awk 'NR>1{print $5}' | cut -d: -f1 | sort -u)
    while IFS= read -r ip; do
        [[ -z "$ip" || "$ip" == "127.0.0.1" ]] && continue
        if ! grep -qF "$ip" "$LOGDIR/baseline_ips.txt" 2>/dev/null; then
            # New IP - log it with full connection details
            CONN_DETAIL=$(ss -tnp state established 2>/dev/null | grep "$ip")
            log_evidence "[NEW-CONNECTION] IP=$ip DETAILS=$CONN_DETAIL"
            echo "$ip" >> "$LOGDIR/baseline_ips.txt"
            # Log to network file with full context
            {
                echo "[$(ts)] === New connection from $ip ==="
                echo "$CONN_DETAIL"
                echo "Process info: $(ss -tnp state established 2>/dev/null | grep "$ip" | grep -oP 'users:\(\("[^"]+",pid=\K[^,]+' | xargs -I{} ps -p {} -o pid,user,cmd 2>/dev/null)"
                echo ""
            } >> "$NETWORK_LOG"
        fi
    done <<< "$CURRENT_IPS"

    # ----------------------------------------------------------
    # B. DETECT NEW USER SESSIONS (hijacked sessions)
    # ----------------------------------------------------------
    CURRENT_SESSIONS=$(who)
    if [[ "$CURRENT_SESSIONS" != "$(cat "$LOGDIR/baseline_sessions.txt" 2>/dev/null)" ]]; then
        # Sessions changed - log who appeared or disappeared
        NEW_SESSIONS=$(comm -13 \
            <(sort "$LOGDIR/baseline_sessions.txt" 2>/dev/null) \
            <(echo "$CURRENT_SESSIONS" | sort))
        GONE_SESSIONS=$(comm -23 \
            <(sort "$LOGDIR/baseline_sessions.txt" 2>/dev/null) \
            <(echo "$CURRENT_SESSIONS" | sort))

        if [[ -n "$NEW_SESSIONS" ]]; then
            log_evidence "[NEW-SESSION] $NEW_SESSIONS"
            {
                echo "[$(ts)] === New session detected ==="
                echo "$NEW_SESSIONS"
                echo "--- Full who output ---"
                echo "$CURRENT_SESSIONS"
                echo "--- Last logins ---"
                last -5
                echo ""
            } >> "$SESSIONS_LOG"
        fi
        if [[ -n "$GONE_SESSIONS" ]]; then
            log_evidence "[SESSION-ENDED] $GONE_SESSIONS"
        fi

        echo "$CURRENT_SESSIONS" > "$LOGDIR/baseline_sessions.txt"
    fi

    # ----------------------------------------------------------
    # C. DETECT NEW PROCESSES (what did attacker run?)
    # ----------------------------------------------------------
    CURRENT_PIDS=$(ps aux --no-headers | awk '{print $2}' | sort -n)
    NEW_PIDS=$(comm -13 \
        <(cat "$LOGDIR/baseline_pids.txt" 2>/dev/null) \
        <(echo "$CURRENT_PIDS"))

    for pid in $NEW_PIDS; do
        # Get process info
        PROC_INFO=$(ps -p "$pid" -o pid,user,cmd --no-headers 2>/dev/null)
        [[ -z "$PROC_INFO" ]] && continue

        USER=$(echo "$PROC_INFO" | awk '{print $2}')
        CMD=$(echo "$PROC_INFO" | awk '{$1=$2=""; print $0}')

        # Flag suspicious: not root, not known services, or running from temp/home
        if echo "$CMD" | grep -qiE "nc |ncat|netcat|/tmp/|/dev/shm/|wget|curl.*sh|bash -i|python.*-c|perl.*-e|msfconsole|mimikatz"; then
            log_evidence "[SUSPICIOUS-PROC] PID=$pid USER=$USER CMD=$CMD"
        fi

        # Log non-system processes
        if [[ "$USER" != "root" && "$USER" != "www-data" && "$USER" != "mysql" \
           && "$USER" != "postfix" && "$USER" != "nobody" && "$USER" != "daemon" \
           && "$USER" != "systemd" ]]; then
            echo "[$(ts)] PID=$pid USER=$USER CMD=$CMD" >> "$PROCESSES_LOG"
            log_evidence "[USER-PROCESS] PID=$pid USER=$USER CMD=$CMD"
        fi
    done

    # Update baseline pids
    echo "$CURRENT_PIDS" > "$LOGDIR/baseline_pids.txt"

    # ----------------------------------------------------------
    # D. DETECT LISTENING PORT CHANGES (new backdoor?)
    # ----------------------------------------------------------
    CURRENT_PORTS=$(ss -tlnp 2>/dev/null)
    if [[ "$CURRENT_PORTS" != "$(cat "$LOGDIR/baseline_ports.txt" 2>/dev/null)" ]]; then
        NEW_PORTS=$(comm -13 \
            <(sort "$LOGDIR/baseline_ports.txt" 2>/dev/null) \
            <(echo "$CURRENT_PORTS" | sort))
        if [[ -n "$NEW_PORTS" ]]; then
            log_evidence "[NEW-LISTENER] $NEW_PORTS"
        fi
        echo "$CURRENT_PORTS" > "$LOGDIR/baseline_ports.txt"
    fi

    sleep "$INTERVAL"
done
