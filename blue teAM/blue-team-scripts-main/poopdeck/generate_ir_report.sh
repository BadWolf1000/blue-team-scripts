#!/bin/bash
# ============================================================
# DreadWatch Blue Team - IR Report Generator (Linux)
#
# WHAT THIS SCRIPT DOES:
#   Reads all the evidence collected by ir_monitor.sh and
#   formats it into a structured IR report that directly
#   matches the 4 things the White Crew scores:
#     1. Attacker IP addresses
#     2. Processes the attacker ran
#     3. User accounts they used
#     4. Active sessions they hijacked
#   The report is ready to convert to PDF and submit to Discord.
#
# PREREQUISITE:
#   ir_monitor.sh must have been running to collect evidence.
#   If it wasn't running, use ir_collector.sh first for a snapshot.
#
# HOW TO USE:
#   Step 1 - Make sure ir_monitor.sh has been running and collecting.
#            Check: ls $HOME/Desktop/blueteam_logs/
#            You should see EVIDENCE.log with content in it.
#
#   Step 2 - Run the report generator with a title describing the attack:
#            sudo bash generate_ir_report.sh "SSH Brute Force Attack"
#            sudo bash generate_ir_report.sh "RCE via Webshell Upload"
#            sudo bash generate_ir_report.sh "Credential Theft via FTP"
#
#   Step 3 - The report is saved to:
#            $HOME/Desktop/blueteam_logs/IR_REPORT_<timestamp>.txt
#            A quick summary prints to the screen immediately.
#
#   Step 4 - Convert the .txt report to PDF for Discord submission:
#            enscript -p /tmp/report.ps $HOME/Desktop/blueteam_logs/IR_REPORT_*.txt
#            ps2pdf /tmp/report.ps /tmp/IR_REPORT.pdf
#            --- OR if enscript isn't available ---
#            libreoffice --headless --convert-to pdf $HOME/Desktop/blueteam_logs/IR_REPORT_*.txt
#
#   Step 5 - Upload the PDF to Discord before the deadline.
#
# OUTPUT: $HOME/Desktop/blueteam_logs/IR_REPORT_<timestamp>.txt
# ============================================================

LOGDIR="$HOME/Desktop/blueteam_logs"
EVIDENCE_LOG="$LOGDIR/EVIDENCE.log"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$LOGDIR/IR_REPORT_${TIMESTAMP}.txt"
TITLE="${1:-Security Incident Report}"

if [[ ! -d "$LOGDIR" ]]; then
    echo "[!] No IR logs found. Run ir_monitor.sh first."
    exit 1
fi

# ============================================================
# PARSE EVIDENCE LOG FOR EACH CATEGORY
# ============================================================

get_section() {
    local tag="$1"
    grep "\[$tag\]" "$EVIDENCE_LOG" 2>/dev/null | \
        sed "s/\[.*\] \[$tag\] //" | \
        sort -u
}

ATTACKER_IPS=$(get_section "NEW-CONNECTION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
AUTH_SUCCESSES=$(get_section "AUTH-SUCCESS")
AUTH_FAILS=$(get_section "AUTH-FAIL")
SESSIONS=$(get_section "NEW-SESSION")
SUDO_EVENTS=$(get_section "SUDO")
PROCESSES=$(get_section "USER-PROCESS")
SUSPICIOUS_PROCS=$(get_section "SUSPICIOUS-PROC")
ACCOUNT_CHANGES=$(get_section "ACCOUNT-CHANGE")
NEW_LISTENERS=$(get_section "NEW-LISTENER")

# Get user accounts used (extract from auth successes)
USERS_SEEN=$(echo "$AUTH_SUCCESSES" | grep -oE 'for user [a-zA-Z0-9_]+' | awk '{print $3}' | sort -u)

# ============================================================
# WRITE REPORT
# ============================================================
cat > "$REPORT" << EOF
================================================================================
                    INCIDENT RESPONSE REPORT
                    $TITLE
================================================================================
Organization:  Dread Pirate Ventures
Host:          $(hostname) | $(hostname -I | awk '{print $1}')
OS:            $(uname -a)
Report Time:   $(date)
Prepared by:   DreadWatch Blue Team
Evidence Dir:  $LOGDIR
================================================================================

EXECUTIVE SUMMARY
-----------------
This report documents unauthorized access attempts and confirmed intrusions
detected on host $(hostname) during the competition window.

--------------------------------------------------------------------------------
SECTION 1: ATTACKER IP ADDRESSES
--------------------------------------------------------------------------------
The following external IP addresses established connections to this host:

$(if [[ -n "$ATTACKER_IPS" ]]; then
    echo "$ATTACKER_IPS" | while read -r ip; do
        echo "  IP: $ip"
        # Try to get more connection context from network log
        grep "$ip" "$LOGDIR/network_connections.log" 2>/dev/null | head -3 | sed 's/^/    /'
    done
else
    echo "  No new external connections detected."
fi)

Raw connection log entries:
$(get_section "NEW-CONNECTION" | head -30 | sed 's/^/  /')

--------------------------------------------------------------------------------
SECTION 2: PROCESSES EXECUTED BY ATTACKERS
--------------------------------------------------------------------------------
The following processes were observed running under non-system user accounts:

$(if [[ -n "$SUSPICIOUS_PROCS" ]]; then
    echo "  !! SUSPICIOUS PROCESSES DETECTED !!"
    echo "$SUSPICIOUS_PROCS" | sed 's/^/  [SUSPICIOUS] /'
    echo ""
fi)

$(if [[ -n "$PROCESSES" ]]; then
    echo "$PROCESSES" | sed 's/^/  /'
else
    echo "  No user-level processes detected outside monitoring window."
fi)

Full process log: $LOGDIR/processes.log

--------------------------------------------------------------------------------
SECTION 3: USER ACCOUNTS USED
--------------------------------------------------------------------------------
Accounts seen in authentication events:

$(if [[ -n "$USERS_SEEN" ]]; then
    echo "$USERS_SEEN" | sed 's/^/  Account: /'
else
    echo "  No user accounts identified from auth events."
fi)

Successful logins:
$(if [[ -n "$AUTH_SUCCESSES" ]]; then
    echo "$AUTH_SUCCESSES" | sed 's/^/  /'
else
    echo "  None captured."
fi)

Sudo usage:
$(if [[ -n "$SUDO_EVENTS" ]]; then
    echo "$SUDO_EVENTS" | sed 's/^/  /'
else
    echo "  None detected."
fi)

Account modifications:
$(if [[ -n "$ACCOUNT_CHANGES" ]]; then
    echo "$ACCOUNT_CHANGES" | sed 's/^/  /'
else
    echo "  None detected."
fi)

Failed login attempts:
$(echo "$AUTH_FAILS" | head -20 | sed 's/^/  /')

Full auth log: $LOGDIR/auth_events.log

--------------------------------------------------------------------------------
SECTION 4: ACTIVE SESSIONS / HIJACKED SESSIONS
--------------------------------------------------------------------------------
Session changes detected during monitoring:

$(if [[ -n "$SESSIONS" ]]; then
    echo "$SESSIONS" | sed 's/^/  /'
else
    echo "  No unexpected session changes detected."
fi)

Full sessions log: $LOGDIR/sessions.log

Current sessions at report time:
$(who -a | sed 's/^/  /')

--------------------------------------------------------------------------------
SECTION 5: ADDITIONAL INDICATORS OF COMPROMISE
--------------------------------------------------------------------------------

New listening ports (potential backdoors):
$(if [[ -n "$NEW_LISTENERS" ]]; then
    echo "$NEW_LISTENERS" | sed 's/^/  [NEW PORT] /'
else
    echo "  No new listeners detected."
fi)

Recently modified files (last 2 hours at report time):
$(find / -mmin -120 -type f \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/run/*' ! -path '/dev/*' \
    ! -path "$LOGDIR/*" 2>/dev/null | head -30 | sed 's/^/  /')

--------------------------------------------------------------------------------
SECTION 6: FULL EVIDENCE TIMELINE
--------------------------------------------------------------------------------
(All events in chronological order from EVIDENCE.log)

$(cat "$EVIDENCE_LOG" 2>/dev/null | sed 's/^/  /' || echo "  No evidence log found.")

================================================================================
ATTESTATION
================================================================================
I certify that the evidence presented in this report was collected directly from
system logs on host $(hostname) and has not been altered.

Submitted by: DreadWatch Blue Team
Date/Time:    $(date)
================================================================================
EOF

echo "[+] Report saved: $REPORT"
echo ""
echo "--- QUICK SUMMARY FOR WHITE CREW ---"
echo "Attacker IPs:    ${ATTACKER_IPS:-none detected}"
echo "Accounts used:   ${USERS_SEEN:-none detected}"
echo "Suspicious procs: $(echo "$SUSPICIOUS_PROCS" | grep -c . || echo 0)"
echo "Session changes:  $(echo "$SESSIONS" | grep -c . || echo 0)"
echo ""
echo "To convert to PDF for Discord submission:"
echo "  enscript -p /tmp/ir_report.ps '$REPORT' && ps2pdf /tmp/ir_report.ps /tmp/IR_REPORT.pdf"
echo "  OR: cat '$REPORT'   (copy text into a PDF converter)"
