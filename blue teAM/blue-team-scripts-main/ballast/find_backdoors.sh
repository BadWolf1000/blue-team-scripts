#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Backdoor & Persistence Scanner
#
# WHAT THIS SCRIPT DOES:
#   Red team will plant backdoors immediately after gaining
#   access so they can get back in even after you change
#   passwords. This script hunts for all common persistence
#   methods and flags them with [!!BACKDOOR] in red.
#   Checks:
#     - SSH authorized_keys planted in user home dirs
#     - Webshells in web server directories
#     - Malicious cron jobs added by red team
#     - Tampered .bashrc/.profile (commands that auto-run on login)
#     - Unusual SUID binaries (privilege escalation)
#     - Active reverse shell listeners (nc, socat, etc.)
#     - Rogue user accounts created by red team
#     - New/suspicious systemd services added
#     - Executables dropped in /tmp or /dev/shm
#
# HOW TO USE:
#   --- Scan only (safe, no changes made) ---
#   Step 1: sudo bash find_backdoors.sh
#   Step 2: Review all [!!BACKDOOR] lines carefully.
#   Step 3: Save findings - they're logged to $HOME/Desktop/blueteam_logs/backdoors_<timestamp>.txt
#
#   --- Scan AND interactively remove backdoors ---
#   Step 1: sudo bash find_backdoors.sh --clean
#   Step 2: For each finding, you'll be prompted: "Remove this? [y/N]"
#           Type y to remove it, Enter/n to skip.
#   Step 3: After cleaning, run the script again to confirm nothing was missed.
#
# WHEN TO RUN:
#   - During the first 30 minutes (before red team attacks)
#   - Immediately after detecting any intrusion
#   - Any time you suspect red team has been on the box
#
# OUTPUT: $HOME/Desktop/blueteam_logs/backdoors_<timestamp>.txt
# ============================================================
# ============================================================

CLEAN_MODE=false
[[ "${1:-}" == "--clean" ]] && CLEAN_MODE=true

LOGDIR="$HOME/Desktop/blueteam_logs"
mkdir -p "$LOGDIR"
REPORT="$LOGDIR/backdoors_$(date +%Y%m%d_%H%M%S).txt"
FOUND=0

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

flag()  { echo -e "${RED}[!!BACKDOOR]${NC} $*" | tee -a "$REPORT"; ((FOUND++)); }
warn()  { echo -e "${YEL}[SUSPECT]${NC}   $*" | tee -a "$REPORT"; }
ok()    { echo -e "${GRN}[OK]${NC}        $*"; }
hdr()   { echo "" | tee -a "$REPORT"; echo -e "=== $* ===" | tee -a "$REPORT"; }

echo "============================================" | tee "$REPORT"
echo " Backdoor Scanner - $(hostname) - $(date)"   | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"

# ============================================================
# 1. SSH AUTHORIZED_KEYS
# ============================================================
hdr "SSH AUTHORIZED_KEYS"

KNOWN_KEY_COMMENT="blueteam"  # Set this to your team's key comment if you have one

for home in /root /home/*; do
    keyfile="$home/.ssh/authorized_keys"
    [[ ! -f "$keyfile" ]] && continue
    user=$(basename "$home")
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        key_comment=$(echo "$line" | awk '{print $NF}')
        flag "Authorized key found for $user: $key_comment"
        echo "  Full key: ${line:0:80}..." | tee -a "$REPORT"
        if $CLEAN_MODE; then
            read -rp "  Remove this key? [y/N] " ans
            if [[ "$ans" =~ ^[Yy]$ ]]; then
                # Remove matching line
                grep -vF "$line" "$keyfile" > "${keyfile}.tmp" && mv "${keyfile}.tmp" "$keyfile"
                echo "  [+] Key removed"
            fi
        fi
    done < "$keyfile"
done
[[ $FOUND -eq 0 ]] && ok "No authorized_keys found"

# ============================================================
# 2. WEBSHELLS IN WEB ROOTS
# ============================================================
hdr "WEBSHELL SCAN"

WEB_ROOTS=(
    "/var/www" "/var/www/html" "/srv/www"
    "/usr/share/nginx/html" "/opt/silkroad" "/opt/wiki"
    "/var/www/roundcube" "/etc/roundcube"
)

# Add any running web root from apache/nginx config
APACHE_CONF=$(grep -r "DocumentRoot" /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v '#' | awk '{print $2}' | sort -u)
NGINX_CONF=$(grep -r "root " /etc/nginx/ 2>/dev/null | grep -v '#' | awk '{print $2}' | tr -d ';' | sort -u)
for root in $APACHE_CONF $NGINX_CONF; do
    WEB_ROOTS+=("$root")
done

WEBSHELL_PATTERNS=(
    'eval\s*(' 'base64_decode\s*(' 'system\s*(' 'passthru\s*('
    'shell_exec\s*(' 'exec\s*(' 'popen\s*(' 'proc_open\s*('
    '\$_REQUEST\[' '\$_POST\[' '\$_GET\[' 'str_rot13'
    'gzinflate' 'gzuncompress' 'str_replace.*base64'
    'preg_replace.*\/e' 'assert\s*(' 'create_function'
    'FilesMan' 'c99shell' 'r57shell' 'b374k' 'wso\.php'
)

WEBSHELL_FOUND=0
for webroot in "${WEB_ROOTS[@]}"; do
    [[ ! -d "$webroot" ]] && continue
    echo "[*] Scanning: $webroot" | tee -a "$REPORT"

    # Check for suspicious filenames
    find "$webroot" -type f -name "*.php" 2>/dev/null | while read -r phpfile; do
        basename_f=$(basename "$phpfile")
        # Suspicious filename patterns
        if echo "$basename_f" | grep -qiE '^(cmd|shell|c99|r57|wso|b374k|bypass|hack|exploit|backdoor|webshell|upload|exec|eval)\.(php|php5|phtml|php3)$'; then
            flag "Suspicious filename: $phpfile"
            ((WEBSHELL_FOUND++))
        fi

        # Check content for webshell patterns
        for pattern in "${WEBSHELL_PATTERNS[@]}"; do
            if grep -qiP "$pattern" "$phpfile" 2>/dev/null; then
                flag "Webshell pattern '$pattern' in: $phpfile"
                grep -niP "$pattern" "$phpfile" 2>/dev/null | head -3 | sed 's/^/    /' | tee -a "$REPORT"
                ((WEBSHELL_FOUND++))
                if $CLEAN_MODE; then
                    read -rp "  Quarantine $phpfile? [y/N] " ans
                    if [[ "$ans" =~ ^[Yy]$ ]]; then
                        mv "$phpfile" "/tmp/quarantine_$(basename "$phpfile")_$(date +%s)"
                        echo "  [+] Quarantined to /tmp/"
                    fi
                fi
                break
            fi
        done
    done

    # Non-PHP files in web root that look executable
    find "$webroot" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" \) 2>/dev/null | while read -r f; do
        warn "Executable script in web root: $f"
    done
done
[[ $WEBSHELL_FOUND -eq 0 ]] && ok "No webshells detected"

# ============================================================
# 3. CRON JOBS
# ============================================================
hdr "CRON JOBS"

# System cron locations
CRON_FILES=(
    /etc/crontab
    /etc/cron.d/*
    /etc/cron.hourly/*
    /etc/cron.daily/*
    /etc/cron.weekly/*
    /etc/cron.monthly/*
    /var/spool/cron/crontabs/*
)

for cfile in "${CRON_FILES[@]}"; do
    [[ ! -f "$cfile" ]] && continue
    # Look for suspicious content
    if grep -qiP '(wget|curl|bash\s+-[ic]|nc\s+|ncat|/tmp/|/dev/shm|python.*-c|perl.*-e)' "$cfile" 2>/dev/null; then
        flag "Suspicious cron in $cfile:"
        grep -iP '(wget|curl|bash\s+-[ic]|nc\s+|ncat|/tmp/|/dev/shm|python.*-c|perl.*-e)' "$cfile" | sed 's/^/    /' | tee -a "$REPORT"
        if $CLEAN_MODE; then
            read -rp "  Remove suspicious lines from $cfile? [y/N] " ans
            if [[ "$ans" =~ ^[Yy]$ ]]; then
                grep -viP '(wget|curl|bash\s+-[ic]|nc\s+|ncat|/tmp/|/dev/shm|python.*-c|perl.*-e)' "$cfile" > "${cfile}.clean"
                mv "${cfile}.clean" "$cfile"
                echo "  [+] Cleaned"
            fi
        fi
    else
        ok "Clean: $cfile"
    fi
done

# Per-user crontabs
for user in $(cut -d: -f1 /etc/passwd); do
    cron=$(crontab -l -u "$user" 2>/dev/null)
    if [[ -n "$cron" ]]; then
        if echo "$cron" | grep -qiP '(wget|curl|bash\s+-[ic]|nc\s+|ncat|/tmp/|/dev/shm)'; then
            flag "Suspicious crontab for user $user:"
            echo "$cron" | sed 's/^/    /' | tee -a "$REPORT"
        else
            warn "Crontab exists for $user (review manually):"
            echo "$cron" | sed 's/^/    /' | tee -a "$REPORT"
        fi
    fi
done

# ============================================================
# 4. TAMPERED SHELL PROFILES
# ============================================================
hdr "SHELL PROFILE TAMPERING"

PROFILE_FILES=()
for home in /root /home/*; do
    for f in .bashrc .bash_profile .profile .zshrc .bash_logout; do
        [[ -f "$home/$f" ]] && PROFILE_FILES+=("$home/$f")
    done
done
PROFILE_FILES+=(/etc/bash.bashrc /etc/profile /etc/profile.d/*)

for pfile in "${PROFILE_FILES[@]}"; do
    [[ ! -f "$pfile" ]] && continue
    if grep -qiP '(wget|curl|nc\s+|ncat|bash\s+-i|/tmp/|/dev/shm|python.*-c|perl.*-e|exec.*>&)' "$pfile" 2>/dev/null; then
        flag "Suspicious content in $pfile:"
        grep -niP '(wget|curl|nc\s+|ncat|bash\s+-i|/tmp/|/dev/shm|python.*-c|perl.*-e|exec.*>&)' "$pfile" | sed 's/^/    /' | tee -a "$REPORT"
    fi
done
ok "Profile scan complete"

# ============================================================
# 5. REVERSE SHELL LISTENERS
# ============================================================
hdr "REVERSE SHELL / UNUSUAL LISTENERS"

# Check all listening ports and flag unexpected ones
EXPECTED_PORTS_BY_HOST() {
    local h
    h=$(hostname | tr '[:upper:]' '[:lower:]')
    case "$h" in
        *ballast*)   echo "21 22 5900 5901" ;;
        *silkroad*)  echo "22 80 443 3306" ;;
        *poopdeck*)  echo "22 53 80 443 123" ;;
        *courier*)   echo "22 25 80 143 443 587 993" ;;
        *)           echo "22" ;;
    esac
}

EXPECTED=$(EXPECTED_PORTS_BY_HOST)
ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | grep -oE '[0-9]+$' | sort -un | while read -r port; do
    if ! echo "$EXPECTED" | grep -qw "$port"; then
        PROC=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'users:\(\("[^"]+",pid=\K[^,]+' | head -1)
        PROC_NAME=$(ps -p "$PROC" -o cmd --no-headers 2>/dev/null || echo "unknown")
        warn "Unexpected listener on port $port (PID:$PROC CMD:$PROC_NAME)"
    fi
done

# Check specifically for netcat/socat listeners
for tool in nc ncat netcat socat; do
    if pgrep -a "$tool" 2>/dev/null | grep -v "^$$"; then
        flag "ACTIVE: $tool process found!"
        pgrep -a "$tool" | sed 's/^/    /' | tee -a "$REPORT"
    fi
done

# ============================================================
# 6. ROGUE USER ACCOUNTS
# ============================================================
hdr "ROGUE USER ACCOUNTS"

KNOWN_USERS_SET="root AdmiralNelson quartermaster skulllord dreadpirate blackflag SaltyDog23 PlunderMate56 RumRider12 GoldTooth89 HighTide74 SeaScourge30 ParrotJack67 CannonDeck45 BarnacleBill98 StormBringer09"

while IFS=: read -r uname _ uid gid _ homedir shell; do
    [[ "$uid" -lt 1000 ]] && continue  # skip system accounts
    [[ "$shell" == "/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
    if ! echo "$KNOWN_USERS_SET" | grep -qw "$uname"; then
        flag "Unknown user account with login shell: $uname (UID=$uid shell=$shell)"
        if $CLEAN_MODE; then
            read -rp "  Lock account $uname? [y/N] " ans
            [[ "$ans" =~ ^[Yy]$ ]] && usermod -L "$uname" && echo "  [+] Locked $uname"
        fi
    fi
done < /etc/passwd

# Check for UID 0 accounts other than root
awk -F: '$3 == 0 && $1 != "root" {print "[!!] UID=0 account: " $1}' /etc/passwd | tee -a "$REPORT" | while read -r line; do
    flag "$line"
done

# ============================================================
# 7. SUSPICIOUS SUID BINARIES
# ============================================================
hdr "SUID BINARY AUDIT"

# Known safe SUID binaries (adjust for your distro)
KNOWN_SUID=(
    "/usr/bin/sudo" "/usr/bin/passwd" "/usr/bin/su"
    "/usr/bin/newgrp" "/usr/bin/gpasswd" "/usr/bin/chsh"
    "/usr/bin/chfn" "/usr/bin/mount" "/usr/bin/umount"
    "/bin/ping" "/bin/su" "/sbin/unix_chkpwd"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
)

find / -perm /4000 -type f 2>/dev/null | grep -v -E '^/(proc|sys|run|snap)' | while read -r suid_file; do
    KNOWN=false
    for known in "${KNOWN_SUID[@]}"; do
        [[ "$suid_file" == "$known" ]] && KNOWN=true && break
    done
    if ! $KNOWN; then
        flag "Unexpected SUID binary: $suid_file"
        ls -la "$suid_file" | tee -a "$REPORT"
    fi
done

# ============================================================
# 8. UNUSUAL SYSTEMD SERVICES / STARTUP
# ============================================================
hdr "STARTUP PERSISTENCE"

# Look for recently added systemd units
find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" -newer /etc/passwd 2>/dev/null | while read -r svc; do
    warn "Recently modified service file: $svc"
    cat "$svc" | tee -a "$REPORT"
done

# Check /etc/rc.local
if [[ -f /etc/rc.local ]]; then
    if grep -qiP '(wget|curl|nc\s+|bash\s+-i|/tmp/)' /etc/rc.local 2>/dev/null; then
        flag "Suspicious content in /etc/rc.local"
        cat /etc/rc.local | tee -a "$REPORT"
    fi
fi

# ============================================================
# 9. /tmp AND /dev/shm (common malware drop zones)
# ============================================================
hdr "TEMP DIRECTORY AUDIT"

for tmpdir in /tmp /dev/shm /var/tmp; do
    [[ ! -d "$tmpdir" ]] && continue
    # Find executables
    find "$tmpdir" -type f -executable 2>/dev/null | while read -r f; do
        flag "Executable in $tmpdir: $f"
        ls -la "$f" | tee -a "$REPORT"
        file "$f" 2>/dev/null | tee -a "$REPORT"
        if $CLEAN_MODE; then
            read -rp "  Delete $f? [y/N] " ans
            [[ "$ans" =~ ^[Yy]$ ]] && rm -f "$f" && echo "  [+] Deleted"
        fi
    done
    # Find files (non-executable but suspicious names)
    find "$tmpdir" -type f -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null | while read -r f; do
        warn "Script in $tmpdir: $f"
        head -3 "$f" | sed 's/^/    /' | tee -a "$REPORT"
    done
done

# ============================================================
# SUMMARY
# ============================================================
echo "" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
if [[ $FOUND -gt 0 ]]; then
    echo -e "${RED}[!!] FOUND $FOUND BACKDOOR/PERSISTENCE INDICATOR(S)${NC}" | tee -a "$REPORT"
    echo "     Re-run with --clean to interactively remove them" | tee -a "$REPORT"
else
    echo -e "${GRN}[+] No obvious backdoors found${NC}" | tee -a "$REPORT"
fi
echo "Full report: $REPORT" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
