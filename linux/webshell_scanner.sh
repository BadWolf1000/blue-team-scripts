#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Webshell Scanner
#
# WHAT THIS SCRIPT DOES:
#   Red team loves to upload PHP webshells to web servers because
#   it gives them a persistent browser-accessible backdoor.
#   This script scans all web directories for webshells using:
#     - Suspicious filenames (cmd.php, shell.php, c99.php, etc.)
#     - Dangerous code patterns (eval+base64, system($_GET), etc.)
#     - High entropy files (obfuscated/encoded malicious code)
#     - PHP files in upload directories (almost always malicious)
#     - Shell scripts / Python files dropped in web roots
#   Auto-detects web roots from Apache/Nginx config.
#
# RELEVANT HOSTS (run on these only):
#   SilkRoad  - 10.x.2.10 - HTTP-SilkRoad app
#   PoopDeck  - 10.x.1.11 - WikiJS
#   Courier   - 10.x.3.12 - Roundcube webmail
#
# HOW TO USE:
#   --- Scan only (safe, read-only) ---
#   Step 1: sudo bash webshell_scanner.sh
#   Step 2: Review all [WEBSHELL] findings in red.
#   Step 3: Manually inspect flagged files before deleting them.
#           Read the file: cat /var/www/html/suspicious_file.php
#
#   --- Scan and automatically quarantine found webshells ---
#   Step 1: sudo bash webshell_scanner.sh --quarantine
#   Step 2: Webshells are replaced with a safe placeholder and
#           the originals are moved to /var/quarantine_<date>/
#   Step 3: The web service keeps running - scored service stays UP.
#
#   --- After cleaning, re-scan to confirm everything is gone ---
#   sudo bash webshell_scanner.sh
#
# WHEN TO RUN:
#   - During initial hardening (red team may have pre-planted them)
#   - After any suspected file upload attack
#   - If you notice your web service behaving strangely
#
# OUTPUT: /var/log/blueteam_ir/webshell_scan_<timestamp>.txt
# ============================================================

QUARANTINE=false
[[ "${1:-}" == "--quarantine" ]] && QUARANTINE=true

LOGDIR="/var/log/blueteam_ir"
mkdir -p "$LOGDIR"
REPORT="$LOGDIR/webshell_scan_$(date +%Y%m%d_%H%M%S).txt"
QUARANTINE_DIR="/var/quarantine_$(date +%Y%m%d)"
FOUND=0

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'

flag() { echo -e "${RED}[WEBSHELL]${NC} $*" | tee -a "$REPORT"; ((FOUND++)); }
warn() { echo -e "${YEL}[SUSPECT]${NC}  $*" | tee -a "$REPORT"; }
ok()   { echo -e "${GRN}[CLEAN]${NC}    $*"; }

$QUARANTINE && mkdir -p "$QUARANTINE_DIR"

echo "============================================" | tee "$REPORT"
echo " Webshell Scanner - $(hostname) - $(date)" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"

# ============================================================
# AUTO-DETECT WEB ROOTS
# ============================================================
WEB_ROOTS=()

# Common static paths
for path in \
    /var/www /var/www/html /var/www/roundcube \
    /srv/www /srv/http \
    /usr/share/nginx/html \
    /opt/silkroad /opt/wiki /opt/wikijs \
    /var/lib/wikijs; do
    [[ -d "$path" ]] && WEB_ROOTS+=("$path")
done

# From Apache config
while IFS= read -r root; do
    [[ -d "$root" ]] && WEB_ROOTS+=("$root")
done < <(grep -rh "DocumentRoot" /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v '#' | awk '{print $2}' | sort -u)

# From Nginx config
while IFS= read -r root; do
    [[ -d "$root" ]] && WEB_ROOTS+=("$root")
done < <(grep -rh "^\s*root " /etc/nginx/ 2>/dev/null | grep -v '#' | awk '{print $2}' | tr -d ';' | sort -u)

# Deduplicate
IFS=$'\n' WEB_ROOTS=($(printf '%s\n' "${WEB_ROOTS[@]}" | sort -u))

if [[ ${#WEB_ROOTS[@]} -eq 0 ]]; then
    echo "[!] No web roots found. Scanning /var/www as fallback."
    WEB_ROOTS=("/var/www")
fi

echo "[*] Scanning web roots: ${WEB_ROOTS[*]}" | tee -a "$REPORT"

# ============================================================
# DETECTION PATTERNS
# ============================================================

# Suspicious filenames
SUSPICIOUS_NAMES=(
    "cmd.php" "shell.php" "c99.php" "r57.php" "wso.php" "b374k.php"
    "bypass.php" "hack.php" "exploit.php" "backdoor.php" "webshell.php"
    "upload.php" "uploader.php" "filemanager.php" "FilesMan.php"
    "sh.php" "1.php" "x.php" "test.php" "tmp.php" "temp.php"
    "agent.php" "spy.php" "crack.php" "pass.php" "root.php"
)

# Content signatures (PHP)
declare -A PHP_SIGS
PHP_SIGS["eval_decode"]='eval\s*\(\s*base64_decode'
PHP_SIGS["eval_gzip"]='eval\s*\(\s*gzinflate\|eval\s*\(\s*gzuncompress'
PHP_SIGS["system_call"]='system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
PHP_SIGS["passthru"]='passthru\s*\(\s*\$_(GET|POST|REQUEST)'
PHP_SIGS["shell_exec"]='shell_exec\s*\(\s*\$_(GET|POST|REQUEST)'
PHP_SIGS["preg_replace_e"]='preg_replace\s*\(.*\/e["\x27]'
PHP_SIGS["assert_request"]='assert\s*\(\s*\$_(GET|POST|REQUEST)'
PHP_SIGS["create_function"]='create_function\s*\('
PHP_SIGS["base64_exec"]='base64_decode.*system\|system.*base64_decode'
PHP_SIGS["rot13_eval"]='eval\s*\(\s*str_rot13'
PHP_SIGS["obfuscated_var"]='\$[a-zA-Z0-9]{1,3}\s*=\s*\$[a-zA-Z0-9]{1,3}\s*\(\s*\$[a-zA-Z0-9]{1,3}'
PHP_SIGS["raw_post_exec"]='file_get_contents\s*\(\s*["\x27]php://input'

# Script content signatures
declare -A SCRIPT_SIGS
SCRIPT_SIGS["reverse_shell_bash"]='bash -i >&\|bash -c.*>&\|/dev/tcp'
SCRIPT_SIGS["reverse_shell_python"]='socket.connect\|subprocess.*PIPE'
SCRIPT_SIGS["nc_backdoor"]='nc -e\|ncat -e\|netcat -e'

quarantine_file() {
    local f="$1"
    if $QUARANTINE; then
        local dest="$QUARANTINE_DIR/$(date +%s)_$(basename "$f")"
        cp "$f" "$dest"
        # Replace with safe placeholder
        echo "<?php /* FILE QUARANTINED BY BLUETEAM - $(date) */ ?>" > "$f"
        echo -e "    ${GRN}[QUARANTINED]${NC} -> $dest" | tee -a "$REPORT"
    fi
}

# ============================================================
# SCAN EACH WEB ROOT
# ============================================================
for webroot in "${WEB_ROOTS[@]}"; do
    echo "" | tee -a "$REPORT"
    echo "=== Scanning: $webroot ===" | tee -a "$REPORT"

    # ---------- PHP FILES ----------
    while IFS= read -r phpfile; do
        basename_f=$(basename "$phpfile")
        file_flagged=false

        # Check suspicious filename
        for sus_name in "${SUSPICIOUS_NAMES[@]}"; do
            if [[ "${basename_f,,}" == "${sus_name,,}" ]]; then
                flag "SUSPICIOUS FILENAME: $phpfile"
                file_flagged=true
                break
            fi
        done

        # Check file age - recently created files are suspicious
        if find "$phpfile" -newer /etc/passwd -type f &>/dev/null; then
            warn "Recently modified: $phpfile ($(stat -c '%y' "$phpfile" 2>/dev/null | cut -d. -f1))"
        fi

        # Content scan
        for sig_name in "${!PHP_SIGS[@]}"; do
            pattern="${PHP_SIGS[$sig_name]}"
            if grep -qiP "$pattern" "$phpfile" 2>/dev/null; then
                flag "Pattern '$sig_name' in: $phpfile"
                echo "  Match:" | tee -a "$REPORT"
                grep -inP "$pattern" "$phpfile" 2>/dev/null | head -5 | \
                    sed 's/^/    /' | tee -a "$REPORT"
                file_flagged=true
            fi
        done

        # Check for very high entropy (obfuscated code)
        if command -v python3 &>/dev/null; then
            entropy=$(python3 -c "
import math, sys
try:
    data = open('$phpfile','rb').read().decode('utf-8','ignore')
    freq = {}
    for c in data: freq[c] = freq.get(c,0)+1
    total = len(data)
    entropy = -sum((f/total)*math.log2(f/total) for f in freq.values() if f > 0)
    print(f'{entropy:.2f}')
except: print('0')
" 2>/dev/null)
            if (( $(echo "$entropy > 5.5" | bc -l 2>/dev/null || echo 0) )); then
                warn "High entropy ($entropy) - possible obfuscation: $phpfile"
            fi
        fi

        $file_flagged && quarantine_file "$phpfile"

    done < <(find "$webroot" -type f -name "*.php" 2>/dev/null)

    # ---------- OTHER SCRIPT TYPES ----------
    while IFS= read -r scriptfile; do
        ext="${scriptfile##*.}"
        for sig_name in "${!SCRIPT_SIGS[@]}"; do
            pattern="${SCRIPT_SIGS[$sig_name]}"
            if grep -qiP "$pattern" "$scriptfile" 2>/dev/null; then
                flag "Script backdoor pattern '$sig_name' in: $scriptfile"
                grep -inP "$pattern" "$scriptfile" 2>/dev/null | head -3 | \
                    sed 's/^/    /' | tee -a "$REPORT"
            fi
        done
    done < <(find "$webroot" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" \) 2>/dev/null)

    # ---------- NON-WEB FILES IN WEB ROOT ----------
    while IFS= read -r execfile; do
        warn "Executable binary in web root: $execfile"
        file "$execfile" 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT"
    done < <(find "$webroot" -type f -executable ! -name "*.php" ! -name "*.js" ! -name "*.py" 2>/dev/null)
done

# ============================================================
# FILE UPLOAD DIRECTORY CHECK
# ============================================================
echo "" | tee -a "$REPORT"
echo "=== Upload Directory Audit ===" | tee -a "$REPORT"
for webroot in "${WEB_ROOTS[@]}"; do
    find "$webroot" -type d \( -name "upload*" -o -name "files" -o -name "tmp" -o -name "temp" -o -name "cache" \) 2>/dev/null | while read -r uploaddir; do
        echo "[*] Checking upload dir: $uploaddir" | tee -a "$REPORT"
        # PHP files in upload dirs = almost certainly webshells
        find "$uploaddir" -name "*.php" -o -name "*.phtml" -o -name "*.php5" 2>/dev/null | while read -r f; do
            flag "PHP FILE IN UPLOAD DIR: $f"
            quarantine_file "$f"
        done
    done
done

# ============================================================
# SUMMARY
# ============================================================
echo "" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
if [[ $FOUND -gt 0 ]]; then
    echo -e "${RED}[!!] FOUND $FOUND WEBSHELL INDICATOR(S)${NC}" | tee -a "$REPORT"
    $QUARANTINE && echo "[+] Quarantined to: $QUARANTINE_DIR" | tee -a "$REPORT"
    $QUARANTINE || echo "    Re-run with --quarantine to neutralize them" | tee -a "$REPORT"
else
    echo -e "${GRN}[+] No webshells detected${NC}" | tee -a "$REPORT"
fi
echo "Full report: $REPORT" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
