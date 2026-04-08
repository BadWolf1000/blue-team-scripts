#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Rapid Password Rotator
#
# WHAT THIS SCRIPT DOES:
#   Changes passwords for ALL known competition accounts on
#   this machine to a new value. Also automatically locks
#   any unknown accounts it finds (red team may have created one).
#   Use this when:
#     - You first get onto a machine (default passwords are known)
#     - Red team may have stolen credentials
#     - You want to kick active red team sessions
#     - harden_linux.sh has already been run but passwords need rotating again
#
# HOW TO USE:
#   --- Option 1: You choose the new password ---
#   sudo bash rotate_passwords.sh
#   (You'll be prompted to type and confirm the new password)
#
#   --- Option 2: Pass password directly (faster) ---
#   sudo bash rotate_passwords.sh "MyNewPassword123!"
#
#   --- Option 3: Generate a random strong password ---
#   sudo bash rotate_passwords.sh --random
#   IMPORTANT: The random password is printed to the screen once.
#              Screenshot it or write it down immediately!
#
# AFTER RUNNING:
#   Step 1 - Tell your teammates the new password RIGHT AWAY.
#            They need it to log back in if their sessions drop.
#   Step 2 - Update the password in harden_linux.sh for consistency.
#   Step 3 - If MySQL is on this machine, run mysql_harden.sh too
#            (this script does NOT change database passwords).
#
# SAFE TO RUN: Yes, it only changes passwords - no services are restarted.
#
# LOG FILE: /var/log/blueteam_ir/password_rotations.log
# ============================================================

LOG="/var/log/blueteam_ir/password_rotations.log"
mkdir -p "$(dirname "$LOG")"

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] $*" | tee -a "$LOG"; }

# ---------- DETERMINE NEW PASSWORD ----------
if [[ "${1:-}" == "--random" ]]; then
    NEW_PASS=$(tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 20)
    log "Generated random password: $NEW_PASS"
    echo ""
    echo "========================================="
    echo "  NEW PASSWORD: $NEW_PASS"
    echo "  WRITE THIS DOWN NOW"
    echo "========================================="
    echo ""
elif [[ -n "${1:-}" ]]; then
    NEW_PASS="$1"
    log "Using provided password"
else
    echo "[*] Enter new password for all accounts:"
    read -rs NEW_PASS
    echo ""
    echo "[*] Confirm password:"
    read -rs NEW_PASS2
    echo ""
    if [[ "$NEW_PASS" != "$NEW_PASS2" ]]; then
        echo "[!!] Passwords don't match. Exiting."
        exit 1
    fi
fi

if [[ ${#NEW_PASS} -lt 8 ]]; then
    echo "[!!] Password too short (min 8 chars). Exiting."
    exit 1
fi

log "=== Password rotation started on $(hostname) ==="

# All known competition accounts
DOMAIN_USERS=(
    "AdmiralNelson" "quartermaster" "skulllord"
    "dreadpirate" "blackflag"
)
LOCAL_USERS=(
    "SaltyDog23" "PlunderMate56" "RumRider12" "GoldTooth89"
    "HighTide74" "SeaScourge30" "ParrotJack67" "CannonDeck45"
    "BarnacleBill98" "StormBringer09"
)
SYSTEM_USERS=("root")

ALL_USERS=("${DOMAIN_USERS[@]}" "${LOCAL_USERS[@]}" "${SYSTEM_USERS[@]}")

CHANGED=0
SKIPPED=0

for user in "${ALL_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        echo "$user:$NEW_PASS" | chpasswd 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log "[+] Changed: $user"
            ((CHANGED++))
        else
            log "[!] Failed: $user"
            ((SKIPPED++))
        fi
    else
        log "[*] Not found on this host: $user"
        ((SKIPPED++))
    fi
done

# Also change any OTHER non-system user that might have been created by red team
log "[*] Checking for additional login accounts..."
while IFS=: read -r uname _ uid _ _ _ shell; do
    if [[ "$uid" -ge 1000 && "$shell" != "/sbin/nologin" && "$shell" != "/bin/false" ]]; then
        KNOWN=false
        for known in "${ALL_USERS[@]}"; do
            [[ "$uname" == "$known" ]] && KNOWN=true && break
        done
        if ! $KNOWN; then
            log "[!] UNKNOWN account $uname - locking it"
            usermod -L "$uname" 2>/dev/null
            # Also change password in case lock doesn't work
            echo "$uname:$NEW_PASS" | chpasswd 2>/dev/null
        fi
    fi
done < /etc/passwd

log "=== Rotation complete: $CHANGED changed, $SKIPPED skipped ==="
echo ""
echo "============================================"
echo "[+] Passwords rotated on: $(hostname)"
echo "[+] Changed: $CHANGED accounts"
echo "[+] Log: $LOG"
echo "============================================"
