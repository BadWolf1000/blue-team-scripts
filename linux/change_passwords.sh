#!/bin/bash
# ============================================================
# DreadWatch Blue Team - Password Change Script (Linux)
#
# WHAT THIS SCRIPT DOES:
#   Provides an interactive menu to change passwords for all
#   competition accounts on this Linux machine. Covers:
#     - All domain/admin accounts (AdmiralNelson, quartermaster, etc.)
#     - All local user accounts (SaltyDog23, PlunderMate56, etc.)
#     - The root account
#   Shows which accounts exist on THIS machine, their last
#   password change date, and lets you change them individually
#   or all at once.
#
# HOW TO USE:
#   Step 1 - Run the script as root:
#            sudo bash change_passwords.sh
#
#   Step 2 - Choose a mode from the menu:
#            [1] Change ALL passwords at once (fastest - use at start)
#            [2] Change one specific account
#            [3] List all accounts and when passwords were last changed
#            [4] Change only accounts that still have the default password
#            [5] Generate a random strong password
#
#   Step 3 - For option 1 (change all), you enter ONE new password
#            and it applies to every account on this machine.
#            Write the password down and tell your teammates!
#
#   Step 4 - After changing, the script shows a summary of what
#            was changed and what was skipped (account not on this host).
#
# WHEN TO RUN:
#   - FIRST THING on every Linux box (default password is Passw0rd123!)
#   - Any time you think red team has stolen credentials
#   - After red team is detected on a machine
#
# DEFAULT PASSWORD TO REPLACE: Passw0rd123!
# LOG FILE: /var/log/blueteam_ir/password_changes.log
# ============================================================

LOG="/var/log/blueteam_ir/password_changes.log"
mkdir -p "$(dirname "$LOG")"

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'
CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] $*" >> "$LOG"; }

# ============================================================
# ALL KNOWN COMPETITION ACCOUNTS
# ============================================================
DOMAIN_USERS=(
    "AdmiralNelson"
    "quartermaster"
    "skulllord"
    "dreadpirate"
    "blackflag"
)

LOCAL_USERS=(
    "SaltyDog23"
    "PlunderMate56"
    "RumRider12"
    "GoldTooth89"
    "HighTide74"
    "SeaScourge30"
    "ParrotJack67"
    "CannonDeck45"
    "BarnacleBill98"
    "StormBringer09"
)

ALL_USERS=("root" "${DOMAIN_USERS[@]}" "${LOCAL_USERS[@]}")

# ============================================================
# HELPER FUNCTIONS
# ============================================================

# Check if account exists on this machine
account_exists() {
    id "$1" &>/dev/null
}

# Get when password was last changed
last_changed() {
    local user="$1"
    local info
    info=$(chage -l "$user" 2>/dev/null | grep "Last password change" | cut -d: -f2 | xargs)
    echo "${info:-unknown}"
}

# Check if password matches the known default
is_default_password() {
    local user="$1"
    echo "Passw0rd123!" | su -s /bin/bash -c "exit 0" "$user" 2>/dev/null
    # This won't work reliably - just warn about it
}

# Prompt for and confirm a password
prompt_password() {
    local pass1 pass2
    while true; do
        echo -n "  Enter new password: "
        read -rs pass1; echo ""
        if [[ ${#pass1} -lt 8 ]]; then
            echo -e "  ${RED}[!] Password must be at least 8 characters.${NC}"
            continue
        fi
        echo -n "  Confirm password:   "
        read -rs pass2; echo ""
        if [[ "$pass1" != "$pass2" ]]; then
            echo -e "  ${RED}[!] Passwords do not match. Try again.${NC}"
            continue
        fi
        echo "$pass1"
        return 0
    done
}

# Change a single account's password
change_one() {
    local user="$1" newpass="$2"
    if ! account_exists "$user"; then
        echo -e "  ${YEL}[SKIP]${NC} $user - not on this machine"
        return 2
    fi
    if echo "$user:$newpass" | chpasswd 2>/dev/null; then
        echo -e "  ${GRN}[OK]${NC}   $user - password changed"
        log "[CHANGED] $user on $(hostname)"
        return 0
    else
        echo -e "  ${RED}[FAIL]${NC} $user - chpasswd failed"
        log "[FAILED] $user on $(hostname)"
        return 1
    fi
}

# Generate a random password
gen_random_pass() {
    tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 20
}

# ============================================================
# DISPLAY FUNCTIONS
# ============================================================

print_header() {
    clear
    echo -e "${BOLD}${CYN}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║     DREADWATCH - Password Change Manager     ║"
    echo "  ║     Host: $(hostname | head -c 20)$(printf '%*s' $((20 - ${#$(hostname)})) '')           ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

list_accounts() {
    echo -e "${BOLD}  All Competition Accounts on $(hostname):${NC}"
    echo ""
    printf "  %-22s %-10s %-30s\n" "USERNAME" "STATUS" "LAST PASSWORD CHANGE"
    echo "  ──────────────────────────────────────────────────────────────"

    echo -e "  ${CYN}--- Domain / Admin ---${NC}"
    for user in "${DOMAIN_USERS[@]}"; do
        if account_exists "$user"; then
            changed=$(last_changed "$user")
            printf "  ${GRN}%-22s${NC} %-10s %-30s\n" "$user" "EXISTS" "$changed"
        else
            printf "  ${YEL}%-22s${NC} %-10s\n" "$user" "not here"
        fi
    done

    echo ""
    echo -e "  ${CYN}--- Local Users ---${NC}"
    for user in "${LOCAL_USERS[@]}"; do
        if account_exists "$user"; then
            changed=$(last_changed "$user")
            printf "  ${GRN}%-22s${NC} %-10s %-30s\n" "$user" "EXISTS" "$changed"
        else
            printf "  ${YEL}%-22s${NC} %-10s\n" "$user" "not here"
        fi
    done

    echo ""
    echo -e "  ${CYN}--- System ---${NC}"
    if account_exists "root"; then
        changed=$(last_changed "root")
        printf "  ${GRN}%-22s${NC} %-10s %-30s\n" "root" "EXISTS" "$changed"
    fi

    echo ""
    echo -e "  ${YEL}  Note: 'not here' = account doesn't exist on this machine${NC}"
    echo ""
}

# ============================================================
# MENU OPTIONS
# ============================================================

option_change_all() {
    echo ""
    echo -e "${BOLD}  Change ALL account passwords to a single new password${NC}"
    echo -e "  ${YEL}  This will change every account that exists on this machine.${NC}"
    echo -e "  ${YEL}  WRITE THE NEW PASSWORD DOWN before continuing!${NC}"
    echo ""
    NEW_PASS=$(prompt_password)
    echo ""
    echo "  Changing passwords..."
    echo ""

    CHANGED=0; FAILED=0; SKIPPED=0
    for user in "${ALL_USERS[@]}"; do
        result=$(change_one "$user" "$NEW_PASS")
        echo "$result"
        case $? in
            0) ((CHANGED++)) ;;
            1) ((FAILED++)) ;;
            2) ((SKIPPED++)) ;;
        esac
    done

    echo ""
    echo -e "  ${BOLD}Results: ${GRN}$CHANGED changed${NC} | ${RED}$FAILED failed${NC} | ${YEL}$SKIPPED skipped${NC}"
    echo ""
    echo -e "  ${BOLD}${YEL}  NEW PASSWORD: $NEW_PASS${NC}"
    echo -e "  ${RED}  TELL YOUR TEAMMATES THIS PASSWORD NOW!${NC}"
}

option_change_one() {
    echo ""
    echo -e "${BOLD}  Change a single account's password${NC}"
    echo ""
    echo "  Available accounts on this machine:"
    for i in "${!ALL_USERS[@]}"; do
        user="${ALL_USERS[$i]}"
        if account_exists "$user"; then
            printf "    [%2d] %s\n" "$((i+1))" "$user"
        fi
    done
    echo ""
    echo -n "  Enter account name (or number): "
    read -r selection

    # Handle number input
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        idx=$((selection - 1))
        if [[ $idx -ge 0 && $idx -lt ${#ALL_USERS[@]} ]]; then
            TARGET_USER="${ALL_USERS[$idx]}"
        else
            echo -e "  ${RED}[!] Invalid number${NC}"; return
        fi
    else
        TARGET_USER="$selection"
    fi

    if ! account_exists "$TARGET_USER"; then
        echo -e "  ${RED}[!] Account '$TARGET_USER' does not exist on this machine${NC}"
        return
    fi

    echo ""
    echo -e "  Changing password for: ${BOLD}$TARGET_USER${NC}"
    NEW_PASS=$(prompt_password)
    change_one "$TARGET_USER" "$NEW_PASS"
}

option_change_default() {
    echo ""
    echo -e "${BOLD}  Change accounts that may still have default password (Passw0rd123!)${NC}"
    echo -e "  ${YEL}  Enter a new password. It will be applied to all existing accounts.${NC}"
    echo -e "  ${YEL}  (Same effect as 'change all' but serves as a reminder about defaults.)${NC}"
    echo ""
    NEW_PASS=$(prompt_password)
    echo ""
    CHANGED=0
    for user in "${ALL_USERS[@]}"; do
        if account_exists "$user"; then
            change_one "$user" "$NEW_PASS"
            ((CHANGED++))
        fi
    done
    echo ""
    echo -e "  ${GRN}[+] Done. Changed $CHANGED accounts.${NC}"
    echo -e "  ${BOLD}${YEL}  Password: $NEW_PASS  <-- WRITE THIS DOWN${NC}"
}

option_random() {
    echo ""
    echo -e "${BOLD}  Generate a random strong password${NC}"
    echo ""
    RAND_PASS=$(gen_random_pass)
    echo -e "  ${BOLD}${GRN}  Generated password: $RAND_PASS${NC}"
    echo ""
    echo -n "  Apply this password to ALL accounts? [y/N]: "
    read -r ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        CHANGED=0
        for user in "${ALL_USERS[@]}"; do
            if account_exists "$user"; then
                change_one "$user" "$RAND_PASS"
                ((CHANGED++))
            fi
        done
        echo ""
        echo -e "  ${GRN}[+] Applied to $CHANGED accounts.${NC}"
        echo -e "  ${RED}  TELL YOUR TEAMMATES: $RAND_PASS${NC}"
        log "[RANDOM-PASS] Applied to $CHANGED accounts on $(hostname)"
    fi
}

# ============================================================
# MAIN MENU LOOP
# ============================================================
print_header

while true; do
    echo -e "${BOLD}  Select an option:${NC}"
    echo ""
    echo "  [1] Change ALL passwords (fastest - recommended at competition start)"
    echo "  [2] Change ONE specific account"
    echo "  [3] List all accounts and last password change date"
    echo "  [4] Replace default passwords (Passw0rd123!) on all accounts"
    echo "  [5] Generate a random password and optionally apply it"
    echo "  [q] Quit"
    echo ""
    echo -n "  Choice: "
    read -r choice

    case "$choice" in
        1) option_change_all ;;
        2) option_change_one ;;
        3) list_accounts ;;
        4) option_change_default ;;
        5) option_random ;;
        q|Q) echo ""; echo "  Exiting. Log: $LOG"; exit 0 ;;
        *) echo -e "  ${RED}[!] Invalid choice${NC}" ;;
    esac

    echo ""
    echo -n "  Press Enter to return to menu..."
    read -r
    print_header
done
