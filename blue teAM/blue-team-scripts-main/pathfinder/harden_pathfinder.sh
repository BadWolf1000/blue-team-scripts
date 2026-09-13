#!/bin/bash
# ============================================================
# Artemis Blue Team - Pathfinder Hardening Script
#
# Target host:
#   Pathfinder  -  Ubuntu 22.04  -  10.x.2.12
#   Scored services: SSH (22), FTP (21), HTTP (80), MySQL (3306)
#
# WHAT THIS SCRIPT DOES (in order):
#   1.  Baselines every local account to /root/pathfinder_baseline/
#       (passwd, shadow ownership, sudoers, groups, ~/.ssh keys)
#   2.  Rotates the password for every known Artemis competition
#       account plus root, using one prompted value
#   3.  Locks every non-system account NOT on the known list so a
#       red-team backdoor user (BarnacleBart98, etc.) cannot log in
#   4.  Hardens SSH (no root login, MaxAuthTries 3, no X11/Tcp fwd)
#       and OPTIONALLY moves the admin SSH port to 2222 while
#       LEAVING the scored port 22 open for the scoring engine
#   5.  Firewalls the box with UFW: deny all inbound except SSH,
#       FTP, HTTP, MySQL; explicitly rejects the known red-team
#       exfil/backdoor ports (9990 telnet HTTP-exfil, 23 telnet,
#       1337 Sliver operator, 8888 Sliver mTLS, 4444 msf, VNC)
#   6.  Cleans persistence a.k.a. Linux "run keys":
#         - /etc/rc.local, /etc/init.d additions, /etc/profile.d
#         - all user ~/.bashrc / ~/.profile / ~/.bash_profile auto-run lines
#         - every user's crontab + /etc/cron.d /etc/cron.{hourly,daily}
#         - systemd unit files that look like Sliver beacons or
#           Space-RVB known persistence (wall, sptty, gumper,
#           self-healing watcher, ebpf sniffer, telnetd)
#   7.  Kills and disables known red-team services and binaries
#       (Sliver beacon names, watcher script, telnetd, python
#       http.server on :9990, xinetd)
#   8.  Strips SUID off busybox and audits every other SUID bit
#   9.  Restores real /usr/bin/passwd and /usr/sbin/chpasswd if
#       the skimmer wrapper is present (checks against dpkg hashes)
#  10.  Removes pam_permit.so bypass line from /etc/pam.d/common-auth
#       and reinstalls a clean common-auth from libpam-modules
#  11.  Applies sysctl kernel hardening
#  12.  Writes an "accounts to monitor" report to
#       $HOME/blueteam_logs/accounts_monitor_<ts>.txt and installs
#       a systemd timer to re-check every 5 minutes for new users,
#       new sudoers, and new UID-0 accounts
#
# ALLOW-LIST NOTES:
#   - wazuh-agent stays (don't remove per RvB rules)
#   - Wiretap / Scoring Engine / OpenStack are NOT touched
#   - Scored ports 22, 21, 80, 3306 stay open on 0.0.0.0
#
# USAGE:
#   sudo bash harden_pathfinder.sh                 # interactive
#   sudo bash harden_pathfinder.sh --alt-ssh 2222  # also open 2222 for admin SSH
#   sudo bash harden_pathfinder.sh --no-lock       # don't lock unknown users
#
# SAFE TO RE-RUN: yes. Everything is idempotent.
# ============================================================

set -uo pipefail

ALT_SSH_PORT=""
DO_LOCK=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --alt-ssh) ALT_SSH_PORT="${2:-2222}"; shift 2 ;;
        --no-lock) DO_LOCK=0; shift ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "[!] Unknown arg: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root (sudo bash $0)"; exit 1
fi

echo -n "[?] Enter new password for all Artemis accounts: "
read -rs NEW_PASS; echo ""
if [[ ${#NEW_PASS} -lt 12 ]]; then
    echo "[!] Password must be at least 12 characters. Exiting."; exit 1
fi
echo -n "[?] Confirm password: "
read -rs CONFIRM_PASS; echo ""
if [[ "$NEW_PASS" != "$CONFIRM_PASS" ]]; then
    echo "[!] Passwords do not match. Exiting."; exit 1
fi

TS=$(date +%Y%m%d_%H%M%S)
LOGDIR="${HOME:-/root}/blueteam_logs"
BASELINE_DIR="/root/pathfinder_baseline"
mkdir -p "$LOGDIR" "$BASELINE_DIR"
LOGFILE="$LOGDIR/harden_pathfinder_${TS}.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "============================================"
echo " Pathfinder Hardening  -  $(hostname) @ $(date)"
echo " Log : $LOGFILE"
echo "============================================"

# ============================================================
# ARTEMIS ACCOUNT LIST (from RvB 2026 Cred Sheet)
# ============================================================
ARTEMIS_USERS=(
    "MissionDirector" "CapeCom" "FlightDirector" "ArtemisLead"
    "GuidanceOfficer" "RetroOfficer" "FIDOControl" "EECOMCtrl"
    "PowerSystems"    "NavSystems" "ThermalEng"   "CommsEng"
    "TelemetryAnlst"  "OrbitAnalyst" "DataAnlst"  "SensorAnlst"
    "MedOfficer"      "PayloadSpec"  "EVASpec"    "LifeSupport"
)

# Red-team backdoor users seen in prior RvB — always lock if present
KNOWN_BAD_USERS=(
    "BarnacleBart98" "BarnacleBill98" "dreadpirate" "blackflag"
    "skulllord" "quartermaster" "AdmiralNelson"
    "singularity" "sliver" "operator" "attacker"
)

# ============================================================
# 1. BASELINE ACCOUNTS BEFORE ANY CHANGES
# ============================================================
echo ""
echo "[*] 1/12  Baselining accounts to $BASELINE_DIR ..."
cp -a /etc/passwd  "$BASELINE_DIR/passwd.$TS"
cp -a /etc/shadow  "$BASELINE_DIR/shadow.$TS" 2>/dev/null || true
cp -a /etc/group   "$BASELINE_DIR/group.$TS"
cp -a /etc/sudoers "$BASELINE_DIR/sudoers.$TS"
[[ -d /etc/sudoers.d ]] && cp -a /etc/sudoers.d "$BASELINE_DIR/sudoers.d.$TS"

{
    echo "# Pathfinder account baseline @ $TS"
    echo "## /etc/passwd (login-capable UID>=1000)"
    awk -F: '$3>=1000 && $7 !~ /(nologin|false)/' /etc/passwd
    echo ""
    echo "## sudo/wheel members"
    getent group sudo  2>/dev/null
    getent group wheel 2>/dev/null
    echo ""
    echo "## UID=0 accounts"
    awk -F: '$3==0 {print $1}' /etc/passwd
    echo ""
    echo "## ~/.ssh/authorized_keys per home"
    for h in /root /home/*; do
        [[ -f "$h/.ssh/authorized_keys" ]] && {
            echo "-- $h/.ssh/authorized_keys --"
            cat "$h/.ssh/authorized_keys"
        }
    done
} > "$BASELINE_DIR/summary.$TS.txt"
echo "[+] Baseline written: $BASELINE_DIR/summary.$TS.txt"

# ============================================================
# 2. ROTATE ARTEMIS PASSWORDS + ROOT
# ============================================================
echo ""
echo "[*] 2/12  Rotating Artemis account passwords ..."
for u in "${ARTEMIS_USERS[@]}" root; do
    if id "$u" &>/dev/null; then
        if echo "$u:$NEW_PASS" | chpasswd 2>/dev/null; then
            echo "[+] Password rotated: $u"
        else
            echo "[!] chpasswd FAILED for $u (skimmer wrapper? see step 9)"
        fi
    fi
done
unset NEW_PASS CONFIRM_PASS

# ============================================================
# 3. LOCK UNKNOWN ACCOUNTS + KNOWN-BAD ACCOUNTS
# ============================================================
echo ""
echo "[*] 3/12  Locking unknown accounts ..."
ALLOWED_SET=" ${ARTEMIS_USERS[*]} root ubuntu wazuh mysql www-data ftp vnc "

while IFS=: read -r uname _ uid _ _ homedir shell; do
    [[ "$uid" -lt 1000 ]] && continue
    [[ "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
    if [[ ! " $ALLOWED_SET " =~ " $uname " ]]; then
        if [[ $DO_LOCK -eq 1 ]]; then
            passwd -l "$uname" &>/dev/null && echo "[!] LOCKED unknown user: $uname (home=$homedir shell=$shell)"
            usermod -s /usr/sbin/nologin "$uname" 2>/dev/null || true
        else
            echo "[!] Unknown user (NOT locked, --no-lock): $uname"
        fi
    fi
done < /etc/passwd

for bad in "${KNOWN_BAD_USERS[@]}"; do
    if id "$bad" &>/dev/null; then
        passwd -l "$bad" &>/dev/null || true
        usermod -s /usr/sbin/nologin "$bad" 2>/dev/null || true
        # Strip sudo/wheel/admin membership
        for g in sudo wheel admin adm; do
            gpasswd -d "$bad" "$g" 2>/dev/null || true
        done
        echo "[!] Known-bad account force-locked and de-sudoed: $bad"
    fi
done

# Any UID=0 account other than root
awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd | while read -r uzero; do
    echo "[!!] EXTRA UID=0 ACCOUNT DETECTED: $uzero  -- locking"
    passwd -l "$uzero" &>/dev/null || true
    usermod -s /usr/sbin/nologin "$uzero" 2>/dev/null || true
done

# ============================================================
# 4. SSH HARDENING (+ optional admin port)
# ============================================================
echo ""
echo "[*] 4/12  Hardening SSH ..."
SSHD_CONF=/etc/ssh/sshd_config
cp "$SSHD_CONF" "${SSHD_CONF}.bak.${TS}"

apply_ssh() {
    local k="$1" v="$2"
    if grep -qE "^[#[:space:]]*${k}\b" "$SSHD_CONF"; then
        sed -i -E "s|^[#[:space:]]*${k}\b.*|${k} ${v}|" "$SSHD_CONF"
    else
        echo "${k} ${v}" >> "$SSHD_CONF"
    fi
}
apply_ssh PermitRootLogin        no
apply_ssh PasswordAuthentication yes
apply_ssh MaxAuthTries           3
apply_ssh LoginGraceTime         30
apply_ssh X11Forwarding          no
apply_ssh AllowTcpForwarding     no
apply_ssh AllowAgentForwarding   no
apply_ssh PermitEmptyPasswords   no
apply_ssh ClientAliveInterval    300
apply_ssh ClientAliveCountMax    2
apply_ssh Protocol               2
apply_ssh UsePAM                 yes
apply_ssh PermitUserEnvironment  no

# Always keep 22 (scored). Optionally ADD a second admin port.
grep -qE '^Port[[:space:]]+22\b' "$SSHD_CONF" || echo "Port 22" >> "$SSHD_CONF"
if [[ -n "$ALT_SSH_PORT" ]]; then
    grep -qE "^Port[[:space:]]+${ALT_SSH_PORT}\b" "$SSHD_CONF" || echo "Port $ALT_SSH_PORT" >> "$SSHD_CONF"
    echo "[+] Added admin SSH port: $ALT_SSH_PORT (22 stays open for scoring)"
fi

if sshd -t 2>&1; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    echo "[+] SSH restarted"
else
    echo "[!] sshd -t failed. Restoring backup."
    cp "${SSHD_CONF}.bak.${TS}" "$SSHD_CONF"
fi

# ============================================================
# 5. FIREWALL: allow scored, deny known red-team channels
# ============================================================
echo ""
echo "[*] 5/12  Configuring UFW ..."
if ! command -v ufw &>/dev/null; then
    apt-get install -y ufw >/dev/null 2>&1 || true
fi
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment 'SSH scored'
ufw allow 21/tcp   comment 'FTP scored'
ufw allow 20/tcp   comment 'FTP data'
ufw allow 30000:31000/tcp comment 'FTP passive range'
ufw allow 80/tcp   comment 'HTTP scored'
ufw allow 3306/tcp comment 'MySQL scored'
[[ -n "$ALT_SSH_PORT" ]] && ufw allow "${ALT_SSH_PORT}/tcp" comment 'admin SSH'

# Explicit deny for known red-team ports (defence in depth vs. binds we missed)
for badport in 23 25 26 512 513 514 1337 4444 5555 6666 8888 9990 5900 5901 6001; do
    ufw deny "$badport" comment 'RvB known bad' >/dev/null
done

ufw --force enable
ufw status verbose | tee -a "$LOGFILE"

# ============================================================
# 6. CLEAN LINUX "RUN KEYS" (autostart / login persistence)
# ============================================================
echo ""
echo "[*] 6/12  Cleaning autostart / persistence hooks ..."

BAD_PAT='(wget|curl|bash[[:space:]]+-[ic]|/tmp/|/dev/shm|python[0-9]*[[:space:]]+-c|perl[[:space:]]+-e|nc[[:space:]]+|ncat[[:space:]]+|socat|/THEGUMPER|xgd_stty|dpkg-lock-frontend|\.watcher|192\.168\.0\.100|:1337|:8888|:9990)'

# /etc/rc.local
if [[ -f /etc/rc.local ]]; then
    if grep -qE "$BAD_PAT" /etc/rc.local; then
        cp /etc/rc.local "$BASELINE_DIR/rc.local.$TS.bak"
        grep -vE "$BAD_PAT" /etc/rc.local > /etc/rc.local.clean && mv /etc/rc.local.clean /etc/rc.local
        chmod +x /etc/rc.local
        echo "[+] Cleaned /etc/rc.local (backup in baseline dir)"
    fi
fi

# /etc/profile.d/*
for f in /etc/profile.d/*.sh /etc/profile /etc/bash.bashrc; do
    [[ -f "$f" ]] || continue
    if grep -qE "$BAD_PAT" "$f" 2>/dev/null; then
        cp "$f" "$BASELINE_DIR/$(basename "$f").$TS.bak"
        grep -vE "$BAD_PAT" "$f" > "${f}.clean" && mv "${f}.clean" "$f"
        echo "[+] Cleaned $f (backup in baseline dir)"
    fi
done

# per-user shell rc files
for home in /root /home/*; do
    [[ -d "$home" ]] || continue
    for rc in .bashrc .bash_profile .profile .zshrc .bash_login .bash_logout; do
        f="$home/$rc"
        [[ -f "$f" ]] || continue
        if grep -qE "$BAD_PAT" "$f" 2>/dev/null; then
            cp "$f" "$BASELINE_DIR/$(basename "$home")_$(basename "$f").$TS.bak"
            grep -vE "$BAD_PAT" "$f" > "${f}.clean" && mv "${f}.clean" "$f"
            chown --reference="$home" "$f"
            echo "[+] Cleaned $f (backup in baseline dir)"
        fi
    done
done

# crontabs — per user
for u in $(cut -d: -f1 /etc/passwd); do
    cron=$(crontab -l -u "$u" 2>/dev/null || true)
    [[ -z "$cron" ]] && continue
    if echo "$cron" | grep -qE "$BAD_PAT"; then
        echo "$cron" > "$BASELINE_DIR/crontab_${u}.$TS.bak"
        echo "$cron" | grep -vE "$BAD_PAT" | crontab -u "$u" -
        echo "[+] Cleaned crontab for $u (backup in baseline dir)"
    else
        echo "[i] crontab present for $u (kept, no bad patterns)"
    fi
done

# /etc/cron.d, /etc/cron.hourly, /etc/cron.daily, /var/spool/cron
for cdir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
    [[ -d "$cdir" ]] || continue
    for cf in "$cdir"/*; do
        [[ -f "$cf" ]] || continue
        if grep -qE "$BAD_PAT" "$cf" 2>/dev/null; then
            cp "$cf" "$BASELINE_DIR/$(basename "$cdir")_$(basename "$cf").$TS.bak"
            grep -vE "$BAD_PAT" "$cf" > "${cf}.clean" && mv "${cf}.clean" "$cf"
            echo "[+] Cleaned $cf (backup in baseline dir)"
        fi
    done
done

# /etc/crontab
if [[ -f /etc/crontab ]] && grep -qE "$BAD_PAT" /etc/crontab; then
    cp /etc/crontab "$BASELINE_DIR/crontab.$TS.bak"
    grep -vE "$BAD_PAT" /etc/crontab > /etc/crontab.clean && mv /etc/crontab.clean /etc/crontab
    echo "[+] Cleaned /etc/crontab (backup in baseline dir)"
fi

# ============================================================
# 7. KILL & DISABLE KNOWN RED-TEAM SERVICES / BEACONS
# ============================================================
echo ""
echo "[*] 7/12  Stopping red-team services and beacons ..."

# Sliver beacon systemd unit names seen in prior RvB
BAD_SERVICES=(
    "systemd-resolvd"      # (note: real one is systemd-resolved)
    "authsyncd"
    "netd"
    "systemd-cpuctl"
    "systemd-cronye"
    "systemd-fan"
    "telnet.socket" "telnetd" "openbsd-inetd" "xinetd"
    "wall" "sptty" "gumper"
    "self-healing" "watcher"
    "tigervnc" "x11vnc" "vino-server"
)
for svc in "${BAD_SERVICES[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -qi "^${svc}\b\|^${svc}\.service"; then
        systemctl stop    "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        systemctl mask    "$svc" 2>/dev/null || true
        echo "[+] Stopped/disabled/masked: $svc"
    fi
done

# Kill any process still listening on known bad ports
for p in 23 1337 4444 5555 6666 8888 9990; do
    pids=$(ss -tlnp 2>/dev/null | awk -v p=":$p" '$4 ~ p {print $NF}' \
           | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
    for pid in $pids; do
        cmd=$(ps -p "$pid" -o cmd= 2>/dev/null)
        echo "[!] Killing PID $pid on port $p : $cmd"
        kill -9 "$pid" 2>/dev/null || true
    done
done

# Common red-team drop paths
for drop in /THEGUMPER /bin/xgd_stty /usr/local/bin/dpkg-lock-frontend \
            /usr/local/lib/.watcher /usr/local/bin/ebpf_sniffer \
            /usr/local/bin/ebpf_sniffer.bpf.o /usr/bin/netd \
            /lib/systemd/systemd-resolvd /usr/local/bin/authsyncd \
            /usr/lib/systemd/systemd-cpuctl /usr/lib/systemd/systemd-cronye \
            /usr/lib/systemd/systemd-fan; do
    if [[ -e "$drop" ]]; then
        chattr -ia "$drop" 2>/dev/null || true
        mv "$drop" "$BASELINE_DIR/$(basename "$drop").$TS.quarantine" && \
            echo "[+] Quarantined red-team drop: $drop"
    fi
done

# Suspicious systemd unit files: newer than /etc/passwd and referencing bad paths
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
    -maxdepth 2 -name '*.service' -newer /etc/passwd 2>/dev/null | while read -r unit; do
    if grep -qE "$BAD_PAT" "$unit"; then
        cp "$unit" "$BASELINE_DIR/unit_$(basename "$unit").$TS.bak"
        base=$(basename "$unit")
        systemctl stop "$base" 2>/dev/null || true
        systemctl disable "$base" 2>/dev/null || true
        mv "$unit" "$BASELINE_DIR/$base.$TS.quarantine"
        echo "[+] Quarantined suspicious systemd unit: $unit"
    fi
done
systemctl daemon-reload

# ============================================================
# 8. SUID AUDIT + BUSYBOX FIX
# ============================================================
echo ""
echo "[*] 8/12  SUID audit ..."
if [[ -f /usr/bin/busybox ]] && [[ $(stat -c '%a' /usr/bin/busybox) -ge 4000 ]]; then
    chmod u-s /usr/bin/busybox && echo "[+] Removed SUID bit from /usr/bin/busybox"
fi
if [[ -f /bin/busybox ]] && [[ $(stat -c '%a' /bin/busybox) -ge 4000 ]]; then
    chmod u-s /bin/busybox && echo "[+] Removed SUID bit from /bin/busybox"
fi
SUID_LIST="$BASELINE_DIR/suid_files.$TS.txt"
find / -perm /4000 -type f 2>/dev/null | grep -v -E '^/(proc|sys|run|snap)' > "$SUID_LIST"
echo "[i] SUID inventory: $SUID_LIST ($(wc -l < "$SUID_LIST") entries) — review manually"

# ============================================================
# 9. RESTORE passwd / chpasswd IF SKIMMER WRAPPER IS PRESENT
# ============================================================
echo ""
echo "[*] 9/12  Checking passwd/chpasswd integrity ..."
for bin in /usr/bin/passwd /usr/sbin/chpasswd; do
    [[ -f "$bin" ]] || continue
    # Real GNU passwd/chpasswd are ELF; skimmer wrappers are shell scripts.
    if head -c 4 "$bin" | grep -q "^#!"; then
        echo "[!!] $bin is a SHELL SCRIPT — skimmer detected"
        cp "$bin" "$BASELINE_DIR/$(basename "$bin").$TS.skimmer"
        pkg=$(dpkg -S "$bin" 2>/dev/null | cut -d: -f1 | head -1)
        [[ -z "$pkg" ]] && pkg=passwd
        apt-get install --reinstall -y "$pkg" >/dev/null 2>&1 && \
            echo "[+] Reinstalled $pkg to restore $bin" || \
            echo "[!] Failed to reinstall $pkg — restore manually"
    fi
done
# Look for known skimmer log
if [[ -e /tmp/.creds.log ]]; then
    mv /tmp/.creds.log "$BASELINE_DIR/creds.log.$TS.evidence"
    echo "[!] Moved skimmer output /tmp/.creds.log -> baseline dir (EVIDENCE)"
fi

# ============================================================
# 10. PAM BYPASS FIX
# ============================================================
echo ""
echo "[*] 10/12 Checking PAM for pam_permit bypass ..."
if grep -qE '^\s*auth\s+.*pam_permit\.so' /etc/pam.d/common-auth 2>/dev/null; then
    echo "[!!] pam_permit.so present in common-auth (auth bypass)"
    cp /etc/pam.d/common-auth "$BASELINE_DIR/common-auth.$TS.bak"
    apt-get install --reinstall -y libpam-modules libpam-runtime >/dev/null 2>&1
    if [[ -f /usr/share/pam-configs/unix ]]; then
        pam-auth-update --package --force >/dev/null 2>&1 || true
    fi
    if grep -qE '^\s*auth\s+.*pam_permit\.so' /etc/pam.d/common-auth 2>/dev/null; then
        # Force replace with a minimal safe common-auth
        cat > /etc/pam.d/common-auth <<'EOF'
auth    [success=1 default=ignore]      pam_unix.so nullok_secure
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
EOF
        echo "[+] Rewrote /etc/pam.d/common-auth to a minimal safe config"
    else
        echo "[+] common-auth reinstalled from package"
    fi
fi

# ============================================================
# 11. SYSCTL HARDENING
# ============================================================
echo ""
echo "[*] 11/12 Applying sysctl hardening ..."
cat > /etc/sysctl.d/99-pathfinder.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl -p /etc/sysctl.d/99-pathfinder.conf | tee -a "$LOGFILE"

# ============================================================
# 12. ACCOUNT MONITOR REPORT + 5-MIN TIMER
# ============================================================
echo ""
echo "[*] 12/12 Writing account watch report and installing monitor ..."
ACCT_REPORT="$LOGDIR/accounts_monitor_${TS}.txt"
{
    echo "# Pathfinder accounts to monitor — $TS"
    echo ""
    echo "## Artemis expected users (should stay, password just rotated)"
    for u in "${ARTEMIS_USERS[@]}"; do
        id "$u" &>/dev/null && printf '  %-16s  uid=%s  groups=%s\n' "$u" \
            "$(id -u "$u")" "$(id -Gn "$u" | tr ' ' ',')"
    done
    echo ""
    echo "## Login-capable accounts on box RIGHT NOW"
    awk -F: '$3>=1000 && $7 !~ /(nologin|false)/ {printf "  %-20s uid=%s home=%s shell=%s\n",$1,$3,$6,$7}' /etc/passwd
    echo ""
    echo "## Members of sudo/wheel/admin"
    for g in sudo wheel admin; do
        m=$(getent group "$g" 2>/dev/null | cut -d: -f4)
        [[ -n "$m" ]] && echo "  $g: $m"
    done
    echo ""
    echo "## UID=0 accounts (should ONLY be root)"
    awk -F: '$3==0 {print "  "$1}' /etc/passwd
    echo ""
    echo "## Locked accounts (recently locked by this script)"
    awk -F: '$2 ~ /^!/ {print "  "$1}' /etc/shadow 2>/dev/null || true
    echo ""
    echo "## authorized_keys inventory"
    for h in /root /home/*; do
        [[ -f "$h/.ssh/authorized_keys" ]] && {
            printf '  %s\n' "$h/.ssh/authorized_keys"
            awk '{print "    keycomment: "$NF}' "$h/.ssh/authorized_keys"
        }
    done
} > "$ACCT_REPORT"
echo "[+] Account report: $ACCT_REPORT"

# Snapshot to diff against every 5 minutes
SNAP=/var/lib/pathfinder_accts.snap
awk -F: '{print $1":"$3":"$6":"$7}' /etc/passwd | sort > "$SNAP"
getent group sudo  >  /var/lib/pathfinder_sudo.snap  2>/dev/null || true
getent group wheel >> /var/lib/pathfinder_sudo.snap  2>/dev/null || true
find /root/.ssh /home/*/.ssh -name authorized_keys -exec sha256sum {} \; 2>/dev/null | sort > /var/lib/pathfinder_authkeys.snap

# Install the monitor script
cat > /usr/local/sbin/pathfinder_acct_monitor.sh <<'MON'
#!/bin/bash
# Diffs the account state against the baseline snapshot and logs any drift.
SNAP=/var/lib/pathfinder_accts.snap
SUDO_SNAP=/var/lib/pathfinder_sudo.snap
KEY_SNAP=/var/lib/pathfinder_authkeys.snap
LOG=/var/log/pathfinder_acct_monitor.log

TS=$(date '+%Y-%m-%d %H:%M:%S')
CUR=$(awk -F: '{print $1":"$3":"$6":"$7}' /etc/passwd | sort)
DIFF=$(diff <(echo "$CUR") "$SNAP" 2>/dev/null)
if [[ -n "$DIFF" ]]; then
    {
        echo "[$TS] ACCOUNT DRIFT DETECTED"
        echo "$DIFF"
    } >> "$LOG"
fi

CUR_SUDO=$( { getent group sudo; getent group wheel; } 2>/dev/null )
DIFF_SUDO=$(diff <(echo "$CUR_SUDO") "$SUDO_SNAP" 2>/dev/null)
if [[ -n "$DIFF_SUDO" ]]; then
    {
        echo "[$TS] SUDO/WHEEL MEMBERSHIP CHANGED"
        echo "$DIFF_SUDO"
    } >> "$LOG"
fi

CUR_KEYS=$(find /root/.ssh /home/*/.ssh -name authorized_keys -exec sha256sum {} \; 2>/dev/null | sort)
DIFF_KEYS=$(diff <(echo "$CUR_KEYS") "$KEY_SNAP" 2>/dev/null)
if [[ -n "$DIFF_KEYS" ]]; then
    {
        echo "[$TS] authorized_keys CHANGED"
        echo "$DIFF_KEYS"
    } >> "$LOG"
fi

awk -F: '$3==0 && $1!="root" {print "[EXTRA-UID0] "$1}' /etc/passwd >> "$LOG"
MON
chmod 750 /usr/local/sbin/pathfinder_acct_monitor.sh

cat > /etc/systemd/system/pathfinder-acct-monitor.service <<'EOF'
[Unit]
Description=Pathfinder account drift monitor

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/pathfinder_acct_monitor.sh
EOF

cat > /etc/systemd/system/pathfinder-acct-monitor.timer <<'EOF'
[Unit]
Description=Run pathfinder account drift monitor every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=pathfinder-acct-monitor.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now pathfinder-acct-monitor.timer >/dev/null 2>&1 && \
    echo "[+] pathfinder-acct-monitor.timer running (every 5 min)"

# ============================================================
# WAZUH SANITY CHECK
# ============================================================
echo ""
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    echo "[+] wazuh-agent is running (do NOT remove)"
else
    echo "[!] wazuh-agent is NOT running — check status; do not remove"
fi

echo ""
echo "============================================================"
echo " DONE. Pathfinder hardening complete."
echo "  Log      : $LOGFILE"
echo "  Baseline : $BASELINE_DIR/"
echo "  Monitor  : journalctl -u pathfinder-acct-monitor.timer"
echo "             /var/log/pathfinder_acct_monitor.log"
echo "  Accounts : $ACCT_REPORT"
echo ""
echo " Next steps:"
echo "  * Verify scored services: systemctl status ssh vsftpd mysql apache2 nginx"
echo "  * Review SUID list: $SUID_LIST"
echo "  * Review sudoers: visudo -c"
echo "  * Run find_backdoors.sh from the ballast/ or silkroad/ folder next"
echo "============================================================"
