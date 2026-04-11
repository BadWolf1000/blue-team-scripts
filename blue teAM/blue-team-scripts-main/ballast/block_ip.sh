#!/bin/bash
# ============================================================
# DreadWatch Blue Team - IP Blocker
#
# WHAT THIS SCRIPT DOES:
#   Blocks individual attacker IP addresses using iptables.
#   Blocks both inbound AND outbound traffic to/from that IP.
#   Keeps a log of all blocks with timestamps.
#   Validates that you're not accidentally blocking a subnet
#   (which would violate competition rules).
#
# COMPETITION RULE: You CAN block individual IPs.
#                   You CANNOT block entire subnets (e.g. 10.x.x.0/24).
#                   This script enforces that rule automatically.
#
# HOW TO USE:
#   --- Block a single attacker IP ---
#   sudo bash block_ip.sh 10.x.x.x
#
#   --- See all currently blocked IPs ---
#   sudo bash block_ip.sh list
#
#   --- Unblock an IP (if you blocked the wrong one) ---
#   sudo bash block_ip.sh unblock 10.x.x.x
#
#   --- Block multiple IPs from a file (one IP per line) ---
#   sudo bash block_ip.sh bulk /tmp/attacker_ips.txt
#
# HOW TO FIND ATTACKER IPs TO BLOCK:
#   From ir_monitor.sh evidence:  cat $HOME/blueteam_logs/connected_ips.txt
#   From active connections:      ss -tnp state established
#   From auth log:                grep "Failed password" /var/log/auth.log
#
# NOTE: Blocks are NOT persistent across reboots by default.
#       If the machine reboots, re-run your blocks.
#       Log of all blocks: /var/log/blueteam_blocked_ips.txt
# ============================================================

ACTION="${1:-help}"
TARGET="${2:-}"

BLOCKED_LOG="/var/log/blueteam_blocked_ips.txt"

block_ip() {
    local ip="$1"
    # Validate it's a single IP, not a subnet
    if [[ "$ip" =~ / ]]; then
        echo "[!] RULE VIOLATION: Blocking subnets is NOT allowed! Use single IPs only."
        exit 1
    fi
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "[!] Invalid IP: $ip"
        exit 1
    fi

    # Use iptables (works on all distros)
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo "[*] $ip is already blocked"
    else
        iptables -I INPUT -s "$ip" -j DROP
        iptables -I OUTPUT -d "$ip" -j DROP
        echo "[+] BLOCKED: $ip"
        echo "$(date '+%Y-%m-%d %H:%M:%S') BLOCKED $ip" >> "$BLOCKED_LOG"
    fi
}

case "$ACTION" in
    list)
        echo "=== Currently blocked IPs ==="
        iptables -L INPUT -n --line-numbers | grep DROP
        echo ""
        echo "=== Block history ==="
        cat "$BLOCKED_LOG" 2>/dev/null || echo "(no log yet)"
        ;;
    unblock)
        if [[ -z "$TARGET" ]]; then echo "Usage: $0 unblock <IP>"; exit 1; fi
        iptables -D INPUT -s "$TARGET" -j DROP 2>/dev/null && echo "[+] Unblocked INPUT: $TARGET"
        iptables -D OUTPUT -d "$TARGET" -j DROP 2>/dev/null && echo "[+] Unblocked OUTPUT: $TARGET"
        ;;
    bulk)
        FILE="${2:-}"
        if [[ ! -f "$FILE" ]]; then echo "File not found: $FILE"; exit 1; fi
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            block_ip "$line"
        done < "$FILE"
        ;;
    help|--help|-h)
        grep '^# Usage' "$0" | sed 's/^# //'
        ;;
    *)
        # Treat first arg as an IP to block
        block_ip "$ACTION"
        ;;
esac
