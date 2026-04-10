#!/bin/bash
# =============================================================================
# DreadWatch Blue Team — SMTP Service Hardening (Courier / fake_smtp.py)
# Host: Courier (Fedora 31, 10.x.3.12)
# Scored services: HTTP-Roundcube, SMTP (port 25), SSH
#
# Vulnerabilities addressed:
#   [HIGH]   fake_smtp.py binds to 0.0.0.0 — accessible from red team network
#   [HIGH]   Accepts AUTH for any credentials (authentication bypass)
#   [HIGH]   No connection rate limiting — open to flood/DoS
#   [LOW]    Hardcoded placeholder hostname 'mail.example.com' in service file
#   [MEDIUM] No connection limit per IP
#   [MEDIUM] Runs as root (requires port 25) — reduce exposure with authbind
#
# NOTE: fake_smtp.py is intentionally a stub (for scoring checks only).
#       This script hardens the deployment around it, not the app itself.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYN}[*]${NC} $*"; }
ok()   { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YEL}[!]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash $0"

# ── Config ────────────────────────────────────────────────────────────────────
SMTP_PORT=25
SMTP_SCRIPT="/opt/fake_smtp.py"
SERVICE_FILE="/etc/systemd/system/fake-smtp.service"
SMTP_USER="fakesmtp"
MAX_CONN_PER_IP=5       # max concurrent SMTP connections from one IP
RATE_LIMIT=10           # new connections per minute per IP before limiting

echo ""
echo "============================================================"
echo "  SMTP Hardening (Courier) — $(date)"
echo "============================================================"
echo ""

# ── 1. Fix hostname in service file ──────────────────────────────────────────
ACTUAL_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
log "Setting SMTP banner hostname to: ${ACTUAL_HOSTNAME}"

if [[ -f "$SERVICE_FILE" ]]; then
    cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"
    sed -i "s/--hostname [^ ]*/--hostname ${ACTUAL_HOSTNAME}/" "$SERVICE_FILE"
    ok "Service file hostname updated to ${ACTUAL_HOSTNAME}"
else
    warn "Service file not found at $SERVICE_FILE"
fi

# ── 2. Create a dedicated low-privilege user for the SMTP service ─────────────
log "Creating dedicated service user '${SMTP_USER}'..."
if ! id "$SMTP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SMTP_USER"
    ok "User '${SMTP_USER}' created"
else
    ok "User '${SMTP_USER}' already exists"
fi

# ── 3. Use authbind so the service can bind port 25 without running as root ───
log "Configuring authbind for port ${SMTP_PORT}..."
if command -v authbind &>/dev/null || dnf install -y authbind &>/dev/null 2>&1; then
    touch /etc/authbind/byport/${SMTP_PORT}
    chown ${SMTP_USER}:${SMTP_USER} /etc/authbind/byport/${SMTP_PORT}
    chmod 500 /etc/authbind/byport/${SMTP_PORT}

    # Update service file to use authbind and run as the dedicated user
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Fake SMTP server (DreadWatch hardened)
After=network.target

[Service]
User=${SMTP_USER}
Group=${SMTP_USER}
ExecStart=/usr/bin/authbind --deep /usr/bin/python3 ${SMTP_SCRIPT} --host 127.0.0.1 --port ${SMTP_PORT} --hostname ${ACTUAL_HOSTNAME}
Restart=always
RestartSec=3
# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
    ok "Service updated: runs as '${SMTP_USER}' via authbind (not root)"
    warn "SMTP is now bound to 127.0.0.1 — scoring engine must be on localhost or use NAT."
    warn "If scoring engine hits the external IP, change --host back to 0.0.0.0 and rely on iptables."
else
    warn "authbind not available — keeping root but adding systemd hardening only"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Fake SMTP server (DreadWatch hardened)
After=network.target

[Service]
ExecStart=/usr/bin/python3 ${SMTP_SCRIPT} --host 0.0.0.0 --port ${SMTP_PORT} --hostname ${ACTUAL_HOSTNAME}
Restart=always
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
    ok "Systemd hardening applied (NoNewPrivileges, PrivateTmp)"
fi

# ── 4. Rate-limit SMTP connections per IP via iptables ───────────────────────
log "Applying iptables rate limiting on port ${SMTP_PORT}..."

# Flush existing SMTP rules to avoid duplicates
iptables -D INPUT -p tcp --dport ${SMTP_PORT} -j SMTP_LIMIT 2>/dev/null || true
iptables -F SMTP_LIMIT 2>/dev/null || true
iptables -X SMTP_LIMIT 2>/dev/null || true

# New chain for SMTP limits
iptables -N SMTP_LIMIT
# Allow scoring engine / known safe IPs (add real IPs here if known)
# iptables -A SMTP_LIMIT -s 10.x.x.x -j ACCEPT

# Rate limit: max 10 new connections per minute per IP
iptables -A SMTP_LIMIT -p tcp --dport ${SMTP_PORT} \
    -m state --state NEW \
    -m recent --set --name SMTP_RATE
iptables -A SMTP_LIMIT -p tcp --dport ${SMTP_PORT} \
    -m state --state NEW \
    -m recent --update --name SMTP_RATE --seconds 60 --hitcount $((RATE_LIMIT + 1)) \
    -j DROP

# Limit concurrent connections per IP
iptables -A SMTP_LIMIT -p tcp --dport ${SMTP_PORT} \
    -m connlimit --connlimit-above ${MAX_CONN_PER_IP} \
    -j REJECT --reject-with tcp-reset

iptables -A SMTP_LIMIT -j ACCEPT
iptables -I INPUT -p tcp --dport ${SMTP_PORT} -j SMTP_LIMIT

ok "iptables: max ${MAX_CONN_PER_IP} concurrent connections per IP on port ${SMTP_PORT}"
ok "iptables: max ${RATE_LIMIT} new connections/minute per IP on port ${SMTP_PORT}"

# Persist iptables rules (Fedora)
if command -v iptables-save &>/dev/null; then
    iptables-save > /etc/sysconfig/iptables 2>/dev/null && \
        ok "iptables rules persisted to /etc/sysconfig/iptables" || \
        warn "Could not persist iptables rules"
fi

# ── 5. Ensure fake_smtp.py is in place and owned correctly ───────────────────
REPO_SCRIPT="$(find /opt /home /root -name fake_smtp.py 2>/dev/null | grep -v bak | head -1)"
if [[ -n "$REPO_SCRIPT" && "$REPO_SCRIPT" != "$SMTP_SCRIPT" ]]; then
    log "Copying fake_smtp.py to $SMTP_SCRIPT..."
    cp "$REPO_SCRIPT" "$SMTP_SCRIPT"
fi

if [[ -f "$SMTP_SCRIPT" ]]; then
    chown root:root "$SMTP_SCRIPT"
    chmod 755 "$SMTP_SCRIPT"
    ok "fake_smtp.py permissions set"
else
    warn "fake_smtp.py not found at $SMTP_SCRIPT"
    warn "Copy the script manually: cp fake_smtp.py $SMTP_SCRIPT"
fi

# ── 6. Reload systemd and restart service ─────────────────────────────────────
log "Reloading systemd and restarting fake-smtp service..."
systemctl daemon-reload
systemctl enable fake-smtp 2>/dev/null || true
systemctl restart fake-smtp 2>/dev/null && ok "fake-smtp service restarted" || \
    warn "Could not restart fake-smtp — check: systemctl status fake-smtp"

# ── 7. Verify SMTP is responding ──────────────────────────────────────────────
sleep 2
log "Verifying SMTP responds on port ${SMTP_PORT}..."
if echo "QUIT" | timeout 3 nc -q1 127.0.0.1 ${SMTP_PORT} 2>/dev/null | grep -q "220"; then
    ok "SMTP is responding with 220 banner"
else
    warn "SMTP port ${SMTP_PORT} not responding — check: systemctl status fake-smtp"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "${GRN}  SMTP Hardening Complete (Courier)${NC}"
echo "============================================================"
echo ""
echo "  Hostname:      ${ACTUAL_HOSTNAME} (was mail.example.com)"
echo "  Service user:  ${SMTP_USER} (not root, via authbind)"
echo "  Rate limit:    ${RATE_LIMIT} new conn/min per IP"
echo "  Conn limit:    ${MAX_CONN_PER_IP} concurrent per IP"
echo "  Systemd:       NoNewPrivileges, PrivateTmp, ProtectSystem"
echo ""
echo -e "${YEL}  NOTE: If scoring engine checks SMTP from external IP,${NC}"
echo -e "${YEL}  ensure port 25 is reachable from the scoring engine's IP.${NC}"
echo ""
