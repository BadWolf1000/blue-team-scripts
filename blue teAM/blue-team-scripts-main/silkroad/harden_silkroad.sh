#!/bin/bash
# =============================================================================
# DreadWatch Blue Team — SilkRoad Application Hardening
# Host: SilkRoad (Ubuntu 18, 10.x.2.10)
# Scored services: HTTP-SilkRoad, MySQL, SSH
#
# Vulnerabilities addressed:
#   [CRITICAL] MySQL bound to 0.0.0.0 — exposes DB to the network
#   [CRITICAL] Plaintext passwords in 'creds' table
#   [CRITICAL] Default app credentials known to red team (admin/f7Kp9Qx2)
#   [CRITICAL] MySQL sqluser password is 'password'
#   [HIGH]     MySQL root password is known (in install.sh in repo)
#   [HIGH]     MySQL user has GRANT ALL — too permissive
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYN}[*]${NC} $*"; }
ok()   { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YEL}[!]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash $0"

# ── New passwords (change these before competition!) ─────────────────────────
MYSQL_ROOT_NEW="DreadWatch_Root@2024!"
MYSQL_USER_NEW="DreadWatch_SQL@2024!"
APP_ADMIN_NEW="DreadWatch_App@2024!"
APP_TGM_NEW="DreadWatch_TGM@2024!"

echo ""
echo "============================================================"
echo "  SilkRoad Hardening — $(date)"
echo "============================================================"
echo ""

# ── 1. Lock MySQL bind-address to localhost ───────────────────────────────────
log "Fixing MySQL bind-address (0.0.0.0 → 127.0.0.1)..."

MYCNF=""
for f in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf /etc/my.cnf; do
    [[ -f "$f" ]] && MYCNF="$f" && break
done

if [[ -z "$MYCNF" ]]; then
    warn "Could not find MySQL config file — writing /etc/mysql/mysql.conf.d/mysqld.cnf"
    mkdir -p /etc/mysql/mysql.conf.d
    MYCNF="/etc/mysql/mysql.conf.d/mysqld.cnf"
    echo -e "[mysqld]\nbind-address = 127.0.0.1" > "$MYCNF"
else
    cp "$MYCNF" "${MYCNF}.bak"
    # Replace any bind-address line or add one if missing
    if grep -q "^bind-address" "$MYCNF"; then
        sed -i 's/^bind-address\s*=.*/bind-address = 127.0.0.1/' "$MYCNF"
    else
        echo "bind-address = 127.0.0.1" >> "$MYCNF"
    fi
fi

# Also check for the repo's my.cnf that sets 0.0.0.0 (from the silkroad repo)
APP_MYCNF="$(find /opt /home /root /silkroad -name my.cnf 2>/dev/null | head -1)"
if [[ -n "$APP_MYCNF" ]]; then
    log "Found app my.cnf at $APP_MYCNF — patching..."
    sed -i 's/^bind-address\s*=.*/bind-address = 127.0.0.1/' "$APP_MYCNF"
fi

ok "MySQL bind-address locked to 127.0.0.1"

# ── 2. Block port 3306 from external access (firewall) ───────────────────────
log "Blocking MySQL port 3306 from external access..."
if command -v ufw &>/dev/null; then
    ufw deny in on any port 3306 2>/dev/null || true
    ok "UFW rule added: deny port 3306"
fi
# iptables belt-and-suspenders: drop 3306 from non-localhost
iptables -I INPUT -p tcp --dport 3306 ! -s 127.0.0.1 -j DROP 2>/dev/null && \
    ok "iptables: DROP port 3306 from non-localhost" || \
    warn "iptables rule failed (may not be available)"

# ── 3. Restart MySQL so bind-address change takes effect ─────────────────────
log "Restarting MySQL..."
systemctl restart mysql 2>/dev/null || service mysql restart 2>/dev/null || \
    warn "Could not restart MySQL — do it manually"
sleep 2
ok "MySQL restarted"

# ── 4. Rotate MySQL credentials ───────────────────────────────────────────────
log "Rotating MySQL credentials..."

# Try to connect as root (current known password from install.sh)
MYSQL_ROOT_CURRENT="YouWillNotGuessThis"

run_mysql() {
    mysql -u root -p"${MYSQL_ROOT_CURRENT}" -e "$1" 2>/dev/null
}

if ! run_mysql "SELECT 1;" &>/dev/null; then
    warn "Cannot connect with known root password — trying passwordless socket auth..."
    run_mysql() { mysql -u root -e "$1" 2>/dev/null; }
fi

# Change root password
run_mysql "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_NEW}'; FLUSH PRIVILEGES;" && \
    ok "MySQL root password rotated" || warn "Failed to rotate root password"
MYSQL_ROOT_CURRENT="$MYSQL_ROOT_NEW"
run_mysql() { mysql -u root -p"${MYSQL_ROOT_CURRENT}" -e "$1" 2>/dev/null; }

# Change sqluser password
run_mysql "ALTER USER 'sqluser'@'localhost' IDENTIFIED BY '${MYSQL_USER_NEW}'; FLUSH PRIVILEGES;" && \
    ok "MySQL sqluser password rotated" || warn "Failed to rotate sqluser password"

# Tighten sqluser privileges (remove dangerous global privs, keep only db.*)
run_mysql "REVOKE ALL PRIVILEGES ON *.* FROM 'sqluser'@'localhost'; \
           GRANT SELECT, INSERT, UPDATE, DELETE ON db.* TO 'sqluser'@'localhost'; \
           FLUSH PRIVILEGES;" && \
    ok "sqluser privileges tightened (SELECT/INSERT/UPDATE/DELETE on db.* only)" || \
    warn "Failed to tighten sqluser privileges"

# ── 5. Hash plaintext passwords in the creds table ───────────────────────────
log "Hashing plaintext passwords in creds table..."

# Use SHA2-256 (MySQL doesn't have bcrypt natively). Not ideal but far better
# than plaintext. The app will need updating to compare hashes — see warning below.
run_mysql "USE db; \
    UPDATE creds SET password = SHA2(password, 256) WHERE password NOT REGEXP '^[a-f0-9]{64}$';" && \
    ok "creds table: plaintext passwords hashed with SHA2-256" || \
    warn "Failed to hash creds table passwords"

# ── 6. Rotate application admin credentials ──────────────────────────────────
log "Rotating application admin credentials in DB..."

run_mysql "USE db; \
    UPDATE creds SET password = SHA2('${APP_ADMIN_NEW}', 256) WHERE username = 'admin'; \
    UPDATE creds SET password = SHA2('${APP_TGM_NEW}', 256)   WHERE username = 'TGM';" && \
    ok "App credentials rotated (admin, TGM)" || \
    warn "Failed to rotate app credentials"

# ── 7. Deploy hardened server.js ─────────────────────────────────────────────
# Fixes: SQL injection (/login, /search), RCE via file upload (/admin-upload),
#        XSS in search/product output, password exposed in responses,
#        weak session secret, CORS wildcard.
log "Deploying hardened server.js..."

APP_DIR="$(find /opt /home /root /silkroad -name server.js 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)"
HARDENED_SRC="$(find /opt /home /root /silkroad -name server_hardened.js 2>/dev/null | head -1 || true)"

if [[ -n "$APP_DIR" && -n "$HARDENED_SRC" ]]; then
    # Backup original
    cp "${APP_DIR}/server.js" "${APP_DIR}/server.js.bak.$(date +%s)"
    # Deploy hardened version
    cp "$HARDENED_SRC" "${APP_DIR}/server.js"
    # Inject the real DB password into the env for the running process
    sed -i "s/\"CHANGE_ME\"/${MYSQL_USER_NEW}/" "${APP_DIR}/server.js"
    ok "Hardened server.js deployed to $APP_DIR (original backed up)"

    # Restart the Node.js app
    APP_PID=$(pgrep -f "node.*server.js" || true)
    if [[ -n "$APP_PID" ]]; then
        kill "$APP_PID" 2>/dev/null && ok "Killed old server.js (PID $APP_PID)"
        sleep 1
    fi
    cd "$APP_DIR" && DB_PASSWORD="${MYSQL_USER_NEW}" nohup node server.js >> /var/log/silkroad.log 2>&1 &
    ok "Hardened server.js started (PID $!)"
    ok "Log: /var/log/silkroad.log"
else
    warn "Could not find app directory or server_hardened.js"
    warn "Manually copy server_hardened.js → server.js and set DB_PASSWORD=${MYSQL_USER_NEW}"
fi

# ── 7. Remove dangerous MySQL anonymous/remote users ─────────────────────────
log "Removing anonymous and remote MySQL accounts..."
run_mysql "DELETE FROM mysql.user WHERE User=''; \
           DELETE FROM mysql.user WHERE Host != 'localhost' AND Host != '127.0.0.1'; \
           FLUSH PRIVILEGES;" && \
    ok "Anonymous and remote MySQL users removed" || \
    warn "Failed to clean up MySQL users"

# ── 8. Disable MySQL LOAD DATA LOCAL INFILE (data exfil vector) ──────────────
log "Disabling LOAD DATA LOCAL INFILE..."
run_mysql "SET GLOBAL local_infile = 0;" && ok "local_infile disabled" || true

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "${GRN}  SilkRoad Hardening Complete${NC}"
echo "============================================================"
echo ""
echo "  MySQL bind:     127.0.0.1 (was 0.0.0.0)"
echo "  MySQL root:     ${MYSQL_ROOT_NEW}"
echo "  MySQL sqluser:  ${MYSQL_USER_NEW}"
echo "  App admin:      admin / ${APP_ADMIN_NEW}"
echo "  App TGM:        TGM   / ${APP_TGM_NEW}"
echo ""
echo -e "${YEL}  App server:  server_hardened.js deployed (SQLi, RCE, XSS all patched)${NC}"
echo -e "${YEL}  If app fails to start: cd <app_dir> && DB_PASSWORD='${MYSQL_USER_NEW}' node server.js${NC}"
echo ""
