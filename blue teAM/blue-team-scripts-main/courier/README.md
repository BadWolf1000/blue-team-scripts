# Courier — Fedora 31 | 10.x.3.12
**Scored:** HTTP-Roundcube, SMTP, SSH

---

## Setup (run once at start)
```bash
cd /opt/bt/courier && chmod +x *.sh

# 1. Harden the OS
sudo bash harden_linux.sh

# 2. Harden the SMTP service (fake_smtp.py)
#    - Fixes banner hostname (was 'mail.example.com')
#    - Drops root via authbind → runs as dedicated 'fakesmtp' user
#    - Rate-limits: max 10 new connections/min per IP, max 5 concurrent per IP
#    - Adds systemd sandboxing (NoNewPrivileges, PrivateTmp, ProtectSystem)
sudo bash harden_smtp.sh

# 3. Scan for webshells (Roundcube is a web app — check early)
sudo bash webshell_scanner.sh

# 4. Scan for pre-planted backdoors
sudo bash find_backdoors.sh

# 5. Start evidence monitor (keep running all match)
sudo bash ir_monitor.sh &

# 6. Start service watchdog (keeps Roundcube/SMTP/SSH alive)
sudo bash service_watchdog.sh &

# 7. Verify scored services are UP
systemctl status postfix apache2 ssh fake-smtp
# SMTP check:      echo "QUIT" | nc localhost 25
# Roundcube check: curl -s http://localhost | head -5
```

---

## SMTP notes
The SMTP service is `fake_smtp.py` — a stub server for scoring only.
It accepts all connections and discards messages. This is intentional.
Key things harden_smtp.sh fixes:
- Was running as root → now runs as `fakesmtp`
- Was binding to `0.0.0.0` with no rate limiting → now rate-limited

---

## During the match
```bash
# Block an attacker IP
sudo bash block_ip.sh 10.x.x.x
sudo bash block_ip.sh list

# Service went down?
sudo bash recover_service.sh all
sudo bash recover_service.sh web
sudo bash recover_service.sh smtp

# SMTP service specifically:
sudo systemctl restart fake-smtp
sudo systemctl status fake-smtp

# Re-scan for new webshells
sudo bash webshell_scanner.sh
sudo bash webshell_scanner.sh --quarantine

# Passwords compromised?
sudo bash change_passwords.sh
```

---

## Incident Response
```bash
sudo bash ir_collector.sh
sudo bash generate_ir_report.sh "Red Team SMTP Relay / Roundcube Webshell"
# Convert to PDF → upload to Discord
```
