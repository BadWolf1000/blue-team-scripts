# SilkRoad — Ubuntu 18 | 10.x.2.10
**Scored:** HTTP-SilkRoad, MySQL, SSH

---

## Setup (run once at start)
```bash
cd /opt/bt/silkroad && chmod +x *.sh

# 1. Harden the OS
sudo bash harden_linux.sh

# 2. Harden SilkRoad app + MySQL (do this BEFORE red team attacks)
#    - Locks MySQL to 127.0.0.1 (was 0.0.0.0)
#    - Rotates MySQL root, sqluser, app passwords
#    - Hashes plaintext passwords in DB
#    - Deploys hardened server.js (fixes SQLi, RCE upload, XSS)
sudo bash harden_silkroad.sh

# 3. Additional MySQL hardening
sudo bash mysql_harden.sh

# 4. Scan for webshells
sudo bash webshell_scanner.sh

# 5. Scan for pre-planted backdoors
sudo bash find_backdoors.sh

# 6. Start evidence monitor (keep running all match)
sudo bash ir_monitor.sh &

# 7. Start service watchdog (keeps HTTP/MySQL/SSH alive)
sudo bash service_watchdog.sh &

# 8. Verify scored services are UP
systemctl status nginx mysql ssh   # (use apache2 if nginx not present)
```

---

## Known vulnerabilities in SilkRoad app (patched by harden_silkroad.sh)
| Where | What |
|-------|------|
| `/login` | SQL injection — username/password interpolated directly |
| `/search` | SQL injection — query param interpolated into LIKE |
| `/admin-upload` | RCE — any uploaded file executed as bash immediately |
| `/admin` page | Plaintext password rendered in HTML response |
| `/login` response | Plaintext password returned in response body |
| Session config | Secret is `'secret-key'` — trivially forgeable |
| MySQL `my.cnf` | `bind-address = 0.0.0.0` — DB exposed on network |
| `creds` table | Passwords stored in plaintext |

---

## During the match
```bash
# Block an attacker IP
sudo bash block_ip.sh 10.x.x.x
sudo bash block_ip.sh list

# Service went down?
sudo bash recover_service.sh all
sudo bash recover_service.sh web
sudo bash recover_service.sh db

# Passwords compromised?
sudo bash change_passwords.sh

# Re-scan for new webshells
sudo bash webshell_scanner.sh
sudo bash webshell_scanner.sh --quarantine
```

---

## Incident Response
```bash
sudo bash ir_collector.sh
sudo bash generate_ir_report.sh "Red Team SQLi on SilkRoad"
# Convert to PDF → upload to Discord
```
