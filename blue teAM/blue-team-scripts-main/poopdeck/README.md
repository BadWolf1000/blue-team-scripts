# PoopDeck — Debian 10 | 10.x.1.11
**Scored:** DNS, HTTP-WikiJS, SSH

---

## Setup (run once at start)
```bash
cd /opt/bt/poopdeck && chmod +x *.sh

# 1. Harden the OS
sudo bash harden_linux.sh

# 2. Scan for webshells (WikiJS is a web app — check early)
sudo bash webshell_scanner.sh

# 3. Scan for pre-planted backdoors
sudo bash find_backdoors.sh

# 4. Start evidence monitor (keep running all match)
sudo bash ir_monitor.sh &

# 5. Start service watchdog (keeps DNS/WikiJS/SSH alive)
sudo bash service_watchdog.sh &

# 6. Verify scored services are UP
systemctl status named nginx ssh
# WikiJS check: curl -s http://localhost | head -5
# DNS check:    dig @localhost google.com
```

---

## During the match
```bash
# Block an attacker IP
sudo bash block_ip.sh 10.x.x.x
sudo bash block_ip.sh list
sudo bash block_ip.sh unblock 10.x.x.x

# Service went down?
sudo bash recover_service.sh all
sudo bash recover_service.sh web
sudo bash recover_service.sh dns

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
sudo bash generate_ir_report.sh "Red Team DNS Hijack / WikiJS Webshell"
# Convert to PDF → upload to Discord
```
