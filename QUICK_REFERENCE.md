# DreadWatch Blue Team - Quick Reference

## First 30 Minutes Checklist (before red team attacks)

### On EVERY Linux box (Ballast, SilkRoad, PoopDeck, Courier):
```bash
# 1. Pull scripts from GitHub
git clone https://github.com/BadWolf1000/blueteam-scripts.git /opt/bt
cd /opt/bt/linux && chmod +x *.sh

# 2. Run hardening FIRST
sudo bash harden_linux.sh

# 3. Start watchdog in background
sudo bash service_watchdog.sh &

# 4. Verify scored services are UP
# Ballast:   systemctl status vsftpd ssh
# SilkRoad:  systemctl status nginx mysql ssh  (or apache2)
# PoopDeck:  systemctl status named ssh nginx
# Courier:   systemctl status postfix dovecot apache2 ssh
```

### On EVERY Windows box (BlackPearl, JollyRoger):
```powershell
# Run from elevated PowerShell
Set-ExecutionPolicy Bypass -Scope Process -Force

# 1. Hardening
.\harden_windows.ps1

# 2. Watchdog (new window)
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File service_watchdog.ps1"

# 3. Verify services
Get-Service TermService, WinRM  # JollyRoger
Get-Service TermService, WinRM, NTDS, DNS  # BlackPearl
```

---

## Scored Services Reference

| Host       | OS              | IP          | Scored Services                        |
|------------|-----------------|-------------|----------------------------------------|
| Ballast    | Ubuntu 20       | 10.x.2.12   | FTP, SSH, VNC                          |
| BlackPearl | Win Server 2022 | 10.x.1.10   | LDAP, RDP, SMB, WinRM                  |
| Courier    | Fedora 31       | 10.x.3.12   | HTTP-Roundcube, SMTP, SSH              |
| JollyRoger | Win Server 2022 | 10.x.2.11   | RDP, WinRM                             |
| PoopDeck   | Debian 10       | 10.x.1.11   | DNS, HTTP-WikiJS, SSH                  |
| SilkRoad   | Ubuntu 18       | 10.x.2.10   | HTTP-SilkRoad, MySQL, SSH              |

---

## Block an Attacker IP (Linux)
```bash
sudo bash block_ip.sh 10.x.x.x        # block
sudo bash block_ip.sh list             # show all blocked
sudo bash block_ip.sh unblock 10.x.x.x
```

## Block an Attacker IP (Windows)
```powershell
New-NetFirewallRule -DisplayName "Block-ATTACKER" -Direction Inbound `
    -RemoteAddress "10.x.x.x" -Action Block
# Note: Single IPs only - blocking subnets violates competition rules!
```

---

## Incident Response - Collect Evidence
```bash
# Linux
sudo bash ir_collector.sh
# Output: /tmp/IR_EVIDENCE_<timestamp>.tar.gz
```
```powershell
# Windows
.\ir_collector.ps1
# Output: C:\IR_EVIDENCE_<timestamp>.zip
```

### IR Report must include:
- Attacker IP addresses (from `connected_ips.txt`)
- Processes they ran (from `processes.txt` / `process_events.txt`)
- User accounts they used (from `auth_events.txt` / `auth_log.txt`)
- Active sessions they hijacked (from `sessions.txt`)

---

## Key Rules (don't get penalized!)
- Block individual IPs ONLY - **no subnets**
- **DO NOT** remove `elastic-agent`
- **DO NOT** touch Wiretap, Scoring Engine, OpenStack
- No antivirus
- Upload scripts via GitHub (no copy/paste)
- IR reports submitted as PDF to Discord

---

## Default Credentials (CHANGE IMMEDIATELY)
All accounts start with: `Passw0rd123!`
New password set in scripts: `DreadWatch@2024!`
**Change `NEW_PASS` in harden_linux.sh and `$NewPass` in harden_windows.ps1 before the competition!**
