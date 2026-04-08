# DreadWatch Blue Team - Quick Reference

## First 30 Minutes Checklist (before red team attacks)

### On EVERY Linux box (Ballast, SilkRoad, PoopDeck, Courier):
```bash
# 1. Pull scripts from GitHub
git clone https://github.com/BadWolf1000/blue-team-scripts.git /opt/bt
cd /opt/bt/linux && chmod +x *.sh

# 2. Run hardening FIRST
sudo bash harden_linux.sh

# 3. Start IR monitor in background (captures attacker evidence in real-time)
sudo bash ir_monitor.sh &

# 4. Start service watchdog in background
sudo bash service_watchdog.sh &

# 5. Scan for backdoors red team may have pre-planted
sudo bash find_backdoors.sh

# 6. Scan for webshells (SilkRoad, PoopDeck, Courier only)
sudo bash webshell_scanner.sh

# 7. SilkRoad only - harden MySQL
sudo bash mysql_harden.sh

# 8. Verify scored services are UP
# Ballast:   systemctl status vsftpd ssh
# SilkRoad:  systemctl status nginx mysql ssh  (or apache2)
# PoopDeck:  systemctl status named ssh nginx
# Courier:   systemctl status postfix dovecot apache2 ssh
```

### On EVERY Windows box (BlackPearl, JollyRoger):
```powershell
# Run from elevated PowerShell
Set-ExecutionPolicy Bypass -Scope Process -Force

# 1. General hardening
.\harden_windows.ps1

# 2. BlackPearl ONLY - AD/DC specific hardening
.\windows_ad_harden.ps1

# 3. BlackPearl ONLY - AD security audit (fix findings immediately)
.\ad_audit.ps1

# 4. IR Monitor in dedicated window (IMPORTANT - start early!)
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File ir_monitor.ps1"

# 5. Service Watchdog in another window
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File service_watchdog.ps1"

# 6. Verify services
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

## Incident Response Workflow

### Step 1 — Monitor runs automatically (started above)
Evidence is written in real-time to:
- Linux: `/var/log/blueteam_ir/EVIDENCE.log`
- Windows: `C:\blueteam_ir\EVIDENCE.log`

### Step 2 — Point-in-time snapshot (run anytime)
```bash
sudo bash ir_collector.sh          # Linux - full snapshot to /tmp/IR_EVIDENCE_*/
```
```powershell
.\ir_collector.ps1                 # Windows - full snapshot to C:\IR_EVIDENCE_*\
```

### Step 3 — Generate IR Report (when you have an incident to report)
```bash
sudo bash generate_ir_report.sh "Red Team SSH Brute Force"
# Output: /var/log/blueteam_ir/IR_REPORT_<timestamp>.txt
```
```powershell
.\generate_ir_report.ps1 -Title "Red Team RDP Compromise"
# Output: C:\blueteam_ir\IR_REPORT_<timestamp>.txt
```

### Step 4 — Convert to PDF and submit to Discord
```bash
# Linux - convert text report to PDF
enscript -p /tmp/report.ps /var/log/blueteam_ir/IR_REPORT_*.txt
ps2pdf /tmp/report.ps /tmp/IR_REPORT.pdf
# If enscript not available:
# libreoffice --headless --convert-to pdf /var/log/blueteam_ir/IR_REPORT_*.txt
```

### IR Report scoring criteria (all captured automatically):
| Evidence Needed | Where It's Captured |
|----------------|---------------------|
| Attacker IP addresses | `[NEW-CONNECTION]` events in EVIDENCE.log |
| Processes they ran | `[USER-PROCESS]` and `[SUSPICIOUS-PROC]` events |
| User accounts they used | `[AUTH-SUCCESS]` events (EventID 4624 / auth.log) |
| Active sessions hijacked | `[SESSION-CHANGE]` events |

---

## Panic / Emergency Commands

```bash
# Services got killed? One command recovery:
sudo bash recover_service.sh all          # restart everything for this host
sudo bash recover_service.sh ssh          # just SSH
sudo bash recover_service.sh web          # just web
sudo bash recover_service.sh db           # just MySQL

# Passwords compromised? Rotate all at once:
sudo bash rotate_passwords.sh             # prompts for new password
sudo bash rotate_passwords.sh --random    # generates a random one

# Check all 6 hosts at once:
bash network_audit.sh <team_number>       # e.g. bash network_audit.sh 3
bash status_dashboard.sh --loop           # live dashboard, refreshes every 15s

# Found a backdoor? Clean it:
sudo bash find_backdoors.sh --clean       # interactive removal
sudo bash webshell_scanner.sh --quarantine
```

---

## Full Script Reference

| Script | Platform | When to use |
|--------|----------|-------------|
| `harden_linux.sh` | Linux | First thing on every Linux box |
| `harden_windows.ps1` | Windows | First thing on every Windows box |
| `windows_ad_harden.ps1` | BlackPearl | After harden_windows - DC specific |
| `ad_audit.ps1` | BlackPearl | Find AD attack vectors to fix |
| `mysql_harden.sh` | SilkRoad | Harden MySQL scored service |
| `ir_monitor.sh/ps1` | All | Run in background immediately - collects evidence |
| `service_watchdog.sh/ps1` | All | Run in background - keeps services alive |
| `find_backdoors.sh` | Linux | Hunt for red team persistence |
| `webshell_scanner.sh` | Linux web hosts | Hunt for webshells |
| `block_ip.sh` | Linux | Block attacker IPs |
| `recover_service.sh` | Linux | Panic button - restart all services |
| `rotate_passwords.sh` | Linux | Emergency password rotation |
| `status_dashboard.sh` | Any Linux | Live view of all 6 hosts |
| `network_audit.sh` | Any Linux | Verify scoring engine will see services UP |
| `ir_collector.sh/ps1` | All | Point-in-time evidence snapshot |
| `generate_ir_report.sh/ps1` | All | Format evidence into IR report |

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
