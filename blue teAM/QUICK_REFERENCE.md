# DreadWatch Blue Team - Quick Reference

## First 30 Minutes Checklist (before red team attacks)

### Linux Boxes — clone once, then cd into YOUR host's folder

```bash
# Pull scripts from GitHub (do this on EVERY Linux box)
git clone https://github.com/BadWolf1000/blue-team-scripts.git /opt/bt
cd /opt/bt/<hostname>      # e.g. cd /opt/bt/silkroad
chmod +x *.sh
```

---

### Ballast (Ubuntu 20 — 10.x.2.12) — FTP, SSH, VNC
```bash
cd /opt/bt/ballast && chmod +x *.sh

sudo bash harden_linux.sh
sudo bash find_backdoors.sh
sudo bash ir_monitor.sh &
sudo bash service_watchdog.sh &

# Verify scored services
systemctl status vsftpd ssh
```

---

### SilkRoad (Ubuntu 18 — 10.x.2.10) — HTTP-SilkRoad, MySQL, SSH
```bash
cd /opt/bt/silkroad && chmod +x *.sh

sudo bash harden_linux.sh
sudo bash harden_silkroad.sh     # MySQL lockdown + app credential rotation + deploy hardened server.js
sudo bash mysql_harden.sh        # additional MySQL hardening
sudo bash find_backdoors.sh
sudo bash webshell_scanner.sh
sudo bash ir_monitor.sh &
sudo bash service_watchdog.sh &

# Verify scored services
systemctl status nginx mysql ssh   # (or apache2)
```

---

### PoopDeck (Debian 10 — 10.x.1.11) — DNS, HTTP-WikiJS, SSH
```bash
cd /opt/bt/poopdeck && chmod +x *.sh

sudo bash harden_linux.sh
sudo bash find_backdoors.sh
sudo bash webshell_scanner.sh
sudo bash ir_monitor.sh &
sudo bash service_watchdog.sh &

# Verify scored services
systemctl status named nginx ssh
```

---

### Courier (Fedora 31 — 10.x.3.12) — HTTP-Roundcube, SMTP, SSH
```bash
cd /opt/bt/courier && chmod +x *.sh

sudo bash harden_linux.sh
sudo bash harden_smtp.sh         # fix SMTP hostname, rate-limit, drop root via authbind
sudo bash find_backdoors.sh
sudo bash webshell_scanner.sh
sudo bash ir_monitor.sh &
sudo bash service_watchdog.sh &

# Verify scored services
systemctl status postfix apache2 ssh
```

---

### BlackPearl (Win Server 2022 — 10.x.1.10) — LDAP, RDP, SMB, WinRM  ← DC
```powershell
# Run from elevated PowerShell
Set-ExecutionPolicy Bypass -Scope Process -Force

cd C:\
git clone https://github.com/BadWolf1000/blue-team-scripts.git bt
cd C:\bt\blackpearl

.\harden_windows.ps1
.\windows_ad_harden.ps1
.\ad_audit.ps1

# Enable process creation auditing (required for CVE monitors)
auditpol /set /subcategory:"Process Creation" /success:enable

# Start monitors in dedicated windows
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\blackpearl; .\ir_monitor.ps1`""
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\blackpearl; .\service_watchdog.ps1`""
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\blackpearl; .\Detect-CVE-2021-42287.ps1 -Beep`""
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\blackpearl; .\Detect-CVE-2023-36874.ps1 -Beep`""

# Verify scored services
Get-Service NTDS, DNS, LanmanServer, WinRM, TermService
```

---

### JollyRoger (Win Server 2022 — 10.x.2.11) — RDP, WinRM
```powershell
# Run from elevated PowerShell
Set-ExecutionPolicy Bypass -Scope Process -Force

cd C:\
git clone https://github.com/BadWolf1000/blue-team-scripts.git bt
cd C:\bt\jollyroger

.\harden_windows.ps1

# Start monitors in dedicated windows
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\jollyroger; .\ir_monitor.ps1`""
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\jollyroger; .\service_watchdog.ps1`""
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\jollyroger; .\Detect-CVE-2023-36874.ps1 -Beep`""

# Verify scored services
Get-Service WinRM, TermService
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
- Linux: `~/Desktop/blueteam_logs/EVIDENCE.log`
- Windows: `%USERPROFILE%\Desktop\blueteam_logs\EVIDENCE.log`

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
sudo bash change_passwords.sh             # prompts for new password
sudo bash change_passwords.sh --random    # generates a random one

# Check all 6 hosts at once (run from any Linux box):
bash /opt/bt/utils/network_audit.sh <team_number>
bash /opt/bt/utils/status_dashboard.sh --loop    # live dashboard, refreshes every 15s

# Found a backdoor? Clean it:
sudo bash find_backdoors.sh --clean
sudo bash webshell_scanner.sh --quarantine
```

---

## Full Script Reference

| Script | Host(s) | Purpose |
|--------|---------|---------|
| `harden_linux.sh` | All Linux | First thing — OS hardening |
| `harden_silkroad.sh` | SilkRoad | MySQL bind-addr, credential rotation, deploy hardened server.js |
| `mysql_harden.sh` | SilkRoad | Additional MySQL hardening |
| `harden_smtp.sh` | Courier | SMTP hostname fix, rate-limit, drop root |
| `webshell_scanner.sh` | SilkRoad, PoopDeck, Courier | Hunt for webshells |
| `find_backdoors.sh` | All Linux | Hunt for red team persistence |
| `ir_monitor.sh` | All Linux | Background — real-time evidence collection |
| `service_watchdog.sh` | All Linux | Background — keeps scored services alive |
| `ir_collector.sh` | All Linux | Point-in-time evidence snapshot |
| `generate_ir_report.sh` | All Linux | Format evidence into IR report |
| `change_passwords.sh` | All Linux | Emergency password rotation |
| `recover_service.sh` | All Linux | Panic button — restart services |
| `block_ip.sh` | All Linux | Block attacker IPs |
| `network_audit.sh` | utils/ (any Linux) | Verify all 6 hosts' services are UP |
| `status_dashboard.sh` | utils/ (any Linux) | Live dashboard of all 6 hosts |
| `harden_windows.ps1` | BlackPearl, JollyRoger | OS hardening |
| `windows_ad_harden.ps1` | BlackPearl | DC/AD specific hardening |
| `ad_audit.ps1` | BlackPearl | Find AD attack vectors |
| `ir_monitor.ps1` | BlackPearl, JollyRoger | Background — real-time evidence collection |
| `service_watchdog.ps1` | BlackPearl, JollyRoger | Background — keeps scored services alive |
| `ir_collector.ps1` | BlackPearl, JollyRoger | Point-in-time evidence snapshot |
| `generate_ir_report.ps1` | BlackPearl, JollyRoger | Format evidence into IR report |
| `change_passwords.ps1` | BlackPearl, JollyRoger | Emergency password rotation |
| `Detect-CVE-2021-42287.ps1` | BlackPearl | Real-time SAMAccountName spoofing monitor |
| `Detect-CVE-2023-36874.ps1` | BlackPearl, JollyRoger | Real-time WER LPE monitor |

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
