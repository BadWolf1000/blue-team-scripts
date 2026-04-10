# JollyRoger — Windows Server 2022 | 10.x.2.11
**Scored:** RDP, WinRM

---

## Setup (run once at start)
```powershell
# Run from elevated PowerShell
Set-ExecutionPolicy Bypass -Scope Process -Force

cd C:\
git clone https://github.com/BadWolf1000/blue-team-scripts.git bt
cd C:\bt\jollyroger

# 1. General Windows hardening
.\harden_windows.ps1

# 2. Start IR monitor in a dedicated window
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\jollyroger; .\ir_monitor.ps1`""

# 3. Start service watchdog in a dedicated window
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\jollyroger; .\service_watchdog.ps1`""

# 4. CVE-2023-36874 monitor — Windows Error Reporting LPE
#    Detects: WerFault.exe spawning suspicious child processes as SYSTEM
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\jollyroger; .\Detect-CVE-2023-36874.ps1 -Beep`""

# 5. Verify scored services are UP
Get-Service WinRM, TermService
```

---

## CVE-2023-36874 — WER Local Privilege Escalation
- Unprivileged user creates malicious directory structure to hijack WerFault.exe
- WerFault.exe executes attacker-controlled binary as SYSTEM
- **Requires:** Process creation auditing enabled
  ```powershell
  auditpol /set /subcategory:"Process Creation" /success:enable
  ```
- **Alert fires on:** Event ID 4688 where WerFault.exe spawns cmd/powershell/etc.

---

## During the match
```powershell
# Block an attacker IP (single IPs only — no subnets!)
New-NetFirewallRule -DisplayName "Block-ATTACKER" -Direction Inbound `
    -RemoteAddress "10.x.x.x" -Action Block

# Take an evidence snapshot
.\ir_collector.ps1

# Generate IR report
.\generate_ir_report.ps1 -Title "Description of attack"

# Emergency password rotation
.\change_passwords.ps1
```

---

## Incident Response
```powershell
.\ir_collector.ps1
.\generate_ir_report.ps1 -Title "Description of attack"
# Output: C:\blueteam_ir\IR_REPORT_<timestamp>.txt
# Convert to PDF → upload to Discord
```

---

## Key reminders
- Do NOT remove `elastic-agent`
- Do NOT touch Wiretap, Scoring Engine, OpenStack
- Block single IPs only — **no subnets**
