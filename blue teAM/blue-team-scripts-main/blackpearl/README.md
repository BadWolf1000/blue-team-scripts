# BlackPearl — Windows Server 2022 | 10.x.1.10
**Scored:** LDAP, RDP, SMB, WinRM  |  **Role:** Domain Controller

---

## Setup (run once at start)
```powershell
# Run from elevated PowerShell
Set-ExecutionPolicy Bypass -Scope Process -Force

cd C:\
git clone https://github.com/BadWolf1000/blue-team-scripts.git bt
cd C:\bt\blackpearl

# 1. General Windows hardening
.\harden_windows.ps1

# 2. DC/AD specific hardening
.\windows_ad_harden.ps1

# 3. AD security audit — fix anything it flags immediately
.\ad_audit.ps1

# 4. Enable process creation auditing (required for CVE monitors below)
auditpol /set /subcategory:"Process Creation" /success:enable

# 5. Start IR monitor in a dedicated window
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\blackpearl; .\ir_monitor.ps1`""

# 6. Start service watchdog in a dedicated window
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\blackpearl; .\service_watchdog.ps1`""

# 7. CVE-2021-42287 monitor — SAMAccountName spoofing (DC-specific, HIGH priority)
#    Detects: computer account renamed to drop the '$' — used for DC impersonation
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\blackpearl; .\Detect-CVE-2021-42287.ps1 -Beep`""

# 8. CVE-2023-36874 monitor — Windows Error Reporting LPE
#    Detects: WerFault.exe spawning suspicious child processes as SYSTEM
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command `"cd C:\bt\blackpearl; .\Detect-CVE-2023-36874.ps1 -Beep`""

# 9. Verify scored services are UP
Get-Service NTDS, DNS, LanmanServer, WinRM, TermService
```

---

## CVE monitors — what to watch for

### CVE-2021-42287 — SAMAccountName Spoofing
- Red team renames a computer account (e.g. `DESKTOP-ABC$`) to match a DC name without `$`
- Allows them to obtain a Kerberos ticket as the DC → full domain compromise
- **Alert fires on:** Event ID 4781 where OldName has `$` and NewName does not

### CVE-2023-36874 — WER Local Privilege Escalation
- Red team (non-admin) creates malicious directory structure to hijack WerFault.exe's path resolution
- WerFault.exe executes attacker binary as SYSTEM
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
.\generate_ir_report.ps1 -Title "Red Team Kerberoast / DCSync"

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
