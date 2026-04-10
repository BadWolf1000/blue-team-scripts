# ============================================================
# DreadWatch Blue Team - IR Report Generator (Windows)
#
# WHAT THIS SCRIPT DOES:
#   Reads $env:USERPROFILE\Desktop\blueteam_logs\EVIDENCE.log (collected by ir_monitor.ps1)
#   and formats it into a structured Incident Response report that
#   directly addresses the 4 scoring criteria the White Crew uses:
#     1. Attacker IP addresses
#     2. Processes the attacker ran
#     3. User accounts they used
#     4. Active sessions they hijacked
#   Also includes a full timestamped evidence timeline.
#
# PREREQUISITE:
#   ir_monitor.ps1 must have been running to collect evidence.
#   Check if evidence exists:  Get-Content $env:USERPROFILE\Desktop\blueteam_logs\EVIDENCE.log
#
# HOW TO USE:
#   Step 1 - Open a second PowerShell window (keep ir_monitor running).
#
#   Step 2 - Run the report generator with a title:
#            Set-ExecutionPolicy Bypass -Scope Process -Force
#            .\generate_ir_report.ps1 -Title "RDP Brute Force Attack"
#            .\generate_ir_report.ps1 -Title "Lateral Movement via WinRM"
#            .\generate_ir_report.ps1 -Title "New Admin Account Created"
#
#   Step 3 - A summary prints to screen. The full report is saved to:
#            $env:USERPROFILE\Desktop\blueteam_logs\IR_REPORT_<timestamp>.txt
#
#   Step 4 - Convert to PDF for Discord submission:
#            Option A: Open the .txt file in Notepad, File -> Print ->
#                      select "Microsoft Print to PDF"
#            Option B: Open in Word and Save As -> PDF
#            Option C: If you have LibreOffice:
#                      soffice --headless --convert-to pdf $env:USERPROFILE\Desktop\blueteam_logs\IR_REPORT_*.txt
#
#   Step 5 - Upload the PDF to Discord before the inject deadline.
#
# OUTPUT: $env:USERPROFILE\Desktop\blueteam_logs\IR_REPORT_<timestamp>.txt
# ============================================================

param([string]$Title = "Security Incident Report")

$LogDir      = "$env:USERPROFILE\Desktop\blueteam_logs"
$EvidenceLog = "$LogDir\EVIDENCE.log"
$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = "$LogDir\IR_REPORT_$Timestamp.txt"

if (-not (Test-Path $LogDir)) {
    Write-Error "No IR logs found at $LogDir. Run ir_monitor.ps1 first."
    exit 1
}

function Get-EvidenceSection {
    param([string]$Tag)
    if (-not (Test-Path $EvidenceLog)) { return @() }
    Get-Content $EvidenceLog | Where-Object { $_ -match "\[$Tag\]" } |
        ForEach-Object { $_ -replace "^\[.*?\] \[$Tag\] ", "" } |
        Sort-Object -Unique
}

# Parse sections
$AttackerConns    = Get-EvidenceSection "NEW-CONNECTION"
$AuthSuccesses    = Get-EvidenceSection "AUTH-SUCCESS"
$AuthFails        = Get-EvidenceSection "AUTH-FAIL"
$ExplicitCreds    = Get-EvidenceSection "EXPLICIT-CREDS"
$UserProcesses    = Get-EvidenceSection "USER-PROCESS"
$SuspiciousProcs  = Get-EvidenceSection "SUSPICIOUS-PROC"
$SessionChanges   = Get-EvidenceSection "SESSION-CHANGE"
$NewAccounts      = Get-EvidenceSection "NEW-ACCOUNT"
$AdminAdded       = Get-EvidenceSection "ADMIN-ADDED"
$NewServices      = Get-EvidenceSection "NEW-SERVICE"

# Extract unique attacker IPs
$AttackerIPs = $AttackerConns |
    ForEach-Object { if ($_ -match 'IP=([0-9.]+)') { $Matches[1] } } |
    Sort-Object -Unique

# Extract user accounts from auth successes
$AccountsUsed = $AuthSuccesses |
    ForEach-Object { if ($_ -match 'Account Name:\s+(\S+)') { $Matches[1] } } |
    Where-Object { $_ -ne '-' -and $_ -ne '' } |
    Sort-Object -Unique

# ============================================================
# WRITE REPORT
# ============================================================
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress

$report = @"
================================================================================
                    INCIDENT RESPONSE REPORT
                    $Title
================================================================================
Organization:  Dread Pirate Ventures
Host:          $env:COMPUTERNAME | $ip
OS:            $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
Report Time:   $(Get-Date)
Prepared by:   DreadWatch Blue Team
Evidence Dir:  $LogDir
================================================================================

EXECUTIVE SUMMARY
-----------------
This report documents unauthorized access attempts and confirmed intrusions
detected on $env:COMPUTERNAME during the competition window. Evidence was
collected by continuous real-time monitoring (ir_monitor.ps1).

--------------------------------------------------------------------------------
SECTION 1: ATTACKER IP ADDRESSES
--------------------------------------------------------------------------------
The following external IP addresses made connections to this host:

$(if ($AttackerIPs) {
    $AttackerIPs | ForEach-Object { "  IP: $_" }
} else { "  No new external connections detected during monitoring." })

Full connection details:
$(($AttackerConns | ForEach-Object { "  $_" }) -join "`n")

Raw network log: $LogDir\network_connections.log

--------------------------------------------------------------------------------
SECTION 2: PROCESSES EXECUTED BY ATTACKERS
--------------------------------------------------------------------------------
$(if ($SuspiciousProcs) {
    "!! SUSPICIOUS / MALICIOUS PROCESSES DETECTED !!"
    $SuspiciousProcs | ForEach-Object { "  [SUSPICIOUS] $_" }
    ""
})

User-level processes observed:
$(if ($UserProcesses) {
    $UserProcesses | ForEach-Object { "  $_" }
} else { "  No user-level processes detected." })

Full process log: $LogDir\processes.log

--------------------------------------------------------------------------------
SECTION 3: USER ACCOUNTS USED
--------------------------------------------------------------------------------
Accounts identified in authentication events:
$(if ($AccountsUsed) {
    $AccountsUsed | ForEach-Object { "  Account: $_" }
} else { "  No accounts identified from parsed events." })

Successful authentications:
$(($AuthSuccesses | Select-Object -First 20 | ForEach-Object { "  $_" }) -join "`n")

Explicit credential use (runas / pass-the-hash indicators):
$(($ExplicitCreds | ForEach-Object { "  $_" }) -join "`n")

New accounts created during incident:
$(if ($NewAccounts) { ($NewAccounts | ForEach-Object { "  [NEW ACCOUNT] $_" }) -join "`n" } else { "  None detected." })

Accounts added to admin group:
$(if ($AdminAdded) { ($AdminAdded | ForEach-Object { "  [PRIVILEGE ESCALATION] $_" }) -join "`n" } else { "  None detected." })

Failed login attempts:
$(($AuthFails | Select-Object -First 20 | ForEach-Object { "  $_" }) -join "`n")

Full auth log: $LogDir\auth_events.log

--------------------------------------------------------------------------------
SECTION 4: ACTIVE SESSIONS / HIJACKED SESSIONS
--------------------------------------------------------------------------------
Session changes detected during monitoring:
$(if ($SessionChanges) {
    $SessionChanges | ForEach-Object { "  $_" }
} else { "  No unexpected session changes detected." })

Sessions at report time:
$(query user 2>&1 | ForEach-Object { "  $_" })

Full sessions log: $LogDir\sessions.log

--------------------------------------------------------------------------------
SECTION 5: ADDITIONAL INDICATORS OF COMPROMISE
--------------------------------------------------------------------------------
New services installed (potential persistence):
$(if ($NewServices) { ($NewServices | ForEach-Object { "  [NEW SERVICE] $_" }) -join "`n" } else { "  None detected." })

Recent files modified (last 2 hours):
$(Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -gt (Get-Date).AddHours(-2) } |
    Select-Object -First 30 FullName, LastWriteTime |
    ForEach-Object { "  $($_.LastWriteTime) $($_.FullName)" })

--------------------------------------------------------------------------------
SECTION 6: FULL EVIDENCE TIMELINE
--------------------------------------------------------------------------------
$(if (Test-Path $EvidenceLog) {
    Get-Content $EvidenceLog | ForEach-Object { "  $_" }
} else { "  Evidence log not found." })

================================================================================
ATTESTATION
================================================================================
I certify that the evidence in this report was collected directly from system
logs on $env:COMPUTERNAME and has not been altered.

Submitted by: DreadWatch Blue Team
Date/Time:    $(Get-Date)
================================================================================
"@

$report | Out-File -FilePath $ReportFile -Encoding UTF8

Write-Host "[+] Report saved: $ReportFile" -ForegroundColor Green
Write-Host ""
Write-Host "--- QUICK SUMMARY FOR WHITE CREW ---" -ForegroundColor Cyan
Write-Host "Attacker IPs:      $($AttackerIPs -join ', ')"
Write-Host "Accounts used:     $($AccountsUsed -join ', ')"
Write-Host "Suspicious procs:  $($SuspiciousProcs.Count)"
Write-Host "Session changes:   $($SessionChanges.Count)"
Write-Host "New accounts:      $($NewAccounts.Count)"
Write-Host ""
Write-Host "To convert to PDF:" -ForegroundColor Yellow
Write-Host "  Open $ReportFile in Notepad/Word and Save As PDF"
Write-Host "  OR use: \$report | Out-Printer (if printer to PDF available)"
