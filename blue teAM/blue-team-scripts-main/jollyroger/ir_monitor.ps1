# ============================================================
# DreadWatch Blue Team - Continuous IR Monitor (Windows)
#
# WHAT THIS SCRIPT DOES:
#   Runs continuously and logs attacker activity in real-time
#   to $env:USERPROFILE\blueteam_logs\EVIDENCE.log. Each event is tagged so
#   the IR report generator can extract exactly what the White
#   Crew needs to score your Incident Report.
#   Monitors every 10 seconds for:
#     [NEW-CONNECTION]   - New external IP connects to this machine
#     [AUTH-SUCCESS]     - Successful login (EventID 4624)
#     [AUTH-FAIL]        - Failed login attempt (EventID 4625)
#     [EXPLICIT-CREDS]   - Runas / pass-the-hash (EventID 4648)
#     [USER-PROCESS]     - Process launched by a non-system user
#     [SUSPICIOUS-PROC]  - Process matching known attack patterns
#     [SESSION-CHANGE]   - User logged in or session appeared
#     [NEW-ACCOUNT]      - New user account created (EventID 4720)
#     [ADMIN-ADDED]      - Account added to Administrators (EventID 4732)
#     [NEW-SERVICE]      - New service installed (EventID 7045)
#
# HOW TO USE:
#   Step 1 - Open an ELEVATED PowerShell window (Run as Administrator).
#            Keep this window open the entire competition.
#
#   Step 2 - Start the monitor:
#            Set-ExecutionPolicy Bypass -Scope Process -Force
#            .\ir_monitor.ps1
#
#   Step 3 - You will see events scroll as they happen.
#            Yellow lines = new evidence captured.
#
#   Step 4 - Check the evidence log at any time:
#            Get-Content $env:USERPROFILE\blueteam_logs\EVIDENCE.log
#            or search for a specific IP:
#            Select-String "10.x.x.x" $env:USERPROFILE\blueteam_logs\EVIDENCE.log
#
#   Step 5 - When ready to write an IR report, open a SECOND
#            PowerShell window and run:
#            .\generate_ir_report.ps1 -Title "Describe the attack"
#            Leave the monitor running - don't close it!
#
# TIP: Start this BEFORE hardening so you capture everything
#      from minute one.
#
# LOG FILES (all in $env:USERPROFILE\blueteam_logs\):
#   EVIDENCE.log          <- Main file for IR reports
#   network_connections.log
#   processes.log
#   sessions.log
#   auth_events.log
# ============================================================

$LogDir   = "$env:USERPROFILE\blueteam_logs"
$MainLog  = "$LogDir\monitor.log"
$EvidenceLog = "$LogDir\EVIDENCE.log"    # Used for IR report generation
$NetworkLog  = "$LogDir\network_connections.log"
$ProcessLog  = "$LogDir\processes.log"
$SessionLog  = "$LogDir\sessions.log"
$AuthLog     = "$LogDir\auth_events.log"

$Interval = 10  # seconds between sweeps

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

function ts { Get-Date -Format "yyyy-MM-dd HH:mm:ss" }

function Log-Main {
    param([string]$msg)
    $line = "[$(ts)] $msg"
    Write-Host $line
    Add-Content $MainLog $line
}

function Log-Evidence {
    param([string]$tag, [string]$msg)
    $line = "[$(ts)] [$tag] $msg"
    Write-Host -ForegroundColor Yellow $line
    Add-Content $EvidenceLog $line
}

Log-Main "=== IR Monitor Started on $env:COMPUTERNAME ==="

# ============================================================
# BASELINE SNAPSHOT
# ============================================================
Log-Main "[*] Taking baseline..."

# Baseline connections
$BaselineIPs = @{}
netstat -tnao | Select-String "ESTABLISHED" | ForEach-Object {
    $parts = ($_ -replace '\s+', ' ').Trim() -split ' '
    if ($parts.Count -ge 3) {
        $ip = ($parts[2] -replace ':\d+$', '')
        $BaselineIPs[$ip] = $true
    }
}

# Baseline processes
$BaselinePIDs = @{}
Get-Process | ForEach-Object { $BaselinePIDs[$_.Id] = $true }

# Baseline sessions
$BaselineSessions = query user 2>&1 | Out-String

# Last event log position
$LastEventTime = Get-Date

Log-Main "[+] Baseline complete. Monitoring every ${Interval}s"
Log-Main "[*] Evidence log: $EvidenceLog"

# ============================================================
# MAIN MONITORING LOOP
# ============================================================
while ($true) {

    # ----------------------------------------------------------
    # A. NEW NETWORK CONNECTIONS (Attacker IPs)
    # ----------------------------------------------------------
    $CurrentConns = netstat -tnao | Select-String "ESTABLISHED"
    foreach ($conn in $CurrentConns) {
        $parts = ($conn -replace '\s+', ' ').Trim() -split ' '
        if ($parts.Count -lt 5) { continue }
        $remoteAddr = $parts[2]
        $remoteIP   = $remoteAddr -replace ':\d+$', ''
        $pid        = $parts[4]

        if ($remoteIP -eq '127.0.0.1' -or $remoteIP -eq '0.0.0.0') { continue }
        if (-not $BaselineIPs.ContainsKey($remoteIP)) {
            # New connection - get process that owns it
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            $procName = if ($proc) { "$($proc.Name) (PID:$pid)" } else { "PID:$pid" }
            $procPath = if ($proc) { $proc.Path } else { "unknown" }

            Log-Evidence "NEW-CONNECTION" "IP=$remoteIP RemoteAddr=$remoteAddr Process=$procName Path=$procPath"
            Add-Content $NetworkLog "[$(ts)] IP=$remoteIP Process=$procName Path=$procPath Full=$conn"
            $BaselineIPs[$remoteIP] = $true
        }
    }

    # ----------------------------------------------------------
    # B. NEW PROCESSES (What did attacker run?)
    # ----------------------------------------------------------
    Get-Process | ForEach-Object {
        if (-not $BaselinePIDs.ContainsKey($_.Id)) {
            $proc = $_
            $pid  = $proc.Id
            $name = $proc.Name
            $path = try { $proc.Path } catch { "unknown" }

            # Get command line via WMI
            $cmdLine = try {
                (Get-WmiObject Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue).CommandLine
            } catch { "" }

            # Get owner
            $owner = try {
                $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
                $o = $wmi.GetOwner()
                "$($o.Domain)\$($o.User)"
            } catch { "unknown" }

            $entry = "PID=$pid NAME=$name OWNER=$owner PATH=$path CMD=$cmdLine"
            Add-Content $ProcessLog "[$(ts)] $entry"

            # Flag suspicious
            $suspicious = $false
            $suspFlags = @("powershell -enc","cmd /c","nc.exe","ncat","netcat",
                           "mimikatz","meterpreter","Invoke-","FromBase64",
                           "\\Temp\\","\\AppData\\","\\Downloads\\",
                           "wscript","cscript","mshta")
            foreach ($flag in $suspFlags) {
                if ($cmdLine -like "*$flag*" -or $path -like "*$flag*") {
                    $suspicious = $true; break
                }
            }

            if ($suspicious) {
                Log-Evidence "SUSPICIOUS-PROC" $entry
            } else {
                # Still log non-system processes
                $systemOwners = @('NT AUTHORITY\SYSTEM','NT AUTHORITY\LOCAL SERVICE',
                                   'NT AUTHORITY\NETWORK SERVICE','')
                if ($owner -notin $systemOwners) {
                    Log-Evidence "USER-PROCESS" $entry
                }
            }

            $BaselinePIDs[$pid] = $true
        }
    }

    # ----------------------------------------------------------
    # C. SESSION CHANGES (Hijacked sessions)
    # ----------------------------------------------------------
    $CurrentSessions = query user 2>&1 | Out-String
    if ($CurrentSessions -ne $BaselineSessions) {
        Log-Evidence "SESSION-CHANGE" "Sessions changed. Before: $BaselineSessions | After: $CurrentSessions"
        Add-Content $SessionLog "[$(ts)] === Session Change Detected ===`nBEFORE:`n$BaselineSessions`nAFTER:`n$CurrentSessions`n"
        $BaselineSessions = $CurrentSessions
    }

    # ----------------------------------------------------------
    # D. SECURITY EVENT LOG (Auth events, new accounts)
    # ----------------------------------------------------------
    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = @(4624, 4625, 4648, 4720, 4732, 4756, 7045)  # logon,fail,explicit,newuser,adminadd,newsvc
            StartTime = $LastEventTime
        } -ErrorAction SilentlyContinue

        foreach ($evt in $Events) {
            $evtMsg = $evt.Message -replace "`n", " " -replace "\s+", " "
            $shortMsg = $evtMsg.Substring(0, [Math]::Min(300, $evtMsg.Length))

            switch ($evt.Id) {
                4624 { Log-Evidence "AUTH-SUCCESS" "EventID=4624 $shortMsg"
                        Add-Content $AuthLog "[$(ts)] SUCCESS $shortMsg" }
                4625 { Log-Evidence "AUTH-FAIL"    "EventID=4625 $shortMsg"
                        Add-Content $AuthLog "[$(ts)] FAILED  $shortMsg" }
                4648 { Log-Evidence "EXPLICIT-CREDS" "EventID=4648 $shortMsg"
                        Add-Content $AuthLog "[$(ts)] EXPLICIT $shortMsg" }
                4720 { Log-Evidence "NEW-ACCOUNT"  "EventID=4720 NEW USER CREATED $shortMsg" }
                4732 { Log-Evidence "ADMIN-ADDED"  "EventID=4732 USER ADDED TO ADMIN GROUP $shortMsg" }
                4756 { Log-Evidence "GROUP-CHANGE" "EventID=4756 UNIVERSAL GROUP MEMBER ADDED $shortMsg" }
                7045 { Log-Evidence "NEW-SERVICE"  "EventID=7045 NEW SERVICE INSTALLED $shortMsg" }
            }
        }
    } catch {}

    $LastEventTime = Get-Date

    Start-Sleep $Interval
}
