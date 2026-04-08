# ============================================================
# DreadWatch Blue Team - Windows IR Evidence Collector
# Captures evidence for Incident Response reports:
#   - Active sessions & logged-in users
#   - Running processes (with paths - catches malware)
#   - Network connections + attacker IPs
#   - Recent event log entries (auth, process creation)
#   - Scheduled tasks / startup entries
#   - Modified files
# Usage: Run as Administrator in PowerShell
# ============================================================

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir = "C:\IR_EVIDENCE_$Timestamp"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Log { param([string]$msg)
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line
    Add-Content "$OutDir\collection.log" $line
}

Log "=== IR Evidence Collection ==="
Log "Host: $env:COMPUTERNAME | $(Get-Date)"

# ============================================================
# 1. ACTIVE SESSIONS
# ============================================================
Log "[1] Active sessions..."
@"
=== Currently logged-in users (query user) ===
$(query user 2>&1)

=== Active sessions (qwinsta) ===
$(qwinsta 2>&1)
"@ | Out-File "$OutDir\sessions.txt"

# ============================================================
# 2. RUNNING PROCESSES (with full path - catches malware from temp dirs)
# ============================================================
Log "[2] Processes..."
Get-Process | Select-Object Id, Name, Path, StartTime, CPU, @{
    Name="Owner"; Expression={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User}
} | Sort-Object StartTime -Descending | Format-Table -AutoSize | Out-File "$OutDir\processes.txt"

# Flag suspicious process locations
Log "[2b] Checking for processes in suspicious locations..."
$SuspiciousPaths = @("C:\Users","C:\Temp","C:\Windows\Temp","AppData","Downloads")
Get-Process | ForEach-Object {
    try {
        $path = $_.Path
        if ($path) {
            foreach ($sus in $SuspiciousPaths) {
                if ($path -like "*$sus*") {
                    Log "[!!] SUSPICIOUS PROCESS: $($_.Name) PID:$($_.Id) Path:$path"
                }
            }
        }
    } catch {}
}

# ============================================================
# 3. NETWORK CONNECTIONS + ATTACKER IPs
# ============================================================
Log "[3] Network connections..."
@"
=== ESTABLISHED connections ===
$(netstat -tnao | Where-Object { $_ -match "ESTABLISHED" })

=== All connections with PIDs ===
$(netstat -tnao)

=== Listening ports ===
$(netstat -tlnao)
"@ | Out-File "$OutDir\network.txt"

# Extract unique remote IPs
$ConnectedIPs = netstat -tnao | Select-String "ESTABLISHED" | ForEach-Object {
    ($_ -split '\s+')[3]  # Remote address column
} | ForEach-Object {
    $_ -replace ':\d+$',''  # Strip port
} | Sort-Object -Unique | Where-Object { $_ -ne "0.0.0.0" -and $_ -ne "127.0.0.1" }

$ConnectedIPs | Out-File "$OutDir\connected_ips.txt"
Log "[*] Connected IPs: $($ConnectedIPs -join ', ')"

# ============================================================
# 4. EVENT LOG - LOGON EVENTS (4624, 4625, 4648)
# ============================================================
Log "[4] Auth events from event log..."
try {
    $LogonEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = @(4624, 4625, 4648, 4720, 4732, 4756)  # logon, fail, explicit creds, new user, admin added
        StartTime = (Get-Date).AddHours(-4)
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message

    $LogonEvents | ForEach-Object {
        "[$($_.TimeCreated)] EventID:$($_.Id)`n$($_.Message)`n---"
    } | Out-File "$OutDir\auth_events.txt"

    Log "[*] Auth events captured: $($LogonEvents.Count)"
} catch { Log "[!] Event log: $_" }

# ============================================================
# 5. PROCESS CREATION EVENTS (4688) - What did attackers run?
# ============================================================
Log "[5] Process creation events..."
try {
    $ProcEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4688
        StartTime = (Get-Date).AddHours(-4)
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message

    $ProcEvents | ForEach-Object {
        "[$($_.TimeCreated)]`n$($_.Message)`n---"
    } | Out-File "$OutDir\process_events.txt"

    Log "[*] Process creation events: $($ProcEvents.Count)"
} catch { Log "[!] Process events: $_" }

# ============================================================
# 6. SCHEDULED TASKS (persistence/backdoors)
# ============================================================
Log "[6] Scheduled tasks..."
Get-ScheduledTask | Select-Object TaskName, TaskPath, State, @{
    Name="Actions"; Expression={($_.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join "; "}
} | Format-Table -AutoSize | Out-File "$OutDir\scheduled_tasks.txt"

# ============================================================
# 7. LOCAL USERS AND ADMINS
# ============================================================
Log "[7] User accounts..."
@"
=== Local Users ===
$(Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Format-Table -AutoSize | Out-String)

=== Local Administrators ===
$(Get-LocalGroupMember -Group "Administrators" | Format-Table -AutoSize | Out-String)

=== RDP Users ===
$(Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
"@ | Out-File "$OutDir\users.txt"

# ============================================================
# 8. RECENTLY MODIFIED FILES (last 2 hours)
# ============================================================
Log "[8] Recently modified files..."
$RecentFiles = Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -gt (Get-Date).AddHours(-2) } |
    Select-Object FullName, LastWriteTime, Length |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 100
$RecentFiles | Format-Table -AutoSize | Out-File "$OutDir\recent_files.txt"

# ============================================================
# 9. IR SUMMARY
# ============================================================
Log "[9] Writing IR summary..."
@"
====================================================
 INCIDENT RESPONSE SUMMARY - $(Get-Date)
 Host: $env:COMPUTERNAME
====================================================

ACTIVE SESSIONS:
$(query user 2>&1)

CONNECTED EXTERNAL IPs:
$($ConnectedIPs -join "`n")

SUSPICIOUS PROCESSES (in user/temp dirs):
$(Get-Process | ForEach-Object {
    try { $p = $_.Path; if ($p -match "Users|Temp|AppData|Downloads") { "$($_.Name) PID:$($_.Id) $p" } } catch {}
})

RECENT LOGON FAILURES:
$(Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625;StartTime=(Get-Date).AddHours(-4)} -ErrorAction SilentlyContinue |
    Select-Object -First 10 TimeCreated, Message | ForEach-Object { "[$($_.TimeCreated)] $($_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)))" })

====================================================
Evidence files in: $OutDir
Include in IR report: sessions.txt, connected_ips.txt, processes.txt, auth_events.txt
====================================================
"@ | Out-File "$OutDir\IR_SUMMARY.txt"

Get-Content "$OutDir\IR_SUMMARY.txt"

# Package everything
Compress-Archive -Path $OutDir -DestinationPath "C:\IR_EVIDENCE_$Timestamp.zip" -Force
Log "Evidence packaged: C:\IR_EVIDENCE_$Timestamp.zip"
Log "=== Collection Complete ==="
