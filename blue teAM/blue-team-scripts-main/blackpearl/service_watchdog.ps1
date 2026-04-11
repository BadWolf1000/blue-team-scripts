# ============================================================
# DreadWatch Blue Team - Windows Service Watchdog
#
# WHAT THIS SCRIPT DOES:
#   Loops every 30 seconds and checks that all scored Windows
#   services are running. If red team stops a service, this
#   automatically restarts it and logs the event.
#   Monitors:
#     BlackPearl: RDP (TermService), WinRM, AD DS (NTDS),
#                 DNS Server, Kerberos, SMB (LanmanServer)
#     JollyRoger: RDP (TermService), WinRM, SMB, FTP, IIS
#
# HOW TO USE:
#   Step 1 - Open a DEDICATED elevated PowerShell window.
#            This window will run the watchdog all competition.
#            Do NOT use this window for anything else.
#
#   Step 2 - Start it:
#            Set-ExecutionPolicy Bypass -Scope Process -Force
#            .\service_watchdog.ps1
#
#   Step 3 - You will see it checking services every 30 seconds.
#            If a service restarts, you'll see a [!] warning.
#
#   Step 4 - Leave it running the entire competition.
#            Do NOT close this window.
#
#   Step 5 - Check its log if you want to see restart history:
#            Get-Content $env:USERPROFILE\blueteam_logs\watchdog.log
#
# TIP: Open 3 PowerShell windows total on each Windows box:
#      Window 1 -> ir_monitor.ps1      (evidence collection)
#      Window 2 -> service_watchdog.ps1 (keep services alive)
#      Window 3 -> your working terminal for other tasks
#
# LOG FILE: $env:USERPROFILE\blueteam_logs\watchdog.log
# ============================================================

$LogFile = "$env:USERPROFILE\blueteam_logs\watchdog.log"
$Interval = 30  # seconds

function Log { param([string]$msg)
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line
    Add-Content $LogFile $line
}

function Watch-Service {
    param([string]$ServiceName, [string]$Label)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return }  # Service doesn't exist on this host
    if ($svc.Status -ne "Running") {
        Log "[!] $Label ($ServiceName) is $($svc.Status) - restarting..."
        try {
            Start-Service -Name $ServiceName -ErrorAction Stop
            Start-Sleep 3
            $svc.Refresh()
            if ($svc.Status -eq "Running") {
                Log "[+] $Label restarted successfully"
            } else {
                Log "[!!] $Label FAILED to restart!"
            }
        } catch { Log "[!!] Error restarting $Label`: $_" }
    }
}

$Hostname = $env:COMPUTERNAME.ToLower()
Log "=== Watchdog starting on $Hostname ==="

while ($true) {
    # --- Services common to all Windows hosts ---
    Watch-Service "TermService"     "RDP"
    Watch-Service "WinRM"           "WinRM"

    # --- BlackPearl-specific ---
    if ($Hostname -like "*blackpearl*") {
        Watch-Service "NTDS"            "Active Directory DS"
        Watch-Service "DNS"             "DNS Server"
        Watch-Service "Kerberos"        "Kerberos"
        Watch-Service "LanmanServer"    "SMB/File Sharing"
        Watch-Service "LDAP"            "LDAP"
        Watch-Service "NetLogon"        "NetLogon"
    }

    # --- JollyRoger-specific (Windows Server - check what's actually running) ---
    if ($Hostname -like "*jollyroger*") {
        Watch-Service "LanmanServer"    "SMB/File Sharing"
        Watch-Service "FTPSVC"          "FTP"
        Watch-Service "W3SVC"           "IIS/HTTP"
    }

    Start-Sleep $Interval
}
