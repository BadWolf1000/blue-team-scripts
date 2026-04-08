# ============================================================
# DreadWatch Blue Team - Windows Service Watchdog
# Keeps scored services alive on BlackPearl and JollyRoger
# Run as Administrator. Loops every 30 seconds.
# Usage: powershell -ExecutionPolicy Bypass -File service_watchdog.ps1
# ============================================================

$LogFile = "C:\blueteam_watchdog.log"
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
