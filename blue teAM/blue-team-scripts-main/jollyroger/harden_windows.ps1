# ============================================================
# DreadWatch Blue Team - Windows Server Hardening Script
# Targets: BlackPearl (10.x.1.10) and JollyRoger (10.x.2.11)
#
# WHAT THIS SCRIPT DOES:
#   Hardens a Windows Server against common red team attacks
#   while keeping all scored services running:
#     1. Changes all known competition account passwords
#     2. Changes the built-in Administrator password
#     3. If on BlackPearl (AD/DC), also changes domain account passwords
#     4. Disables the Guest account
#     5. Configures Windows Firewall (enables it, sets host-specific rules)
#     6. Disables dangerous services (Telnet, RemoteRegistry, etc.)
#     7. Enables audit logging (logon events, process creation)
#     8. Hardens RDP to require Network Level Authentication (NLA)
#     9. Sets account lockout policy (5 attempts = 30 min lockout)
#    10. Disables SMBv1 (prevents EternalBlue/WannaCry)
#    11. Audits scheduled tasks for backdoors
#    12. Lists all local admins for review
#
# HOW TO USE:
#   Step 1 - Pull scripts from GitHub. Open PowerShell as Administrator:
#            cd C:\
#            git clone https://github.com/BadWolf1000/blue-team-scripts.git bt
#            cd bt\windows
#
#   Step 2 - Allow script execution for this session:
#            Set-ExecutionPolicy Bypass -Scope Process -Force
#
#   Step 3 - Run the hardening script:
#            .\harden_windows.ps1
#
#   Step 4 - Review the output. Note the new password that was set.
#            The log is saved to $env:USERPROFILE\Desktop\blueteam_logs\harden_<timestamp>.log
#
#   Step 5 - Verify scored services are still running:
#            Get-Service TermService, WinRM           (JollyRoger)
#            Get-Service TermService, WinRM, NTDS, DNS (BlackPearl)
#
#   Step 6 - On BlackPearl ONLY, also run:
#            .\windows_ad_harden.ps1   (AD-specific hardening)
#            .\ad_audit.ps1            (find AD attack vectors)
#
# NOTE: Run on BOTH BlackPearl and JollyRoger during the first 30 minutes.
# ============================================================

$ErrorActionPreference = "Continue"
$LogFile = "$env:USERPROFILE\Desktop\blueteam_logs\harden_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log {
    param([string]$msg)
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Log "=== DreadWatch Windows Hardening Started ==="
Log "Host: $env:COMPUTERNAME"

# ============================================================
# 1. CHANGE ALL KNOWN ACCOUNT PASSWORDS
# ============================================================
Log "[1] Changing passwords..."

$NewPass = ConvertTo-SecureString "DreadWatch@2024!" -AsPlainText -Force

$KnownUsers = @(
    "AdmiralNelson","quartermaster","skulllord","dreadpirate","blackflag",
    "SaltyDog23","PlunderMate56","RumRider12","GoldTooth89","HighTide74",
    "SeaScourge30","ParrotJack67","CannonDeck45","BarnacleBill98","StormBringer09"
)

foreach ($user in $KnownUsers) {
    try {
        $account = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
        if ($account) {
            Set-LocalUser -Name $user -Password $NewPass
            Log "[+] Password changed: $user (local)"
        }
    } catch { Log "[!] Could not change $user`: $_" }
}

# Also change Administrator password
try {
    $AdminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($AdminAccount) {
        Set-LocalUser -Name "Administrator" -Password $NewPass
        Log "[+] Administrator password changed"
    }
} catch { Log "[!] Could not change Administrator: $_" }

# Domain accounts (if this is a DC)
if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
    Log "[*] Detected Active Directory - changing domain accounts..."
    foreach ($user in $KnownUsers) {
        try {
            $adUser = Get-ADUser -Identity $user -ErrorAction SilentlyContinue
            if ($adUser) {
                Set-ADAccountPassword -Identity $user -NewPassword $NewPass -Reset
                Log "[+] AD password changed: $user"
            }
        } catch { Log "[!] AD user $user not found or error: $_" }
    }
}

# ============================================================
# 2. DISABLE GUEST AND DEFAULT ACCOUNTS
# ============================================================
Log "[2] Disabling Guest account..."
try {
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Log "[+] Guest disabled"
} catch { Log "[!] Guest: $_" }

# ============================================================
# 3. FIREWALL CONFIGURATION
# ============================================================
Log "[3] Configuring Windows Firewall..."

# Enable firewall on all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Log "[+] Firewall enabled on all profiles"

# Set default: block inbound, allow outbound
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# Remove all existing allow rules (be careful - add back what's needed)
# Instead, we'll add specific rules for scored services

# Determine which services this host runs based on hostname
$hostname = $env:COMPUTERNAME.ToLower()

# Always needed
$rules = @()

if ($hostname -like "*blackpearl*") {
    Log "[*] Configuring BlackPearl rules (LDAP, RDP, SMB, WinRM)"
    $rules += @(
        @{Name="RDP-In";        Port=3389; Proto="TCP"; Description="RDP scored"},
        @{Name="LDAP-In";       Port=389;  Proto="TCP"; Description="LDAP scored"},
        @{Name="LDAPS-In";      Port=636;  Proto="TCP"; Description="LDAPS"},
        @{Name="SMB-In";        Port=445;  Proto="TCP"; Description="SMB scored"},
        @{Name="WinRM-HTTP";    Port=5985; Proto="TCP"; Description="WinRM HTTP scored"},
        @{Name="WinRM-HTTPS";   Port=5986; Proto="TCP"; Description="WinRM HTTPS"},
        @{Name="Kerberos-TCP";  Port=88;   Proto="TCP"; Description="Kerberos"},
        @{Name="Kerberos-UDP";  Port=88;   Proto="UDP"; Description="Kerberos UDP"},
        @{Name="DNS-TCP";       Port=53;   Proto="TCP"; Description="DNS"},
        @{Name="DNS-UDP";       Port=53;   Proto="UDP"; Description="DNS UDP"},
        @{Name="NetBIOS";       Port=137;  Proto="UDP"; Description="NetBIOS"},
        @{Name="NetBIOS-SSN";   Port=139;  Proto="TCP"; Description="NetBIOS Session"}
    )
} elseif ($hostname -like "*jollyroger*") {
    Log "[*] Configuring JollyRoger rules (RDP, WinRM)"
    $rules += @(
        @{Name="RDP-In";        Port=3389; Proto="TCP"; Description="RDP scored"},
        @{Name="WinRM-HTTP";    Port=5985; Proto="TCP"; Description="WinRM HTTP scored"},
        @{Name="WinRM-HTTPS";   Port=5986; Proto="TCP"; Description="WinRM HTTPS"}
    )
} else {
    Log "[*] Unknown host - applying minimal rules"
    $rules += @(
        @{Name="RDP-In"; Port=3389; Proto="TCP"; Description="RDP"}
    )
}

# Apply rules
foreach ($rule in $rules) {
    try {
        New-NetFirewallRule -DisplayName "BT-$($rule.Name)" `
            -Direction Inbound `
            -Protocol $rule.Proto `
            -LocalPort $rule.Port `
            -Action Allow `
            -Profile Any `
            -Description $rule.Description `
            -ErrorAction Stop | Out-Null
        Log "[+] Firewall rule added: $($rule.Name) port $($rule.Port)"
    } catch {
        Log "[!] Rule $($rule.Name): $_"
    }
}

# ============================================================
# 4. DISABLE DANGEROUS SERVICES
# ============================================================
Log "[4] Disabling risky services..."
$DangerousServices = @("Telnet","RemoteRegistry","SharedAccess","XblGameSave","XboxGipSvc")

foreach ($svc in $DangerousServices) {
    try {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Log "[+] Disabled: $svc"
        }
    } catch { }
}

# ============================================================
# 5. AUDIT POLICY (LOG LOGONS, PROCESS CREATION)
# ============================================================
Log "[5] Enabling audit policies..."
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable 2>$null
auditpol /set /category:"Account Logon" /success:enable /failure:enable 2>$null
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable 2>$null
Log "[+] Audit policies enabled"

# ============================================================
# 6. RDP HARDENING
# ============================================================
Log "[6] Hardening RDP..."
# Require NLA
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 1 -ErrorAction SilentlyContinue
# Limit connections
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name "MaxConnectionPolicy" -Value 2 -ErrorAction SilentlyContinue
Log "[+] RDP NLA required"

# ============================================================
# 7. ACCOUNT LOCKOUT POLICY
# ============================================================
Log "[7] Setting account lockout policy..."
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 2>$null
Log "[+] Account lockout: 5 attempts -> 30 min lockout"

# ============================================================
# 8. DISABLE SMBv1 (ETERNALBLUE PREVENTION)
# ============================================================
Log "[8] Disabling SMBv1..."
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Log "[+] SMBv1 disabled"
} catch { Log "[!] SMBv1: $_" }

# ============================================================
# 9. CHECK SCHEDULED TASKS FOR BACKDOORS
# ============================================================
Log "[9] Auditing scheduled tasks..."
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
foreach ($task in $tasks) {
    $action = $task.Actions | Where-Object { $_.Execute -match "powershell|cmd|wscript|cscript|mshta" }
    if ($action) {
        Log "[!] SUSPICIOUS TASK: $($task.TaskName) -> $($action.Execute) $($action.Arguments)"
    }
}

# ============================================================
# 10. CHECK FOR UNEXPECTED LOCAL ADMINS
# ============================================================
Log "[10] Checking local admins..."
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
foreach ($admin in $admins) {
    Log "[*] Local admin: $($admin.Name)"
}

Log ""
Log "================================================"
Log "[+] Windows hardening complete!"
Log "Log saved to: $LogFile"
Log "[!] REVIEW SCHEDULED TASKS AND LOCAL ADMINS!"
Log "================================================"
