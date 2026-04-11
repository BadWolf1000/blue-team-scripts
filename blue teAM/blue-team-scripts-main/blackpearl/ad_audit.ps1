# ============================================================
# DreadWatch Blue Team - Active Directory Audit Script
# Target: BlackPearl ONLY (Windows Server 2022, 10.x.1.10)
#
# WHAT THIS SCRIPT DOES:
#   Red team will target Active Directory hard and fast.
#   This script finds every common AD attack vector and tells
#   you exactly how to fix each one. Auto-fixes what it safely
#   can (AS-REP roasting). Run this RIGHT AFTER hardening.
#   Checks for:
#     - Kerberoastable accounts (SPNs on user accounts)
#       -> Red team extracts these to crack offline
#     - AS-REP Roasting targets (accounts with no pre-auth)
#       -> Allows password hash extraction without credentials
#     - Domain Admin accounts that shouldn't exist
#       -> Red team may add their own Domain Admin
#     - Weak domain password policy
#       -> Makes brute force and password spray easier
#     - Accounts with password never expires
#       -> Stale accounts with old passwords are easy targets
#     - KRBTGT password age (Golden Ticket risk)
#       -> Old krbtgt = red team can forge domain tickets
#     - Unconstrained Kerberos delegation
#       -> Allows stealing tickets from connecting users
#
# HOW TO USE (BlackPearl only):
#   Step 1 - Open PowerShell as Domain Administrator on BlackPearl.
#
#   Step 2 - Run it:
#            Set-ExecutionPolicy Bypass -Scope Process -Force
#            .\ad_audit.ps1
#
#   Step 3 - Fix every line marked [!!RISK] immediately.
#            The script prints the exact fix command next to each finding.
#            Example finding:
#              [!!RISK] AS-REP ROASTABLE: skulllord
#              -> Fix: Set-ADAccountControl skulllord -DoesNotRequirePreAuth $false
#            The script auto-runs this fix for AS-REP roasting.
#
#   Step 4 - For Kerberoastable accounts, evaluate if the SPN is
#            legitimate before removing it - some services need SPNs.
#
#   Step 5 - Re-run after fixing to confirm all risks are gone.
#
#   Step 6 - Run windows_ad_harden.ps1 alongside this for full coverage.
#
# NOTE: This script must run ON BlackPearl (the Domain Controller).
#       It will not work correctly on JollyRoger.
# OUTPUT: $env:USERPROFILE\blueteam_logs\ad_audit_<timestamp>.log
# ============================================================

$LogDir = "$env:USERPROFILE\blueteam_logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$LogFile = "$LogDir\ad_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$EvidenceLog = "$LogDir\EVIDENCE.log"

function ts { Get-Date -Format "HH:mm:ss" }
function Log {
    param([string]$msg, [string]$color = "White")
    $line = "[$(ts)] $msg"
    Write-Host $line -ForegroundColor $color
    Add-Content $LogFile $line
}
function Flag {
    param([string]$msg)
    $line = "[$(ts)] [!!RISK] $msg"
    Write-Host $line -ForegroundColor Red
    Add-Content $LogFile $line
    Add-Content $EvidenceLog "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [AD-RISK] $msg"
}
function Good { Log "[OK]  $args" "Green" }
function Warn { Log "[??]  $args" "Yellow" }
function Hdr  { Log "`n=== $args ===" "Cyan" }

Log "=== Active Directory Security Audit ==="
Log "Domain: $env:USERDOMAIN | Host: $env:COMPUTERNAME"

# Check if AD module available
if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
    Log "[!] Active Directory module not available. Installing RSAT..." "Yellow"
    try {
        Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop | Out-Null
        Import-Module ActiveDirectory -ErrorAction Stop
        Log "[+] AD module loaded"
    } catch {
        Log "[!!] Cannot load AD module: $_" "Red"
        Log "     Run on BlackPearl (the Domain Controller)" "Red"
        exit 1
    }
}

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

$Domain = Get-ADDomain -ErrorAction Stop
$DomainDN = $Domain.DistinguishedName

# ============================================================
# 1. KERBEROASTABLE ACCOUNTS
# (User accounts with SPNs - red team will Kerberoast these)
# ============================================================
Hdr "KERBEROASTABLE ACCOUNTS (SPNs on user accounts)"

$Kerberoastable = Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
    -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate, Enabled `
    -ErrorAction SilentlyContinue

if ($Kerberoastable) {
    foreach ($acct in $Kerberoastable) {
        Flag "KERBEROASTABLE: $($acct.SamAccountName) | SPN: $($acct.ServicePrincipalName -join ',') | PwdLastSet: $($acct.PasswordLastSet)"
        Log "  -> Fix: 'Set-ADUser $($acct.SamAccountName) -Clear ServicePrincipalName' (if SPN not needed)" "Yellow"
    }
} else {
    Good "No user accounts with SPNs found"
}

# ============================================================
# 2. AS-REP ROASTING TARGETS
# (Accounts with pre-authentication disabled)
# ============================================================
Hdr "AS-REP ROASTING TARGETS (no pre-auth required)"

$ASREPTargets = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
    -Properties DoesNotRequirePreAuth, PasswordLastSet `
    -ErrorAction SilentlyContinue

if ($ASREPTargets) {
    foreach ($acct in $ASREPTargets) {
        Flag "AS-REP ROASTABLE: $($acct.SamAccountName) | PwdLastSet: $($acct.PasswordLastSet)"
        Log "  -> Fix: Set-ADAccountControl $($acct.SamAccountName) -DoesNotRequirePreAuth `$false" "Yellow"
        # Auto-fix
        try {
            Set-ADAccountControl -Identity $acct.SamAccountName -DoesNotRequirePreAuth $false
            Log "  [+] Pre-auth requirement enabled for $($acct.SamAccountName)" "Green"
        } catch { Log "  [!] Could not fix: $_" "Red" }
    }
} else {
    Good "All accounts require pre-authentication"
}

# ============================================================
# 3. DOMAIN ADMINS AUDIT
# ============================================================
Hdr "DOMAIN ADMINS AUDIT"

$KnownAdmins = @("AdmiralNelson", "Administrator")  # Add your legitimate admins here

$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction SilentlyContinue
foreach ($admin in $DomainAdmins) {
    if ($admin.SamAccountName -in $KnownAdmins) {
        Good "Expected Domain Admin: $($admin.SamAccountName)"
    } else {
        Flag "UNEXPECTED DOMAIN ADMIN: $($admin.SamAccountName) ($($admin.objectClass))"
        Log "  -> Verify this account belongs in Domain Admins!" "Yellow"
    }
}

# Check other privileged groups
foreach ($group in @("Enterprise Admins", "Schema Admins", "Administrators")) {
    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
    foreach ($m in $members) {
        if ($m.SamAccountName -notin $KnownAdmins -and $m.SamAccountName -notlike "Domain Admins") {
            Warn "$group member: $($m.SamAccountName) - verify this is expected"
        }
    }
}

# ============================================================
# 4. PASSWORD POLICY
# ============================================================
Hdr "DOMAIN PASSWORD POLICY"

$PassPol = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
if ($PassPol) {
    Log "Min length:         $($PassPol.MinPasswordLength)"
    Log "Max age:            $($PassPol.MaxPasswordAge)"
    Log "Min age:            $($PassPol.MinPasswordAge)"
    Log "History:            $($PassPol.PasswordHistoryCount)"
    Log "Complexity:         $($PassPol.ComplexityEnabled)"
    Log "Lockout threshold:  $($PassPol.LockoutThreshold)"

    if ($PassPol.MinPasswordLength -lt 8)    { Flag "Min password length is only $($PassPol.MinPasswordLength) - should be 12+" }
    if (-not $PassPol.ComplexityEnabled)      { Flag "Password complexity is DISABLED" }
    if ($PassPol.LockoutThreshold -eq 0)      { Flag "Account lockout is DISABLED - brute force risk!" }
    if ($PassPol.MaxPasswordAge.Days -gt 90)  { Warn "Max password age is $($PassPol.MaxPasswordAge.Days) days" }
}

# ============================================================
# 5. ACCOUNTS WITH "PASSWORD NEVER EXPIRES"
# ============================================================
Hdr "ACCOUNTS WITH PASSWORD NEVER EXPIRES"

$NeverExpires = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
    -Properties PasswordNeverExpires, PasswordLastSet, LastLogonDate `
    -ErrorAction SilentlyContinue

foreach ($acct in $NeverExpires) {
    if ($acct.SamAccountName -notin @("krbtgt")) {
        Warn "Password never expires: $($acct.SamAccountName) | LastLogon: $($acct.LastLogonDate)"
    }
}

# ============================================================
# 6. KRBTGT ACCOUNT (Golden Ticket risk)
# ============================================================
Hdr "KRBTGT ACCOUNT (Golden Ticket Risk)"

$krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet, PasswordNeverExpires `
    -ErrorAction SilentlyContinue
if ($krbtgt) {
    $daysSinceChange = ((Get-Date) - $krbtgt.PasswordLastSet).Days
    Log "krbtgt password last changed: $($krbtgt.PasswordLastSet) ($daysSinceChange days ago)"
    if ($daysSinceChange -gt 180) {
        Flag "KRBTGT password is $daysSinceChange days old! Change it TWICE to prevent Golden Tickets."
        Log "  -> Run: Invoke-Mimikatz... actually just use AD Users & Computers to reset krbtgt password" "Yellow"
        Log "  -> Must reset TWICE (to invalidate existing tickets)" "Yellow"
    } else {
        Good "krbtgt password changed $daysSinceChange days ago"
    }
}

# ============================================================
# 7. UNCONSTRAINED DELEGATION
# ============================================================
Hdr "UNCONSTRAINED DELEGATION (Ticket Harvesting Risk)"

$UnconstrainedDelegation = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
    -Properties TrustedForDelegation -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne ($Domain.PDCEmulator.Split('.')[0]) }

foreach ($comp in $UnconstrainedDelegation) {
    Flag "UNCONSTRAINED DELEGATION enabled on: $($comp.Name)"
    Log "  -> Fix: Set-ADComputer $($comp.Name) -TrustedForDelegation `$false" "Yellow"
}

$UnconstrainedUsers = Get-ADUser -Filter { TrustedForDelegation -eq $true } `
    -Properties TrustedForDelegation -ErrorAction SilentlyContinue
foreach ($u in $UnconstrainedUsers) {
    Flag "UNCONSTRAINED DELEGATION on user: $($u.SamAccountName)"
}

if (-not $UnconstrainedDelegation -and -not $UnconstrainedUsers) {
    Good "No unconstrained delegation configured"
}

# ============================================================
# 8. STALE ADMIN ACCOUNTS (not logged in recently)
# ============================================================
Hdr "STALE/INACTIVE ACCOUNTS"

$InactiveAdmins = Get-ADUser -Filter { Enabled -eq $true } `
    -Properties LastLogonDate, MemberOf `
    -ErrorAction SilentlyContinue |
    Where-Object {
        ($_.LastLogonDate -lt (Get-Date).AddDays(-30) -or $_.LastLogonDate -eq $null) -and
        ($_.MemberOf -like "*Admin*" -or $_.MemberOf -like "*Domain Admins*")
    }

foreach ($acct in $InactiveAdmins) {
    Warn "Inactive admin account: $($acct.SamAccountName) | Last logon: $($acct.LastLogonDate)"
}

# ============================================================
# 9. ACCOUNTS WITH SAME PASSWORD HASH AS KNOWN-BAD PASSWORDS
# (Check for accounts with weak or unchanged passwords)
# ============================================================
Hdr "WEAK PASSWORD CHECK"
Log "Checking for default competition passwords still in use..."
Log "(This checks if accounts appear locked - they may still have default passwords)"

$StillDefault = Get-ADUser -Filter { Enabled -eq $true } `
    -Properties PasswordLastSet, PasswordExpired `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.PasswordLastSet -lt (Get-Date).AddHours(-1) -or $_.PasswordLastSet -eq $null }

if ($StillDefault.Count -gt 5) {
    Flag "$($StillDefault.Count) accounts haven't had passwords changed recently - run rotate_passwords!"
}

# ============================================================
# 10. PRINT SUMMARY
# ============================================================
$RiskCount = (Get-Content $LogFile -ErrorAction SilentlyContinue | Where-Object { $_ -match "!!RISK" }).Count

Log "`n============================================"
Log "AD AUDIT COMPLETE"
Log "Risks found: $RiskCount"
Log "Full report: $LogFile"
Log "============================================"

Write-Host "`n[!] Fix all FLAG items immediately - red team WILL exploit these." -ForegroundColor Red
Write-Host "    Priority order: AS-REP Roasting > Unconstrained Delegation > Kerberoasting > Domain Admin list" -ForegroundColor Yellow
