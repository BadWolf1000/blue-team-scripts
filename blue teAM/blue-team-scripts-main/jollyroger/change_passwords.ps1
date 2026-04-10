# ============================================================
# DreadWatch Blue Team - Password Change Script (Windows)
# Targets: BlackPearl (10.x.1.10) and JollyRoger (10.x.2.11)
#
# WHAT THIS SCRIPT DOES:
#   Provides an interactive menu to change passwords for all
#   competition accounts on this Windows machine. Handles both:
#     - Local accounts (using Set-LocalUser)
#     - Domain/AD accounts (using Set-ADAccountPassword) on BlackPearl
#   Shows which accounts exist, when passwords were last set,
#   and whether they're enabled or locked.
#
# HOW TO USE:
#   Step 1 - Open PowerShell as Administrator.
#
#   Step 2 - Allow script execution and run it:
#            Set-ExecutionPolicy Bypass -Scope Process -Force
#            .\change_passwords.ps1
#
#   Step 3 - Choose from the menu:
#            [1] Change ALL passwords at once (use this first!)
#            [2] Change one specific account
#            [3] List all accounts with status and last password date
#            [4] Generate a random password and apply it
#            [5] Unlock locked accounts (red team may have locked yours)
#
#   Step 4 - For option 1, enter ONE password - it applies to every
#            account that exists on this machine (local + domain if DC).
#            WRITE IT DOWN and tell your teammates immediately.
#
# WHEN TO RUN:
#   - FIRST THING on both BlackPearl and JollyRoger
#   - Default password is Passw0rd123! - change it immediately
#   - Any time red team may have credentials
#
# DEFAULT PASSWORD TO REPLACE: Passw0rd123!
# LOG FILE: $env:USERPROFILE\Desktop\blueteam_logs\password_changes.log
# ============================================================

$ErrorActionPreference = "SilentlyContinue"
$LogDir = "$env:USERPROFILE\Desktop\blueteam_logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$LogFile = "$LogDir\password_changes.log"

function ts { Get-Date -Format "yyyy-MM-dd HH:mm:ss" }
function Log { param([string]$msg) Add-Content $LogFile "[$(ts)] $msg" }

# ============================================================
# ALL KNOWN COMPETITION ACCOUNTS
# ============================================================
$DomainUsers = @(
    "AdmiralNelson", "quartermaster", "skulllord",
    "dreadpirate", "blackflag"
)

$LocalUsers = @(
    "SaltyDog23", "PlunderMate56", "RumRider12", "GoldTooth89",
    "HighTide74", "SeaScourge30", "ParrotJack67", "CannonDeck45",
    "BarnacleBill98", "StormBringer09"
)

$SystemUsers = @("Administrator")
$AllUsers = $SystemUsers + $DomainUsers + $LocalUsers

$IsDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Get-AccountInfo {
    param([string]$username)
    $local = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if ($local) {
        return @{
            Exists       = $true
            Type         = "Local"
            Enabled      = $local.Enabled
            PasswordSet  = if ($local.PasswordLastSet) { $local.PasswordLastSet.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
            Locked       = $false
        }
    }
    if ($IsDC) {
        $ad = Get-ADUser -Identity $username -Properties PasswordLastSet, Enabled, LockedOut -ErrorAction SilentlyContinue
        if ($ad) {
            return @{
                Exists       = $true
                Type         = "Domain"
                Enabled      = $ad.Enabled
                PasswordSet  = if ($ad.PasswordLastSet) { $ad.PasswordLastSet.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
                Locked       = $ad.LockedOut
            }
        }
    }
    return @{ Exists = $false }
}

function Set-AccountPassword {
    param([string]$username, [SecureString]$securePass)

    $info = Get-AccountInfo $username
    if (-not $info.Exists) {
        Write-Host "  [SKIP] $username - not on this machine" -ForegroundColor Yellow
        return "skip"
    }

    try {
        if ($info.Type -eq "Local") {
            Set-LocalUser -Name $username -Password $securePass -ErrorAction Stop
            Write-Host "  [OK]   $username (local) - password changed" -ForegroundColor Green
            Log "[CHANGED-LOCAL] $username on $env:COMPUTERNAME"
            return "ok"
        } elseif ($info.Type -eq "Domain") {
            Set-ADAccountPassword -Identity $username -NewPassword $securePass -Reset -ErrorAction Stop
            # Also unlock if locked
            Unlock-ADAccount -Identity $username -ErrorAction SilentlyContinue
            Write-Host "  [OK]   $username (domain) - password changed" -ForegroundColor Green
            Log "[CHANGED-DOMAIN] $username on $env:COMPUTERNAME"
            return "ok"
        }
    } catch {
        Write-Host "  [FAIL] $username - $_" -ForegroundColor Red
        Log "[FAILED] $username - $_"
        return "fail"
    }
}

function Prompt-Password {
    while ($true) {
        $p1 = Read-Host "  Enter new password" -AsSecureString
        $p2 = Read-Host "  Confirm password  " -AsSecureString

        # Convert to plain text to compare (only for validation)
        $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
        $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))

        if ($plain1 -ne $plain2) {
            Write-Host "  [!] Passwords do not match. Try again." -ForegroundColor Red
            continue
        }
        if ($plain1.Length -lt 8) {
            Write-Host "  [!] Password must be at least 8 characters." -ForegroundColor Red
            continue
        }
        return $p1
    }
}

function Generate-RandomPassword {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789!@#$%^&*'
    $pass = -join ((1..20) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return $pass
}

function Print-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║     DREADWATCH - Password Change Manager     ║" -ForegroundColor Cyan
    Write-Host "  ║     Host: $($env:COMPUTERNAME.PadRight(20))           ║" -ForegroundColor Cyan
    Write-Host "  ║     Type: $(if ($IsDC) {'Domain Controller'.PadRight(20)} else {'Member Server       '})           ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================
# MENU OPTIONS
# ============================================================

function Option-ListAccounts {
    Write-Host ""
    Write-Host "  All Competition Accounts on $env:COMPUTERNAME" -ForegroundColor White
    Write-Host ""
    Write-Host ("  {0,-22} {1,-8} {2,-10} {3,-22} {4}" -f "USERNAME","TYPE","STATUS","LAST PWD CHANGE","LOCKED") -ForegroundColor White
    Write-Host "  $("─" * 80)"

    Write-Host "  --- Domain / Admin ---" -ForegroundColor Cyan
    foreach ($user in ($SystemUsers + $DomainUsers)) {
        $info = Get-AccountInfo $user
        if ($info.Exists) {
            $status  = if ($info.Enabled) { "Enabled" } else { "DISABLED" }
            $locked  = if ($info.Locked)  { "YES(!)" }  else { "No" }
            $color   = if ($info.Locked)  { "Red" }     else { "Green" }
            Write-Host ("  {0,-22} {1,-8} {2,-10} {3,-22} {4}" -f $user,$info.Type,$status,$info.PasswordSet,$locked) -ForegroundColor $color
        } else {
            Write-Host ("  {0,-22} {1,-8} {2}" -f $user,"--","not on this machine") -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "  --- Local Users ---" -ForegroundColor Cyan
    foreach ($user in $LocalUsers) {
        $info = Get-AccountInfo $user
        if ($info.Exists) {
            $status  = if ($info.Enabled) { "Enabled" } else { "DISABLED" }
            $locked  = if ($info.Locked)  { "YES(!)" }  else { "No" }
            $color   = if ($info.Locked)  { "Red" }     else { "Green" }
            Write-Host ("  {0,-22} {1,-8} {2,-10} {3,-22} {4}" -f $user,$info.Type,$status,$info.PasswordSet,$locked) -ForegroundColor $color
        } else {
            Write-Host ("  {0,-22} {1,-8} {2}" -f $user,"--","not on this machine") -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

function Option-ChangeAll {
    Write-Host ""
    Write-Host "  Change ALL account passwords to a single new password" -ForegroundColor White
    Write-Host "  This applies to every account that exists on this machine." -ForegroundColor Yellow
    Write-Host "  WRITE THE NEW PASSWORD DOWN before continuing!" -ForegroundColor Yellow
    Write-Host ""

    $securePass = Prompt-Password

    Write-Host ""
    Write-Host "  Changing passwords..." -ForegroundColor White
    Write-Host ""

    $changed = 0; $failed = 0; $skipped = 0
    foreach ($user in $AllUsers) {
        $result = Set-AccountPassword $user $securePass
        switch ($result) {
            "ok"   { $changed++ }
            "fail" { $failed++ }
            "skip" { $skipped++ }
        }
    }

    # Extract plain text just to display it once
    $plainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass))

    Write-Host ""
    Write-Host "  Results: $changed changed | $failed failed | $skipped skipped" -ForegroundColor White
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "  ║  NEW PASSWORD: $($plainPass.PadRight(26))║" -ForegroundColor Yellow
    Write-Host "  ║  TELL YOUR TEAMMATES NOW!                ║" -ForegroundColor Yellow
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Yellow
}

function Option-ChangeOne {
    Write-Host ""
    Write-Host "  Change a single account's password" -ForegroundColor White
    Write-Host ""
    Write-Host "  Accounts on this machine:"

    $available = @()
    foreach ($user in $AllUsers) {
        $info = Get-AccountInfo $user
        if ($info.Exists) {
            $available += $user
            Write-Host ("  [{0,2}] {1}" -f $available.Count, $user)
        }
    }

    Write-Host ""
    $sel = Read-Host "  Enter account name or number"

    if ($sel -match '^\d+$') {
        $idx = [int]$sel - 1
        if ($idx -ge 0 -and $idx -lt $available.Count) {
            $target = $available[$idx]
        } else {
            Write-Host "  [!] Invalid number" -ForegroundColor Red; return
        }
    } else {
        $target = $sel
    }

    $info = Get-AccountInfo $target
    if (-not $info.Exists) {
        Write-Host "  [!] '$target' not found on this machine" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  Changing password for: $target ($($info.Type))" -ForegroundColor Cyan
    $securePass = Prompt-Password
    Set-AccountPassword $target $securePass | Out-Null
}

function Option-Random {
    Write-Host ""
    Write-Host "  Generate a random strong password" -ForegroundColor White
    Write-Host ""
    $randPass = Generate-RandomPassword
    Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  Generated: $($randPass.PadRight(29))║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    $ans = Read-Host "  Apply this to ALL accounts? [y/N]"
    if ($ans -match '^[Yy]$') {
        $securePass = ConvertTo-SecureString $randPass -AsPlainText -Force
        $changed = 0
        foreach ($user in $AllUsers) {
            $result = Set-AccountPassword $user $securePass
            if ($result -eq "ok") { $changed++ }
        }
        Write-Host ""
        Write-Host "  Applied to $changed accounts." -ForegroundColor Green
        Write-Host "  TELL YOUR TEAMMATES: $randPass" -ForegroundColor Yellow
        Log "[RANDOM-PASS] Applied to $changed accounts on $env:COMPUTERNAME"
    }
}

function Option-UnlockAll {
    Write-Host ""
    Write-Host "  Unlocking all known accounts..." -ForegroundColor White
    Write-Host ""
    foreach ($user in $AllUsers) {
        # Local unlock
        $local = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
        if ($local -and -not $local.Enabled) {
            Enable-LocalUser -Name $user -ErrorAction SilentlyContinue
            Write-Host "  [OK] Enabled local account: $user" -ForegroundColor Green
        }
        # Domain unlock
        if ($IsDC) {
            $ad = Get-ADUser -Identity $user -Properties LockedOut -ErrorAction SilentlyContinue
            if ($ad -and $ad.LockedOut) {
                Unlock-ADAccount -Identity $user -ErrorAction SilentlyContinue
                Write-Host "  [OK] Unlocked domain account: $user" -ForegroundColor Green
                Log "[UNLOCKED] $user on $env:COMPUTERNAME"
            }
        }
    }
    Write-Host ""
    Write-Host "  Done. Run option [3] to review current account status." -ForegroundColor Cyan
}

# ============================================================
# MAIN MENU LOOP
# ============================================================
if ($IsDC) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
}

Print-Header

while ($true) {
    Write-Host "  Select an option:" -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] Change ALL passwords (recommended at competition start)"
    Write-Host "  [2] Change ONE specific account"
    Write-Host "  [3] List all accounts with status and last password change"
    Write-Host "  [4] Generate random password and apply to all accounts"
    Write-Host "  [5] Unlock all locked/disabled accounts"
    Write-Host "  [q] Quit"
    Write-Host ""
    $choice = Read-Host "  Choice"

    switch ($choice) {
        "1" { Option-ChangeAll }
        "2" { Option-ChangeOne }
        "3" { Option-ListAccounts }
        "4" { Option-Random }
        "5" { Option-UnlockAll }
        { $_ -in "q","Q" } {
            Write-Host ""
            Write-Host "  Exiting. Log: $LogFile" -ForegroundColor Cyan
            exit 0
        }
        default { Write-Host "  [!] Invalid choice" -ForegroundColor Red }
    }

    Write-Host ""
    Read-Host "  Press Enter to return to menu"
    Print-Header
}
