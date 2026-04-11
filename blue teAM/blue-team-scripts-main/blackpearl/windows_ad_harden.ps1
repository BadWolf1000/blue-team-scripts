# ============================================================
# DreadWatch Blue Team - Windows AD / DC Hardening
# Target: BlackPearl (Domain Controller) - Primary
#         JollyRoger (Windows Server) - Secondary
#
# WHAT THIS SCRIPT DOES:
#   Closes the most commonly exploited Windows/AD attack vectors
#   that red team uses in competitions. Run this in addition to
#   harden_windows.ps1 (which covers general Windows hardening).
#   Actions:
#     1. Disables LLMNR - prevents Responder poisoning attacks
#        (red team runs Responder to steal NTLMv2 hashes)
#     2. Disables NBT-NS - another Responder attack vector
#     3. Enforces SMB signing - prevents NTLM relay attacks
#        (stops relay of captured hashes to authenticate elsewhere)
#     4. Disables WDigest - stops Mimikatz reading plaintext passwords
#        from memory
#     5. Enables LSA Protection - blocks Mimikatz from LSASS entirely
#     6. Disables PowerShell v2 - prevents bypassing PS logging
#     7. Enables full PowerShell logging - captures attacker PS commands
#     8. Weakens RC4 Kerberos - makes Kerberoasting harder
#     9. Disables Print Spooler on DC - fixes PrintNightmare
#    10. Sets domain account lockout policy
#    11. Restricts anonymous enumeration of AD (prevents BloodHound)
#    12. Disables Remote Registry
#    13. Enables Credential Guard
#
# HOW TO USE:
#   Step 1 - Open PowerShell as Domain Administrator on BlackPearl.
#
#   Step 2 - Run AFTER harden_windows.ps1:
#            Set-ExecutionPolicy Bypass -Scope Process -Force
#            .\windows_ad_harden.ps1
#
#   Step 3 - Review output. Some steps may show warnings if features
#            aren't supported on this hardware - that's okay.
#
#   Step 4 - IMPORTANT: Some protections require a REBOOT to take effect:
#              - LSA Protection (RunAsPPL)
#              - Credential Guard
#            Discuss with your team whether to reboot during competition.
#            Rebooting will temporarily drop your RDP/WinRM uptime score.
#
#   Step 5 - Also run ad_audit.ps1 to find remaining AD attack vectors.
#
# RECOMMENDED ORDER on BlackPearl:
#   1. harden_windows.ps1       (general hardening)
#   2. windows_ad_harden.ps1    (this script - AD specific)
#   3. ad_audit.ps1             (find and fix remaining risks)
#   4. ir_monitor.ps1           (start evidence collection)
#   5. service_watchdog.ps1     (keep services alive)
#
# LOG FILE: $env:USERPROFILE\blueteam_logs\ad_harden_<timestamp>.log
# ============================================================
# ============================================================

$ErrorActionPreference = "Continue"
$LogDir = "$env:USERPROFILE\blueteam_logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$LogFile = "$LogDir\ad_harden_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log {
    param([string]$msg, [string]$color = "White")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor $color
    Add-Content $LogFile $line
}

Log "=== Windows/AD Hardening Started on $env:COMPUTERNAME ===" "Cyan"

$IsDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4

# ============================================================
# 1. DISABLE LLMNR (Responder / Poisoning attacks)
# ============================================================
Log "[1] Disabling LLMNR..."
try {
    $LLMNRKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    New-Item -Path $LLMNRKey -Force | Out-Null
    Set-ItemProperty -Path $LLMNRKey -Name "EnableMulticast" -Value 0 -Type DWord
    Log "[+] LLMNR disabled (prevents Responder poisoning)" "Green"
} catch { Log "[!] LLMNR: $_" "Red" }

# ============================================================
# 2. DISABLE NBT-NS (NetBIOS Name Service - another Responder vector)
# ============================================================
Log "[2] Disabling NBT-NS on all adapters..."
try {
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
    foreach ($adapter in $adapters) {
        # 2 = Disable NetBIOS over TCP/IP
        $adapter.SetTcpipNetbios(2) | Out-Null
    }
    Log "[+] NBT-NS disabled on all adapters" "Green"
} catch { Log "[!] NBT-NS: $_" "Red" }

# ============================================================
# 3. ENFORCE SMB SIGNING (prevents NTLM relay attacks)
# ============================================================
Log "[3] Enforcing SMB signing..."
try {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
    Log "[+] SMB signing required (prevents NTLM relay/pass-the-hash)" "Green"
} catch { Log "[!] SMB signing: $_" "Red" }

# ============================================================
# 4. DISABLE WDIGEST (prevents plaintext passwords in memory)
# ============================================================
Log "[4] Disabling WDigest credential caching..."
try {
    $WDigestKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    Set-ItemProperty -Path $WDigestKey -Name "UseLogonCredential" -Value 0 -Type DWord -Force
    Log "[+] WDigest disabled (prevents Mimikatz from grabbing plaintext passwords)" "Green"
} catch { Log "[!] WDigest: $_" "Red" }

# ============================================================
# 5. ENABLE LSA PROTECTION (Protected Process Light)
# ============================================================
Log "[5] Enabling LSA Protection (blocks Mimikatz)..."
try {
    $LSAKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $LSAKey -Name "RunAsPPL" -Value 1 -Type DWord -Force
    Log "[+] LSA Protection enabled (requires reboot to take effect)" "Green"
} catch { Log "[!] LSA Protection: $_" "Red" }

# ============================================================
# 6. DISABLE POWERSHELL VERSION 2 (downgrade attack prevention)
# ============================================================
Log "[6] Disabling PowerShell v2..."
try {
    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction Stop | Out-Null
    Log "[+] PowerShell v2 disabled (prevents downgrade to bypass logging)" "Green"
} catch { Log "[!] PS v2 disable (may not be installed): $_" "Yellow" }

# ============================================================
# 7. ENABLE POWERSHELL SCRIPT BLOCK LOGGING (catch attacker PS commands)
# ============================================================
Log "[7] Enabling PowerShell logging..."
try {
    $PSLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $PSLogKey -Force | Out-Null
    Set-ItemProperty -Path $PSLogKey -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Set-ItemProperty -Path $PSLogKey -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

    $PSModLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    New-Item -Path $PSModLogKey -Force | Out-Null
    Set-ItemProperty -Path $PSModLogKey -Name "EnableModuleLogging" -Value 1 -Type DWord

    Log "[+] PowerShell script block + module logging enabled" "Green"
} catch { Log "[!] PS logging: $_" "Red" }

# ============================================================
# 8. DISABLE RC4 KERBEROS ENCRYPTION (weak, used in attacks)
# ============================================================
Log "[8] Disabling weak Kerberos encryption types..."
try {
    $KerbKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    New-Item -Path $KerbKey -Force | Out-Null
    # 0x7fffffff = AES128 + AES256 + RC4 (keep RC4 for compatibility during competition)
    # 0x18 = AES128 + AES256 only (more secure but may break older clients)
    Set-ItemProperty -Path $KerbKey -Name "SupportedEncryptionTypes" -Value 0x7ffffff8 -Type DWord
    Log "[+] Kerberos: RC4 de-prioritized, AES preferred" "Green"
} catch { Log "[!] Kerberos encryption: $_" "Red" }

# ============================================================
# 9. PRINT SPOOLER / PRINTNIGHTMARE MITIGATION
# ============================================================
Log "[9] Mitigating PrintNightmare..."
try {
    $SpoolerSvc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($IsDC) {
        # DCs should never run print spooler
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled
        Log "[+] Print Spooler DISABLED on DC (DCs should never run this)" "Green"
    } else {
        # For non-DCs that need printing, restrict point-and-print
        $PrintKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        New-Item -Path $PrintKey -Force | Out-Null
        Set-ItemProperty -Path $PrintKey -Name "NoWarningNoElevationOnInstall" -Value 0 -Type DWord
        Set-ItemProperty -Path $PrintKey -Name "UpdatePromptSettings" -Value 0 -Type DWord
        Log "[+] Point-and-Print restricted" "Green"
    }
} catch { Log "[!] PrintNightmare: $_" "Red" }

# ============================================================
# 10. ACCOUNT LOCKOUT POLICY (domain-wide)
# ============================================================
Log "[10] Setting domain account lockout policy..."
if ($IsDC) {
    try {
        Set-ADDefaultDomainPasswordPolicy `
            -Identity $env:USERDOMAIN `
            -LockoutDuration "00:30:00" `
            -LockoutObservationWindow "00:30:00" `
            -LockoutThreshold 5 `
            -MinPasswordLength 12 `
            -PasswordHistoryCount 10 `
            -ComplexityEnabled $true `
            -ErrorAction Stop
        Log "[+] Domain password policy hardened (lockout:5 attempts, minLen:12, complexity:on)" "Green"
    } catch { Log "[!] Password policy: $_" "Red" }
}

# ============================================================
# 11. RESTRICT ANONYMOUS ENUMERATION
# ============================================================
Log "[11] Restricting anonymous enumeration..."
try {
    $LSAKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $LSAKey -Name "RestrictAnonymous" -Value 1 -Type DWord
    Set-ItemProperty -Path $LSAKey -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
    Set-ItemProperty -Path $LSAKey -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord
    Log "[+] Anonymous enumeration restricted (prevents null-session attacks)" "Green"
} catch { Log "[!] Anonymous restriction: $_" "Red" }

# ============================================================
# 12. DISABLE REMOTE REGISTRY (common lateral movement path)
# ============================================================
Log "[12] Disabling Remote Registry..."
try {
    Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue
    Set-Service RemoteRegistry -StartupType Disabled
    Log "[+] Remote Registry disabled" "Green"
} catch { Log "[!] Remote Registry: $_" "Red" }

# ============================================================
# 13. ENABLE WINDOWS DEFENDER CREDENTIAL GUARD (if supported)
# ============================================================
Log "[13] Enabling Credential Guard..."
try {
    $DevGuardKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    New-Item -Path $DevGuardKey -Force | Out-Null
    Set-ItemProperty -Path $DevGuardKey -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
    Set-ItemProperty -Path $DevGuardKey -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord

    $CredGuardKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $CredGuardKey -Name "LsaCfgFlags" -Value 1 -Type DWord
    Log "[+] Credential Guard enabled (requires reboot, prevents Mimikatz credential theft)" "Green"
} catch { Log "[!] Credential Guard: $_" "Red" }

# ============================================================
# SUMMARY
# ============================================================
Log ""
Log "================================================" "Cyan"
Log "[+] AD/Windows hardening complete!" "Green"
Log "[!] Some changes require a REBOOT to take effect:" "Yellow"
Log "    - LSA Protection (RunAsPPL)" "Yellow"
Log "    - Credential Guard" "Yellow"
Log "Log: $LogFile" "White"
Log "================================================" "Cyan"
Log ""
Log "Run ad_audit.ps1 to verify the AD security posture." "Cyan"
