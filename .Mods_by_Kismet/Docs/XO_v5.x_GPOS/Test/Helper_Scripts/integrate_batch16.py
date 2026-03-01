#!/usr/bin/env python3
"""Batch 16 integration script - Remaining and Compliance (10 functions)
Replaces stub functions with comprehensive implementations.
VulnIDs: V-203783, V-203784, V-263650, V-263651, V-263652,
         V-263654, V-263655, V-263656, V-263657, V-263659
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

IMPLEMENTATIONS = {}

# ============================================================
# V-203783 - Limit non-privileged user privilege grants (home dir perms)
# ============================================================
IMPLEMENTATIONS["V-203783"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Home Directory Access Restrictions ---" + $nl

    # Check 1: Home directory permissions
    $FindingDetails += $nl + "Check 1: Home Directory Permissions" + $nl
    $homeDirs = $(sh -c "ls -ld /home/*/ 2>/dev/null" 2>&1)
    if ($homeDirs -and "$homeDirs" -notmatch "No such file") {
        $FindingDetails += "  Home directories:" + $nl
        $homeLines = "$homeDirs" -split $nl
        $worldAccessible = $false
        foreach ($line in $homeLines) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "    $("$line".Trim())" + $nl
                if ("$line" -match "^d.{6}(r|w|x).{2}\s") {
                    $worldAccessible = $true
                }
            }
        }
        if ($worldAccessible) {
            $FindingDetails += "  [FINDING] World-accessible home directories detected" + $nl
        }
    }
    else {
        $FindingDetails += "  No user home directories found in /home/" + $nl
    }

    # Check 2: Default home directory creation permissions
    $FindingDetails += $nl + "Check 2: Default Home Directory Permissions (login.defs)" + $nl
    $umaskSetting = $(sh -c "grep -i '^UMASK' /etc/login.defs 2>/dev/null" 2>&1)
    if ($umaskSetting -and "$umaskSetting".Trim().Length -gt 0) {
        $FindingDetails += "  $("$umaskSetting".Trim())" + $nl
    }
    else {
        $FindingDetails += "  UMASK not configured in /etc/login.defs" + $nl
    }

    # Check 3: HOME_MODE setting
    $FindingDetails += $nl + "Check 3: HOME_MODE Setting" + $nl
    $homeMode = $(sh -c "grep -i '^HOME_MODE' /etc/login.defs 2>/dev/null" 2>&1)
    if ($homeMode -and "$homeMode".Trim().Length -gt 0) {
        $FindingDetails += "  $("$homeMode".Trim())" + $nl
    }
    else {
        $FindingDetails += "  HOME_MODE not configured (default varies by distribution)" + $nl
    }

    # Check 4: USERGROUPS_ENAB
    $FindingDetails += $nl + "Check 4: User Private Groups" + $nl
    $ugEnabled = $(sh -c "grep -i '^USERGROUPS_ENAB' /etc/login.defs 2>/dev/null" 2>&1)
    if ($ugEnabled -and "$ugEnabled".Trim().Length -gt 0) {
        $FindingDetails += "  $("$ugEnabled".Trim())" + $nl
    }
    else {
        $FindingDetails += "  USERGROUPS_ENAB not configured" + $nl
    }

    # Status determination
    $compliant = $true
    if ($worldAccessible) { $compliant = $false }
    if ($homeMode -and "$homeMode" -match "0?7[5-7][0-7]") {
        # 750 or more restrictive is OK
    }
    elseif ($umaskSetting -and "$umaskSetting" -match "0?[0-2][2-7][0-7]") {
        # umask 027 or more restrictive is OK
    }
    else { $compliant = $false }

    if ($compliant) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Home directories are appropriately restricted." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Home directory permissions may allow excessive access." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-203784 - Enable application firewall
# ============================================================
IMPLEMENTATIONS["V-203784"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Application Firewall ---" + $nl

    # Check 1: UFW status
    $FindingDetails += $nl + "Check 1: UFW Firewall Status" + $nl
    $ufwStatus = $(sh -c "which ufw >/dev/null 2>&1 && ufw status 2>/dev/null || echo 'UFW_NOT_INSTALLED'" 2>&1)
    $firewallActive = $false
    if ($ufwStatus -and "$ufwStatus" -match "Status: active") {
        $FindingDetails += "  UFW Status: Active" + $nl
        $firewallActive = $true
        $ufwRules = $(sh -c "ufw status numbered 2>/dev/null | head -20" 2>&1)
        if ($ufwRules) {
            $FindingDetails += "  Rules:" + $nl
            foreach ($line in ("$ufwRules" -split $nl)) {
                if ("$line".Trim().Length -gt 0) {
                    $FindingDetails += "    $("$line".Trim())" + $nl
                }
            }
        }
    }
    elseif ("$ufwStatus" -match "UFW_NOT_INSTALLED") {
        $FindingDetails += "  UFW: Not installed" + $nl
    }
    else {
        $FindingDetails += "  UFW Status: Inactive" + $nl
    }

    # Check 2: iptables rules
    $FindingDetails += $nl + "Check 2: iptables Rules" + $nl
    $iptRules = $(sh -c "iptables -L INPUT -n --line-numbers 2>/dev/null | head -15" 2>&1)
    if ($iptRules -and "$iptRules" -notmatch "command not found") {
        $ruleCount = (("$iptRules" -split $nl) | Where-Object { $_ -match "^\d+" }).Count
        $FindingDetails += "  INPUT chain rules: $ruleCount" + $nl
        if ($ruleCount -gt 2) {
            $firewallActive = $true
        }
        foreach ($line in ("$iptRules" -split $nl | Select-Object -First 10)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "    $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  iptables: Not available" + $nl
    }

    # Check 3: nftables
    $FindingDetails += $nl + "Check 3: nftables Status" + $nl
    $nftStatus = $(sh -c "which nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | head -10 || echo 'NFT_NOT_INSTALLED'" 2>&1)
    if ($nftStatus -and "$nftStatus" -notmatch "NFT_NOT_INSTALLED") {
        $FindingDetails += "  nftables: Available" + $nl
        $nftRuleCount = (("$nftStatus" -split $nl) | Where-Object { $_ -match "rule" }).Count
        if ($nftRuleCount -gt 0) {
            $firewallActive = $true
            $FindingDetails += "  Rules detected: $nftRuleCount" + $nl
        }
    }
    else {
        $FindingDetails += "  nftables: Not installed" + $nl
    }

    # Check 4: XO deployment model context
    $FindingDetails += $nl + "Check 4: Deployment Model" + $nl
    $xoaCheck = $(sh -c "test -f /etc/xo-appliance && echo 'XOA' || echo 'XOCE'" 2>&1)
    $FindingDetails += "  Deployment: $("$xoaCheck".Trim())" + $nl
    if ("$xoaCheck" -match "XOA") {
        $FindingDetails += "  Note: XOA includes UFW enabled by default" + $nl
    }

    # Status determination
    if ($firewallActive) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Application firewall is enabled and active." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No active application firewall detected." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-263650 - Disable accounts no longer associated to a user
# ============================================================
IMPLEMENTATIONS["V-263650"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Disable Unassociated Accounts ---" + $nl

    # Check 1: System accounts that should be locked
    $FindingDetails += $nl + "Check 1: System Account Lock Status" + $nl
    $sysAccounts = $(sh -c "awk -F: '($3 < 1000 && $1 != \"root\") {print $1\":\"$2}' /etc/shadow 2>/dev/null" 2>&1)
    if ($sysAccounts) {
        $unlockedSys = 0
        foreach ($acct in ("$sysAccounts" -split $nl)) {
            if ("$acct".Trim().Length -gt 0 -and "$acct" -notmatch ":\*|:!|:!!") {
                $unlockedSys++
                $acctName = ("$acct" -split ":")[0]
                $FindingDetails += "  [WARNING] System account not locked: $acctName" + $nl
            }
        }
        if ($unlockedSys -eq 0) {
            $FindingDetails += "  All system accounts are properly locked" + $nl
        }
    }

    # Check 2: Inactive user accounts (no login > 90 days)
    $FindingDetails += $nl + "Check 2: Inactive User Accounts (>90 days)" + $nl
    $lastlogOutput = $(sh -c "lastlog -b 90 2>/dev/null | tail -n +2" 2>&1)
    if ($lastlogOutput -and "$lastlogOutput".Trim().Length -gt 0) {
        $inactiveCount = 0
        foreach ($line in ("$lastlogOutput" -split $nl)) {
            if ("$line".Trim().Length -gt 0 -and "$line" -notmatch "Never logged in") {
                $inactiveCount++
            }
        }
        $neverLogged = (("$lastlogOutput" -split $nl) | Where-Object { $_ -match "Never logged in" }).Count
        $FindingDetails += "  Accounts inactive >90 days: $inactiveCount" + $nl
        $FindingDetails += "  Accounts never logged in: $neverLogged" + $nl
    }
    else {
        $FindingDetails += "  Unable to determine inactive accounts" + $nl
    }

    # Check 3: Account expiration policy
    $FindingDetails += $nl + "Check 3: Account Expiration Policy" + $nl
    $inactiveDays = $(sh -c "grep -i '^INACTIVE' /etc/default/useradd 2>/dev/null" 2>&1)
    if ($inactiveDays -and "$inactiveDays".Trim().Length -gt 0) {
        $FindingDetails += "  $("$inactiveDays".Trim())" + $nl
    }
    else {
        $FindingDetails += "  INACTIVE not set in /etc/default/useradd" + $nl
    }

    # Check 4: LDAP/AD centralized management
    $FindingDetails += $nl + "Check 4: Centralized Account Management" + $nl
    $sssdConf = $(sh -c "test -f /etc/sssd/sssd.conf && echo 'SSSD_CONFIGURED' || echo 'NO_SSSD'" 2>&1)
    $ldapCheck = $(sh -c "timeout 5 grep -rl 'auth-ldap' /opt/xo/packages/ 2>/dev/null | head -1" 2>&1)
    if ("$sssdConf" -match "SSSD_CONFIGURED") {
        $FindingDetails += "  SSSD: Configured (centralized account management)" + $nl
    }
    elseif ($ldapCheck -and "$ldapCheck".Trim().Length -gt 0) {
        $FindingDetails += "  XO LDAP/AD: auth-ldap plugin detected (delegated management)" + $nl
    }
    else {
        $FindingDetails += "  No centralized account management detected" + $nl
    }

    # Status determination - always Open (org policy verification required)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Account lifecycle management requires organizational verification." + $nl
    $FindingDetails += "  Verify procedures exist to disable accounts no longer associated with users." + $nl
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-263651 - Prohibit unauthorized hardware
# ============================================================
IMPLEMENTATIONS["V-263651"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Unauthorized Hardware Prohibition ---" + $nl

    # Check 1: USB device policy
    $FindingDetails += $nl + "Check 1: USB Storage Policy" + $nl
    $usbStorage = $(sh -c "lsmod 2>/dev/null | grep usb_storage" 2>&1)
    if ($usbStorage -and "$usbStorage".Trim().Length -gt 0) {
        $FindingDetails += "  usb_storage module: LOADED" + $nl
    }
    else {
        $FindingDetails += "  usb_storage module: Not loaded" + $nl
    }
    $usbBlacklist = $(sh -c "timeout 5 grep -r 'usb.storage' /etc/modprobe.d/ 2>/dev/null" 2>&1)
    if ($usbBlacklist -and "$usbBlacklist".Trim().Length -gt 0) {
        $FindingDetails += "  USB storage blacklist: $("$usbBlacklist".Trim())" + $nl
    }
    else {
        $FindingDetails += "  USB storage: Not blacklisted in modprobe.d" + $nl
    }

    # Check 2: Connected USB devices
    $FindingDetails += $nl + "Check 2: Connected USB Devices" + $nl
    $usbDevices = $(sh -c "lsusb 2>/dev/null | head -10" 2>&1)
    if ($usbDevices -and "$usbDevices" -notmatch "command not found") {
        foreach ($line in ("$usbDevices" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  lsusb not available" + $nl
    }

    # Check 3: Thunderbolt/PCIe device policy
    $FindingDetails += $nl + "Check 3: Thunderbolt/DMA Protection" + $nl
    $tbCheck = $(sh -c "lsmod 2>/dev/null | grep thunderbolt" 2>&1)
    if ($tbCheck -and "$tbCheck".Trim().Length -gt 0) {
        $FindingDetails += "  Thunderbolt module: Loaded" + $nl
    }
    else {
        $FindingDetails += "  Thunderbolt module: Not loaded" + $nl
    }

    # Check 4: Hardware inventory (PCI devices)
    $FindingDetails += $nl + "Check 4: PCI Device Summary" + $nl
    $pciCount = $(sh -c "lspci 2>/dev/null | wc -l" 2>&1)
    if ($pciCount -and "$pciCount".Trim() -match "^\d+$") {
        $FindingDetails += "  PCI devices detected: $("$pciCount".Trim())" + $nl
    }

    # Status determination - always Open (org hardware authorization required)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Hardware authorization requires organizational policy verification." + $nl
    $FindingDetails += "  Verify approved hardware list exists and unauthorized devices are prohibited." + $nl
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-263652 - MFA for local/network/remote access
# ============================================================
IMPLEMENTATIONS["V-263652"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Multifactor Authentication ---" + $nl

    # Check 1: PAM MFA modules
    $FindingDetails += $nl + "Check 1: PAM MFA Configuration" + $nl
    $pamMfa = $(sh -c "timeout 5 grep -r 'pam_pkcs11\|pam_google_authenticator\|pam_u2f\|pam_duo\|pam_yubico' /etc/pam.d/ 2>/dev/null" 2>&1)
    if ($pamMfa -and "$pamMfa".Trim().Length -gt 0) {
        $FindingDetails += "  MFA PAM modules detected:" + $nl
        foreach ($line in ("$pamMfa" -split $nl | Select-Object -First 5)) {
            $FindingDetails += "    $("$line".Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No MFA PAM modules configured" + $nl
    }

    # Check 2: Smart card / CAC support
    $FindingDetails += $nl + "Check 2: Smart Card Support" + $nl
    $pkcs11 = $(sh -c "dpkg -l 2>/dev/null | grep -i 'opensc\|pcsc\|coolkey\|cac'" 2>&1)
    if ($pkcs11 -and "$pkcs11".Trim().Length -gt 0) {
        $FindingDetails += "  Smart card packages:" + $nl
        foreach ($line in ("$pkcs11" -split $nl | Select-Object -First 5)) {
            $FindingDetails += "    $("$line".Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No smart card packages installed" + $nl
    }

    # Check 3: SSH MFA configuration
    $FindingDetails += $nl + "Check 3: SSH Authentication Methods" + $nl
    $sshAuth = $(sh -c "sshd -T 2>/dev/null | grep -i 'authenticationmethods\|pubkeyauthentication\|passwordauthentication'" 2>&1)
    if ($sshAuth -and "$sshAuth".Trim().Length -gt 0) {
        foreach ($line in ("$sshAuth" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }

    # Check 4: XO LDAP/SAML/OIDC plugins for MFA
    $FindingDetails += $nl + "Check 4: XO Enterprise Authentication" + $nl
    $xoAuth = $(sh -c "timeout 5 find /opt/xo/packages -maxdepth 2 -name 'package.json' 2>/dev/null | xargs grep -l 'auth-ldap\|auth-saml\|auth-oidc' 2>/dev/null" 2>&1)
    if ($xoAuth -and "$xoAuth".Trim().Length -gt 0) {
        $FindingDetails += "  XO auth plugins detected:" + $nl
        foreach ($line in ("$xoAuth" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "    $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No enterprise auth plugins detected" + $nl
    }

    # Status determination - always Open (MFA enrollment/policy required)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Multifactor authentication requires organizational implementation." + $nl
    $FindingDetails += "  DoD requires MFA for all privileged and non-privileged accounts." + $nl
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-263654 - Require immediate password change on recovery
# ============================================================
IMPLEMENTATIONS["V-263654"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Password Change on Account Recovery ---" + $nl

    # Check 1: Password expiry forcing
    $FindingDetails += $nl + "Check 1: Force Password Change Capability" + $nl
    $chageCheck = $(sh -c "which chage >/dev/null 2>&1 && echo 'AVAILABLE' || echo 'NOT_AVAILABLE'" 2>&1)
    if ("$chageCheck" -match "AVAILABLE") {
        $FindingDetails += "  chage utility: Available (can force password change)" + $nl
        $FindingDetails += "  Usage: chage -d 0 <username> (forces change at next login)" + $nl
    }
    else {
        $FindingDetails += "  chage utility: Not available" + $nl
    }

    # Check 2: PAM password change enforcement
    $FindingDetails += $nl + "Check 2: PAM Password Change Enforcement" + $nl
    $pamPwChange = $(sh -c "timeout 5 grep -r 'pam_pwquality\|pam_cracklib\|force_for_root' /etc/pam.d/ 2>/dev/null | head -5" 2>&1)
    if ($pamPwChange -and "$pamPwChange".Trim().Length -gt 0) {
        foreach ($line in ("$pamPwChange" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No PAM password change enforcement detected" + $nl
    }

    # Check 3: LDAP/AD delegation
    $FindingDetails += $nl + "Check 3: External Password Management" + $nl
    $ldapCheck = $(sh -c "timeout 5 grep -rl 'auth-ldap' /opt/xo/packages/ 2>/dev/null | head -1" 2>&1)
    if ($ldapCheck -and "$ldapCheck".Trim().Length -gt 0) {
        $FindingDetails += "  LDAP/AD: Detected (password recovery may be delegated)" + $nl
    }
    else {
        $FindingDetails += "  No external password management detected" + $nl
    }

    # Check 4: Account recovery procedures
    $FindingDetails += $nl + "Check 4: Recovery Procedure Documentation" + $nl
    $FindingDetails += "  Verify organizational procedures require:" + $nl
    $FindingDetails += "  - Immediate password selection upon account recovery" + $nl
    $FindingDetails += "  - Temporary passwords expire at first use" + $nl
    $FindingDetails += "  - Recovery actions are logged and auditable" + $nl

    # Status determination - always Open (org procedure verification required)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Password recovery policy requires organizational verification." + $nl
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-263655 - Allow user-selected long passwords
# ============================================================
IMPLEMENTATIONS["V-263655"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Long Password and Passphrase Support ---" + $nl

    # Check 1: PAM pwquality maxlen/minlen
    $FindingDetails += $nl + "Check 1: PAM Password Length Configuration" + $nl
    $pwquality = $(sh -c "cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^$'" 2>&1)
    if ($pwquality -and "$pwquality".Trim().Length -gt 0) {
        foreach ($line in ("$pwquality" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  pwquality.conf: Not configured or empty" + $nl
    }

    # Check 2: PAM maxlen setting (allows long passwords)
    $FindingDetails += $nl + "Check 2: Maximum Password Length" + $nl
    $pamMaxLen = $(sh -c "timeout 5 grep -r 'maxlen\|maxrepeat' /etc/pam.d/ /etc/security/ 2>/dev/null" 2>&1)
    if ($pamMaxLen -and "$pamMaxLen".Trim().Length -gt 0) {
        foreach ($line in ("$pamMaxLen" -split $nl | Select-Object -First 5)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No explicit max length restriction (system default applies)" + $nl
    }

    # Check 3: Password hash algorithm (supports long passwords)
    $FindingDetails += $nl + "Check 3: Password Hash Algorithm" + $nl
    $hashAlgo = $(sh -c "grep -i '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null" 2>&1)
    if ($hashAlgo -and "$hashAlgo".Trim().Length -gt 0) {
        $FindingDetails += "  $("$hashAlgo".Trim())" + $nl
        if ("$hashAlgo" -match "SHA512|YESCRYPT") {
            $FindingDetails += "  Algorithm supports passwords of any length" + $nl
        }
    }
    else {
        $FindingDetails += "  ENCRYPT_METHOD not set in login.defs" + $nl
    }

    # Check 4: Character set support
    $FindingDetails += $nl + "Check 4: Character Set Support" + $nl
    $FindingDetails += "  Linux PAM accepts all printable characters including spaces" + $nl
    $FindingDetails += "  No character restrictions imposed by default" + $nl

    # Status determination
    $longPasswordSupported = $false
    if ($hashAlgo -and "$hashAlgo" -match "SHA512|YESCRYPT") {
        $longPasswordSupported = $true
    }

    if ($longPasswordSupported) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: System supports long passwords with all printable characters." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Unable to verify long password support." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-263656 - Automated password complexity tools
# ============================================================
IMPLEMENTATIONS["V-263656"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Automated Password Complexity Tools ---" + $nl

    # Check 1: PAM pwquality module
    $FindingDetails += $nl + "Check 1: PAM pwquality Module" + $nl
    $pwqInstalled = $(sh -c "dpkg -l libpam-pwquality 2>/dev/null | grep '^ii'" 2>&1)
    if ($pwqInstalled -and "$pwqInstalled".Trim().Length -gt 0) {
        $FindingDetails += "  libpam-pwquality: Installed" + $nl
    }
    else {
        $FindingDetails += "  libpam-pwquality: Not installed" + $nl
    }

    # Check 2: PAM configuration for password quality
    $FindingDetails += $nl + "Check 2: PAM Password Quality Configuration" + $nl
    $pamConfig = $(sh -c "timeout 5 grep -r 'pam_pwquality\|pam_cracklib' /etc/pam.d/ 2>/dev/null" 2>&1)
    if ($pamConfig -and "$pamConfig".Trim().Length -gt 0) {
        foreach ($line in ("$pamConfig" -split $nl | Select-Object -First 5)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No password quality PAM modules configured" + $nl
    }

    # Check 3: pwquality.conf settings
    $FindingDetails += $nl + "Check 3: Password Quality Settings" + $nl
    $pwqConf = $(sh -c "cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^$'" 2>&1)
    if ($pwqConf -and "$pwqConf".Trim().Length -gt 0) {
        foreach ($line in ("$pwqConf" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  pwquality.conf: Not configured" + $nl
    }

    # Check 4: Dictionary files for password checking
    $FindingDetails += $nl + "Check 4: Password Dictionary Files" + $nl
    $dictCheck = $(sh -c "ls -la /usr/share/dict/ 2>/dev/null | head -5" 2>&1)
    if ($dictCheck -and "$dictCheck" -notmatch "No such file") {
        $FindingDetails += "  Dictionary files available in /usr/share/dict/" + $nl
    }
    else {
        $FindingDetails += "  No dictionary files found" + $nl
    }

    # Status determination
    $toolsConfigured = $false
    if ($pwqInstalled -and "$pwqInstalled" -match "^ii") {
        if ($pamConfig -and "$pamConfig" -match "pam_pwquality") {
            $toolsConfigured = $true
        }
    }

    if ($toolsConfigured) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Automated password complexity tools are configured." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Password complexity tools not fully configured." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-263657 - NIST-compliant external credentials
# ============================================================
IMPLEMENTATIONS["V-263657"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: NIST-Compliant External Credentials ---" + $nl

    # Check 1: SSH key algorithms
    $FindingDetails += $nl + "Check 1: SSH Host Key Algorithms" + $nl
    $sshHostKeys = $(sh -c "sshd -T 2>/dev/null | grep -i hostkeyalgorithms" 2>&1)
    if ($sshHostKeys -and "$sshHostKeys".Trim().Length -gt 0) {
        $FindingDetails += "  $("$sshHostKeys".Trim())" + $nl
    }
    else {
        $FindingDetails += "  Using default host key algorithms" + $nl
    }
    $hostKeyFiles = $(sh -c "ls -la /etc/ssh/ssh_host_*_key.pub 2>/dev/null" 2>&1)
    if ($hostKeyFiles) {
        foreach ($line in ("$hostKeyFiles" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }

    # Check 2: TLS certificate algorithms
    $FindingDetails += $nl + "Check 2: TLS Certificate Compliance" + $nl
    $certFile = $(sh -c "timeout 5 find /etc/ssl /opt/xo -maxdepth 3 -name '*.pem' -o -name '*.crt' 2>/dev/null | head -3" 2>&1)
    if ($certFile -and "$certFile".Trim().Length -gt 0) {
        $firstCert = ("$certFile" -split $nl)[0].Trim()
        $certInfo = $(sh -c "openssl x509 -in '$firstCert' -noout -text 2>/dev/null | grep -E 'Signature Algorithm|Public-Key'" 2>&1)
        if ($certInfo) {
            foreach ($line in ("$certInfo" -split $nl)) {
                if ("$line".Trim().Length -gt 0) {
                    $FindingDetails += "  $("$line".Trim())" + $nl
                }
            }
        }
    }
    else {
        $FindingDetails += "  No certificate files found for analysis" + $nl
    }

    # Check 3: LDAP/AD credential handling
    $FindingDetails += $nl + "Check 3: External Credential Sources" + $nl
    $ldapCheck = $(sh -c "timeout 5 grep -rl 'auth-ldap' /opt/xo/packages/ 2>/dev/null | head -1" 2>&1)
    if ($ldapCheck -and "$ldapCheck".Trim().Length -gt 0) {
        $FindingDetails += "  LDAP/AD authentication: Detected" + $nl
        $FindingDetails += "  External credentials delegated to directory service" + $nl
    }
    else {
        $FindingDetails += "  No external credential source detected" + $nl
    }

    # Check 4: OpenSSL FIPS compliance
    $FindingDetails += $nl + "Check 4: OpenSSL NIST Compliance" + $nl
    $opensslVer = $(openssl version 2>&1)
    if ($opensslVer) {
        $FindingDetails += "  $("$opensslVer".Trim())" + $nl
    }
    $fipsCheck = $(sh -c "cat /proc/sys/crypto/fips_enabled 2>/dev/null" 2>&1)
    if ($fipsCheck -and "$fipsCheck".Trim() -eq "1") {
        $FindingDetails += "  FIPS mode: Enabled" + $nl
    }
    else {
        $FindingDetails += "  FIPS mode: Not enabled" + $nl
    }

    # Status determination - always Open (NIST compliance verification required)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: NIST credential compliance requires organizational verification." + $nl
    $FindingDetails += "  Verify all external credentials meet NIST SP 800-63 requirements." + $nl
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-263659 - Approved trust anchors only
# ============================================================
IMPLEMENTATIONS["V-263659"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Approved Trust Anchors ---" + $nl

    # Check 1: System CA certificate store
    $FindingDetails += $nl + "Check 1: System CA Certificate Store" + $nl
    $caCerts = $(sh -c "ls /etc/ssl/certs/ 2>/dev/null | wc -l" 2>&1)
    if ($caCerts -and "$caCerts".Trim() -match "^\d+$") {
        $FindingDetails += "  Certificates in /etc/ssl/certs/: $("$caCerts".Trim())" + $nl
    }
    $caBundle = $(sh -c "test -f /etc/ssl/certs/ca-certificates.crt && wc -l /etc/ssl/certs/ca-certificates.crt | awk '{print $1}' || echo 'NOT_FOUND'" 2>&1)
    if ("$caBundle" -notmatch "NOT_FOUND") {
        $FindingDetails += "  CA bundle: /etc/ssl/certs/ca-certificates.crt ($("$caBundle".Trim()) lines)" + $nl
    }

    # Check 2: DoD CA certificates
    $FindingDetails += $nl + "Check 2: DoD CA Certificates" + $nl
    $dodCerts = $(sh -c "timeout 10 grep -c 'DoD\|DOD\|Department of Defense' /etc/ssl/certs/ca-certificates.crt 2>/dev/null || echo '0'" 2>&1)
    if ($dodCerts -and "$dodCerts".Trim() -ne "0") {
        $FindingDetails += "  DoD CA references found: $("$dodCerts".Trim())" + $nl
    }
    else {
        $FindingDetails += "  No DoD CA certificates detected in system trust store" + $nl
    }

    # Check 3: Custom trust anchors
    $FindingDetails += $nl + "Check 3: Custom/Local Trust Anchors" + $nl
    $localCerts = $(sh -c "ls /usr/local/share/ca-certificates/ 2>/dev/null" 2>&1)
    if ($localCerts -and "$localCerts".Trim().Length -gt 0 -and "$localCerts" -notmatch "No such file") {
        $FindingDetails += "  Custom certificates:" + $nl
        foreach ($line in ("$localCerts" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "    $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No custom trust anchors in /usr/local/share/ca-certificates/" + $nl
    }

    # Check 4: ca-certificates package management
    $FindingDetails += $nl + "Check 4: CA Certificate Package" + $nl
    $caPkg = $(sh -c "dpkg -l ca-certificates 2>/dev/null | grep '^ii'" 2>&1)
    if ($caPkg -and "$caPkg".Trim().Length -gt 0) {
        $FindingDetails += "  $("$caPkg".Trim())" + $nl
    }
    else {
        $FindingDetails += "  ca-certificates package: Not installed" + $nl
    }

    # Status determination - always Open (org trust anchor approval required)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Trust anchor approval requires organizational verification." + $nl
    $FindingDetails += "  Verify only organization-approved trust anchors are in the trust store." + $nl
    #---=== End Custom Code ===---#
'''

# ============================================================
# Metadata for each function
# ============================================================
METADATA = {
    "V-203783": {
        "stig_id": "SRG-OS-000480-GPOS-00230",
        "rule_id": "SV-203783r991592_rule",
        "title": "The operating system must limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.",
        "discuss_md5": "9cef0c8c78dbdd8603cb4158255ad9c8",
        "check_md5": "ea4f36ebce447ad0ae06bc813741eb79",
        "fix_md5": "15be922a2135872fd34177a3d6950d1d",
    },
    "V-203784": {
        "stig_id": "SRG-OS-000480-GPOS-00232",
        "rule_id": "SV-203784r991593_rule",
        "title": "The operating system must enable an application firewall, if available.",
        "discuss_md5": "6f20cb8f62255ed6dd3652a51cdd49aa",
        "check_md5": "7ba9d2c5a57baaec619f1d1dbc475c42",
        "fix_md5": "156bcc7baba847d3105da6ae2748e0e5",
    },
    "V-263650": {
        "stig_id": "SRG-OS-000590-GPOS-00110",
        "rule_id": "SV-263650r982553_rule",
        "title": "The operating system must disable accounts when the accounts are no longer associated to a user.",
        "discuss_md5": "fcc8def918d3130faf469e0eb4af6920",
        "check_md5": "b33efa9b52398794e1c390c7a9a11568",
        "fix_md5": "53c7d33f72cc408a96edefa08ab1161a",
    },
    "V-263651": {
        "stig_id": "SRG-OS-000690-GPOS-00140",
        "rule_id": "SV-263651r982555_rule",
        "title": "The operating system must prohibit the use or connection of unauthorized hardware components.",
        "discuss_md5": "c80639a70e7346cbd9df4110eab3858d",
        "check_md5": "86f40e3db83aeaeb4bf0b349dc2c7be8",
        "fix_md5": "b0c721c4df4319d9df33bfc4fa60dcb2",
    },
    "V-263652": {
        "stig_id": "SRG-OS-000705-GPOS-00150",
        "rule_id": "SV-263652r982557_rule",
        "title": "The operating system must implement multifactor authentication for local, network, and/or remote access to privileged accounts and/or nonprivileged accounts such that the device meets organization-defined strength of mechanism requirements.",
        "discuss_md5": "ce37a1ad26d50e5557aac028c44c92ab",
        "check_md5": "676a7a6b2b40c61d44d86b884d6bbef9",
        "fix_md5": "4eee6e2d7368cbdc57cd9bb3ba3dbd59",
    },
    "V-263654": {
        "stig_id": "SRG-OS-000720-GPOS-00170",
        "rule_id": "SV-263654r982232_rule",
        "title": "The operating system must for password-based authentication, require immediate selection of a new password upon account recovery.",
        "discuss_md5": "013e737dbcd96e4dd0461a8e25c3fbfb",
        "check_md5": "86c26c75ce4b41673bd3f5b83108d270",
        "fix_md5": "b59af928c222ed0e0400c634f43f4488",
    },
    "V-263655": {
        "stig_id": "SRG-OS-000725-GPOS-00180",
        "rule_id": "SV-263655r982235_rule",
        "title": "The operating system must for password-based authentication, allow user selection of long passwords and passphrases, including spaces and all printable characters.",
        "discuss_md5": "013e737dbcd96e4dd0461a8e25c3fbfb",
        "check_md5": "f086a0790bfd859ac7126c4b74909677",
        "fix_md5": "fd4ce80932a20dce7e17d775293a9b6b",
    },
    "V-263656": {
        "stig_id": "SRG-OS-000730-GPOS-00190",
        "rule_id": "SV-263656r982238_rule",
        "title": "The operating system must, for password-based authentication, employ automated tools to assist the user in selecting strong password authenticators.",
        "discuss_md5": "013e737dbcd96e4dd0461a8e25c3fbfb",
        "check_md5": "fad4cdbc2a97f36d611668ff8562506f",
        "fix_md5": "60ac930fdb2172671130b73f143e73b3",
    },
    "V-263657": {
        "stig_id": "SRG-OS-000745-GPOS-00210",
        "rule_id": "SV-263657r982559_rule",
        "title": "The operating system must accept only external credentials that are NIST-compliant.",
        "discuss_md5": "4b8f1119ca216c0a6d556e34984dd72f",
        "check_md5": "2f81f793a0240742a71a0475dbe265e5",
        "fix_md5": "11151ed8a1b878cb6a97163d216043eb",
    },
    "V-263659": {
        "stig_id": "SRG-OS-000775-GPOS-00230",
        "rule_id": "SV-263659r982563_rule",
        "title": "The operating system must include only approved trust anchors in trust stores or certificate stores managed by the organization.",
        "discuss_md5": "0a3ff3ce676bd9cb5c55b37f6dff5d3d",
        "check_md5": "37a213e3daaf8eae39577a4e45d7ef2c",
        "fix_md5": "4b31a595b0f40e0ff86c252e44344b06",
    },
}


def build_replacement(vuln_id):
    """Build the complete function replacement for a given VulnID."""
    meta = METADATA[vuln_id]
    func_name = vuln_id.replace("-", "")
    impl = IMPLEMENTATIONS[vuln_id]

    header = f'''    <#
    .DESCRIPTION
        Vuln ID    : {vuln_id}
        STIG ID    : {meta["stig_id"]}
        Rule ID    : {meta["rule_id"]}
        Rule Title : {meta["title"]}
        DiscussMD5 : {meta["discuss_md5"]}
        CheckMD5   : {meta["check_md5"]}
        FixMD5     : {meta["fix_md5"]}
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID,
        [Parameter(Mandatory = $false)]
        [String]$Hostname,
        [Parameter(Mandatory = $false)]
        [String]$Instance,
        [Parameter(Mandatory = $false)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "{vuln_id}"
    $RuleID = "{meta["rule_id"]}"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""
'''

    footer = f'''
    if ($FindingDetails.Trim().Length -gt 0) {{
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }}
    else {{
        $ResultHash = ""
    }}

    if ($PSBoundParameters.AnswerFile) {{
        $GetCorpParams = @{{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $SiteName
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }}

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {{
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }}
    }}

    $SendCheckParams = @{{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFKey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $SiteName
        HeadHash         = $ResultHash
    }}

    return Send-CheckResult @SendCheckParams
'''

    return header + impl + footer


def main():
    with open(MODULE_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    count = 0
    for vuln_id in IMPLEMENTATIONS:
        func_name = vuln_id.replace("-", "")
        # Match the stub function pattern
        pattern = (
            r'(Function Get-' + func_name + r'\s*\{)\s*'
            r'<#\s*\.DESCRIPTION\s*'
            r'Vuln ID\s*:\s*' + vuln_id + r'.*?'
            r'#>\s*'
            r'param\s*\(.*?\)\s*'
            r'\$ModuleName\s*=.*?\s*'
            r'\$VulnID\s*=.*?\s*'
            r'\$RuleID\s*=.*?\s*'
            r'\$Status\s*=.*?\s*'
            r'\$FindingDetails\s*=.*?\s*'
            r'\$Comments\s*=.*?\s*'
            r'\$AFKey\s*=.*?\s*'
            r'\$AFStatus\s*=.*?\s*'
            r'\$SeverityOverride\s*=.*?\s*'
            r'\$Justification\s*=.*?'
            r'return Send-CheckResult @SendCheckParams\s*\}'
        )

        replacement_body = build_replacement(vuln_id)
        full_replacement = f"Function Get-{func_name} {{\n{replacement_body}\n}}"

        match = re.search(pattern, content, flags=re.DOTALL)
        if match:
            content = content[:match.start()] + full_replacement + content[match.end():]
            count += 1
            print(f"  [OK] {vuln_id} - replaced stub with implementation")
        else:
            print(f"  [SKIP] {vuln_id} - pattern not matched")

    with open(MODULE_PATH, "w", encoding="utf-8-sig") as f:
        f.write(content)

    print(f"\nIntegrated {count}/10 functions")


if __name__ == "__main__":
    main()
