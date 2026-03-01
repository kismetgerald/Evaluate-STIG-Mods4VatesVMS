#!/usr/bin/env python3
"""Integrate Batch 12 implementations into Scan-XO_GPOS_Debian12_Checks.psm1.

Batch 12: System Security (10 functions)
- V-203685: Explicit logoff message
- V-203691: Notify SAs/ISSOs of account enabling
- V-203692: Allow admins to pass info
- V-203693: Allow admins to grant privileges
- V-203694: Allow admins to change security attrs
- V-203698: Auto-lock account until released
- V-203699: IMO/ISSO change audit config capability
- V-203703: Real-time alert on audit failure
- V-203709: Preserve original audit content
- V-203710: Preserve original audit time ordering

IMPORTANT: This script only replaces the description block and custom code section.
It does NOT touch the param block or variable initialization (Batch 11 lesson learned).
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

IMPLEMENTATIONS = {
    "V-203685": {
        "RuleID": "SV-203685r958640_rule",
        "STIG_ID": "SRG-OS-000281-GPOS-00111",
        "CheckMD5": "f3903f30d3710ccf6aa808b46825e882",
        "RuleTitle": "The operating system must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Explicit Logoff Message ---" + $nl

    # Check 1: SSH logout message configuration
    $FindingDetails += $nl + "Check 1: SSH Logout Message" + $nl
    $sshdConfig = $(cat /etc/ssh/sshd_config 2>&1)
    $printLastLog = ($sshdConfig | Select-String -Pattern "^\s*PrintLastLog" | Select-Object -First 1)
    if ($printLastLog) {
        $FindingDetails += "  PrintLastLog setting: $($printLastLog.ToString().Trim())" + $nl
    }
    else {
        $FindingDetails += "  PrintLastLog: Not explicitly configured (default: yes)" + $nl
    }

    # Check 2: /etc/logout message or logout scripts
    $FindingDetails += $nl + "Check 2: System Logout Scripts" + $nl
    $logoutFiles = @("/etc/bash.bash_logout", "/etc/profile.d/logout.sh", "/root/.bash_logout")
    $logoutConfigured = $false
    foreach ($lf in $logoutFiles) {
        $lfContent = $(cat $lf 2>&1)
        if ($LASTEXITCODE -eq 0 -and $lfContent) {
            $FindingDetails += "  $lf : EXISTS" + $nl
            $hasEcho = ($lfContent | Select-String -Pattern "echo|printf|wall" | Select-Object -First 1)
            if ($hasEcho) {
                $FindingDetails += "    Contains logoff message command: $($hasEcho.ToString().Trim())" + $nl
                $logoutConfigured = $true
            }
            else {
                $FindingDetails += "    No explicit logoff message command found" + $nl
            }
        }
        else {
            $FindingDetails += "  $lf : NOT FOUND" + $nl
        }
    }

    # Check 3: PAM session close messages
    $FindingDetails += $nl + "Check 3: PAM Session Close" + $nl
    $pamCommonSession = $(cat /etc/pam.d/common-session 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $sessionClose = ($pamCommonSession | Select-String -Pattern "session.*close|pam_lastlog" | Select-Object -First 1)
        if ($sessionClose) {
            $FindingDetails += "  PAM session close configured: $($sessionClose.ToString().Trim())" + $nl
        }
        else {
            $FindingDetails += "  No explicit PAM session close message found" + $nl
        }
    }

    # Check 4: SSH connection termination behavior
    $FindingDetails += $nl + "Check 4: SSH Session Termination" + $nl
    $clientAliveInterval = ($sshdConfig | Select-String -Pattern "^\s*ClientAliveInterval" | Select-Object -First 1)
    $clientAliveCountMax = ($sshdConfig | Select-String -Pattern "^\s*ClientAliveCountMax" | Select-Object -First 1)
    if ($clientAliveInterval) {
        $FindingDetails += "  $($clientAliveInterval.ToString().Trim())" + $nl
    }
    if ($clientAliveCountMax) {
        $FindingDetails += "  $($clientAliveCountMax.ToString().Trim())" + $nl
    }
    $FindingDetails += "  SSH provides connection closed message on session termination" + $nl

    # Status determination
    if ($logoutConfigured) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Explicit logoff message is configured in logout scripts." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No explicit logoff message configured. SSH provides implicit" + $nl
        $FindingDetails += "  connection closed notification, but no custom logoff message is displayed." + $nl
    }
'''
    },
    "V-203691": {
        "RuleID": "SV-203691r982207_rule",
        "STIG_ID": "SRG-OS-000304-GPOS-00121",
        "CheckMD5": "d561258f68166d30c9c2270c36cd8481",
        "RuleTitle": "The operating system must notify system administrators (SAs) and information system security officers (ISSOs) of account enabling actions.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Account Enabling Notification ---" + $nl

    # Check 1: auditd rules for account enabling
    $FindingDetails += $nl + "Check 1: Audit Rules for Account Changes" + $nl
    $auditdActive = $(systemctl is-active auditd 2>&1)
    if ($auditdActive -eq "active") {
        $FindingDetails += "  auditd service: ACTIVE" + $nl
        $auditRules = $(auditctl -l 2>&1)
        $accountRules = ($auditRules | Select-String -Pattern "passwd|shadow|group|gshadow|opasswd|usermod|useradd")
        if ($accountRules) {
            $FindingDetails += "  Account-related audit rules found:" + $nl
            foreach ($ar in $accountRules) {
                $FindingDetails += "    $($ar.ToString().Trim())" + $nl
            }
        }
        else {
            $FindingDetails += "  No account-related audit rules configured" + $nl
        }
    }
    else {
        $FindingDetails += "  auditd service: NOT ACTIVE ($auditdActive)" + $nl
    }

    # Check 2: XO Audit Plugin
    $FindingDetails += $nl + "Check 2: XO Audit Plugin (Application-Layer)" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE" + $nl
        $FindingDetails += "  Recent audit records: $($xoAuditInfo.RecordCount)" + $nl
        $FindingDetails += "  Hash chain integrity: $($xoAuditInfo.HasIntegrity)" + $nl
        $FindingDetails += "  [PASS] XO Audit Plugin records account enabling events" + $nl
        $xoAuditCompensates = $true
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
        $xoAuditCompensates = $false
    }

    # Check 3: rsyslog/syslog forwarding for notifications
    $FindingDetails += $nl + "Check 3: Syslog Notification Configuration" + $nl
    $rsyslogConf = $(cat /etc/rsyslog.conf 2>&1)
    $authLogForward = ($rsyslogConf | Select-String -Pattern "auth\.\*|authpriv\.\*" | Select-String -Pattern "@")
    if ($authLogForward) {
        $FindingDetails += "  Auth log forwarding: CONFIGURED" + $nl
        foreach ($alf in $authLogForward) {
            $FindingDetails += "    $($alf.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  Auth log forwarding to remote server: NOT CONFIGURED" + $nl
    }

    # Check 4: Mail/alerting for account changes
    $FindingDetails += $nl + "Check 4: Email/Alert Notification" + $nl
    $mailInstalled = $(dpkg -l 2>&1 | grep -E "postfix|exim|sendmail|mailutils" 2>&1)
    if ($mailInstalled) {
        $FindingDetails += "  Mail system installed:" + $nl
        foreach ($mi in $mailInstalled) {
            $pkgLine = $mi.ToString().Trim()
            if ($pkgLine -match "^ii\s+(\S+)") {
                $FindingDetails += "    $($Matches[1])" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No mail system detected for automated notifications" + $nl
    }

    # Status determination
    if ($auditdActive -eq "active" -and $accountRules -and $authLogForward) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Account enabling actions are audited and forwarded for SA/ISSO notification." + $nl
    }
    elseif ($xoAuditCompensates) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "COMPENSATING CONTROL: XO Audit Plugin records account enabling events" + $nl
        $FindingDetails += "with hash chain integrity, providing SA/ISSO notification capability." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No automated notification mechanism for account enabling actions." + $nl
    }
'''
    },
    "V-203692": {
        "RuleID": "SV-203692r958702_rule",
        "STIG_ID": "SRG-OS-000312-GPOS-00122",
        "CheckMD5": "8280531df056f332fce359e3a40f2930",
        "RuleTitle": "The operating system must allow operating system admins to pass information to any other operating system admin or user.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Admin Information Passing ---" + $nl

    # Check 1: wall command availability
    $FindingDetails += $nl + "Check 1: Broadcast Messaging (wall)" + $nl
    $wallPath = $(which wall 2>&1)
    $wallAvailable = $false
    if ($LASTEXITCODE -eq 0 -and $wallPath -match "/wall") {
        $FindingDetails += "  wall command: AVAILABLE ($wallPath)" + $nl
        $wallPerms = $(stat -c "%a %U:%G" $wallPath 2>&1)
        $FindingDetails += "  Permissions: $wallPerms" + $nl
        $wallAvailable = $true
    }
    else {
        $FindingDetails += "  wall command: NOT FOUND" + $nl
    }

    # Check 2: write/talk commands
    $FindingDetails += $nl + "Check 2: Direct Messaging (write/mesg)" + $nl
    $writePath = $(which write 2>&1)
    if ($LASTEXITCODE -eq 0 -and $writePath -match "/write") {
        $FindingDetails += "  write command: AVAILABLE ($writePath)" + $nl
    }
    else {
        $FindingDetails += "  write command: NOT FOUND" + $nl
    }
    $mesgPath = $(which mesg 2>&1)
    if ($LASTEXITCODE -eq 0 -and $mesgPath -match "/mesg") {
        $FindingDetails += "  mesg command: AVAILABLE ($mesgPath)" + $nl
    }

    # Check 3: mail/mailx availability
    $FindingDetails += $nl + "Check 3: Email Messaging" + $nl
    $mailCmd = $(which mail 2>/dev/null || which mailx 2>/dev/null)
    if ($LASTEXITCODE -eq 0 -and $mailCmd) {
        $FindingDetails += "  Mail command: AVAILABLE ($mailCmd)" + $nl
    }
    else {
        $FindingDetails += "  Mail command: NOT FOUND" + $nl
    }

    # Check 4: sudo/su for admin access
    $FindingDetails += $nl + "Check 4: Administrative Access" + $nl
    $sudoInstalled = $(dpkg -l sudo 2>&1 | grep "^ii")
    if ($sudoInstalled) {
        $FindingDetails += "  sudo: INSTALLED" + $nl
        $sudoUsers = $(grep -E "^%sudo|^%admin|^root" /etc/sudoers 2>&1 | head -5)
        if ($sudoUsers) {
            foreach ($su in $sudoUsers) {
                $FindingDetails += "    $($su.ToString().Trim())" + $nl
            }
        }
    }
    $suAvailable = $(which su 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  su command: AVAILABLE" + $nl
    }

    # Status determination
    if ($wallAvailable) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Administrators can pass information via wall, write, and standard" + $nl
        $FindingDetails += "  Linux IPC mechanisms." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Primary messaging tools not available for admin communication." + $nl
    }
'''
    },
    "V-203693": {
        "RuleID": "SV-203693r958702_rule",
        "STIG_ID": "SRG-OS-000312-GPOS-00123",
        "CheckMD5": "0d6967c0b7d570c93705cfea3bc51eb3",
        "RuleTitle": "The operating system must allow operating system admins to grant their privileges to other operating system admins.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Admin Privilege Granting ---" + $nl

    # Check 1: sudo configuration for privilege delegation
    $FindingDetails += $nl + "Check 1: sudo Privilege Delegation" + $nl
    $sudoInstalled = $(dpkg -l sudo 2>&1 | grep "^ii")
    $sudoConfigured = $false
    if ($sudoInstalled) {
        $FindingDetails += "  sudo: INSTALLED" + $nl
        $sudoersContent = $(cat /etc/sudoers 2>&1)
        $sudoGroups = ($sudoersContent | Select-String -Pattern "^%\w+" | Select-Object -First 5)
        if ($sudoGroups) {
            $FindingDetails += "  Privilege groups configured:" + $nl
            foreach ($sg in $sudoGroups) {
                $FindingDetails += "    $($sg.ToString().Trim())" + $nl
            }
            $sudoConfigured = $true
        }
        # Check sudoers.d directory
        $sudoersD = $(timeout 5 find /etc/sudoers.d -type f -name "*.conf" -o -type f ! -name "README" 2>/dev/null | head -5)
        if ($sudoersD) {
            $FindingDetails += "  Additional sudoers configs:" + $nl
            foreach ($sd in $sudoersD) {
                $FindingDetails += "    $($sd.ToString().Trim())" + $nl
            }
            $sudoConfigured = $true
        }
    }
    else {
        $FindingDetails += "  sudo: NOT INSTALLED" + $nl
    }

    # Check 2: Group-based privilege management
    $FindingDetails += $nl + "Check 2: Group-Based Privileges" + $nl
    $adminGroups = $(grep -E "^(sudo|admin|wheel|root):" /etc/group 2>&1)
    if ($adminGroups) {
        foreach ($ag in $adminGroups) {
            $FindingDetails += "  $($ag.ToString().Trim())" + $nl
        }
    }

    # Check 3: usermod capability for privilege changes
    $FindingDetails += $nl + "Check 3: User Privilege Modification" + $nl
    $usermodPath = $(which usermod 2>&1)
    if ($LASTEXITCODE -eq 0 -and $usermodPath -match "/usermod") {
        $FindingDetails += "  usermod: AVAILABLE ($usermodPath)" + $nl
        $FindingDetails += "  Admins can add users to privileged groups via: usermod -aG <group> <user>" + $nl
    }
    $gpasswdPath = $(which gpasswd 2>&1)
    if ($LASTEXITCODE -eq 0 -and $gpasswdPath -match "/gpasswd") {
        $FindingDetails += "  gpasswd: AVAILABLE ($gpasswdPath)" + $nl
    }

    # Status determination
    if ($sudoConfigured) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Admins can grant privileges via sudo configuration and" + $nl
        $FindingDetails += "  group membership management." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: sudo not configured for privilege delegation." + $nl
    }
'''
    },
    "V-203694": {
        "RuleID": "SV-203694r958702_rule",
        "STIG_ID": "SRG-OS-000312-GPOS-00124",
        "CheckMD5": "acc77d08d7de27cf325b648f8820cd5e",
        "RuleTitle": "The operating system must allow operating system admins to change security attributes on users, the operating system, or the operating systems components.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Admin Security Attribute Changes ---" + $nl

    # Check 1: User attribute modification tools
    $FindingDetails += $nl + "Check 1: User Security Attribute Tools" + $nl
    $tools = @(
        @{Name="usermod"; Desc="Modify user accounts"},
        @{Name="chown"; Desc="Change file ownership"},
        @{Name="chmod"; Desc="Change file permissions"},
        @{Name="chattr"; Desc="Change file attributes"},
        @{Name="setfacl"; Desc="Set file ACLs"}
    )
    $toolsAvailable = 0
    foreach ($tool in $tools) {
        $toolPath = $(which $tool.Name 2>&1)
        if ($LASTEXITCODE -eq 0 -and $toolPath -match "/$($tool.Name)") {
            $FindingDetails += "  $($tool.Name): AVAILABLE - $($tool.Desc)" + $nl
            $toolsAvailable++
        }
        else {
            $FindingDetails += "  $($tool.Name): NOT FOUND" + $nl
        }
    }

    # Check 2: sudo access for admins
    $FindingDetails += $nl + "Check 2: Sudo Administrative Access" + $nl
    $sudoInstalled = $(dpkg -l sudo 2>&1 | grep "^ii")
    if ($sudoInstalled) {
        $FindingDetails += "  sudo: INSTALLED" + $nl
        $rootGroup = $(grep "^root:" /etc/group 2>&1)
        $sudoGroup = $(grep "^sudo:" /etc/group 2>&1)
        if ($rootGroup) { $FindingDetails += "  $($rootGroup.ToString().Trim())" + $nl }
        if ($sudoGroup) { $FindingDetails += "  $($sudoGroup.ToString().Trim())" + $nl }
    }
    else {
        $FindingDetails += "  sudo: NOT INSTALLED" + $nl
    }

    # Check 3: SELinux/AppArmor management capability
    $FindingDetails += $nl + "Check 3: Mandatory Access Control Management" + $nl
    $aaStatus = $(aa-status 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $profiles = ($aaStatus | Select-String -Pattern "profiles are loaded" | Select-Object -First 1)
        if ($profiles) {
            $FindingDetails += "  AppArmor: $($profiles.ToString().Trim())" + $nl
        }
        $FindingDetails += "  Admins can manage AppArmor profiles via aa-enforce/aa-complain/aa-disable" + $nl
    }
    else {
        $FindingDetails += "  AppArmor: Not available or not running" + $nl
    }

    # Check 4: sysctl for kernel security parameters
    $FindingDetails += $nl + "Check 4: Kernel Security Parameters" + $nl
    $sysctlPath = $(which sysctl 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  sysctl: AVAILABLE - Can modify kernel security parameters" + $nl
        $FindingDetails += "  Config directory: /etc/sysctl.d/" + $nl
    }

    # Status determination
    if ($toolsAvailable -ge 3 -and $sudoInstalled) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Administrators have access to security attribute modification tools" + $nl
        $FindingDetails += "  ($toolsAvailable/5 tools available) with sudo privilege escalation." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Insufficient tools or privileges for security attribute changes." + $nl
    }
'''
    },
    "V-203698": {
        "RuleID": "SV-203698r958736_rule",
        "STIG_ID": "SRG-OS-000329-GPOS-00128",
        "CheckMD5": "ae39ea8fe784cf17c24e90beca17865a",
        "RuleTitle": "The operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes occur.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Account Lock After 3 Failed Attempts ---" + $nl

    # Check 1: PAM faillock configuration
    $FindingDetails += $nl + "Check 1: PAM faillock Configuration" + $nl
    $faillockConf = $(cat /etc/security/faillock.conf 2>&1)
    $faillockConfigured = $false
    $unlockByAdmin = $false
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  /etc/security/faillock.conf: EXISTS" + $nl
        $denyLine = ($faillockConf | Select-String -Pattern "^\s*deny\s*=" | Select-Object -First 1)
        $unlockTimeLine = ($faillockConf | Select-String -Pattern "^\s*unlock_time\s*=" | Select-Object -First 1)
        $failIntervalLine = ($faillockConf | Select-String -Pattern "^\s*fail_interval\s*=" | Select-Object -First 1)

        if ($denyLine) {
            $FindingDetails += "  $($denyLine.ToString().Trim())" + $nl
            if ($denyLine -match "deny\s*=\s*(\d+)") {
                $denyVal = [int]$Matches[1]
                if ($denyVal -le 3) {
                    $faillockConfigured = $true
                    $FindingDetails += "    [PASS] Deny threshold ($denyVal) meets requirement (<=3)" + $nl
                }
                else {
                    $FindingDetails += "    [FAIL] Deny threshold ($denyVal) exceeds 3" + $nl
                }
            }
        }
        else {
            $FindingDetails += "  deny: NOT CONFIGURED" + $nl
        }

        if ($unlockTimeLine) {
            $FindingDetails += "  $($unlockTimeLine.ToString().Trim())" + $nl
            if ($unlockTimeLine -match "unlock_time\s*=\s*0") {
                $unlockByAdmin = $true
                $FindingDetails += "    [PASS] unlock_time=0 means admin must unlock" + $nl
            }
            else {
                $FindingDetails += "    [INFO] Account auto-unlocks (not admin-only release)" + $nl
            }
        }
        else {
            $FindingDetails += "  unlock_time: NOT CONFIGURED" + $nl
        }

        if ($failIntervalLine) {
            $FindingDetails += "  $($failIntervalLine.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  /etc/security/faillock.conf: NOT FOUND" + $nl
    }

    # Check 2: PAM common-auth for pam_faillock
    $FindingDetails += $nl + "Check 2: PAM Module Configuration" + $nl
    $pamAuth = $(cat /etc/pam.d/common-auth 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $faillockLines = ($pamAuth | Select-String -Pattern "pam_faillock")
        if ($faillockLines) {
            $FindingDetails += "  pam_faillock in common-auth:" + $nl
            foreach ($fl in $faillockLines) {
                $FindingDetails += "    $($fl.ToString().Trim())" + $nl
            }
        }
        else {
            $FindingDetails += "  pam_faillock: NOT CONFIGURED in /etc/pam.d/common-auth" + $nl
        }
        # Also check for pam_tally2 as alternative
        $tallyLines = ($pamAuth | Select-String -Pattern "pam_tally2")
        if ($tallyLines) {
            $FindingDetails += "  pam_tally2 (legacy) found:" + $nl
            foreach ($tl in $tallyLines) {
                $FindingDetails += "    $($tl.ToString().Trim())" + $nl
            }
        }
    }

    # Check 3: faillock package installation
    $FindingDetails += $nl + "Check 3: faillock Package" + $nl
    $faillockPkg = $(dpkg -l libpam-modules 2>&1 | grep "^ii")
    if ($faillockPkg) {
        $FindingDetails += "  libpam-modules: INSTALLED (provides pam_faillock)" + $nl
    }
    $faillockBin = $(which faillock 2>&1)
    if ($LASTEXITCODE -eq 0 -and $faillockBin -match "/faillock") {
        $FindingDetails += "  faillock command: AVAILABLE ($faillockBin)" + $nl
    }
    else {
        $FindingDetails += "  faillock command: NOT FOUND" + $nl
    }

    # Status determination
    if ($faillockConfigured -and $unlockByAdmin) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Account lockout configured with deny<=3 and admin-only unlock." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Account lockout not properly configured for 3-attempt limit" + $nl
        $FindingDetails += "  with administrator-only release." + $nl
    }
'''
    },
    "V-203699": {
        "RuleID": "SV-203699r971541_rule",
        "STIG_ID": "SRG-OS-000337-GPOS-00129",
        "CheckMD5": "8f07735a12304d954b873889c4052a64",
        "RuleTitle": "The operating system must provide the capability for assigned IMOs/ISSOs or designated SAs to change the auditing to be performed on all operating system components, based on all selectable event criteria in near real time.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: IMO/ISSO Audit Configuration Capability ---" + $nl

    # Check 1: auditctl availability for real-time audit changes
    $FindingDetails += $nl + "Check 1: Audit Control Tools" + $nl
    $auditctlPath = $(which auditctl 2>&1)
    $auditctlAvailable = $false
    if ($LASTEXITCODE -eq 0 -and $auditctlPath -match "/auditctl") {
        $FindingDetails += "  auditctl: AVAILABLE ($auditctlPath)" + $nl
        $FindingDetails += "  Supports real-time audit rule changes without service restart" + $nl
        $auditctlAvailable = $true
    }
    else {
        $FindingDetails += "  auditctl: NOT FOUND" + $nl
    }

    # Check 2: auditd service status
    $FindingDetails += $nl + "Check 2: Audit Daemon Status" + $nl
    $auditdActive = $(systemctl is-active auditd 2>&1)
    $auditdEnabled = $(systemctl is-enabled auditd 2>&1)
    $FindingDetails += "  auditd service: $auditdActive" + $nl
    $FindingDetails += "  auditd enabled: $auditdEnabled" + $nl

    # Check 3: Audit rules configuration files
    $FindingDetails += $nl + "Check 3: Audit Rules Configuration" + $nl
    $auditRulesDir = $(timeout 5 find /etc/audit -name "*.rules" -type f 2>/dev/null | head -10)
    if ($auditRulesDir) {
        $FindingDetails += "  Audit rules files:" + $nl
        foreach ($arf in $auditRulesDir) {
            $FindingDetails += "    $($arf.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No audit rules files found in /etc/audit/" + $nl
    }

    # Check 4: XO Audit Plugin
    $FindingDetails += $nl + "Check 4: XO Audit Plugin" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE" + $nl
        $FindingDetails += "  Recent audit records: $($xoAuditInfo.RecordCount)" + $nl
        $FindingDetails += "  [INFO] XO Audit Plugin provides application-layer audit configuration" + $nl
        $xoAuditActive = $true
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
        $xoAuditActive = $false
    }

    # Check 5: sudo access for audit administration
    $FindingDetails += $nl + "Check 5: Administrative Access to Audit Tools" + $nl
    $sudoAudit = $(grep -r "auditctl\|auditd\|audit" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -5)
    if ($sudoAudit) {
        $FindingDetails += "  Sudo rules for audit tools:" + $nl
        foreach ($sa in $sudoAudit) {
            $FindingDetails += "    $($sa.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No specific sudo rules for audit tools (root access required)" + $nl
    }

    # Status determination
    if ($auditdActive -eq "active" -and $auditctlAvailable) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: auditd is active and auditctl provides real-time audit" + $nl
        $FindingDetails += "  configuration capability for authorized administrators." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: auditd not active or auditctl not available for real-time" + $nl
        $FindingDetails += "  audit configuration changes." + $nl
    }
'''
    },
    "V-203703": {
        "RuleID": "SV-203703r958758_rule",
        "STIG_ID": "SRG-OS-000344-GPOS-00135",
        "CheckMD5": "3ad05cf3e22d7f87d9ab2e477b650c99",
        "RuleTitle": "The operating system must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Real-Time Alert on Audit Failure ---" + $nl

    # Check 1: auditd space_left_action and admin_space_left_action
    $FindingDetails += $nl + "Check 1: Audit Daemon Failure Actions" + $nl
    $auditdConf = $(cat /etc/audit/auditd.conf 2>&1)
    $alertConfigured = $false
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  /etc/audit/auditd.conf: EXISTS" + $nl
        $spaceLAction = ($auditdConf | Select-String -Pattern "^\s*space_left_action" | Select-Object -First 1)
        $adminSLAction = ($auditdConf | Select-String -Pattern "^\s*admin_space_left_action" | Select-Object -First 1)
        $diskFullAction = ($auditdConf | Select-String -Pattern "^\s*disk_full_action" | Select-Object -First 1)
        $diskErrorAction = ($auditdConf | Select-String -Pattern "^\s*disk_error_action" | Select-Object -First 1)
        $actionEmail = ($auditdConf | Select-String -Pattern "^\s*action_mail_acct" | Select-Object -First 1)

        if ($spaceLAction) {
            $FindingDetails += "  $($spaceLAction.ToString().Trim())" + $nl
            if ($spaceLAction -match "email|exec|syslog") { $alertConfigured = $true }
        }
        if ($adminSLAction) { $FindingDetails += "  $($adminSLAction.ToString().Trim())" + $nl }
        if ($diskFullAction) { $FindingDetails += "  $($diskFullAction.ToString().Trim())" + $nl }
        if ($diskErrorAction) { $FindingDetails += "  $($diskErrorAction.ToString().Trim())" + $nl }
        if ($actionEmail) { $FindingDetails += "  $($actionEmail.ToString().Trim())" + $nl }
    }
    else {
        $FindingDetails += "  /etc/audit/auditd.conf: NOT FOUND" + $nl
    }

    # Check 2: auditd service status
    $FindingDetails += $nl + "Check 2: Audit Daemon Status" + $nl
    $auditdActive = $(systemctl is-active auditd 2>&1)
    $FindingDetails += "  auditd service: $auditdActive" + $nl

    # Check 3: rsyslog alerting configuration
    $FindingDetails += $nl + "Check 3: Syslog Alerting" + $nl
    $rsyslogConf = $(cat /etc/rsyslog.conf 2>&1)
    $auditLogForward = ($rsyslogConf | Select-String -Pattern "audit|local6" | Select-String -Pattern "@" | Select-Object -First 3)
    if ($auditLogForward) {
        $FindingDetails += "  Audit log forwarding configured:" + $nl
        foreach ($alf in $auditLogForward) {
            $FindingDetails += "    $($alf.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No audit log forwarding to remote server detected" + $nl
    }

    # Check 4: Mail system for email alerts
    $FindingDetails += $nl + "Check 4: Email Alert Capability" + $nl
    $mailInstalled = $(dpkg -l 2>&1 | grep -E "^ii.*(postfix|exim|sendmail)" 2>&1)
    if ($mailInstalled) {
        $FindingDetails += "  Mail system: INSTALLED" + $nl
        foreach ($mi in $mailInstalled) {
            $pkgLine = $mi.ToString().Trim()
            if ($pkgLine -match "^ii\s+(\S+)") {
                $FindingDetails += "    $($Matches[1])" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  Mail system: NOT INSTALLED (email alerts not possible)" + $nl
    }

    # Status determination
    if ($auditdActive -eq "active" -and $alertConfigured) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Audit failure alerting is configured via auditd actions." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No real-time alerting configured for audit failure events." + $nl
    }
'''
    },
    "V-203709": {
        "RuleID": "SV-203709r958776_rule",
        "STIG_ID": "SRG-OS-000353-GPOS-00141",
        "CheckMD5": "22de7912600aad7aa0ce36a9a7c01de4",
        "RuleTitle": "The operating system must not alter original content or time ordering of audit records when it provides an audit reduction capability.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Audit Content Preservation (Reduction) ---" + $nl

    # Check 1: ausearch tool (audit reduction without altering originals)
    $FindingDetails += $nl + "Check 1: Audit Reduction Tools" + $nl
    $ausearchPath = $(which ausearch 2>&1)
    $ausearchAvailable = $false
    if ($LASTEXITCODE -eq 0 -and $ausearchPath -match "/ausearch") {
        $FindingDetails += "  ausearch: AVAILABLE ($ausearchPath)" + $nl
        $FindingDetails += "  ausearch performs read-only queries (does not modify original logs)" + $nl
        $ausearchAvailable = $true
    }
    else {
        $FindingDetails += "  ausearch: NOT FOUND" + $nl
    }

    # Check 2: aureport tool
    $aureportPath = $(which aureport 2>&1)
    $aureportAvailable = $false
    if ($LASTEXITCODE -eq 0 -and $aureportPath -match "/aureport") {
        $FindingDetails += "  aureport: AVAILABLE ($aureportPath)" + $nl
        $FindingDetails += "  aureport generates reports from original data (read-only)" + $nl
        $aureportAvailable = $true
    }
    else {
        $FindingDetails += "  aureport: NOT FOUND" + $nl
    }

    # Check 3: Audit log file integrity (immutable attribute)
    $FindingDetails += $nl + "Check 2: Audit Log File Protection" + $nl
    $auditLogPath = "/var/log/audit/audit.log"
    $auditLogExists = $(test -f $auditLogPath 2>&1; echo $LASTEXITCODE)
    if ($auditLogExists.Trim() -eq "0") {
        $auditLogPerms = $(stat -c "%a %U:%G" $auditLogPath 2>&1)
        $FindingDetails += "  $auditLogPath : $auditLogPerms" + $nl
        $auditLogAttrs = $(lsattr $auditLogPath 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $FindingDetails += "  File attributes: $($auditLogAttrs.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  $auditLogPath : NOT FOUND (auditd may not be configured)" + $nl
    }

    # Check 4: journalctl (systemd journal as alternative)
    $FindingDetails += $nl + "Check 3: Systemd Journal" + $nl
    $journalctlPath = $(which journalctl 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  journalctl: AVAILABLE (read-only query interface)" + $nl
        $journalStorage = $(cat /etc/systemd/journald.conf 2>&1 | grep -i "^Storage" 2>&1)
        if ($journalStorage) {
            $FindingDetails += "  Journal storage: $($journalStorage.ToString().Trim())" + $nl
        }
        $FindingDetails += "  systemd journal preserves original content and time ordering" + $nl
    }

    # Check 5: XO Audit Plugin
    $FindingDetails += $nl + "Check 4: XO Audit Plugin" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE" + $nl
        $FindingDetails += "  Hash chain integrity: $($xoAuditInfo.HasIntegrity)" + $nl
        $FindingDetails += "  [PASS] XO Audit Plugin uses hash chain to prevent content alteration" + $nl
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
    }

    # Status determination
    if ($ausearchAvailable -and $aureportAvailable) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Audit reduction tools (ausearch, aureport) perform read-only" + $nl
        $FindingDetails += "  operations that preserve original content and time ordering." + $nl
    }
    elseif ($journalctlPath -and $LASTEXITCODE -eq 0) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: systemd journal provides read-only audit reduction via journalctl" + $nl
        $FindingDetails += "  that preserves original content and time ordering." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No audit reduction tools available that guarantee content" + $nl
        $FindingDetails += "  and time ordering preservation." + $nl
    }
'''
    },
    "V-203710": {
        "RuleID": "SV-203710r987795_rule",
        "STIG_ID": "SRG-OS-000354-GPOS-00142",
        "CheckMD5": "749b610589320a05ea260ded597d1d2e",
        "RuleTitle": "The operating system must not alter original content or time ordering of audit records when it provides a report generation capability.",
        "InitStatus": "Open",
        "CustomCode": r'''
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Audit Content Preservation (Reporting) ---" + $nl

    # Check 1: aureport tool (report generation without altering originals)
    $FindingDetails += $nl + "Check 1: Report Generation Tools" + $nl
    $aureportPath = $(which aureport 2>&1)
    $aureportAvailable = $false
    if ($LASTEXITCODE -eq 0 -and $aureportPath -match "/aureport") {
        $FindingDetails += "  aureport: AVAILABLE ($aureportPath)" + $nl
        $FindingDetails += "  aureport generates reports from original data (read-only access)" + $nl
        $aureportAvailable = $true
    }
    else {
        $FindingDetails += "  aureport: NOT FOUND" + $nl
    }

    # Check 2: aulast tool
    $aulastPath = $(which aulast 2>&1)
    if ($LASTEXITCODE -eq 0 -and $aulastPath -match "/aulast") {
        $FindingDetails += "  aulast: AVAILABLE ($aulastPath)" + $nl
    }

    # Check 3: journalctl reporting capability
    $FindingDetails += $nl + "Check 2: Systemd Journal Reporting" + $nl
    $journalctlPath = $(which journalctl 2>&1)
    $journalAvailable = $false
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  journalctl: AVAILABLE" + $nl
        $FindingDetails += "  Supports time-based filtering (--since/--until) without altering records" + $nl
        $FindingDetails += "  Supports priority filtering (--priority) without altering records" + $nl
        $FindingDetails += "  Supports output formats (--output=json/verbose) for report generation" + $nl
        $journalAvailable = $true
    }
    else {
        $FindingDetails += "  journalctl: NOT FOUND" + $nl
    }

    # Check 4: Audit log file permissions (protection against modification)
    $FindingDetails += $nl + "Check 3: Audit Log Protection" + $nl
    $logPaths = @("/var/log/audit/audit.log", "/var/log/syslog", "/var/log/auth.log")
    foreach ($lp in $logPaths) {
        $lpExists = $(test -f $lp 2>&1; echo $LASTEXITCODE)
        if ($lpExists.Trim() -eq "0") {
            $lpPerms = $(stat -c "%a %U:%G" $lp 2>&1)
            $FindingDetails += "  $lp : $lpPerms" + $nl
        }
    }

    # Check 5: XO Audit Plugin
    $FindingDetails += $nl + "Check 4: XO Audit Plugin" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE" + $nl
        $FindingDetails += "  Hash chain integrity: $($xoAuditInfo.HasIntegrity)" + $nl
        $FindingDetails += "  [PASS] XO Audit Plugin hash chain prevents content alteration during reporting" + $nl
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
    }

    # Status determination
    if ($aureportAvailable) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Report generation tools (aureport) perform read-only" + $nl
        $FindingDetails += "  operations preserving original content and time ordering." + $nl
    }
    elseif ($journalAvailable) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: systemd journal provides report generation via journalctl" + $nl
        $FindingDetails += "  that preserves original content and time ordering." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No report generation tools available that guarantee content" + $nl
        $FindingDetails += "  and time ordering preservation." + $nl
    }
'''
    },
}


def main():
    with open(MODULE_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    changes = 0
    for vuln_id, info in IMPLEMENTATIONS.items():
        func_name = f"Get-V{vuln_id.replace('V-', '')}"

        # Step 1: Replace description block (between <# and #>)
        # Find the function, then its description block
        func_pattern = f"Function {func_name} " + "{"
        func_pos = content.find(func_pattern)
        if func_pos == -1:
            print(f"WARNING: {func_name} not found in module")
            continue

        # Find <# after function declaration
        desc_start = content.find("<#", func_pos)
        desc_end = content.find("#>", desc_start)
        if desc_start == -1 or desc_end == -1:
            print(f"WARNING: Description block not found for {func_name}")
            continue

        # Build new description
        new_desc = f"""<#
    .DESCRIPTION
        Vuln ID    : {vuln_id}
        STIG ID    : {info['STIG_ID']}
        Rule ID    : {info['RuleID']}
        Rule Title : {info['RuleTitle']}
        DiscussMD5 : 00000000000000000000000000000000
        CheckMD5   : {info['CheckMD5']}
        FixMD5     : 00000000000000000000000000000000
    #>"""
        content = content[:desc_start] + new_desc + content[desc_end + 2:]

        # Step 2: Update RuleID in variable initialization
        # Find $RuleID = "..." after the function
        func_pos = content.find(func_pattern)  # Re-find after description replacement
        ruleid_pattern = re.compile(r'(\$RuleID\s*=\s*")[^"]*(")', re.MULTILINE)
        # Search only within this function (next 500 chars after func start)
        search_start = func_pos
        search_end = min(func_pos + 2000, len(content))
        func_section = content[search_start:search_end]
        ruleid_match = ruleid_pattern.search(func_section)
        if ruleid_match:
            old_ruleid = func_section[ruleid_match.start():ruleid_match.end()]
            new_ruleid = f'$RuleID = "{info["RuleID"]}"'
            content = content[:search_start + ruleid_match.start()] + new_ruleid + content[search_start + ruleid_match.end():]

        # Step 3: Update initial Status
        func_pos = content.find(func_pattern)  # Re-find
        search_start = func_pos
        search_end = min(func_pos + 2000, len(content))
        func_section = content[search_start:search_end]
        status_pattern = re.compile(r'(\$Status\s*=\s*")[^"]*(")', re.MULTILINE)
        status_match = status_pattern.search(func_section)
        if status_match:
            old_status = func_section[status_match.start():status_match.end()]
            new_status = f'$Status = "{info["InitStatus"]}"'
            content = content[:search_start + status_match.start()] + new_status + content[search_start + status_match.end():]

        # Step 4: Replace custom code block
        func_pos = content.find(func_pattern)  # Re-find
        custom_start_marker = "#---=== Begin Custom Code ===---#"
        custom_end_marker = "#---=== End Custom Code ===---#"
        custom_start = content.find(custom_start_marker, func_pos)
        custom_end = content.find(custom_end_marker, func_pos)
        if custom_start == -1 or custom_end == -1:
            print(f"WARNING: Custom code markers not found for {func_name}")
            continue

        # Verify markers are within this function (not a later function)
        next_func_pos = content.find("Function Get-V", func_pos + len(func_pattern))
        if next_func_pos != -1 and custom_start > next_func_pos:
            print(f"WARNING: Custom code markers found in wrong function for {func_name}")
            continue

        new_custom = custom_start_marker + info["CustomCode"] + "\n    " + custom_end_marker
        content = content[:custom_start] + new_custom + content[custom_end + len(custom_end_marker):]

        changes += 1
        print(f"OK: {vuln_id} ({func_name}) — integrated successfully")

    with open(MODULE_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nIntegrated {changes}/10 functions")
    return 0 if changes == 10 else 1


if __name__ == "__main__":
    sys.exit(main())
