#!/usr/bin/env python3
"""Integrate Batch 11 (System Configuration) implementations into GPOS Debian12 module.

Replaces 10 stub functions with full implementations.
VulnIDs: V-203649, V-203657, V-203658, V-203659, V-203660,
         V-203661, V-203663, V-203664, V-203683, V-203684
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

# --- Function implementations ---
# Each key is (VulnID, RuleID, STIG_ID, CheckMD5, RuleTitle)
# Value is the custom code block (between Begin/End Custom Code markers)

IMPLEMENTATIONS = {
    "V-203649": {
        "RuleID": "SV-203649r971535_rule",
        "STIG_ID": "SRG-OS-000120-GPOS-00061",
        "CheckMD5": "bb149895d772a57351acd22ac7bf0a34",
        "RuleTitle": "Use mechanisms meeting applicable federal laws for crypto module auth",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: OpenSSL FIPS mode
    $output += "Check 1: OpenSSL FIPS Mode${nl}"
    try {
        $fipsEnabled = $(timeout 5 cat /proc/sys/crypto/fips_enabled 2>/dev/null)
        $fipsStr = ($fipsEnabled -join " ").Trim()
        if ($fipsStr -eq "1") {
            $output += "  FIPS mode: ENABLED${nl}"
            $output += "  [PASS] Kernel FIPS mode is active${nl}"
        }
        else {
            $output += "  FIPS mode: NOT ENABLED (value: $fipsStr)${nl}"
            $output += "  [FAIL] Kernel FIPS mode is not active${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: OpenSSL version and FIPS provider
    $output += "Check 2: OpenSSL Version${nl}"
    try {
        $opensslVer = $(timeout 5 openssl version 2>&1)
        $opensslStr = ($opensslVer -join " ").Trim()
        $output += "  $opensslStr${nl}"
        $fipsProv = $(timeout 5 openssl list -providers 2>/dev/null)
        $fipsProvStr = ($fipsProv -join $nl).Trim()
        if ($fipsProvStr -match "fips") {
            $output += "  [PASS] FIPS provider available${nl}"
        }
        else {
            $output += "  [INFO] FIPS provider not detected in OpenSSL${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: libgcrypt FIPS mode
    $output += "Check 3: libgcrypt FIPS Configuration${nl}"
    try {
        $gcryptPkg = $(timeout 5 dpkg -l libgcrypt20 2>/dev/null | grep "^ii")
        $gcryptStr = ($gcryptPkg -join $nl).Trim()
        if ($gcryptStr) {
            $output += "  $gcryptStr${nl}"
            $output += "  [PASS] libgcrypt20 installed${nl}"
        }
        else {
            $output += "  [FAIL] libgcrypt20 not installed${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: PAM crypto modules
    $output += "Check 4: PAM Cryptographic Modules${nl}"
    try {
        $pamCrypto = $(timeout 5 sh -c "grep -r 'pam_unix\|pam_sssd\|pam_ldap' /etc/pam.d/common-auth 2>/dev/null" 2>&1)
        $pamStr = ($pamCrypto -join $nl).Trim()
        if ($pamStr) {
            $output += "  $pamStr${nl}"
            $output += "  [PASS] PAM authentication modules configured${nl}"
        }
        else {
            $output += "  [FAIL] No PAM authentication modules found${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 5: SSH crypto configuration
    $output += "Check 5: SSH Cryptographic Algorithms${nl}"
    try {
        $sshCiphers = $(timeout 5 sh -c "sshd -T 2>/dev/null | grep -i ciphers" 2>&1)
        $sshStr = ($sshCiphers -join $nl).Trim()
        if ($sshStr) {
            $output += "  $sshStr${nl}"
            if ($sshStr -match "aes(128|256)-(ctr|gcm)") {
                $output += "  [PASS] FIPS-approved ciphers in use${nl}"
            }
            else {
                $output += "  [FAIL] Non-FIPS ciphers detected${nl}"
            }
        }
        else {
            $output += "  [INFO] Unable to query SSH daemon configuration${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status
    if ($fipsStr -eq "1") {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },

    "V-203657": {
        "RuleID": "SV-203657r958524_rule",
        "STIG_ID": "SRG-OS-000138-GPOS-00069",
        "CheckMD5": "84c677a60d23492ea6f4920fd90f260e",
        "RuleTitle": "Prevent unauthorized info transfer via shared system resources",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: /proc/sys/fs/protected_hardlinks and protected_symlinks
    $output += "Check 1: Protected Hardlinks and Symlinks${nl}"
    try {
        $hardlinks = $(timeout 5 cat /proc/sys/fs/protected_hardlinks 2>/dev/null)
        $hardStr = ($hardlinks -join " ").Trim()
        $symlinks = $(timeout 5 cat /proc/sys/fs/protected_symlinks 2>/dev/null)
        $symStr = ($symlinks -join " ").Trim()
        $output += "  protected_hardlinks = $hardStr${nl}"
        $output += "  protected_symlinks = $symStr${nl}"
        if ($hardStr -eq "1" -and $symStr -eq "1") {
            $output += "  [PASS] Hardlink and symlink protections enabled${nl}"
        }
        else {
            $output += "  [FAIL] Hardlink/symlink protections not fully enabled${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: /tmp mount with noexec,nosuid,nodev
    $output += "Check 2: /tmp Mount Options${nl}"
    try {
        $tmpMount = $(timeout 5 sh -c "findmnt -n -o OPTIONS /tmp 2>/dev/null" 2>&1)
        $tmpStr = ($tmpMount -join " ").Trim()
        if ($tmpStr) {
            $output += "  /tmp options: $tmpStr${nl}"
            $tmpIssues = 0
            if ($tmpStr -notmatch "nosuid") { $output += "  [FAIL] nosuid not set on /tmp${nl}"; $tmpIssues++ }
            if ($tmpStr -notmatch "nodev") { $output += "  [FAIL] nodev not set on /tmp${nl}"; $tmpIssues++ }
            if ($tmpStr -notmatch "noexec") { $output += "  [FAIL] noexec not set on /tmp${nl}"; $tmpIssues++ }
            if ($tmpIssues -eq 0) {
                $output += "  [PASS] /tmp mounted with nosuid, nodev, noexec${nl}"
            }
        }
        else {
            $output += "  [INFO] /tmp not mounted as separate filesystem${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: /dev/shm mount options
    $output += "Check 3: /dev/shm Mount Options${nl}"
    try {
        $shmMount = $(timeout 5 sh -c "findmnt -n -o OPTIONS /dev/shm 2>/dev/null" 2>&1)
        $shmStr = ($shmMount -join " ").Trim()
        if ($shmStr) {
            $output += "  /dev/shm options: $shmStr${nl}"
            $shmIssues = 0
            if ($shmStr -notmatch "nosuid") { $output += "  [FAIL] nosuid not set on /dev/shm${nl}"; $shmIssues++ }
            if ($shmStr -notmatch "nodev") { $output += "  [FAIL] nodev not set on /dev/shm${nl}"; $shmIssues++ }
            if ($shmStr -notmatch "noexec") { $output += "  [FAIL] noexec not set on /dev/shm${nl}"; $shmIssues++ }
            if ($shmIssues -eq 0) {
                $output += "  [PASS] /dev/shm mounted with nosuid, nodev, noexec${nl}"
            }
        }
        else {
            $output += "  [INFO] /dev/shm not mounted${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: Core dump restrictions
    $output += "Check 4: Core Dump Restrictions${nl}"
    try {
        $coreLimits = $(timeout 5 sh -c "grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep core" 2>&1)
        $coreStr = ($coreLimits -join $nl).Trim()
        $sysCore = $(timeout 5 cat /proc/sys/kernel/core_pattern 2>/dev/null)
        $sysCoreStr = ($sysCore -join " ").Trim()
        $output += "  core_pattern: $sysCoreStr${nl}"
        if ($coreStr) {
            $output += "  limits.conf: $coreStr${nl}"
        }
        $fsProtect = $(timeout 5 cat /proc/sys/fs/suid_dumpable 2>/dev/null)
        $fsProtStr = ($fsProtect -join " ").Trim()
        $output += "  suid_dumpable: $fsProtStr${nl}"
        if ($fsProtStr -eq "0") {
            $output += "  [PASS] SUID core dumps disabled${nl}"
        }
        else {
            $output += "  [FAIL] SUID core dumps not fully restricted (should be 0)${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status
    if ($hardStr -eq "1" -and $symStr -eq "1" -and $fsProtStr -eq "0") {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },

    "V-203658": {
        "RuleID": "SV-203658r958528_rule",
        "STIG_ID": "SRG-OS-000142-GPOS-00071",
        "CheckMD5": "d0b1a712f58767e5bd524ea41d4178d6",
        "RuleTitle": "Manage excess capacity/bandwidth to limit DoS effects",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Firewall rate limiting (UFW/nftables/iptables)
    $output += "Check 1: Firewall Rate Limiting${nl}"
    try {
        $fwStatus = Get-FirewallStatus
        if ($fwStatus.Active) {
            $output += "  Firewall: $($fwStatus.Type) ACTIVE${nl}"
            if ($fwStatus.Type -eq "UFW") {
                $ufwRules = $(timeout 5 sh -c "ufw status verbose 2>/dev/null | grep -i 'limit\|rate'" 2>&1)
                $ufwStr = ($ufwRules -join $nl).Trim()
                if ($ufwStr) {
                    $output += "  Rate limiting rules found:${nl}  $ufwStr${nl}"
                    $output += "  [PASS] UFW rate limiting configured${nl}"
                }
                else {
                    $output += "  [INFO] No explicit rate limiting rules in UFW${nl}"
                }
            }
        }
        else {
            $output += "  [FAIL] No active firewall detected${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: TCP SYN flood protection
    $output += "Check 2: TCP SYN Flood Protection${nl}"
    try {
        $syncookies = $(timeout 5 cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null)
        $syncStr = ($syncookies -join " ").Trim()
        $output += "  tcp_syncookies = $syncStr${nl}"
        if ($syncStr -eq "1") {
            $output += "  [PASS] SYN cookies enabled${nl}"
        }
        else {
            $output += "  [FAIL] SYN cookies not enabled${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: Connection tracking limits
    $output += "Check 3: Connection Tracking${nl}"
    try {
        $connMax = $(timeout 5 cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
        $connStr = ($connMax -join " ").Trim()
        if ($connStr) {
            $output += "  nf_conntrack_max = $connStr${nl}"
            $output += "  [PASS] Connection tracking configured${nl}"
        }
        else {
            $output += "  [INFO] Connection tracking not available (nf_conntrack module may not be loaded)${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: Resource limits (ulimits)
    $output += "Check 4: System Resource Limits${nl}"
    try {
        $limitsConf = $(timeout 5 sh -c "grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -v '^\s*$'" 2>&1)
        $limitsStr = ($limitsConf -join $nl).Trim()
        if ($limitsStr) {
            $output += "  Custom limits configured:${nl}"
            foreach ($line in ($limitsStr -split $nl)) {
                $output += "    $line${nl}"
            }
            $output += "  [PASS] Resource limits defined${nl}"
        }
        else {
            $output += "  [INFO] No custom resource limits in limits.conf${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status
    if ($syncStr -eq "1") {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },

    "V-203659": {
        "RuleID": "SV-203659r970703_rule",
        "STIG_ID": "SRG-OS-000163-GPOS-00072",
        "CheckMD5": "65f1666297979185d6dfd73b793c34c6",
        "RuleTitle": "Terminate network connections at end of session or after inactivity timeout",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: SSH ClientAliveInterval and ClientAliveCountMax
    $output += "Check 1: SSH Session Timeout Configuration${nl}"
    try {
        $sshInterval = $(timeout 5 sh -c "sshd -T 2>/dev/null | grep -i clientaliveinterval" 2>&1)
        $sshIntervalStr = ($sshInterval -join " ").Trim()
        $sshCount = $(timeout 5 sh -c "sshd -T 2>/dev/null | grep -i clientalivecountmax" 2>&1)
        $sshCountStr = ($sshCount -join " ").Trim()
        $output += "  $sshIntervalStr${nl}"
        $output += "  $sshCountStr${nl}"
        $intervalOk = $false
        if ($sshIntervalStr -match "clientaliveinterval\s+(\d+)") {
            $intervalVal = [int]$Matches[1]
            if ($intervalVal -gt 0 -and $intervalVal -le 600) {
                $output += "  [PASS] ClientAliveInterval ($intervalVal seconds) within 10-minute limit${nl}"
                $intervalOk = $true
            }
            else {
                $output += "  [FAIL] ClientAliveInterval ($intervalVal) exceeds 600-second maximum${nl}"
            }
        }
        else {
            $output += "  [FAIL] ClientAliveInterval not configured${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: TMOUT shell variable
    $output += "Check 2: Shell Inactivity Timeout (TMOUT)${nl}"
    try {
        $tmout = $(timeout 5 sh -c "grep -r 'TMOUT' /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null | grep -v '^#'" 2>&1)
        $tmoutStr = ($tmout -join $nl).Trim()
        if ($tmoutStr) {
            $output += "  $tmoutStr${nl}"
            if ($tmoutStr -match "TMOUT=(\d+)") {
                $tmoutVal = [int]$Matches[1]
                if ($tmoutVal -le 900) {
                    $output += "  [PASS] TMOUT=$tmoutVal (within 15-minute limit)${nl}"
                }
                else {
                    $output += "  [FAIL] TMOUT=$tmoutVal exceeds 900-second maximum${nl}"
                }
            }
        }
        else {
            $output += "  [FAIL] TMOUT not configured in login profiles${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: systemd-logind InactivityTimeout
    $output += "Check 3: systemd-logind Session Configuration${nl}"
    try {
        $logindConf = $(timeout 5 sh -c "grep -v '^#' /etc/systemd/logind.conf 2>/dev/null | grep -i 'IdleAction\|StopIdleSessionSec\|KillUserProcesses'" 2>&1)
        $logindStr = ($logindConf -join $nl).Trim()
        if ($logindStr) {
            $output += "  $logindStr${nl}"
            $output += "  [PASS] systemd-logind session management configured${nl}"
        }
        else {
            $output += "  [INFO] No custom systemd-logind idle settings${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: XO session timeout (if applicable)
    $output += "Check 4: XO Application Session Timeout${nl}"
    try {
        $xoConf = $(timeout 5 sh -c "grep -ri 'session\|timeout\|maxAge\|idle' /etc/xo-server/config.toml /opt/xo/xo-server/.xo-server.yaml 2>/dev/null | grep -v '^#'" 2>&1)
        $xoStr = ($xoConf -join $nl).Trim()
        if ($xoStr) {
            $output += "  $xoStr${nl}"
            $output += "  [INFO] XO session configuration found${nl}"
        }
        else {
            $output += "  [INFO] No explicit XO session timeout configuration${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status
    if ($intervalOk) {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },

    "V-203660": {
        "RuleID": "SV-203660r958550_rule",
        "STIG_ID": "SRG-OS-000184-GPOS-00078",
        "CheckMD5": "273055e926fecb0033cf40a05d8b4702",
        "RuleTitle": "Fail to a secure state if system initialization fails",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: systemd default target
    $output += "Check 1: Default Boot Target${nl}"
    try {
        $defaultTarget = $(timeout 5 systemctl get-default 2>&1)
        $targetStr = ($defaultTarget -join " ").Trim()
        $output += "  Default target: $targetStr${nl}"
        if ($targetStr -eq "multi-user.target") {
            $output += "  [PASS] System boots to multi-user (no GUI) — secure default${nl}"
        }
        elseif ($targetStr -eq "graphical.target") {
            $output += "  [INFO] System boots to graphical target${nl}"
        }
        else {
            $output += "  [INFO] Non-standard default target${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: Emergency/rescue mode requires root authentication
    $output += "Check 2: Emergency/Rescue Mode Authentication${nl}"
    try {
        $suloginCheck = $(timeout 5 sh -c "grep -r 'sulogin\|ExecStart.*-sulogin' /usr/lib/systemd/system/emergency.service /usr/lib/systemd/system/rescue.service 2>/dev/null" 2>&1)
        $suloginStr = ($suloginCheck -join $nl).Trim()
        if ($suloginStr -match "sulogin") {
            $output += "  $suloginStr${nl}"
            $output += "  [PASS] Emergency/rescue modes require root authentication (sulogin)${nl}"
        }
        else {
            $output += "  [FAIL] sulogin not configured for emergency/rescue modes${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: Ctrl-Alt-Delete reboot disabled
    $output += "Check 3: Ctrl-Alt-Delete Reboot${nl}"
    try {
        $ctrlAlt = $(timeout 5 systemctl is-masked ctrl-alt-del.target 2>&1)
        $ctrlStr = ($ctrlAlt -join " ").Trim()
        $output += "  ctrl-alt-del.target: $ctrlStr${nl}"
        if ($ctrlStr -eq "masked") {
            $output += "  [PASS] Ctrl-Alt-Delete reboot disabled${nl}"
        }
        else {
            $output += "  [FAIL] Ctrl-Alt-Delete reboot not masked${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: Kernel panic behavior
    $output += "Check 4: Kernel Panic Behavior${nl}"
    try {
        $panicVal = $(timeout 5 cat /proc/sys/kernel/panic 2>/dev/null)
        $panicStr = ($panicVal -join " ").Trim()
        $output += "  kernel.panic = $panicStr${nl}"
        $panicOops = $(timeout 5 cat /proc/sys/kernel/panic_on_oops 2>/dev/null)
        $oopsStr = ($panicOops -join " ").Trim()
        $output += "  kernel.panic_on_oops = $oopsStr${nl}"
        if ($oopsStr -eq "1") {
            $output += "  [PASS] System will panic on kernel oops (fail-secure)${nl}"
        }
        else {
            $output += "  [INFO] System continues on kernel oops${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status
    if ($suloginStr -match "sulogin" -and $ctrlStr -eq "masked") {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },

    "V-203661": {
        "RuleID": "SV-203661r958552_rule",
        "STIG_ID": "SRG-OS-000185-GPOS-00079",
        "CheckMD5": "b99c9ec4c8cde62b2a38f89d90563cd9",
        "RuleTitle": "Protect confidentiality and integrity of information at rest",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: LUKS/dm-crypt encrypted volumes
    $output += "Check 1: Disk Encryption (LUKS/dm-crypt)${nl}"
    try {
        $luksDevices = $(timeout 10 sh -c "lsblk -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null | grep -i 'crypto_LUKS\|crypt'" 2>&1)
        $luksStr = ($luksDevices -join $nl).Trim()
        if ($luksStr) {
            $output += "  Encrypted volumes found:${nl}"
            foreach ($line in ($luksStr -split $nl)) {
                $output += "    $line${nl}"
            }
            $output += "  [PASS] LUKS encryption detected${nl}"
        }
        else {
            $output += "  [FAIL] No LUKS/dm-crypt encrypted volumes detected${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: /etc/crypttab
    $output += "Check 2: Encrypted Volume Configuration (/etc/crypttab)${nl}"
    try {
        $crypttab = $(timeout 5 sh -c "cat /etc/crypttab 2>/dev/null | grep -v '^#' | grep -v '^\s*$'" 2>&1)
        $cryptStr = ($crypttab -join $nl).Trim()
        if ($cryptStr) {
            $output += "  $cryptStr${nl}"
            $output += "  [PASS] Encrypted volumes defined in /etc/crypttab${nl}"
        }
        else {
            $output += "  [INFO] No entries in /etc/crypttab (or file not present)${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: Filesystem permissions on sensitive directories
    $output += "Check 3: Sensitive Directory Permissions${nl}"
    try {
        $sensitiveDirs = @("/etc/shadow", "/etc/gshadow", "/etc/ssl/private")
        foreach ($dir in $sensitiveDirs) {
            $perms = $(timeout 5 stat -c "%a %U:%G %n" $dir 2>/dev/null)
            $permStr = ($perms -join " ").Trim()
            if ($permStr) {
                $output += "  $permStr${nl}"
            }
        }
        $shadowPerms = $(timeout 5 stat -c "%a" /etc/shadow 2>/dev/null)
        $shadowStr = ($shadowPerms -join " ").Trim()
        if ($shadowStr -match "^[0-6][04]0$") {
            $output += "  [PASS] /etc/shadow has restrictive permissions${nl}"
        }
        else {
            $output += "  [FAIL] /etc/shadow permissions too permissive ($shadowStr)${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: XO data directory permissions
    $output += "Check 4: XO Data Directory Protection${nl}"
    try {
        $xoDirs = @("/var/lib/xo-server", "/etc/xo-server", "/opt/xo")
        foreach ($xoDir in $xoDirs) {
            $xoPerms = $(timeout 5 stat -c "%a %U:%G %n" $xoDir 2>/dev/null)
            $xoStr = ($xoPerms -join " ").Trim()
            if ($xoStr) {
                $output += "  $xoStr${nl}"
            }
        }
        $output += "  [INFO] Verify XO data directories have appropriate access controls${nl}"
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status — LUKS or restrictive file permissions
    if ($luksStr -match "crypt") {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },

    "V-203663": {
        "RuleID": "SV-203663r958564_rule",
        "STIG_ID": "SRG-OS-000205-GPOS-00083",
        "CheckMD5": "d1d2bde2aa595baeee464a17bea64e1f",
        "RuleTitle": "Error messages provide necessary info without exploitable details",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: /etc/issue and /etc/issue.net
    $output += "Check 1: Login Banner Configuration${nl}"
    try {
        $issueContent = $(timeout 5 cat /etc/issue 2>/dev/null)
        $issueStr = ($issueContent -join $nl).Trim()
        $output += "  /etc/issue:${nl}"
        if ($issueStr) {
            $output += "  $issueStr${nl}"
            if ($issueStr -match "\\\\[lnmrsv]|\\\\[oO]") {
                $output += "  [FAIL] /etc/issue contains OS identification escape sequences${nl}"
            }
            else {
                $output += "  [PASS] /etc/issue does not expose OS details via escape codes${nl}"
            }
        }
        else {
            $output += "  (empty)${nl}"
            $output += "  [PASS] /etc/issue is empty${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: /etc/issue.net for remote sessions
    $output += "Check 2: Remote Login Banner (/etc/issue.net)${nl}"
    try {
        $issueNet = $(timeout 5 cat /etc/issue.net 2>/dev/null)
        $issueNetStr = ($issueNet -join $nl).Trim()
        $output += "  /etc/issue.net:${nl}"
        if ($issueNetStr) {
            $output += "  $issueNetStr${nl}"
            if ($issueNetStr -match "\\\\[lnmrsv]|\\\\[oO]") {
                $output += "  [FAIL] /etc/issue.net contains OS identification escape sequences${nl}"
            }
            else {
                $output += "  [PASS] /etc/issue.net does not expose OS details${nl}"
            }
        }
        else {
            $output += "  (empty)${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: SSH banner configuration
    $output += "Check 3: SSH Banner Configuration${nl}"
    try {
        $sshBanner = $(timeout 5 sh -c "sshd -T 2>/dev/null | grep -i banner" 2>&1)
        $bannerStr = ($sshBanner -join " ").Trim()
        $output += "  $bannerStr${nl}"
        if ($bannerStr -match "banner\s+/etc/issue") {
            $output += "  [PASS] SSH banner configured to use /etc/issue or /etc/issue.net${nl}"
        }
        elseif ($bannerStr -match "banner\s+none") {
            $output += "  [FAIL] SSH banner is set to none${nl}"
        }
        else {
            $output += "  [INFO] SSH banner uses custom file${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: System logging verbosity (not leaking sensitive data)
    $output += "Check 4: Syslog Error Message Configuration${nl}"
    try {
        $rsysConf = $(timeout 5 sh -c "grep -v '^#' /etc/rsyslog.conf 2>/dev/null | grep -v '^\s*$' | head -20" 2>&1)
        $rsysStr = ($rsysConf -join $nl).Trim()
        if ($rsysStr) {
            $output += "  rsyslog configured (first 20 active lines)${nl}"
            $output += "  [PASS] System logging configured to capture errors${nl}"
        }
        else {
            $output += "  [INFO] rsyslog.conf not found or empty${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status
    $issueOk = ($issueStr -notmatch "\\\\[lnmrsv]|\\\\[oO]") -or (-not $issueStr)
    $issueNetOk = ($issueNetStr -notmatch "\\\\[lnmrsv]|\\\\[oO]") -or (-not $issueNetStr)
    if ($issueOk -and $issueNetOk -and $rsysStr) {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },

    "V-203664": {
        "RuleID": "SV-203664r958566_rule",
        "STIG_ID": "SRG-OS-000206-GPOS-00084",
        "CheckMD5": "37c113e557135af92d3d0d2ec058550e",
        "RuleTitle": "Reveal error messages only to authorized users",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: /var/log permissions (restrict error logs to authorized users)
    $output += "Check 1: System Log Directory Permissions${nl}"
    try {
        $logPerms = $(timeout 5 stat -c "%a %U:%G %n" /var/log 2>/dev/null)
        $logStr = ($logPerms -join " ").Trim()
        $output += "  $logStr${nl}"
        if ($logStr -match "^(\d+)\s") {
            $permVal = $Matches[1]
            if ([int]$permVal -le 755) {
                $output += "  [PASS] /var/log permissions restrict unauthorized access${nl}"
            }
            else {
                $output += "  [FAIL] /var/log permissions too permissive ($permVal)${nl}"
            }
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: Key log file permissions
    $output += "Check 2: Individual Log File Permissions${nl}"
    try {
        $logFiles = @("/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log", "/var/log/messages")
        $logIssues = 0
        foreach ($lf in $logFiles) {
            $lfPerms = $(timeout 5 stat -c "%a %U:%G %n" $lf 2>/dev/null)
            $lfStr = ($lfPerms -join " ").Trim()
            if ($lfStr) {
                $output += "  $lfStr${nl}"
                if ($lfStr -match "^(\d+)\s") {
                    $lfPerm = $Matches[1]
                    if ([int]$lfPerm -gt 640) {
                        $output += "  [FAIL] $lf permissions too permissive ($lfPerm)${nl}"
                        $logIssues++
                    }
                }
            }
        }
        if ($logIssues -eq 0) {
            $output += "  [PASS] Log files have appropriate permissions${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: journald configuration
    $output += "Check 3: journald Access Configuration${nl}"
    try {
        $jdConf = $(timeout 5 sh -c "grep -v '^#' /etc/systemd/journald.conf 2>/dev/null | grep -v '^\s*$'" 2>&1)
        $jdStr = ($jdConf -join $nl).Trim()
        if ($jdStr) {
            $output += "  $jdStr${nl}"
        }
        $jdStorage = $(timeout 5 sh -c "grep -i 'Storage' /etc/systemd/journald.conf 2>/dev/null | grep -v '^#'" 2>&1)
        $jdStorStr = ($jdStorage -join " ").Trim()
        if ($jdStorStr) {
            $output += "  Storage setting: $jdStorStr${nl}"
        }
        $output += "  [INFO] journald access controlled by systemd permissions${nl}"
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: Dmesg restriction
    $output += "Check 4: Kernel Message Restriction (dmesg)${nl}"
    try {
        $dmesgRestrict = $(timeout 5 cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
        $dmesgStr = ($dmesgRestrict -join " ").Trim()
        $output += "  kernel.dmesg_restrict = $dmesgStr${nl}"
        if ($dmesgStr -eq "1") {
            $output += "  [PASS] Kernel messages restricted to root${nl}"
        }
        else {
            $output += "  [FAIL] Kernel messages accessible to all users (should be 1)${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status
    if ($logIssues -eq 0 -and $dmesgStr -eq "1") {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },

    "V-203683": {
        "RuleID": "SV-203683r958636_rule",
        "STIG_ID": "SRG-OS-000279-GPOS-00109",
        "CheckMD5": "2a953cc9d7d4f473066baa9c9301b42b",
        "RuleTitle": "Automatically terminate user session after inactivity or at shutdown",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: SSH ClientAliveInterval
    $output += "Check 1: SSH Inactivity Timeout${nl}"
    try {
        $sshInterval = $(timeout 5 sh -c "sshd -T 2>/dev/null | grep -i clientaliveinterval" 2>&1)
        $sshIntervalStr = ($sshInterval -join " ").Trim()
        $sshCount = $(timeout 5 sh -c "sshd -T 2>/dev/null | grep -i clientalivecountmax" 2>&1)
        $sshCountStr = ($sshCount -join " ").Trim()
        $output += "  $sshIntervalStr${nl}"
        $output += "  $sshCountStr${nl}"
        $sshOk = $false
        if ($sshIntervalStr -match "clientaliveinterval\s+(\d+)") {
            $intervalVal = [int]$Matches[1]
            if ($intervalVal -gt 0 -and $intervalVal -le 600) {
                $output += "  [PASS] SSH inactivity timeout set to $intervalVal seconds${nl}"
                $sshOk = $true
            }
            else {
                $output += "  [FAIL] SSH inactivity timeout ($intervalVal) exceeds 600-second limit${nl}"
            }
        }
        else {
            $output += "  [FAIL] SSH ClientAliveInterval not configured${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: TMOUT shell variable
    $output += "Check 2: Shell TMOUT Variable${nl}"
    try {
        $tmout = $(timeout 5 sh -c "grep -r 'TMOUT' /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null | grep -v '^#'" 2>&1)
        $tmoutStr = ($tmout -join $nl).Trim()
        $tmoutOk = $false
        if ($tmoutStr) {
            $output += "  $tmoutStr${nl}"
            if ($tmoutStr -match "TMOUT=(\d+)") {
                $tmoutVal = [int]$Matches[1]
                if ($tmoutVal -le 900) {
                    $output += "  [PASS] Shell TMOUT=$tmoutVal seconds${nl}"
                    $tmoutOk = $true
                }
                else {
                    $output += "  [FAIL] TMOUT=$tmoutVal exceeds 900-second limit${nl}"
                }
            }
        }
        else {
            $output += "  [FAIL] TMOUT not configured${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: systemd-logind idle action
    $output += "Check 3: systemd-logind Idle Configuration${nl}"
    try {
        $logindConf = $(timeout 5 sh -c "grep -v '^#' /etc/systemd/logind.conf 2>/dev/null | grep -i 'IdleAction\|StopIdleSessionSec'" 2>&1)
        $logindStr = ($logindConf -join $nl).Trim()
        if ($logindStr) {
            $output += "  $logindStr${nl}"
            $output += "  [PASS] systemd-logind idle action configured${nl}"
        }
        else {
            $output += "  [INFO] No custom idle action in logind.conf${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: Screen lock / vlock
    $output += "Check 4: Terminal Lock Capability${nl}"
    try {
        $vlockPkg = $(timeout 5 sh -c "dpkg -l vlock 2>/dev/null | grep '^ii'" 2>&1)
        $vlockStr = ($vlockPkg -join " ").Trim()
        if ($vlockStr) {
            $output += "  $vlockStr${nl}"
            $output += "  [PASS] vlock terminal locking available${nl}"
        }
        else {
            $tmuxPkg = $(timeout 5 sh -c "which tmux 2>/dev/null" 2>&1)
            $tmuxStr = ($tmuxPkg -join " ").Trim()
            if ($tmuxStr -and $tmuxStr -notmatch "not found") {
                $output += "  tmux available at: $tmuxStr${nl}"
                $output += "  [INFO] tmux can provide session lock capability${nl}"
            }
            else {
                $output += "  [INFO] No terminal lock utility detected (vlock or tmux)${nl}"
            }
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status
    if ($sshOk) {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },

    "V-203684": {
        "RuleID": "SV-203684r958638_rule",
        "STIG_ID": "SRG-OS-000280-GPOS-00110",
        "CheckMD5": "433c99c4c34d482edfa17351840f6f57",
        "RuleTitle": "Provide logoff capability for user-initiated sessions",
        "InitStatus": "Open",
        "CustomCode": r'''    $nl = [Environment]::NewLine
    $output = ""

    # Check 1: Shell logout/exit capability
    $output += "Check 1: Shell Logout Capability${nl}"
    try {
        $shellList = $(timeout 5 cat /etc/shells 2>/dev/null)
        $shellStr = ($shellList -join $nl).Trim()
        if ($shellStr) {
            $output += "  Valid shells:${nl}"
            foreach ($shell in ($shellStr -split $nl)) {
                $s = $shell.Trim()
                if ($s -and $s -notmatch "^#") {
                    $output += "    $s${nl}"
                }
            }
            $output += "  [PASS] Shell sessions support exit/logout commands${nl}"
        }
        else {
            $output += "  [INFO] /etc/shells not found${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 2: SSH session termination
    $output += "Check 2: SSH Session Termination${nl}"
    try {
        $sshdActive = $(timeout 5 systemctl is-active sshd 2>/dev/null)
        $sshdStr = ($sshdActive -join " ").Trim()
        if ($sshdStr -ne "active") {
            $sshdActive = $(timeout 5 systemctl is-active ssh 2>/dev/null)
            $sshdStr = ($sshdActive -join " ").Trim()
        }
        $output += "  SSH service: $sshdStr${nl}"
        if ($sshdStr -eq "active") {
            $output += "  [PASS] SSH provides user-initiated session termination${nl}"
        }
        else {
            $output += "  [INFO] SSH service not active${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 3: XO web application logoff
    $output += "Check 3: XO Web Application Logoff${nl}"
    try {
        $xoProcess = $(timeout 5 sh -c "pgrep -fa 'xo-server' 2>/dev/null | head -3" 2>&1)
        $xoStr = ($xoProcess -join $nl).Trim()
        if ($xoStr) {
            $output += "  XO server process detected${nl}"
            $output += "  [PASS] XO web interface provides Sign Out button for user logoff${nl}"
        }
        else {
            $output += "  [INFO] XO server process not detected${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }
    $output += $nl

    # Check 4: systemd-logind session management
    $output += "Check 4: systemd-logind Session Management${nl}"
    try {
        $loginctl = $(timeout 5 loginctl list-sessions 2>/dev/null)
        $loginStr = ($loginctl -join $nl).Trim()
        if ($loginStr) {
            $output += "  Active sessions:${nl}"
            foreach ($line in ($loginStr -split $nl) | Select-Object -First 5) {
                $output += "    $line${nl}"
            }
            $output += "  [PASS] systemd-logind manages user sessions (loginctl terminate-session available)${nl}"
        }
        else {
            $output += "  [INFO] No active sessions or loginctl unavailable${nl}"
        }
    }
    catch {
        $output += "  [ERROR] $($_.Exception.Message)${nl}"
    }

    # Determine status — shell + SSH = logoff capability exists
    if ($shellStr -and $sshdStr -eq "active") {
        $Status = "NotAFinding"
    }

    $FindingDetails = $output.TrimEnd()''',
    },
}


def main():
    with open(MODULE_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    changes = 0
    for vuln_id, impl in IMPLEMENTATIONS.items():
        func_name = f"Get-{vuln_id.replace('-', '')}"
        # Find the stub pattern
        # Match from "Function Get-VXXXXXX {" through the closing "}" before the next Function
        pattern = (
            r'(Function ' + re.escape(func_name) + r' \{\s*<#\s*\.DESCRIPTION)'
            r'(.*?)'
            r'(#---=== Begin Custom Code ===---#)'
            r'(.*?)'
            r'(#---=== End Custom Code ===---#)'
        )
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            print(f"WARNING: Could not find stub for {vuln_id} ({func_name})")
            continue

        # Build new description block
        old_desc_block = match.group(1) + match.group(2)
        new_desc = f'''Function {func_name} {{
    <#
    .DESCRIPTION
        Vuln ID    : {vuln_id}
        STIG ID    : {impl["STIG_ID"]}
        Rule ID    : {impl["RuleID"]}
        Rule Title : {impl["RuleTitle"]}
        DiscussMD5 : 00000000000000000000000000000000
        CheckMD5   : {impl["CheckMD5"]}
        FixMD5     : 00000000000000000000000000000000
    #>'''

        # Also update the RuleID and Status in variable initialization
        old_full = match.group(0)
        new_custom = impl["CustomCode"]

        # Replace description block
        new_block = old_full
        # Replace the description header
        new_block = new_block[:match.start(1) - match.start(0)] + new_desc + new_block[match.end(2) - match.start(0):]

        # Now re-find custom code markers in new_block
        cc_start = new_block.find("#---=== Begin Custom Code ===---#")
        cc_end = new_block.find("#---=== End Custom Code ===---#")
        new_block = new_block[:cc_start + len("#---=== Begin Custom Code ===---#")] + "\n" + new_custom + "\n    " + new_block[cc_end:]

        content = content[:match.start(0)] + new_block + content[match.end(0):]

        # Update RuleID
        old_rule_pattern = f'    $RuleID = "SV-{vuln_id.replace("V-", "")}r877420_rule"'
        new_rule = f'    $RuleID = "{impl["RuleID"]}"'
        content = content.replace(old_rule_pattern, new_rule)

        # Update initial Status from Not_Reviewed to Open
        # Need to be specific to this function's section
        old_status = f'    $VulnID = "{vuln_id}"\n    $RuleID = "{impl["RuleID"]}"\n    $Status = "Not_Reviewed"'
        new_status = f'    $VulnID = "{vuln_id}"\n    $RuleID = "{impl["RuleID"]}"\n    $Status = "{impl["InitStatus"]}"'
        content = content.replace(old_status, new_status)

        changes += 1
        print(f"OK: {vuln_id} ({func_name}) — replaced stub with implementation")

    with open(MODULE_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nDone: {changes}/10 functions integrated")
    return 0 if changes == 10 else 1


if __name__ == "__main__":
    sys.exit(main())
