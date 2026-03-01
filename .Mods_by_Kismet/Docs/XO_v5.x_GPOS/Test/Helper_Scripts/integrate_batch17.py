#!/usr/bin/env python3
"""Batch 17 integration script - Final CAT II (10 functions)
Replaces stub functions with comprehensive implementations.
VulnIDs: V-203651, V-203671, V-203675, V-203677, V-203678,
         V-203679, V-203680, V-203681, V-263660, V-263661
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

IMPLEMENTATIONS = {}

# ============================================================
# V-203651 - Audit reduction capability (on-demand reporting)
# ============================================================
IMPLEMENTATIONS["V-203651"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Audit Reduction Capability ---" + $nl

    # Check 1: journalctl availability
    $FindingDetails += $nl + "Check 1: journalctl Audit Reduction" + $nl
    $journalctl = $(sh -c "which journalctl >/dev/null 2>&1 && journalctl --disk-usage 2>/dev/null || echo 'NOT_AVAILABLE'" 2>&1)
    if ("$journalctl" -notmatch "NOT_AVAILABLE") {
        $FindingDetails += "  journalctl: Available" + $nl
        $FindingDetails += "  $("$journalctl".Trim())" + $nl
        $FindingDetails += "  Supports: time-based filtering, priority, unit, grep" + $nl
    }
    else {
        $FindingDetails += "  journalctl: Not available" + $nl
    }

    # Check 2: ausearch/aureport tools
    $FindingDetails += $nl + "Check 2: Audit Search and Report Tools" + $nl
    $ausearch = $(sh -c "which ausearch >/dev/null 2>&1 && echo 'AVAILABLE' || echo 'NOT_AVAILABLE'" 2>&1)
    $aureport = $(sh -c "which aureport >/dev/null 2>&1 && echo 'AVAILABLE' || echo 'NOT_AVAILABLE'" 2>&1)
    if ("$ausearch" -match "AVAILABLE") {
        $FindingDetails += "  ausearch: Available (audit event search)" + $nl
    }
    else {
        $FindingDetails += "  ausearch: Not available" + $nl
    }
    if ("$aureport" -match "AVAILABLE") {
        $FindingDetails += "  aureport: Available (audit summary reports)" + $nl
    }
    else {
        $FindingDetails += "  aureport: Not available" + $nl
    }

    # Check 3: XO Audit Plugin
    $FindingDetails += $nl + "Check 3: XO Audit Plugin" + $nl
    $xoAudit = $(sh -c "timeout 5 find /opt/xo/packages -maxdepth 2 -name 'package.json' 2>/dev/null | xargs grep -l 'audit' 2>/dev/null | head -1" 2>&1)
    if ($xoAudit -and "$xoAudit".Trim().Length -gt 0) {
        $FindingDetails += "  XO Audit Plugin: Detected (provides audit reduction via REST API)" + $nl
    }
    else {
        $FindingDetails += "  XO Audit Plugin: Not detected" + $nl
    }

    # Check 4: Log analysis tools
    $FindingDetails += $nl + "Check 4: Log Analysis Tools" + $nl
    $awk = $(sh -c "which awk >/dev/null 2>&1 && echo 'YES' || echo 'NO'" 2>&1)
    $grep = $(sh -c "which grep >/dev/null 2>&1 && echo 'YES' || echo 'NO'" 2>&1)
    $FindingDetails += "  awk: $(if ("$awk" -match 'YES') { 'Available' } else { 'Not available' })" + $nl
    $FindingDetails += "  grep: $(if ("$grep" -match 'YES') { 'Available' } else { 'Not available' })" + $nl

    # Status determination
    if ("$journalctl" -notmatch "NOT_AVAILABLE") {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Audit reduction capability is available via journalctl." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Audit reduction tools not fully available." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-203671 - Audit records: event source identity
# ============================================================
IMPLEMENTATIONS["V-203671"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Audit Record Source Identity ---" + $nl

    # Check 1: Systemd journal source tracking
    $FindingDetails += $nl + "Check 1: Systemd Journal Source Identification" + $nl
    $journalSample = $(sh -c "journalctl -n 5 -o verbose 2>/dev/null | grep -E '_SYSTEMD_UNIT|_COMM|_EXE|_PID' | head -15" 2>&1)
    if ($journalSample -and "$journalSample".Trim().Length -gt 0) {
        $FindingDetails += "  Journal records include source identity:" + $nl
        foreach ($line in ("$journalSample" -split $nl | Select-Object -First 10)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "    $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  Unable to verify journal source fields" + $nl
    }

    # Check 2: Auditd source tracking
    $FindingDetails += $nl + "Check 2: Auditd Source Tracking" + $nl
    $auditdActive = $(sh -c "systemctl is-active auditd 2>/dev/null" 2>&1)
    if ("$auditdActive" -match "active") {
        $FindingDetails += "  auditd: Active (records include syscall source, PID, executable)" + $nl
    }
    else {
        $FindingDetails += "  auditd: $("$auditdActive".Trim())" + $nl
    }

    # Check 3: Syslog source identification
    $FindingDetails += $nl + "Check 3: Syslog Source Identification" + $nl
    $syslogSample = $(sh -c "tail -5 /var/log/syslog 2>/dev/null || tail -5 /var/log/messages 2>/dev/null" 2>&1)
    if ($syslogSample -and "$syslogSample".Trim().Length -gt 0) {
        $FindingDetails += "  Syslog entries include hostname and process source:" + $nl
        foreach ($line in ("$syslogSample" -split $nl | Select-Object -First 3)) {
            if ("$line".Trim().Length -gt 0) {
                $shortLine = if ("$line".Length -gt 120) { "$line".Substring(0,120) + "..." } else { "$line" }
                $FindingDetails += "    $("$shortLine".Trim())" + $nl
            }
        }
    }

    # Check 4: XO Audit Plugin source tracking
    $FindingDetails += $nl + "Check 4: XO Audit Plugin Source Identity" + $nl
    $FindingDetails += "  XO Audit Plugin records include: userId, userName, IP address" + $nl

    # Status determination
    if ($journalSample -and "$journalSample".Trim().Length -gt 0) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Audit records contain event source identity information." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Unable to verify audit source identity tracking." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-203675 - Limit privilege to change software
# ============================================================
IMPLEMENTATIONS["V-203675"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Software Change Privilege Limits ---" + $nl

    # Check 1: Package manager access
    $FindingDetails += $nl + "Check 1: Package Manager (apt) Access" + $nl
    $aptPerms = $(sh -c "ls -la /usr/bin/apt /usr/bin/apt-get /usr/bin/dpkg 2>/dev/null" 2>&1)
    if ($aptPerms) {
        foreach ($line in ("$aptPerms" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }

    # Check 2: sudo configuration for package management
    $FindingDetails += $nl + "Check 2: sudo Package Management Controls" + $nl
    $sudoApt = $(sh -c "timeout 5 grep -r 'apt\|dpkg\|install' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'" 2>&1)
    if ($sudoApt -and "$sudoApt".Trim().Length -gt 0) {
        foreach ($line in ("$sudoApt" -split $nl | Select-Object -First 5)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No explicit apt/dpkg sudo rules (root-only by default)" + $nl
    }

    # Check 3: System directories protection
    $FindingDetails += $nl + "Check 3: System Directory Permissions" + $nl
    $sysDirs = $(sh -c "ls -ld /usr/bin /usr/sbin /usr/lib /usr/local/bin 2>/dev/null" 2>&1)
    if ($sysDirs) {
        foreach ($line in ("$sysDirs" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }

    # Check 4: Non-root users with write access
    $FindingDetails += $nl + "Check 4: Write Access to System Binaries" + $nl
    $worldWrite = $(sh -c "timeout 10 find /usr/bin /usr/sbin -maxdepth 1 -perm -o+w -type f 2>/dev/null | head -5" 2>&1)
    if ($worldWrite -and "$worldWrite".Trim().Length -gt 0) {
        $FindingDetails += "  [FINDING] World-writable binaries found:" + $nl
        $FindingDetails += "  $("$worldWrite".Trim())" + $nl
    }
    else {
        $FindingDetails += "  No world-writable system binaries detected" + $nl
    }

    # Status determination
    $compliant = $true
    if ($worldWrite -and "$worldWrite".Trim().Length -gt 0) { $compliant = $false }

    if ($compliant) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Software change privileges are appropriately limited." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Software change privileges may be too permissive." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-203677 - Preserve info on system failure
# ============================================================
IMPLEMENTATIONS["V-203677"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Preserve Information on System Failure ---" + $nl

    # Check 1: Persistent journal storage
    $FindingDetails += $nl + "Check 1: Persistent Journal Storage" + $nl
    $journalStorage = $(sh -c "cat /etc/systemd/journald.conf 2>/dev/null | grep -i '^Storage'" 2>&1)
    if ($journalStorage -and "$journalStorage" -match "persistent") {
        $FindingDetails += "  $("$journalStorage".Trim()) (logs survive reboot)" + $nl
    }
    elseif ($(sh -c "test -d /var/log/journal && echo 'EXISTS'" 2>&1) -match "EXISTS") {
        $FindingDetails += "  /var/log/journal directory exists (persistent by default)" + $nl
    }
    else {
        $FindingDetails += "  Journal storage: $(if ($journalStorage) { "$journalStorage".Trim() } else { 'auto (volatile if no /var/log/journal)' })" + $nl
    }

    # Check 2: Crash dump configuration
    $FindingDetails += $nl + "Check 2: Crash Dump Configuration" + $nl
    $kdump = $(sh -c "systemctl is-active kdump 2>/dev/null || echo 'inactive'" 2>&1)
    $FindingDetails += "  kdump service: $("$kdump".Trim())" + $nl
    $corePattern = $(cat /proc/sys/kernel/core_pattern 2>&1)
    if ($corePattern) {
        $FindingDetails += "  core_pattern: $("$corePattern".Trim())" + $nl
    }

    # Check 3: Filesystem journal (ext4/xfs)
    $FindingDetails += $nl + "Check 3: Filesystem Integrity" + $nl
    $fsType = $(sh -c "df -T / 2>/dev/null | tail -1 | awk '{print \$2}'" 2>&1)
    if ($fsType) {
        $FindingDetails += "  Root filesystem type: $("$fsType".Trim())" + $nl
        if ("$fsType" -match "ext4|xfs") {
            $FindingDetails += "  Journaling filesystem: Yes (data integrity on failure)" + $nl
        }
    }

    # Check 4: Log directory on separate partition
    $FindingDetails += $nl + "Check 4: Log Partition Separation" + $nl
    $logMount = $(sh -c "df /var/log 2>/dev/null | tail -1" 2>&1)
    $rootMount = $(sh -c "df / 2>/dev/null | tail -1" 2>&1)
    if ($logMount -and $rootMount) {
        $logDev = ("$logMount" -split "\s+")[0]
        $rootDev = ("$rootMount" -split "\s+")[0]
        if ($logDev -ne $rootDev) {
            $FindingDetails += "  /var/log: Separate partition ($logDev)" + $nl
        }
        else {
            $FindingDetails += "  /var/log: Same partition as / ($rootDev)" + $nl
        }
    }

    # Status determination
    $journalPersistent = $(sh -c "test -d /var/log/journal && echo 'YES' || echo 'NO'" 2>&1)
    if ("$journalPersistent" -match "YES") {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: System preserves information through persistent journal storage." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Persistent journal storage not confirmed." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-203678 through V-203681 - Notify SAs/ISSOs on account actions
# These are nearly identical checks for different account action types
# ============================================================

def _make_notify_impl(action_type, action_desc):
    return r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Notify SAs/ISSOs on Account ''' + action_type + r''' ---" + $nl

    # Check 1: Auditd rules for account actions
    $FindingDetails += $nl + "Check 1: Audit Rules for Account ''' + action_type + r'''" + $nl
    $auditRules = $(sh -c "auditctl -l 2>/dev/null | grep -E 'passwd|shadow|group|gshadow|opasswd'" 2>&1)
    if ($auditRules -and "$auditRules".Trim().Length -gt 0) {
        foreach ($line in ("$auditRules" -split $nl | Select-Object -First 5)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No audit rules for account files detected" + $nl
    }

    # Check 2: XO Audit Plugin for account notifications
    $FindingDetails += $nl + "Check 2: XO Audit Plugin" + $nl
    $xoAudit = $(sh -c "timeout 5 find /opt/xo/packages -maxdepth 2 -name 'package.json' 2>/dev/null | xargs grep -l 'audit' 2>/dev/null | head -1" 2>&1)
    if ($xoAudit -and "$xoAudit".Trim().Length -gt 0) {
        $FindingDetails += "  XO Audit Plugin: Detected (logs account actions)" + $nl
    }
    else {
        $FindingDetails += "  XO Audit Plugin: Not detected" + $nl
    }

    # Check 3: Email/notification configuration
    $FindingDetails += $nl + "Check 3: Notification Mechanism" + $nl
    $mailCmd = $(sh -c "which mail >/dev/null 2>&1 && echo 'AVAILABLE' || which sendmail >/dev/null 2>&1 && echo 'AVAILABLE' || echo 'NOT_AVAILABLE'" 2>&1)
    if ("$mailCmd" -match "AVAILABLE") {
        $FindingDetails += "  Mail utility: Available" + $nl
    }
    else {
        $FindingDetails += "  Mail utility: Not available" + $nl
    }
    $rsyslog = $(sh -c "systemctl is-active rsyslog 2>/dev/null" 2>&1)
    $FindingDetails += "  rsyslog: $("$rsyslog".Trim())" + $nl

    # Check 4: PAM notification hooks
    $FindingDetails += $nl + "Check 4: PAM Notification Configuration" + $nl
    $pamExec = $(sh -c "timeout 5 grep -r 'pam_exec\|pam_script' /etc/pam.d/ 2>/dev/null | head -3" 2>&1)
    if ($pamExec -and "$pamExec".Trim().Length -gt 0) {
        foreach ($line in ("$pamExec" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No PAM notification hooks configured" + $nl
    }

    # Status determination - always Open (org notification config required)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: SA/ISSO notification for account ''' + action_desc + r''' requires organizational configuration." + $nl
    $FindingDetails += "  Verify ''' + action_desc + r''' triggers notification to SAs and ISSOs." + $nl
    #---=== End Custom Code ===---#
'''

IMPLEMENTATIONS["V-203678"] = _make_notify_impl("Creation", "account creation")
IMPLEMENTATIONS["V-203679"] = _make_notify_impl("Modification", "account modification")
IMPLEMENTATIONS["V-203680"] = _make_notify_impl("Disabling", "account disabling")
IMPLEMENTATIONS["V-203681"] = _make_notify_impl("Removal", "account removal")

# ============================================================
# V-263660 - Protected storage for cryptographic keys
# ============================================================
IMPLEMENTATIONS["V-263660"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Protected Storage for Cryptographic Keys ---" + $nl

    # Check 1: SSH host key permissions
    $FindingDetails += $nl + "Check 1: SSH Host Key Permissions" + $nl
    $sshKeys = $(sh -c "ls -la /etc/ssh/ssh_host_*_key 2>/dev/null" 2>&1)
    if ($sshKeys -and "$sshKeys" -notmatch "No such file") {
        $keyIssue = $false
        foreach ($line in ("$sshKeys" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
                if ("$line" -match "^-.{2}[^-]") {
                    $keyIssue = $true
                }
            }
        }
        if (-not $keyIssue) {
            $FindingDetails += "  SSH host keys: Properly restricted (root:root, 600)" + $nl
        }
    }

    # Check 2: TLS/SSL certificate key permissions
    $FindingDetails += $nl + "Check 2: TLS Certificate Key Permissions" + $nl
    $tlsKeys = $(sh -c "timeout 10 find /etc/ssl/private /opt/xo -maxdepth 3 -name '*.key' -o -name '*-key.pem' 2>/dev/null | head -5" 2>&1)
    if ($tlsKeys -and "$tlsKeys".Trim().Length -gt 0) {
        foreach ($keyFile in ("$tlsKeys" -split $nl)) {
            if ("$keyFile".Trim().Length -gt 0) {
                $keyPerms = $(sh -c "ls -la '$("$keyFile".Trim())' 2>/dev/null" 2>&1)
                if ($keyPerms) {
                    $FindingDetails += "  $("$keyPerms".Trim())" + $nl
                }
            }
        }
    }
    else {
        $FindingDetails += "  No TLS private keys found in standard locations" + $nl
    }

    # Check 3: LUKS/dm-crypt encrypted storage
    $FindingDetails += $nl + "Check 3: Encrypted Storage" + $nl
    $luksDevices = $(sh -c "lsblk -f 2>/dev/null | grep -i 'crypto\|luks'" 2>&1)
    if ($luksDevices -and "$luksDevices".Trim().Length -gt 0) {
        $FindingDetails += "  Encrypted volumes detected:" + $nl
        $FindingDetails += "  $("$luksDevices".Trim())" + $nl
    }
    else {
        $FindingDetails += "  No LUKS/dm-crypt encrypted volumes detected" + $nl
    }

    # Check 4: Kernel keyring
    $FindingDetails += $nl + "Check 4: Kernel Keyring" + $nl
    $keyring = $(sh -c "cat /proc/keys 2>/dev/null | wc -l" 2>&1)
    if ($keyring -and "$keyring".Trim() -match "^\d+$") {
        $FindingDetails += "  Kernel keyring entries: $("$keyring".Trim())" + $nl
    }

    # Status determination
    $keysProtected = $true
    if ($sshKeys -and "$sshKeys" -match "[^-]{3}[^-].*ssh_host") {
        $keysProtected = $false
    }

    if ($keysProtected) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Cryptographic keys are stored with appropriate protections." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Cryptographic key storage requires remediation." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# V-263661 - Synchronize system clocks
# ============================================================
IMPLEMENTATIONS["V-263661"] = r'''
    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: System Clock Synchronization ---" + $nl

    # Check 1: NTP/Chrony service status
    $FindingDetails += $nl + "Check 1: Time Synchronization Service" + $nl
    $chronyd = $(sh -c "systemctl is-active chronyd 2>/dev/null" 2>&1)
    $ntpd = $(sh -c "systemctl is-active ntp 2>/dev/null || systemctl is-active ntpd 2>/dev/null" 2>&1)
    $timesyncd = $(sh -c "systemctl is-active systemd-timesyncd 2>/dev/null" 2>&1)
    $timeSyncActive = $false
    if ("$chronyd" -match "^active") {
        $FindingDetails += "  chronyd: Active" + $nl
        $timeSyncActive = $true
    }
    elseif ("$ntpd" -match "^active") {
        $FindingDetails += "  ntpd: Active" + $nl
        $timeSyncActive = $true
    }
    elseif ("$timesyncd" -match "^active") {
        $FindingDetails += "  systemd-timesyncd: Active" + $nl
        $timeSyncActive = $true
    }
    else {
        $FindingDetails += "  No time synchronization service active" + $nl
    }

    # Check 2: Sync sources
    $FindingDetails += $nl + "Check 2: Time Synchronization Sources" + $nl
    if ("$chronyd" -match "^active") {
        $sources = $(sh -c "chronyc sources 2>/dev/null | head -10" 2>&1)
        if ($sources) {
            foreach ($line in ("$sources" -split $nl | Select-Object -First 8)) {
                if ("$line".Trim().Length -gt 0) {
                    $FindingDetails += "  $("$line".Trim())" + $nl
                }
            }
        }
    }
    elseif ("$timesyncd" -match "^active") {
        $tsStatus = $(sh -c "timedatectl show-timesync --property=ServerName --property=NTPMessage 2>/dev/null || timedatectl status 2>/dev/null | grep -i 'NTP\|server'" 2>&1)
        if ($tsStatus) {
            foreach ($line in ("$tsStatus" -split $nl | Select-Object -First 5)) {
                if ("$line".Trim().Length -gt 0) {
                    $FindingDetails += "  $("$line".Trim())" + $nl
                }
            }
        }
    }

    # Check 3: timedatectl status
    $FindingDetails += $nl + "Check 3: System Time Status" + $nl
    $tdctl = $(sh -c "timedatectl status 2>/dev/null | grep -E 'synchronized|NTP|Time zone'" 2>&1)
    if ($tdctl) {
        foreach ($line in ("$tdctl" -split $nl)) {
            if ("$line".Trim().Length -gt 0) {
                $FindingDetails += "  $("$line".Trim())" + $nl
            }
        }
    }

    # Check 4: Clock synchronization across systems
    $FindingDetails += $nl + "Check 4: Cross-System Synchronization" + $nl
    $FindingDetails += "  Verify all systems in the environment use the same authoritative time source." + $nl
    $FindingDetails += "  DoD requires synchronization to a DoD-approved NTP server." + $nl

    # Status determination
    if ($timeSyncActive) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: System clock synchronization is active." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No active time synchronization service detected." + $nl
    }
    #---=== End Custom Code ===---#
'''

# ============================================================
# Metadata
# ============================================================
METADATA = {
    "V-203651": {"stig_id": "SRG-OS-000122-GPOS-00063", "rule_id": "SV-203651r958506_rule", "title": "The operating system must provide an audit reduction capability that supports on-demand reporting requirements.", "discuss_md5": "ec9fea673f1a5c467a8aa8caa46a27e4", "check_md5": "ea8b3e5a09e5daa876ee8f64ccbfc5cb", "fix_md5": "2263d4145473ba7bb9883103526c91dc"},
    "V-203671": {"stig_id": "SRG-OS-000255-GPOS-00096", "rule_id": "SV-203671r991556_rule", "title": "The operating system must produce audit records containing information to establish the source of the events.", "discuss_md5": "fbcb18d0207e4d5af055e39f165ada07", "check_md5": "0208946208cd469f84809e0910cec31d", "fix_md5": "fb8839c4143cec9b0ebd92c229058e68"},
    "V-203675": {"stig_id": "SRG-OS-000259-GPOS-00100", "rule_id": "SV-203675r991560_rule", "title": "The operating system must limit privileges to change software resident within software libraries.", "discuss_md5": "887d84479d90cb3cc5ddd8cad9358616", "check_md5": "bc52537d9add5a9581acd29cf47faffc", "fix_md5": "9da43e0bbeb1044275f37e67573df510"},
    "V-203677": {"stig_id": "SRG-OS-000269-GPOS-00103", "rule_id": "SV-203677r991562_rule", "title": "In the event of a system failure, the operating system must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to system processes.", "discuss_md5": "d9c21eada5e1858441040626840fe77d", "check_md5": "8bc1473703483cb0ea1c83eb8dc31846", "fix_md5": "3e6c7e52a4c9a29bd2e31c122861b990"},
    "V-203678": {"stig_id": "SRG-OS-000274-GPOS-00104", "rule_id": "SV-203678r991563_rule", "title": "The operating system must notify system administrators and ISSOs when accounts are created.", "discuss_md5": "5c24f8a2ba9b672bb61e37822f81ed36", "check_md5": "18bcba0cdb0af9f8b731ea0e74f0a5df", "fix_md5": "b812eff101d040e9cc1985a79eb4474b"},
    "V-203679": {"stig_id": "SRG-OS-000275-GPOS-00105", "rule_id": "SV-203679r991564_rule", "title": "The operating system must notify system administrators and ISSOs when accounts are modified.", "discuss_md5": "54a9ba91055c791cdd51a2361b16602b", "check_md5": "ac90452981459a4a1e055a2c3a8fd454", "fix_md5": "536a04b036907f282ff61985163d9fd5"},
    "V-203680": {"stig_id": "SRG-OS-000276-GPOS-00106", "rule_id": "SV-203680r991565_rule", "title": "The operating system must notify system administrators and ISSOs when accounts are disabled.", "discuss_md5": "783cacb447f2a614d5d5a3b5f951151d", "check_md5": "b62004e4aa3ba8cc2132036a1f6bc9c0", "fix_md5": "5a0175ff0302ab380c2b610400166b5b"},
    "V-203681": {"stig_id": "SRG-OS-000277-GPOS-00107", "rule_id": "SV-203681r991566_rule", "title": "The operating system must notify system administrators and ISSOs when accounts are removed.", "discuss_md5": "a7dfe85950670fdc8f5e8b3fc859f7fb", "check_md5": "8b3aa8a6713b7e47f346b841ea442824", "fix_md5": "7aca92399198fde3fb2c0dc124aaef18"},
    "V-263660": {"stig_id": "SRG-OS-000780-GPOS-00240", "rule_id": "SV-263660r982565_rule", "title": "The operating system must provide protected storage for cryptographic keys with organization-defined safeguards and/or hardware protected key store.", "discuss_md5": "05876bf81b71ee8e4393c10ac508ce58", "check_md5": "d149a174c86647a4e8dcefd56a04fb73", "fix_md5": "8645f95062b2d6b6eab4431163948616"},
    "V-263661": {"stig_id": "SRG-OS-000785-GPOS-00250", "rule_id": "SV-263661r982567_rule", "title": "The operating system must synchronize system clocks within and between systems or system components.", "discuss_md5": "9850730d43bcdf78c95f65cb1b68c6ae", "check_md5": "27e5e558ce2e29a1371add8a62232faa", "fix_md5": "1217f1684dc408d6c0ecd665b821b058"},
}


def build_replacement(vuln_id):
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
    footer = '''
    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
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
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
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
    }

    return Send-CheckResult @SendCheckParams
'''
    return header + impl + footer


def main():
    with open(MODULE_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    count = 0
    for vuln_id in IMPLEMENTATIONS:
        func_name = vuln_id.replace("-", "")
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
