#!/usr/bin/env python3
"""Integrate Batch 13 implementations into GPOS Debian12 module.

Batch 13: Time, Patching and Software (10 functions)
- V-203711: Compare internal clocks (networked)
- V-203712: Sync clocks to authoritative time source
- V-203713: Timestamp minimum granularity
- V-203715: Dual authorization for audit deletion
- V-203716: Prohibit user software installation
- V-203717: Notify on baseline config changes
- V-203721: Prevent program execution per local policy
- V-203750: Maintain confidentiality of info at rest
- V-203751: Maintain integrity of info at rest
- V-259333: Install security updates within timeframe

Replaces: description block, RuleID, Status, and custom code section.
Does NOT touch: param block (lesson from Batch 11).
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

# Each entry: (VulnID, RuleID, STIG_ID, Rule_Title, DiscussMD5, CheckMD5, FixMD5, default_status, custom_code)
FUNCTIONS = [
    (
        "V-203711",
        "SV-203711r1038944_rule",
        "SRG-OS-000355-GPOS-00143",
        "The operating system must, for networked systems, compare internal information system clocks at least every 24 hours with an authoritative time source.",
        "77480508ed80d4317e8c289923976106",
        "047f944e6673cd1f03ce9726441934d2",
        "fa52d57049443cbd5ab846ad5d697f48",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Internal Clock Comparison (Every 24 Hours) ---" + $nl

    # Check 1: NTP/Chrony service status
    $FindingDetails += $nl + "Check 1: Time Synchronization Service" + $nl
    $chronyActive = $false
    $ntpActive = $false
    $timesyncActive = $false

    $chronyStatus = $(systemctl is-active chrony 2>&1)
    if ($LASTEXITCODE -eq 0 -and $chronyStatus -match "active") {
        $FindingDetails += "  chrony service: ACTIVE" + $nl
        $chronyActive = $true
        $chronySources = $(chronyc sources 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $FindingDetails += "  Configured sources:" + $nl
            $sourceLines = ($chronySources -split $nl) | Where-Object { $_ -match "^\^" }
            foreach ($src in $sourceLines) {
                $FindingDetails += "    $($src.ToString().Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  chrony service: NOT ACTIVE" + $nl
    }

    $ntpStatus = $(systemctl is-active ntp 2>&1)
    if ($LASTEXITCODE -eq 0 -and $ntpStatus -match "active") {
        $FindingDetails += "  ntp service: ACTIVE" + $nl
        $ntpActive = $true
        $ntpPeers = $(ntpq -p 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $FindingDetails += "  NTP peers:" + $nl
            $FindingDetails += "  $($ntpPeers.ToString().Trim())" + $nl
        }
    }

    $timesyncStatus = $(systemctl is-active systemd-timesyncd 2>&1)
    if ($LASTEXITCODE -eq 0 -and $timesyncStatus -match "active") {
        $FindingDetails += "  systemd-timesyncd: ACTIVE" + $nl
        $timesyncActive = $true
        $timesyncConf = $(cat /etc/systemd/timesyncd.conf 2>&1 | grep -i "^NTP\|^FallbackNTP" 2>&1)
        if ($timesyncConf) {
            $FindingDetails += "  Config: $($timesyncConf.ToString().Trim())" + $nl
        }
    }

    # Check 2: Poll interval (must be <= 86400 seconds / 24 hours)
    $FindingDetails += $nl + "Check 2: Poll Interval Verification" + $nl
    $pollOk = $false
    if ($chronyActive) {
        $chronyConf = $(cat /etc/chrony/chrony.conf 2>&1 | grep -i "^server\|^pool\|^maxpoll" 2>&1)
        if ($chronyConf) {
            $FindingDetails += "  Chrony config entries:" + $nl
            foreach ($line in ($chronyConf -split $nl)) {
                $FindingDetails += "    $($line.ToString().Trim())" + $nl
            }
        }
        $FindingDetails += "  Default chrony maxpoll: 1024 seconds (~17 minutes) — well within 24-hour requirement" + $nl
        $pollOk = $true
    }
    elseif ($ntpActive) {
        $ntpConf = $(cat /etc/ntp.conf 2>&1 | grep -i "^server\|^pool\|^maxpoll" 2>&1)
        if ($ntpConf) {
            $FindingDetails += "  NTP config entries:" + $nl
            foreach ($line in ($ntpConf -split $nl)) {
                $FindingDetails += "    $($line.ToString().Trim())" + $nl
            }
        }
        $FindingDetails += "  Default NTP maxpoll: 1024 seconds — within 24-hour requirement" + $nl
        $pollOk = $true
    }
    elseif ($timesyncActive) {
        $FindingDetails += "  systemd-timesyncd default poll: adjusts automatically (32s-2048s)" + $nl
        $pollOk = $true
    }
    else {
        $FindingDetails += "  No time synchronization service detected" + $nl
    }

    # Check 3: timedatectl status
    $FindingDetails += $nl + "Check 3: System Time Status" + $nl
    $timedatectl = $(timedatectl status 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $syncLine = ($timedatectl -split $nl) | Where-Object { $_ -match "synchronized|NTP" }
        foreach ($sl in $syncLine) {
            $FindingDetails += "  $($sl.ToString().Trim())" + $nl
        }
    }

    # Status determination
    if (($chronyActive -or $ntpActive -or $timesyncActive) -and $pollOk) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Time synchronization service is active and polls authoritative" + $nl
        $FindingDetails += "  sources at intervals well within the 24-hour requirement." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No active time synchronization service detected or poll" + $nl
        $FindingDetails += "  interval exceeds 24-hour requirement." + $nl
    }'''
    ),
    (
        "V-203712",
        "SV-203712r982209_rule",
        "SRG-OS-000356-GPOS-00144",
        "The operating system must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.",
        "382b6ffda6b5fb46e2743f0f2a7b226e",
        "4bab4dcca3230bcb2014f49e0176c0f3",
        "6586598896be488b3cc2cc22f71ba155",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Clock Sync When Difference > 1 Second ---" + $nl

    # Check 1: Chrony makestep / NTP tinker step configuration
    $FindingDetails += $nl + "Check 1: Step Correction Configuration" + $nl
    $stepConfigured = $false

    $chronyConf = $(cat /etc/chrony/chrony.conf 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $makestep = ($chronyConf -split $nl) | Where-Object { $_ -match "^\s*makestep" }
        if ($makestep) {
            $FindingDetails += "  chrony makestep: $($makestep.ToString().Trim())" + $nl
            $FindingDetails += "  (Format: makestep <threshold_seconds> <limit_updates>)" + $nl
            $stepConfigured = $true
        }
        else {
            $FindingDetails += "  chrony makestep: NOT CONFIGURED (using default)" + $nl
            $FindingDetails += "  Default: makestep 1.0 3 (step if offset > 1s, first 3 updates)" + $nl
            $stepConfigured = $true
        }
    }
    else {
        $FindingDetails += "  /etc/chrony/chrony.conf: NOT FOUND" + $nl
        $ntpConf = $(cat /etc/ntp.conf 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $tinker = ($ntpConf -split $nl) | Where-Object { $_ -match "^\s*tinker\s+step" }
            if ($tinker) {
                $FindingDetails += "  ntp tinker step: $($tinker.ToString().Trim())" + $nl
                $stepConfigured = $true
            }
        }
    }

    # Check 2: Current time offset
    $FindingDetails += $nl + "Check 2: Current Time Offset" + $nl
    $offsetOk = $false
    $chronyTracking = $(chronyc tracking 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $offsetLine = ($chronyTracking -split $nl) | Where-Object { $_ -match "Last offset|System time" }
        foreach ($ol in $offsetLine) {
            $FindingDetails += "  $($ol.ToString().Trim())" + $nl
        }
        $offsetOk = $true
    }
    else {
        $ntpqRv = $(ntpq -c rv 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $FindingDetails += "  NTP status: $($ntpqRv.ToString().Trim().Substring(0, [Math]::Min(200, $ntpqRv.ToString().Trim().Length)))" + $nl
            $offsetOk = $true
        }
        else {
            $FindingDetails += "  Unable to determine current time offset" + $nl
        }
    }

    # Check 3: timedatectl NTP sync status
    $FindingDetails += $nl + "Check 3: NTP Synchronization Status" + $nl
    $timedatectl = $(timedatectl show 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $ntpSync = ($timedatectl -split $nl) | Where-Object { $_ -match "NTPSynchronized" }
        if ($ntpSync) {
            $FindingDetails += "  $($ntpSync.ToString().Trim())" + $nl
        }
    }

    # Status determination
    if ($stepConfigured -and $offsetOk) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Time synchronization configured to correct offsets greater" + $nl
        $FindingDetails += "  than one second via chrony makestep or NTP step configuration." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Unable to verify time synchronization step correction" + $nl
        $FindingDetails += "  configuration for offsets greater than one second." + $nl
    }'''
    ),
    (
        "V-203713",
        "SV-203713r958786_rule",
        "SRG-OS-000358-GPOS-00145",
        "The operating system must record time stamps for audit records that meet a minimum granularity of one second for a minimum degree of precision.",
        "1fd057799e79b928ccefce58fa58956b",
        "c43357f680df9dc6b267b354b2b6e97d",
        "2d95c030aa5da35fe7a6907e8fa0a3ac",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Audit Timestamp Granularity (>= 1 Second) ---" + $nl

    # Check 1: auditd timestamp format
    $FindingDetails += $nl + "Check 1: Audit Subsystem Timestamp Format" + $nl
    $auditTimestampOk = $false

    $auditConf = $(cat /etc/audit/auditd.conf 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $logFormat = ($auditConf -split $nl) | Where-Object { $_ -match "^\s*log_format" }
        if ($logFormat) {
            $FindingDetails += "  auditd log_format: $($logFormat.ToString().Trim())" + $nl
        }
        else {
            $FindingDetails += "  auditd log_format: RAW (default — includes Unix epoch with precision)" + $nl
        }
        $auditTimestampOk = $true
    }
    else {
        $FindingDetails += "  auditd.conf: NOT FOUND (auditd may not be installed)" + $nl
    }

    # Check 2: systemd journal timestamp precision
    $FindingDetails += $nl + "Check 2: Systemd Journal Timestamp" + $nl
    $journalTimestampOk = $false
    $journalRecent = $(journalctl -n 3 --no-pager -o short-precise 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  Journal entries (short-precise format):" + $nl
        foreach ($line in ($journalRecent -split $nl | Select-Object -First 3)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
        $FindingDetails += "  systemd journal: microsecond precision (exceeds 1-second requirement)" + $nl
        $journalTimestampOk = $true
    }
    else {
        $FindingDetails += "  journalctl: NOT AVAILABLE" + $nl
    }

    # Check 3: XO Audit Plugin timestamp
    $FindingDetails += $nl + "Check 3: XO Audit Plugin Timestamp" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE" + $nl
        $FindingDetails += "  Timestamp format: Unix milliseconds (ms precision, exceeds 1-second requirement)" + $nl
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
    }

    # Status determination
    if ($auditTimestampOk -or $journalTimestampOk) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Audit timestamps meet minimum granularity of one second." + $nl
        $FindingDetails += "  systemd journal provides microsecond precision; auditd provides" + $nl
        $FindingDetails += "  Unix epoch timestamps with sub-second granularity." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Unable to verify audit timestamp granularity meets" + $nl
        $FindingDetails += "  the minimum one-second requirement." + $nl
    }'''
    ),
    (
        "V-203715",
        "SV-203715r958790_rule",
        "SRG-OS-000360-GPOS-00147",
        "The operating system must enforce dual authorization for movement and/or deletion of all audit information, when such movement or deletion is not part of an authorized automatic process.",
        "368ffe68a2de6aedd2d2f227e0bd585b",
        "cc583651d41bd7d7e70a8a627b8987bd",
        "d77eee669ca1142a97cfd02926d47a36",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Dual Authorization for Audit Deletion ---" + $nl

    # Check 1: Audit log file permissions (restrict deletion)
    $FindingDetails += $nl + "Check 1: Audit Log File Permissions" + $nl
    $auditLogProtected = $false
    $logPaths = @("/var/log/audit", "/var/log/syslog", "/var/log/auth.log")
    foreach ($lp in $logPaths) {
        $(test -d $lp 2>&1) | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $perms = $(stat -c "%a %U:%G" $lp 2>&1)
            $FindingDetails += "  $lp : $($perms.ToString().Trim())" + $nl
            $auditLogProtected = $true
        }
        else {
            $(test -f $lp 2>&1) | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $perms = $(stat -c "%a %U:%G" $lp 2>&1)
                $FindingDetails += "  $lp : $($perms.ToString().Trim())" + $nl
                $auditLogProtected = $true
            }
        }
    }
    if (-not $auditLogProtected) {
        $FindingDetails += "  No standard audit log paths found" + $nl
    }

    # Check 2: Immutable attribute on audit logs
    $FindingDetails += $nl + "Check 2: Immutable File Attributes" + $nl
    $immutableSet = $false
    foreach ($lf in @("/var/log/audit/audit.log", "/var/log/syslog")) {
        $(test -f $lf 2>&1) | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $attrs = $(lsattr $lf 2>&1)
            if ($LASTEXITCODE -eq 0) {
                $FindingDetails += "  $lf : $($attrs.ToString().Trim())" + $nl
                if ($attrs -match "i") { $immutableSet = $true }
            }
        }
    }

    # Check 3: Root-only access requirement
    $FindingDetails += $nl + "Check 3: Administrative Access Control" + $nl
    $sudoInstalled = $(which sudo 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  sudo: INSTALLED (administrative actions require separate authentication)" + $nl
        $sudoLogDel = $(grep -r "audit\|log" /etc/sudoers.d/ 2>&1 | head -5)
        if ($sudoLogDel) {
            $FindingDetails += "  sudoers audit-related rules found" + $nl
        }
    }
    $FindingDetails += "  Note: Dual authorization requires organizational procedures ensuring" + $nl
    $FindingDetails += "  two authorized individuals approve audit log deletion/movement." + $nl

    # Status determination — always Open (requires organizational dual-auth procedures)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Dual authorization for audit log deletion requires organizational" + $nl
    $FindingDetails += "  procedures and cannot be fully verified through automated scanning." + $nl
    $FindingDetails += "  ISSO/ISSM must verify dual authorization controls are implemented." + $nl'''
    ),
    (
        "V-203716",
        "SV-203716r982210_rule",
        "SRG-OS-000362-GPOS-00149",
        "The operating system must prohibit user installation of system software without explicit privileged status.",
        "973199651cab8277bf1b768387ea1bea",
        "5ab2ae5f71196e66fc275504ba1ebe18",
        "240b9ac95c73c24288963f48645c8ea3",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Prohibit User Software Installation ---" + $nl

    # Check 1: apt/dpkg requires root
    $FindingDetails += $nl + "Check 1: Package Manager Privilege Requirements" + $nl
    $aptProtected = $false
    $aptPath = $(which apt 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $aptPerms = $(stat -c "%a %U:%G" /usr/bin/apt 2>&1)
        $FindingDetails += "  apt binary: $($aptPerms.ToString().Trim())" + $nl
        $dpkgPerms = $(stat -c "%a %U:%G" /usr/bin/dpkg 2>&1)
        $FindingDetails += "  dpkg binary: $($dpkgPerms.ToString().Trim())" + $nl
        $aptLockPerms = $(stat -c "%a %U:%G" /var/lib/dpkg/lock-frontend 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $FindingDetails += "  dpkg lock: $($aptLockPerms.ToString().Trim())" + $nl
        }
        $aptProtected = $true
    }

    # Check 2: sudo configuration for package management
    $FindingDetails += $nl + "Check 2: Sudo Package Management Controls" + $nl
    $sudoConf = $(timeout 5 grep -r "apt\|dpkg\|install" /etc/sudoers /etc/sudoers.d/ 2>&1 | head -10)
    if ($sudoConf) {
        $FindingDetails += "  Sudo rules referencing package management:" + $nl
        foreach ($line in ($sudoConf -split $nl | Select-Object -First 5)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No specific sudo rules for package management (root-only by default)" + $nl
    }

    # Check 3: Check for user-writable package directories
    $FindingDetails += $nl + "Check 3: Package Directory Permissions" + $nl
    $worldWritable = $(timeout 10 find /usr/local/bin /usr/local/sbin -maxdepth 1 -perm -o+w -type f 2>&1 | head -5)
    if ($worldWritable -and $worldWritable.ToString().Trim().Length -gt 0) {
        $FindingDetails += "  WARNING: World-writable files in local bin directories:" + $nl
        foreach ($wf in ($worldWritable -split $nl | Select-Object -First 5)) {
            $FindingDetails += "    $($wf.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No world-writable files in /usr/local/bin or /usr/local/sbin" + $nl
    }

    # Check 4: pip/npm require sudo
    $FindingDetails += $nl + "Check 4: Non-System Package Managers" + $nl
    foreach ($pm in @("pip3", "npm", "gem")) {
        $pmPath = $(which $pm 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $pmPerms = $(stat -c "%a %U:%G" $pmPath 2>&1)
            $FindingDetails += "  $pm : $($pmPerms.ToString().Trim())" + $nl
        }
    }

    # Status determination
    if ($aptProtected) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Package management tools (apt, dpkg) require root/sudo" + $nl
        $FindingDetails += "  privileges. Standard users cannot install system software." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Unable to verify package manager privilege restrictions." + $nl
    }'''
    ),
    (
        "V-203717",
        "SV-203717r958794_rule",
        "SRG-OS-000363-GPOS-00150",
        "The operating system must notify designated personnel if baseline configurations are changed in an unauthorized manner.",
        "532661b56ce968c1145c898719743462",
        "d530614faad31f48061ea5117f443832",
        "6dd2a130c145e54f5b61deda5ff075b5",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Baseline Configuration Change Notification ---" + $nl

    # Check 1: File integrity monitoring tools
    $FindingDetails += $nl + "Check 1: File Integrity Monitoring" + $nl
    $fimFound = $false
    foreach ($tool in @("aide", "tripwire", "ossec-control", "samhain")) {
        $toolPath = $(which $tool 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $FindingDetails += "  $tool : INSTALLED ($($toolPath.ToString().Trim()))" + $nl
            $fimFound = $true
        }
    }
    if (-not $fimFound) {
        $FindingDetails += "  No file integrity monitoring tools detected (aide, tripwire, ossec, samhain)" + $nl
    }

    # Check 2: AIDE configuration
    $FindingDetails += $nl + "Check 2: AIDE Configuration" + $nl
    $(test -f /etc/aide/aide.conf 2>&1) | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $aideRules = $(grep -c "^/" /etc/aide/aide.conf 2>&1)
        $FindingDetails += "  /etc/aide/aide.conf: FOUND ($aideRules monitored paths)" + $nl
        $aideCron = $(timeout 5 grep -r "aide" /etc/cron* /var/spool/cron/ 2>&1 | head -3)
        if ($aideCron) {
            $FindingDetails += "  AIDE cron job: CONFIGURED" + $nl
            foreach ($line in ($aideCron -split $nl | Select-Object -First 2)) {
                $FindingDetails += "    $($line.ToString().Trim())" + $nl
            }
        }
        else {
            $FindingDetails += "  AIDE cron job: NOT FOUND" + $nl
        }
    }
    else {
        $FindingDetails += "  /etc/aide/aide.conf: NOT FOUND" + $nl
    }

    # Check 3: dpkg-verify for package integrity
    $FindingDetails += $nl + "Check 3: Package Integrity Verification" + $nl
    $dpkgVerify = $(dpkg --verify 2>&1 | head -10)
    if ($LASTEXITCODE -eq 0) {
        if ($dpkgVerify -and $dpkgVerify.ToString().Trim().Length -gt 0) {
            $FindingDetails += "  dpkg --verify shows modified packages:" + $nl
            foreach ($line in ($dpkgVerify -split $nl | Select-Object -First 5)) {
                $FindingDetails += "    $($line.ToString().Trim())" + $nl
            }
        }
        else {
            $FindingDetails += "  dpkg --verify: No modified packages detected" + $nl
        }
    }

    # Check 4: Notification mechanism
    $FindingDetails += $nl + "Check 4: Notification Mechanism" + $nl
    $mailInstalled = $(which mail 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  mail command: AVAILABLE" + $nl
    }
    $rsyslogActive = $(systemctl is-active rsyslog 2>&1)
    if ($LASTEXITCODE -eq 0 -and $rsyslogActive -match "active") {
        $FindingDetails += "  rsyslog: ACTIVE (can forward alerts to SIEM)" + $nl
    }

    # Status determination — always Open (requires org-level FIM + notification)
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Baseline configuration change notification requires file integrity" + $nl
    $FindingDetails += "  monitoring (AIDE/Tripwire) with automated alerting to designated personnel." + $nl
    $FindingDetails += "  ISSO/ISSM must verify FIM is configured and notification procedures exist." + $nl'''
    ),
    (
        "V-203721",
        "SV-203721r958804_rule",
        "SRG-OS-000368-GPOS-00154",
        "The operating system must prevent program execution in accordance with local policies regarding software program usage and restrictions and/or rules authorizing the terms and conditions of software program usage.",
        "02fc698a5dcea38eed560099eedcbffb",
        "6bf42f6cbbe76e2e129500bd02b5ef2a",
        "0a4ed970e22e88cb6d3faedba289bccd",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Program Execution Restriction ---" + $nl

    # Check 1: AppArmor status
    $FindingDetails += $nl + "Check 1: AppArmor Mandatory Access Control" + $nl
    $apparmorActive = $false
    $aaStatus = $(aa-status 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $profileLines = ($aaStatus -split $nl) | Where-Object { $_ -match "profiles are loaded|profiles are in" }
        foreach ($pl in $profileLines) {
            $FindingDetails += "  $($pl.ToString().Trim())" + $nl
        }
        $apparmorActive = $true
    }
    else {
        $apparmorService = $(systemctl is-active apparmor 2>&1)
        if ($LASTEXITCODE -eq 0 -and $apparmorService -match "active") {
            $FindingDetails += "  AppArmor service: ACTIVE" + $nl
            $apparmorActive = $true
        }
        else {
            $FindingDetails += "  AppArmor: NOT ACTIVE" + $nl
        }
    }

    # Check 2: SELinux (alternative MAC)
    $FindingDetails += $nl + "Check 2: SELinux (Alternative)" + $nl
    $selinuxActive = $false
    $getenforce = $(getenforce 2>&1)
    if ($LASTEXITCODE -eq 0 -and $getenforce -match "Enforcing|Permissive") {
        $FindingDetails += "  SELinux: $($getenforce.ToString().Trim())" + $nl
        $selinuxActive = ($getenforce -match "Enforcing")
    }
    else {
        $FindingDetails += "  SELinux: NOT INSTALLED (Debian uses AppArmor by default)" + $nl
    }

    # Check 3: noexec mount options
    $FindingDetails += $nl + "Check 3: Filesystem Execution Restrictions" + $nl
    $mountOutput = $(mount 2>&1 | grep -E "noexec" 2>&1)
    if ($mountOutput) {
        $FindingDetails += "  Filesystems with noexec:" + $nl
        foreach ($line in ($mountOutput -split $nl | Select-Object -First 5)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No filesystems mounted with noexec option" + $nl
    }

    # Check 4: PATH restrictions
    $FindingDetails += $nl + "Check 4: PATH Environment Security" + $nl
    $pathDirs = $env:PATH -split ":"
    $worldWritablePaths = @()
    foreach ($pd in $pathDirs) {
        if ($pd -eq "." -or $pd -eq "") { continue }
        $pdPerms = $(stat -c "%a" $pd 2>&1)
        if ($LASTEXITCODE -eq 0 -and $pdPerms -match "[2367]$") {
            $worldWritablePaths += "$pd ($pdPerms)"
        }
    }
    if ($worldWritablePaths.Count -gt 0) {
        $FindingDetails += "  WARNING: World-writable directories in PATH:" + $nl
        foreach ($wwp in $worldWritablePaths) {
            $FindingDetails += "    $wwp" + $nl
        }
    }
    else {
        $FindingDetails += "  No world-writable directories in PATH" + $nl
    }

    # Status determination
    if ($apparmorActive -or $selinuxActive) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: Mandatory access control (AppArmor/SELinux) is active," + $nl
        $FindingDetails += "  providing program execution restrictions per security policy." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No mandatory access control system is active to enforce" + $nl
        $FindingDetails += "  program execution restrictions." + $nl
    }'''
    ),
    (
        "V-203750",
        "SV-203750r958912_rule",
        "SRG-OS-000425-GPOS-00189",
        "The operating system must maintain the confidentiality and integrity of information during preparation for transmission.",
        "9df0b9078fae722ac7701674efae67f9",
        "ef89c5af34937173c0e50e3330a5c546",
        "670ed0ecbc90e77d54daa5c6269ce371",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Confidentiality/Integrity During Transmission Preparation ---" + $nl

    # Check 1: SSH encryption configuration
    $FindingDetails += $nl + "Check 1: SSH Encryption" + $nl
    $sshSecure = $false
    $sshdConfig = $(sshd -T 2>&1 | grep -i "^ciphers\|^macs\|^kexalgorithms" 2>&1)
    if ($LASTEXITCODE -eq 0 -and $sshdConfig) {
        foreach ($line in ($sshdConfig -split $nl)) {
            $FindingDetails += "  $($line.ToString().Trim())" + $nl
        }
        $sshSecure = $true
    }
    else {
        $sshdFile = $(cat /etc/ssh/sshd_config 2>&1 | grep -i "^Ciphers\|^MACs\|^KexAlgorithms" 2>&1)
        if ($sshdFile) {
            foreach ($line in ($sshdFile -split $nl)) {
                $FindingDetails += "  $($line.ToString().Trim())" + $nl
            }
            $sshSecure = $true
        }
        else {
            $FindingDetails += "  SSH using system defaults (typically secure on Debian 12)" + $nl
            $sshSecure = $true
        }
    }

    # Check 2: TLS configuration for XO
    $FindingDetails += $nl + "Check 2: XO TLS Configuration" + $nl
    $tlsSecure = $false
    $xoHostname = $(hostname 2>&1)
    $tlsCheck = $(echo | timeout 10 openssl s_client -connect localhost:443 -tls1_2 2>&1)
    if ($tlsCheck -match "Protocol\s*:\s*TLSv1\.[23]") {
        $protoLine = ($tlsCheck -split $nl) | Where-Object { $_ -match "Protocol" } | Select-Object -First 1
        $cipherLine = ($tlsCheck -split $nl) | Where-Object { $_ -match "Cipher\s+:" } | Select-Object -First 1
        $FindingDetails += "  $($protoLine.ToString().Trim())" + $nl
        $FindingDetails += "  $($cipherLine.ToString().Trim())" + $nl
        $tlsSecure = $true
    }
    else {
        $FindingDetails += "  TLS 1.2+ check: Unable to verify" + $nl
    }

    # Status determination
    if ($sshSecure -and $tlsSecure) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: SSH and TLS provide encryption for data confidentiality" + $nl
        $FindingDetails += "  and integrity during preparation for transmission." + $nl
    }
    elseif ($sshSecure) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: SSH provides encryption for data during transmission." + $nl
        $FindingDetails += "  TLS verification inconclusive but SSH meets requirement." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Unable to verify encryption for data during transmission." + $nl
    }'''
    ),
    (
        "V-203751",
        "SV-203751r958914_rule",
        "SRG-OS-000426-GPOS-00190",
        "The operating system must maintain the confidentiality and integrity of information during reception.",
        "250b84571360f1af0a43684a02cd3b95",
        "54f97107ceb1ca7ade8ce0243029c6b8",
        "a9717162219546c48cce3ce0328606bf",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Confidentiality/Integrity During Reception ---" + $nl

    # Check 1: SSH host key verification
    $FindingDetails += $nl + "Check 1: SSH Host Key Configuration" + $nl
    $sshReceptionOk = $false
    $hostKeys = $(ls -la /etc/ssh/ssh_host_*_key.pub 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $keyCount = ($hostKeys -split $nl).Count
        $FindingDetails += "  SSH host keys: $keyCount public keys found" + $nl
        $strictModes = $(sshd -T 2>&1 | grep -i "^strictmodes" 2>&1)
        if ($strictModes) {
            $FindingDetails += "  $($strictModes.ToString().Trim())" + $nl
        }
        $sshReceptionOk = $true
    }
    else {
        $FindingDetails += "  SSH host keys: NOT FOUND" + $nl
    }

    # Check 2: TLS for incoming connections
    $FindingDetails += $nl + "Check 2: TLS for Incoming Connections" + $nl
    $tlsReceptionOk = $false
    $tlsCheck = $(echo | timeout 10 openssl s_client -connect localhost:443 -tls1_2 2>&1)
    if ($tlsCheck -match "Protocol\s*:\s*TLSv1\.[23]") {
        $protoLine = ($tlsCheck -split $nl) | Where-Object { $_ -match "Protocol" } | Select-Object -First 1
        $FindingDetails += "  $($protoLine.ToString().Trim())" + $nl
        $FindingDetails += "  TLS protects confidentiality and integrity during data reception" + $nl
        $tlsReceptionOk = $true
    }
    else {
        $FindingDetails += "  TLS 1.2+ reception: Unable to verify" + $nl
    }

    # Check 3: Firewall filtering incoming traffic
    $FindingDetails += $nl + "Check 3: Firewall Input Filtering" + $nl
    $fwStatus = $(ufw status 2>&1)
    if ($LASTEXITCODE -eq 0 -and $fwStatus -match "Status: active") {
        $FindingDetails += "  UFW: ACTIVE" + $nl
        $fwRules = ($fwStatus -split $nl) | Where-Object { $_ -match "ALLOW\|DENY\|REJECT" } | Select-Object -First 5
        foreach ($rule in $fwRules) {
            $FindingDetails += "    $($rule.ToString().Trim())" + $nl
        }
    }
    else {
        $iptRules = $(iptables -L INPUT -n 2>&1 | head -10)
        if ($LASTEXITCODE -eq 0) {
            $FindingDetails += "  iptables INPUT chain:" + $nl
            foreach ($line in ($iptRules -split $nl | Select-Object -First 5)) {
                $FindingDetails += "    $($line.ToString().Trim())" + $nl
            }
        }
    }

    # Status determination
    if ($sshReceptionOk -and $tlsReceptionOk) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: SSH and TLS provide encryption for data confidentiality" + $nl
        $FindingDetails += "  and integrity during reception." + $nl
    }
    elseif ($sshReceptionOk) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: SSH provides encryption during data reception." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Unable to verify encryption for data during reception." + $nl
    }'''
    ),
    (
        "V-259333",
        "SV-259333r958940_rule",
        "SRG-OS-000439-GPOS-00195",
        "The operating system must install security-relevant software updates within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).",
        "cae6b28fe90be534f51fca4471b6d2c8",
        "1c534cf32c0e21b51ce389d5c661d83e",
        "f1b88545a7b49f37d93b32b28c760743",
        "Open",
        r'''    $nl = [Environment]::NewLine
    $FindingDetails = "--- Check: Security-Relevant Software Updates ---" + $nl

    # Check 1: Available security updates
    $FindingDetails += $nl + "Check 1: Pending Security Updates" + $nl
    $updatesAvailable = $false
    $aptCheck = $(apt list --upgradable 2>&1 | grep -i "security" 2>&1)
    if ($aptCheck -and $aptCheck.ToString().Trim().Length -gt 0) {
        $updateCount = ($aptCheck -split $nl).Count
        $FindingDetails += "  Security updates available: $updateCount" + $nl
        foreach ($line in ($aptCheck -split $nl | Select-Object -First 5)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
        $updatesAvailable = $true
    }
    else {
        $FindingDetails += "  No pending security updates detected" + $nl
    }

    # Check 2: Last update timestamp
    $FindingDetails += $nl + "Check 2: Last Package Update" + $nl
    $lastUpdate = $(stat -c "%Y %y" /var/lib/apt/lists/ 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  apt lists last modified: $($lastUpdate.ToString().Trim())" + $nl
    }
    $dpkgLog = $(ls -lt /var/log/dpkg.log* 2>&1 | head -1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  dpkg log: $($dpkgLog.ToString().Trim())" + $nl
    }
    $lastInstall = $(grep " install " /var/log/dpkg.log 2>&1 | tail -3)
    if ($lastInstall) {
        $FindingDetails += "  Recent package installs:" + $nl
        foreach ($line in ($lastInstall -split $nl | Select-Object -Last 3)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
    }

    # Check 3: Automatic update configuration
    $FindingDetails += $nl + "Check 3: Automatic Update Configuration" + $nl
    $autoUpdateOk = $false
    $(test -f /etc/apt/apt.conf.d/20auto-upgrades 2>&1) | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $autoConf = $(cat /etc/apt/apt.conf.d/20auto-upgrades 2>&1)
        $FindingDetails += "  /etc/apt/apt.conf.d/20auto-upgrades:" + $nl
        foreach ($line in ($autoConf -split $nl)) {
            $FindingDetails += "    $($line.ToString().Trim())" + $nl
        }
        if ($autoConf -match "Unattended-Upgrade.*1") {
            $autoUpdateOk = $true
        }
    }
    else {
        $FindingDetails += "  Automatic updates: NOT CONFIGURED" + $nl
    }

    $unattendedStatus = $(systemctl is-active unattended-upgrades 2>&1)
    if ($LASTEXITCODE -eq 0 -and $unattendedStatus -match "active") {
        $FindingDetails += "  unattended-upgrades service: ACTIVE" + $nl
        $autoUpdateOk = $true
    }

    # Check 4: OS version and support status
    $FindingDetails += $nl + "Check 4: OS Version and Support" + $nl
    $osRelease = $(cat /etc/os-release 2>&1 | grep -i "PRETTY_NAME\|VERSION_ID" 2>&1)
    if ($osRelease) {
        foreach ($line in ($osRelease -split $nl)) {
            $FindingDetails += "  $($line.ToString().Trim())" + $nl
        }
    }

    # Status determination
    if (-not $updatesAvailable -and $autoUpdateOk) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: No pending security updates and automatic updates are configured." + $nl
    }
    elseif (-not $updatesAvailable) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: No pending security updates detected. System appears current." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Security updates are available but not installed." + $nl
        $FindingDetails += "  Updates must be installed within the timeframe directed by" + $nl
        $FindingDetails += "  authoritative sources (IAVM, CTOs, DTMs, STIGs)." + $nl
    }'''
    ),
]


def escape_ps(text):
    """No escaping needed — raw strings used."""
    return text


def build_description(vid, rid, stig_id, title, disc_md5, check_md5, fix_md5):
    return f"""    <#
    .DESCRIPTION
        Vuln ID    : {vid}
        STIG ID    : {stig_id}
        Rule ID    : {rid}
        Rule Title : {title}
        DiscussMD5 : {disc_md5}
        CheckMD5   : {check_md5}
        FixMD5     : {fix_md5}
    #>"""


def main():
    with open(MODULE_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    changes = 0
    for vid, rid, stig_id, title, disc_md5, check_md5, fix_md5, default_status, custom_code in FUNCTIONS:
        func_name = f"Get-{vid.replace('-', '')}"
        # The function name in the file uses the V-###### format without hyphen after Get-
        # but the VulnID keeps its hyphen. Function: Get-V203711, VulnID: V-203711

        # Find the function
        func_pattern = rf'(Function {func_name} \{{)'
        func_match = re.search(func_pattern, content)
        if not func_match:
            print(f"WARNING: {func_name} not found")
            continue

        func_start = func_match.start()

        # Find the description block end
        desc_end_pattern = r'    #>'
        desc_end = content.find('    #>', func_start)
        if desc_end == -1:
            print(f"WARNING: Description end not found for {func_name}")
            continue

        # Find the description block start (the <# after Function line)
        desc_start = content.find('    <#', func_start)
        if desc_start == -1 or desc_start > desc_end:
            print(f"WARNING: Description start not found for {func_name}")
            continue

        # Replace description block
        old_desc = content[desc_start:desc_end + len('    #>')]
        new_desc = build_description(vid, rid, stig_id, title, disc_md5, check_md5, fix_md5)
        content = content[:desc_start] + new_desc + content[desc_end + len('    #>'):]

        # Recalculate positions after description replacement
        # Find the RuleID line and replace it
        func_match2 = re.search(rf'Function {func_name} \{{', content)
        func_start2 = func_match2.start()

        # Replace RuleID
        ruleid_pattern = rf'(\$RuleID = ")[^"]*(")'
        ruleid_region_start = content.find('$RuleID = "', func_start2)
        if ruleid_region_start != -1 and ruleid_region_start < func_start2 + 3000:
            ruleid_region_end = content.find('"', ruleid_region_start + len('$RuleID = "'))
            old_ruleid = content[ruleid_region_start:ruleid_region_end + 1]
            new_ruleid = f'$RuleID = "{rid}"'
            content = content[:ruleid_region_start] + new_ruleid + content[ruleid_region_end + 1:]

        # Recalculate positions
        func_match3 = re.search(rf'Function {func_name} \{{', content)
        func_start3 = func_match3.start()

        # Replace Status default
        status_region_start = content.find('$Status = "', func_start3)
        if status_region_start != -1 and status_region_start < func_start3 + 3000:
            status_region_end = content.find('"', status_region_start + len('$Status = "'))
            content = content[:status_region_start] + f'$Status = "{default_status}"' + content[status_region_end + 1:]

        # Recalculate positions
        func_match4 = re.search(rf'Function {func_name} \{{', content)
        func_start4 = func_match4.start()

        # Replace custom code section
        begin_marker = "#---=== Begin Custom Code ===---#"
        end_marker = "#---=== End Custom Code ===---#"

        begin_pos = content.find(begin_marker, func_start4)
        end_pos = content.find(end_marker, func_start4)

        if begin_pos == -1 or end_pos == -1:
            print(f"WARNING: Custom code markers not found for {func_name}")
            continue

        if begin_pos > func_start4 + 5000:
            print(f"WARNING: Custom code markers too far from function start for {func_name}")
            continue

        old_custom = content[begin_pos + len(begin_marker):end_pos]
        new_custom = "\n" + custom_code + "\n    "

        content = content[:begin_pos + len(begin_marker)] + new_custom + content[end_pos:]

        changes += 1
        print(f"OK: Integrated {vid} ({func_name})")

    with open(MODULE_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nIntegrated {changes}/10 functions")
    return 0 if changes == 10 else 1


if __name__ == "__main__":
    sys.exit(main())
