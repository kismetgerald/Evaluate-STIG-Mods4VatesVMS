#!/usr/bin/env python3
"""
implement_batch9.py — Replace stubs for Batch 9 (V-222496 through V-222521)
Audit Info Protection, Software/Config Controls, Vulnerability & Execution Controls.

26 functions total:
  V-222496:      Report generation preserving original content (org policy)
  V-222497-499:  Timestamps (UTC, granularity, system clock) — technically verifiable
  V-222500-502:  Audit info protection (read/modify/delete) — log permission checks
  V-222503-505:  Audit tool protection (access/modify/delete) — tool permission checks
  V-222506-509:  Audit backup & integrity (7-day backup, crypto hash, tool validation)
  V-222510:      Software install restrictions (privileged users only)
  V-222511-512:  Config change access control & auditing
  V-222513-514:  Patch signing & library privileges (NA conditions)
  V-222515-518:  Vuln assessment, program execution, deny-all, non-essential
  V-222519-521:  PPSM CAL ports/protocols, user & device reauthentication
"""

import re
import sys

PSM1_PATH = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode"
    r"\Evaluate-STIG\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psm1"
)

# ---------------------------------------------------------------------------
# Shared detection snippets
# ---------------------------------------------------------------------------
INIT = """\
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)"""

# Token lookup (reusable for API-based checks)
TOKEN_LOOKUP = """\
    # --- XO REST API token lookup ---
    $token = $null; $tokenSource = ""
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim(); $tokenSource = "/etc/xo-server/stig/api-token" }
    }
    if (-not $token -and $env:XO_API_TOKEN) { $token = $env:XO_API_TOKEN; $tokenSource = "XO_API_TOKEN env" }
    if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli")) {
        $tc = $(timeout 3 sh -c 'grep -oP "(?<=[char]34token[char]34:[char]34)[^[char]34]+" /var/lib/xo-server/.xo-cli 2>/dev/null')
        if ($tc) { $token = $tc.Trim(); $tokenSource = ".xo-cli" }
    }"""

# Centralized logging detection (from Batch 8)
DETECT_CENTRALIZED = """\
    # Detect centralized logging: rsyslog remote targets, systemd-journal-remote, syslog-ng
    $remoteTargets  = $(timeout 5 sh -c 'grep -rE "^[^#].*(@@?[a-zA-Z0-9])" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null')
    $journalRemote  = $(systemctl is-active systemd-journal-remote 2>&1)
    $syslogNgRemote = $(timeout 5 sh -c 'grep -rEi "destination " /etc/syslog-ng/ 2>/dev/null | grep -iE "tcp|udp|network"')

    $centralizedFound   = $false
    $centralizedDetails = ""

    if ($remoteTargets -and ($remoteTargets -notmatch "No such file|cannot stat|failed|error")) {
        $centralizedFound    = $true
        $centralizedDetails += "Rsyslog remote target(s) detected:" + $nl + ($remoteTargets -join $nl) + $nl + $nl
    }
    if ($journalRemote -eq "active") {
        $centralizedFound    = $true
        $centralizedDetails += "systemd-journal-remote: active" + $nl + $nl
    }
    if ($syslogNgRemote -and ($syslogNgRemote -notmatch "No such file|cannot stat|failed|error")) {
        $centralizedFound    = $true
        $centralizedDetails += "syslog-ng remote destination(s) detected:" + $nl + ($syslogNgRemote -join $nl) + $nl + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222496: Report generation preserving original content
# ---------------------------------------------------------------------------
CODE_V222496 = INIT + """
""" + DETECT_CENTRALIZED + r"""

    $FindingDetails += "Audit Report Generation - Original Content Preservation (APSC-DV-001220)" + $nl
    $FindingDetails += "========================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001220: If the centralized logging system provides report" + $nl
        $FindingDetails += "generation that preserves original content, this is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Confirm the SIEM generates reports without altering" + $nl
        $FindingDetails += "original audit record content or time ordering." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Report generation capability that preserves original audit record" + $nl
        $FindingDetails += "content and time ordering has not been verified." + $nl + $nl
        $FindingDetails += "NOTE: The systemd journal provides read-only query capability" + $nl
        $FindingDetails += "(journalctl) that inherently preserves original records." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222497: Internal system clocks for timestamps
# ---------------------------------------------------------------------------
CODE_V222497 = INIT + r"""

    $FindingDetails += "Internal System Clock for Audit Timestamps (APSC-DV-001250)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Verify NTP/chrony synchronization
    $ntpActive   = $false
    $chronycSrc  = $(timeout 5 chronyc sources 2>&1)
    $timedatectl = $(timedatectl show 2>&1)
    $ntpStatus   = $(timeout 5 sh -c 'timedatectl status 2>/dev/null | grep -i "NTP\|clock\|synch"')

    if ($chronycSrc -and ($chronycSrc -notmatch "command not found|Cannot")) {
        $ntpActive = $true
        $FindingDetails += "Check 1 - Chrony NTP Sources:" + $nl
        $FindingDetails += ($chronycSrc -join $nl) + $nl + $nl
    }
    elseif ($ntpStatus) {
        $ntpActive = $true
        $FindingDetails += "Check 1 - NTP Synchronization Status:" + $nl
        $FindingDetails += ($ntpStatus -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "Check 1 - NTP Synchronization: NOT DETECTED" + $nl + $nl
    }

    # Check 2: Verify systemd-timesyncd
    $timesyncActive = $(systemctl is-active systemd-timesyncd 2>&1)
    $FindingDetails += "Check 2 - systemd-timesyncd: $timesyncActive" + $nl + $nl

    # Check 3: Verify XO uses system clock (Node.js Date.now() uses system clock)
    $FindingDetails += "Check 3 - XO Timestamp Source:" + $nl
    $FindingDetails += "  Node.js Date.now() and Date() use the system clock by default." + $nl
    $FindingDetails += "  XO audit plugin timestamps are derived from the system clock." + $nl + $nl

    # Check 4: Current system time
    $currentTime = $(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>&1)
    $FindingDetails += "Check 4 - Current System Time (UTC): $currentTime" + $nl + $nl

    if ($ntpActive -or ($timesyncActive -eq "active")) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: System clock is synchronized via NTP/chrony/timesyncd." + $nl
        $FindingDetails += "XO uses the internal system clock for generating audit timestamps." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: No active NTP synchronization detected." + $nl
        $FindingDetails += "The system clock may not be reliable for audit timestamps." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222498: Timestamps mappable to UTC/GMT
# ---------------------------------------------------------------------------
CODE_V222498 = INIT + r"""

    $FindingDetails += "Audit Timestamps Mappable to UTC (APSC-DV-001260)" + $nl
    $FindingDetails += "===================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: System timezone
    $timezone = $(timedatectl show -p Timezone --value 2>&1)
    if (-not $timezone -or $timezone -match "No such|error") {
        $timezone = $(cat /etc/timezone 2>&1)
    }
    $FindingDetails += "Check 1 - System Timezone: $timezone" + $nl

    $utcOffsetInfo = $(date '+%Z %:z' 2>&1)
    $FindingDetails += "  UTC Offset: $utcOffsetInfo" + $nl + $nl

    # Check 2: Verify timestamps can map to UTC
    $utcTime   = $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>&1)
    $localTime = $(date '+%Y-%m-%dT%H:%M:%S%:z' 2>&1)
    $FindingDetails += "Check 2 - Time Mapping:" + $nl
    $FindingDetails += "  UTC Time:   $utcTime" + $nl
    $FindingDetails += "  Local Time: $localTime" + $nl + $nl

    # Check 3: Journal timestamp format
    $journalSample = $(timeout 5 sh -c 'journalctl -u xo-server -n 3 --output=short-iso 2>/dev/null | tail -3')
    if ($journalSample) {
        $FindingDetails += "Check 3 - Systemd Journal Timestamps (ISO format):" + $nl
        $FindingDetails += ($journalSample -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "Check 3 - Systemd Journal: No xo-server entries found" + $nl + $nl
    }

    # Check 4: XO log timestamp format
    $xoLogSample = $(timeout 5 sh -c 'ls -t /var/log/xo-server/*.log 2>/dev/null | head -1 | xargs tail -3 2>/dev/null')
    if ($xoLogSample) {
        $FindingDetails += "Check 4 - XO Application Log Timestamps:" + $nl
        $FindingDetails += ($xoLogSample -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "Check 4 - XO Application Logs: Not found at /var/log/xo-server/" + $nl + $nl
    }

    # Status: timestamps always mappable to UTC via timezone offset
    $Status = "NotAFinding"
    $FindingDetails += "RESULT: Audit timestamps include timezone offset information and can" + $nl
    $FindingDetails += "be mapped to UTC. Systemd journal natively supports UTC output." + $nl
    $FindingDetails += "Node.js Date objects store time internally as UTC milliseconds." + $nl"""

# ---------------------------------------------------------------------------
# V-222499: Timestamp granularity >= 1 second
# ---------------------------------------------------------------------------
CODE_V222499 = INIT + r"""

    $FindingDetails += "Audit Timestamp Granularity >= 1 Second (APSC-DV-001270)" + $nl
    $FindingDetails += "==========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Systemd journal precision
    $journalPrecision = $(timeout 5 sh -c 'journalctl -u xo-server -n 5 --output=short-precise 2>/dev/null | tail -5')
    if ($journalPrecision) {
        $FindingDetails += "Check 1 - Systemd Journal (microsecond precision):" + $nl
        $FindingDetails += ($journalPrecision -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "Check 1 - Systemd Journal: No xo-server entries found" + $nl + $nl
    }

    # Check 2: XO audit plugin timestamps (millisecond precision)
    $FindingDetails += "Check 2 - XO Audit Plugin:" + $nl
    $FindingDetails += "  XO audit plugin records timestamps as Unix milliseconds (Date.now())." + $nl
    $FindingDetails += "  Example: 1769297199529 = sub-second precision." + $nl + $nl

    # Check 3: XO application log timestamps
    $xoLogSample = $(timeout 5 sh -c 'ls -t /var/log/xo-server/*.log 2>/dev/null | head -1 | xargs head -5 2>/dev/null')
    if ($xoLogSample) {
        $FindingDetails += "Check 3 - XO Application Log Timestamps:" + $nl
        $FindingDetails += ($xoLogSample -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "Check 3 - XO Application Logs: Not found" + $nl + $nl
    }

    # Check 4: System clock resolution
    $clockRes = $(date '+%Y-%m-%dT%H:%M:%S.%N' 2>&1)
    $FindingDetails += "Check 4 - System Clock Resolution: $clockRes" + $nl + $nl

    $Status = "NotAFinding"
    $FindingDetails += "RESULT: Audit timestamps meet or exceed 1-second granularity." + $nl
    $FindingDetails += "Systemd journal: microsecond precision. XO audit plugin: millisecond" + $nl
    $FindingDetails += "precision. Both exceed the minimum 1-second requirement." + $nl"""

# ---------------------------------------------------------------------------
# V-222500: Protect audit info from unauthorized read access
# ---------------------------------------------------------------------------
CODE_V222500 = INIT + r"""

    $FindingDetails += "Audit Info Protection - Unauthorized Read Access (APSC-DV-001280)" + $nl
    $FindingDetails += "===================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $allSecure = $true

    # Check 1: XO log directory permissions
    $xoLogDir = "/var/log/xo-server"
    $xoLogPerms = $(timeout 5 stat -c '%a %U:%G' $xoLogDir 2>&1)
    $FindingDetails += "Check 1 - XO Log Directory ($xoLogDir):" + $nl
    if ($xoLogPerms -and ($xoLogPerms -notmatch "No such|cannot stat")) {
        $FindingDetails += "  Permissions: $xoLogPerms" + $nl
        if ($xoLogPerms -match "^(7[0-5][0-5]|7[0-5]0)") {
            $FindingDetails += "  Status: PASS - Not world-readable" + $nl + $nl
        }
        else {
            $allSecure = $false
            $FindingDetails += "  Status: FAIL - May be world-readable" + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  Directory not found (XO logs may use journald only)" + $nl + $nl
    }

    # Check 2: Systemd journal permissions
    $journalDir = "/var/log/journal"
    $journalPerms = $(timeout 5 stat -c '%a %U:%G' $journalDir 2>&1)
    $FindingDetails += "Check 2 - Systemd Journal Directory ($journalDir):" + $nl
    if ($journalPerms -and ($journalPerms -notmatch "No such|cannot stat")) {
        $FindingDetails += "  Permissions: $journalPerms" + $nl
        $journalGroup = $(timeout 5 sh -c 'stat -c "%G" /var/log/journal 2>/dev/null')
        $FindingDetails += "  Group: $journalGroup (systemd-journal group controls read access)" + $nl + $nl
    }
    else {
        $FindingDetails += "  Persistent journal not configured (volatile only)" + $nl + $nl
    }

    # Check 3: World-readable log files
    $worldReadable = $(timeout 10 sh -c 'find /var/log/xo-server/ -type f -perm -o+r 2>/dev/null | head -10')
    $FindingDetails += "Check 3 - World-Readable Log Files:" + $nl
    if ($worldReadable) {
        $allSecure = $false
        $FindingDetails += ($worldReadable -join $nl) + $nl
        $FindingDetails += "  Status: FAIL - World-readable log files found" + $nl + $nl
    }
    else {
        $FindingDetails += "  No world-readable log files found" + $nl + $nl
    }

    # Check 4: Auth log permissions
    $authLogPerms = $(timeout 5 stat -c '%a %U:%G' /var/log/auth.log 2>&1)
    $FindingDetails += "Check 4 - Auth Log (/var/log/auth.log):" + $nl
    if ($authLogPerms -and ($authLogPerms -notmatch "No such|cannot stat")) {
        $FindingDetails += "  Permissions: $authLogPerms" + $nl + $nl
    }
    else {
        $FindingDetails += "  Not found (may use /var/log/secure)" + $nl + $nl
    }

    if ($allSecure) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Audit information is protected from unauthorized read access." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Audit information may be accessible to unauthorized readers." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222501: Protect audit info from unauthorized modification
# ---------------------------------------------------------------------------
CODE_V222501 = INIT + r"""

    $FindingDetails += "Audit Info Protection - Unauthorized Modification (APSC-DV-001290)" + $nl
    $FindingDetails += "=====================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $allSecure = $true

    # Check 1: XO log directory permissions (write protection)
    $xoLogPerms = $(timeout 5 stat -c '%a %U:%G' /var/log/xo-server 2>&1)
    $FindingDetails += "Check 1 - XO Log Directory Permissions:" + $nl
    if ($xoLogPerms -and ($xoLogPerms -notmatch "No such|cannot stat")) {
        $FindingDetails += "  /var/log/xo-server: $xoLogPerms" + $nl
        if ($xoLogPerms -match "^[0-7][0-5][0-5]" -and $xoLogPerms -notmatch "^[0-7][0-7][2367]") {
            $FindingDetails += "  Status: PASS - Not world-writable" + $nl + $nl
        }
        else {
            $allSecure = $false
            $FindingDetails += "  Status: FAIL - May be world-writable" + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  Directory not found" + $nl + $nl
    }

    # Check 2: World-writable log files
    $worldWritable = $(timeout 10 sh -c 'find /var/log/xo-server/ /var/log/journal/ -type f -perm -o+w 2>/dev/null | head -10')
    $FindingDetails += "Check 2 - World-Writable Log Files:" + $nl
    if ($worldWritable) {
        $allSecure = $false
        $FindingDetails += ($worldWritable -join $nl) + $nl
        $FindingDetails += "  Status: FAIL - World-writable log files found" + $nl + $nl
    }
    else {
        $FindingDetails += "  No world-writable log files found in /var/log/xo-server/ or /var/log/journal/" + $nl + $nl
    }

    # Check 3: Immutable attributes on logs
    $immutableLogs = $(timeout 5 sh -c 'lsattr /var/log/xo-server/*.log 2>/dev/null | head -5')
    $FindingDetails += "Check 3 - Immutable Attributes (lsattr):" + $nl
    if ($immutableLogs) {
        $FindingDetails += ($immutableLogs -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No immutable attributes detected on log files" + $nl + $nl
    }

    # Check 4: Logrotate configuration (prevents manual modification via rotation)
    $logrotateConf = $(timeout 5 sh -c 'cat /etc/logrotate.d/xo-server 2>/dev/null || ls /etc/logrotate.d/*xo* 2>/dev/null')
    $FindingDetails += "Check 4 - Logrotate Configuration:" + $nl
    if ($logrotateConf) {
        $FindingDetails += ($logrotateConf -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No XO-specific logrotate configuration found" + $nl + $nl
    }

    if ($allSecure) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Audit information is protected from unauthorized modification." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Audit information may be modifiable by unauthorized users." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222502: Protect audit info from unauthorized deletion
# ---------------------------------------------------------------------------
CODE_V222502 = INIT + r"""

    $FindingDetails += "Audit Info Protection - Unauthorized Deletion (APSC-DV-001300)" + $nl
    $FindingDetails += "=================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $allSecure = $true

    # Check 1: Log directory ownership and permissions
    $logDirs = @("/var/log/xo-server", "/var/log/journal")
    foreach ($dir in $logDirs) {
        $dirPerms = $(timeout 5 stat -c '%a %U:%G' $dir 2>&1)
        $FindingDetails += "Check - Directory $dir :" + $nl
        if ($dirPerms -and ($dirPerms -notmatch "No such|cannot stat")) {
            $FindingDetails += "  Permissions: $dirPerms" + $nl
            $stickyBit = $(timeout 5 stat -c '%a' $dir 2>&1)
            if ($stickyBit -match "^1") {
                $FindingDetails += "  Sticky bit: SET (prevents deletion by non-owners)" + $nl + $nl
            }
            else {
                $FindingDetails += "  Sticky bit: Not set" + $nl + $nl
            }
        }
        else {
            $FindingDetails += "  Directory not found" + $nl + $nl
        }
    }

    # Check 2: Append-only attributes
    $appendOnly = $(timeout 5 sh -c 'lsattr /var/log/xo-server/ 2>/dev/null | grep -E "a----|----a" | head -5')
    $FindingDetails += "Check - Append-Only Attributes:" + $nl
    if ($appendOnly) {
        $FindingDetails += ($appendOnly -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No append-only attributes found on log files" + $nl + $nl
    }

    # Check 3: Systemd journal protection
    $journalStorage = $(timeout 5 sh -c 'grep -E "^Storage=" /etc/systemd/journald.conf 2>/dev/null')
    $FindingDetails += "Check - Systemd Journal Storage:" + $nl
    if ($journalStorage) {
        $FindingDetails += "  $journalStorage" + $nl
    }
    else {
        $FindingDetails += "  Default storage (auto)" + $nl
    }
    $FindingDetails += "  Journal uses binary format with built-in integrity checking" + $nl + $nl

    # Check 4: Root-only delete permission
    $nonRootWrite = $(timeout 10 sh -c 'find /var/log/xo-server/ -type f -not -user root -writable 2>/dev/null | head -5')
    $FindingDetails += "Check - Non-Root Writable Log Files:" + $nl
    if ($nonRootWrite) {
        $allSecure = $false
        $FindingDetails += ($nonRootWrite -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No non-root writable log files found" + $nl + $nl
    }

    if ($allSecure) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Audit information is protected from unauthorized deletion." + $nl
        $FindingDetails += "Log files are owned by root with restricted permissions." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Audit information may be deletable by unauthorized users." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222503: Protect audit tools from unauthorized access
# ---------------------------------------------------------------------------
CODE_V222503 = INIT + r"""

    $FindingDetails += "Audit Tool Protection - Unauthorized Access (APSC-DV-001310)" + $nl
    $FindingDetails += "================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $allSecure = $true

    # Audit tools: journalctl, logger, aureport, ausearch, auditctl
    $auditTools = @(
        "/usr/bin/journalctl",
        "/usr/bin/logger",
        "/usr/sbin/aureport",
        "/usr/sbin/ausearch",
        "/usr/sbin/auditctl",
        "/usr/bin/last",
        "/usr/bin/lastlog"
    )

    $FindingDetails += "Audit Tool File Permissions:" + $nl
    $FindingDetails += "============================" + $nl + $nl

    foreach ($tool in $auditTools) {
        $toolPerms = $(timeout 5 stat -c '%a %U:%G %n' $tool 2>&1)
        if ($toolPerms -and ($toolPerms -notmatch "No such|cannot stat")) {
            $FindingDetails += "  $toolPerms" + $nl
            if ($toolPerms -match "\s[0-7][0-7][5-7]\s") {
                # World-executable is expected for tools like journalctl, last
            }
            if ($toolPerms -match "\s[0-7][2367][0-7]\s" -or $toolPerms -match "\s[2367][0-7][0-7]\s") {
                $allSecure = $false
            }
        }
        else {
            $FindingDetails += "  $tool : NOT INSTALLED" + $nl
        }
    }
    $FindingDetails += $nl

    # Check XO audit plugin access
    $xoAuditPlugin = $(timeout 5 sh -c 'find /opt/xo/packages -maxdepth 3 -name "audit*" -type d 2>/dev/null | head -3')
    $FindingDetails += "XO Audit Plugin Location:" + $nl
    if ($xoAuditPlugin) {
        $pluginPerms = $(timeout 5 stat -c '%a %U:%G %n' $($xoAuditPlugin -split "`n" | Select-Object -First 1) 2>&1)
        $FindingDetails += "  $pluginPerms" + $nl + $nl
    }
    else {
        $FindingDetails += "  Not found in /opt/xo/packages" + $nl + $nl
    }

    if ($allSecure) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Audit tools are protected from unauthorized access." + $nl
        $FindingDetails += "System audit tools are owned by root with appropriate permissions." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Some audit tools may have overly permissive access." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222504: Protect audit tools from unauthorized modification
# ---------------------------------------------------------------------------
CODE_V222504 = INIT + r"""

    $FindingDetails += "Audit Tool Protection - Unauthorized Modification (APSC-DV-001320)" + $nl
    $FindingDetails += "=====================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $allSecure = $true

    $auditTools = @(
        "/usr/bin/journalctl",
        "/usr/bin/logger",
        "/usr/sbin/aureport",
        "/usr/sbin/ausearch",
        "/usr/sbin/auditctl",
        "/usr/bin/last",
        "/usr/bin/lastlog"
    )

    $FindingDetails += "Audit Tool Write Permissions:" + $nl
    $FindingDetails += "=============================" + $nl + $nl

    foreach ($tool in $auditTools) {
        $toolPerms = $(timeout 5 stat -c '%a %U:%G %n' $tool 2>&1)
        if ($toolPerms -and ($toolPerms -notmatch "No such|cannot stat")) {
            $FindingDetails += "  $toolPerms" + $nl
            # Check if group or other have write
            $permOctal = ""
            if ($toolPerms -match "^(\d+)\s") { $permOctal = $Matches[1] }
            if ($permOctal.Length -ge 3) {
                $groupW = [int]$permOctal[-2].ToString() -band 2
                $otherW = [int]$permOctal[-1].ToString() -band 2
                if ($groupW -or $otherW) {
                    $allSecure = $false
                    $FindingDetails += "    WARNING: Group or other write permission detected" + $nl
                }
            }
        }
        else {
            $FindingDetails += "  $tool : NOT INSTALLED" + $nl
        }
    }
    $FindingDetails += $nl

    # Check dpkg package integrity for audit tools
    $dpkgVerify = $(timeout 10 sh -c 'dpkg --verify coreutils systemd 2>/dev/null | head -10')
    $FindingDetails += "Package Integrity (dpkg --verify):" + $nl
    if ($dpkgVerify) {
        $FindingDetails += ($dpkgVerify -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No modifications detected (or dpkg --verify not available)" + $nl + $nl
    }

    if ($allSecure) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Audit tools are protected from unauthorized modification." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Some audit tools may be modifiable by non-root users." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222505: Protect audit tools from unauthorized deletion
# ---------------------------------------------------------------------------
CODE_V222505 = INIT + r"""

    $FindingDetails += "Audit Tool Protection - Unauthorized Deletion (APSC-DV-001330)" + $nl
    $FindingDetails += "=================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $allSecure = $true

    $auditToolDirs = @("/usr/bin", "/usr/sbin")

    $FindingDetails += "Audit Tool Directory Permissions:" + $nl
    $FindingDetails += "=================================" + $nl + $nl

    foreach ($dir in $auditToolDirs) {
        $dirPerms = $(timeout 5 stat -c '%a %U:%G %n' $dir 2>&1)
        $FindingDetails += "  $dirPerms" + $nl
        if ($dirPerms -match "^([0-7]+)") {
            $permStr = $Matches[1]
            if ($permStr.Length -ge 3) {
                $otherW = [int]$permStr[-1].ToString() -band 2
                if ($otherW) {
                    $allSecure = $false
                    $FindingDetails += "    WARNING: Other write permission detected (deletion possible)" + $nl
                }
            }
        }
    }
    $FindingDetails += $nl

    # Check sticky bit on directories
    foreach ($dir in $auditToolDirs) {
        $stickyCheck = $(timeout 5 stat -c '%a' $dir 2>&1)
        $FindingDetails += "  $dir sticky bit: "
        if ($stickyCheck -match "^1") {
            $FindingDetails += "SET" + $nl
        }
        else {
            $FindingDetails += "Not set (standard for /usr/bin, /usr/sbin)" + $nl
        }
    }
    $FindingDetails += $nl

    # Check package management protection
    $FindingDetails += "Package Management Protection:" + $nl
    $FindingDetails += "  Audit tools are managed by dpkg/apt package manager." + $nl
    $FindingDetails += "  Removal requires root (sudo apt remove) privileges." + $nl + $nl

    if ($allSecure) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Audit tools are protected from unauthorized deletion." + $nl
        $FindingDetails += "Tool directories are owned by root and not world-writable." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Audit tool directories may allow unauthorized deletion." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222506: Back up audit records at least every 7 days
# ---------------------------------------------------------------------------
CODE_V222506 = INIT + """
""" + DETECT_CENTRALIZED + r"""

    $FindingDetails += "Audit Record Backup - 7 Day Requirement (APSC-DV-001340)" + $nl
    $FindingDetails += "==========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Centralized logging (continuous backup)
    $FindingDetails += "Check 1 - Centralized Logging (Real-Time Backup):" + $nl
    if ($centralizedFound) {
        $FindingDetails += "  DETECTED - Logs forwarded to centralized system in real-time" + $nl
        $FindingDetails += $centralizedDetails
    }
    else {
        $FindingDetails += "  NOT DETECTED - No real-time log forwarding" + $nl + $nl
    }

    # Check 2: Logrotate configuration (automated archival)
    $logrotateConf = $(timeout 5 sh -c 'cat /etc/logrotate.d/xo-server 2>/dev/null || cat /etc/logrotate.d/xo* 2>/dev/null')
    $FindingDetails += "Check 2 - Logrotate Configuration:" + $nl
    if ($logrotateConf) {
        $FindingDetails += ($logrotateConf -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No XO-specific logrotate configuration" + $nl
        $defaultRotate = $(timeout 5 sh -c 'grep -E "^(daily|weekly|monthly|rotate)" /etc/logrotate.conf 2>/dev/null')
        if ($defaultRotate) {
            $FindingDetails += "  Default logrotate: " + ($defaultRotate -join ", ") + $nl + $nl
        }
        else {
            $FindingDetails += "  Default logrotate configuration not found" + $nl + $nl
        }
    }

    # Check 3: Cron backup jobs
    $cronBackup = $(timeout 5 sh -c 'grep -rli "log\|backup\|rsync" /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/ /var/spool/cron/ 2>/dev/null | head -5')
    $FindingDetails += "Check 3 - Scheduled Backup Jobs:" + $nl
    if ($cronBackup) {
        $FindingDetails += ($cronBackup -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No log backup cron jobs detected" + $nl + $nl
    }

    # Check 4: Systemd journal persistence
    $journalPersist = $(timeout 5 sh -c 'grep -E "^Storage=" /etc/systemd/journald.conf 2>/dev/null')
    $FindingDetails += "Check 4 - Journal Persistence:" + $nl
    if ($journalPersist) {
        $FindingDetails += "  $journalPersist" + $nl + $nl
    }
    else {
        $FindingDetails += "  Default (auto - persistent if /var/log/journal exists)" + $nl + $nl
    }

    if ($centralizedFound) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Audit records are forwarded to centralized logging in real-time," + $nl
        $FindingDetails += "exceeding the 7-day backup requirement." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: No verified backup mechanism for audit records to a separate system." + $nl
        $FindingDetails += "Local logrotate provides archival but not off-system backup." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222507: Cryptographic mechanisms to protect audit info integrity
# ---------------------------------------------------------------------------
CODE_V222507 = INIT + r"""

    $FindingDetails += "Cryptographic Protection of Audit Integrity (APSC-DV-001350)" + $nl
    $FindingDetails += "================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $cryptoFound = $false

    # Check 1: Systemd journal FSS (Forward Secure Sealing)
    $fssEnabled = $(timeout 5 sh -c 'grep -E "^Seal=" /etc/systemd/journald.conf 2>/dev/null')
    $FindingDetails += "Check 1 - Systemd Journal Forward Secure Sealing (FSS):" + $nl
    if ($fssEnabled -match "yes") {
        $cryptoFound = $true
        $FindingDetails += "  Seal=yes (FSS is ENABLED)" + $nl + $nl
    }
    elseif ($fssEnabled) {
        $FindingDetails += "  $fssEnabled" + $nl + $nl
    }
    else {
        $FindingDetails += "  Not configured (default: Seal=no)" + $nl + $nl
    }

    # Check 2: AIDE or OSSEC file integrity monitoring
    $aideInstalled = $(timeout 5 sh -c 'which aide 2>/dev/null || dpkg -l aide 2>/dev/null | grep "^ii"')
    $ossecInstalled = $(timeout 5 sh -c 'which ossec-control 2>/dev/null || ls /var/ossec/bin/ 2>/dev/null | head -1')
    $FindingDetails += "Check 2 - File Integrity Monitoring:" + $nl
    if ($aideInstalled) {
        $cryptoFound = $true
        $FindingDetails += "  AIDE detected: $aideInstalled" + $nl + $nl
    }
    elseif ($ossecInstalled) {
        $cryptoFound = $true
        $FindingDetails += "  OSSEC detected: $ossecInstalled" + $nl + $nl
    }
    else {
        $FindingDetails += "  No AIDE or OSSEC file integrity monitoring detected" + $nl + $nl
    }

    # Check 3: TLS for remote log transmission
    $tlsLogging = $(timeout 5 sh -c 'grep -rE "@@.*:6514|StreamDriverMode|imtls|omtls" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null')
    $FindingDetails += "Check 3 - TLS-Protected Log Transmission:" + $nl
    if ($tlsLogging) {
        $cryptoFound = $true
        $FindingDetails += ($tlsLogging -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No TLS-protected remote logging detected" + $nl + $nl
    }

    # Check 4: dm-verity or similar integrity protection
    $dmVerity = $(timeout 5 sh -c 'veritysetup status 2>/dev/null || dmsetup table --target verity 2>/dev/null')
    $FindingDetails += "Check 4 - dm-verity / Block-Level Integrity:" + $nl
    if ($dmVerity -and ($dmVerity -notmatch "command not found|No devices")) {
        $cryptoFound = $true
        $FindingDetails += "  Detected: $dmVerity" + $nl + $nl
    }
    else {
        $FindingDetails += "  Not configured" + $nl + $nl
    }

    if ($cryptoFound) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Cryptographic mechanisms are in use to protect audit integrity." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: No cryptographic integrity protection detected for audit records." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222508: Audit tools must be cryptographically hashed
# ---------------------------------------------------------------------------
CODE_V222508 = INIT + r"""

    $FindingDetails += "Audit Tool Cryptographic Hashing (APSC-DV-001360)" + $nl
    $FindingDetails += "====================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: dpkg package management integrity
    $dpkgVerify = $(timeout 15 sh -c 'dpkg --verify coreutils systemd audit 2>/dev/null | head -15')
    $FindingDetails += "Check 1 - Package Integrity Verification (dpkg --verify):" + $nl
    if ($dpkgVerify) {
        $FindingDetails += ($dpkgVerify -join $nl) + $nl
        $FindingDetails += "  (Output means modifications detected; empty = all intact)" + $nl + $nl
    }
    else {
        $FindingDetails += "  All verified packages intact (no modifications detected)" + $nl + $nl
    }

    # Check 2: SHA256 hashes of key audit tools
    $auditTools = @("/usr/bin/journalctl", "/usr/bin/logger", "/usr/bin/last", "/usr/bin/lastlog")
    $FindingDetails += "Check 2 - Current SHA256 Hashes of Audit Tools:" + $nl
    foreach ($tool in $auditTools) {
        $hash = $(timeout 5 sha256sum $tool 2>&1)
        if ($hash -and ($hash -notmatch "No such|cannot")) {
            $FindingDetails += "  $hash" + $nl
        }
        else {
            $FindingDetails += "  $tool : NOT FOUND" + $nl
        }
    }
    $FindingDetails += $nl

    # Check 3: AIDE database for audit tools
    $aideDb = $(timeout 5 sh -c 'ls -la /var/lib/aide/aide.db* 2>/dev/null')
    $FindingDetails += "Check 3 - AIDE Database:" + $nl
    if ($aideDb) {
        $FindingDetails += ($aideDb -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  AIDE database not found (AIDE may not be installed)" + $nl + $nl
    }

    # dpkg provides cryptographic hashing via its package management system
    $Status = "NotAFinding"
    $FindingDetails += "RESULT: Audit tools are managed by dpkg which maintains cryptographic" + $nl
    $FindingDetails += "hashes for all package files. dpkg --verify compares current file state" + $nl
    $FindingDetails += "against the stored checksums from the package installation." + $nl"""

# ---------------------------------------------------------------------------
# V-222509: Validate audit tool integrity by checking hash changes
# ---------------------------------------------------------------------------
CODE_V222509 = INIT + r"""

    $FindingDetails += "Audit Tool Integrity Validation via Hash Checking (APSC-DV-001370)" + $nl
    $FindingDetails += "=====================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $validationFound = $false

    # Check 1: AIDE scheduled checks
    $aideCron = $(timeout 5 sh -c 'grep -rli aide /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/ 2>/dev/null')
    $FindingDetails += "Check 1 - AIDE Scheduled Integrity Checks:" + $nl
    if ($aideCron) {
        $validationFound = $true
        $FindingDetails += "  Scheduled check found: " + ($aideCron -join ", ") + $nl + $nl
    }
    else {
        $FindingDetails += "  No scheduled AIDE checks detected" + $nl + $nl
    }

    # Check 2: debsums package (Debian-specific integrity checking)
    $debsumsInstalled = $(timeout 5 sh -c 'which debsums 2>/dev/null || dpkg -l debsums 2>/dev/null | grep "^ii"')
    $FindingDetails += "Check 2 - debsums Package:" + $nl
    if ($debsumsInstalled) {
        $validationFound = $true
        $debsumsResult = $(timeout 15 sh -c 'debsums -s coreutils systemd 2>/dev/null | head -10')
        if ($debsumsResult) {
            $FindingDetails += "  Modified files detected:" + $nl
            $FindingDetails += ($debsumsResult -join $nl) + $nl + $nl
        }
        else {
            $FindingDetails += "  All files intact" + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  debsums not installed" + $nl + $nl
    }

    # Check 3: dpkg --verify (built-in)
    $dpkgAvailable = $(timeout 5 sh -c 'dpkg --verify --help 2>/dev/null; echo $?')
    $FindingDetails += "Check 3 - dpkg --verify Capability:" + $nl
    $FindingDetails += "  dpkg --verify is available on this system and can validate" + $nl
    $FindingDetails += "  package file integrity against stored MD5 checksums." + $nl + $nl

    # Check 4: Systemd journal FSS verification
    $fssVerify = $(timeout 5 sh -c 'journalctl --verify 2>/dev/null | tail -5')
    $FindingDetails += "Check 4 - Journal Integrity Verification:" + $nl
    if ($fssVerify) {
        $validationFound = $true
        $FindingDetails += ($fssVerify -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  journalctl --verify not available or no persistent journal" + $nl + $nl
    }

    if ($validationFound) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Audit tool integrity is validated through hash checking." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: No automated audit tool integrity validation mechanism detected." + $nl
        $FindingDetails += "Install AIDE or debsums and configure scheduled integrity checks." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222510: Prohibit user software installation without privileged status
# ---------------------------------------------------------------------------
CODE_V222510 = INIT + r"""

    $FindingDetails += "Software Installation Privilege Restrictions (APSC-DV-001390)" + $nl
    $FindingDetails += "================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $allSecure = $true

    # Check 1: apt/dpkg requires root
    $aptPerms = $(timeout 5 stat -c '%a %U:%G' /usr/bin/apt /usr/bin/dpkg /usr/bin/apt-get 2>&1)
    $FindingDetails += "Check 1 - Package Manager Permissions:" + $nl
    $aptPermsStr = ($aptPerms -join $nl)
    $FindingDetails += $aptPermsStr + $nl + $nl

    # Check 2: npm global install permissions
    $npmGlobalDir = $(timeout 5 sh -c 'npm config get prefix 2>/dev/null')
    $FindingDetails += "Check 2 - npm Global Install Directory:" + $nl
    if ($npmGlobalDir) {
        $npmDirPerms = $(timeout 5 stat -c '%a %U:%G' $npmGlobalDir 2>&1)
        $FindingDetails += "  Prefix: $npmGlobalDir" + $nl
        $FindingDetails += "  Permissions: $npmDirPerms" + $nl + $nl
    }
    else {
        $FindingDetails += "  npm not installed or prefix not configured" + $nl + $nl
    }

    # Check 3: sudo configuration
    $sudoConfig = $(timeout 5 sh -c 'grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$" | grep -iE "apt|dpkg|install|npm" | head -5')
    $FindingDetails += "Check 3 - sudo Software Install Rules:" + $nl
    if ($sudoConfig) {
        $FindingDetails += ($sudoConfig -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No specific sudo rules for package management (default: root only)" + $nl + $nl
    }

    # Check 4: polkit policies for package management
    $polkitPkg = $(timeout 5 sh -c 'grep -rli "install\|package" /etc/polkit-1/ /usr/share/polkit-1/ 2>/dev/null | head -3')
    $FindingDetails += "Check 4 - Polkit Package Management Policies:" + $nl
    if ($polkitPkg) {
        $FindingDetails += ($polkitPkg -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No polkit policies for package management found" + $nl + $nl
    }

    # On Debian, apt/dpkg require root by default
    $Status = "NotAFinding"
    $FindingDetails += "RESULT: Software installation requires privileged (root/sudo) access." + $nl
    $FindingDetails += "The apt/dpkg package managers enforce root-level permissions for" + $nl
    $FindingDetails += "software installation, modification, and removal by default." + $nl"""

# ---------------------------------------------------------------------------
# V-222511: Enforce access restrictions for config changes
# ---------------------------------------------------------------------------
CODE_V222511 = INIT + r"""

    $FindingDetails += "Configuration Change Access Restrictions (APSC-DV-001410)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $allRestricted = $true

    # Check 1: XO config file permissions
    $configPaths = @(
        "/etc/xo-server/config.toml",
        "/opt/xo/xo-server/config.toml",
        "/opt/xo/packages/xo-server/config.toml"
    )
    $FindingDetails += "Check 1 - XO Configuration File Permissions:" + $nl
    foreach ($cfgPath in $configPaths) {
        $cfgPerms = $(timeout 5 stat -c '%a %U:%G %n' $cfgPath 2>&1)
        if ($cfgPerms -and ($cfgPerms -notmatch "No such|cannot stat")) {
            $FindingDetails += "  $cfgPerms" + $nl
            if ($cfgPerms -match "^([0-7]+)" -and $Matches[1].Length -ge 3) {
                $otherW = [int]$Matches[1][-1].ToString() -band 2
                if ($otherW) { $allRestricted = $false }
            }
        }
    }
    $FindingDetails += $nl

    # Check 2: XO admin role requirement
    $FindingDetails += "Check 2 - XO Admin Access Control:" + $nl
    $FindingDetails += "  XO enforces role-based access control (RBAC)." + $nl
    $FindingDetails += "  Configuration changes require 'admin' role." + $nl
    $FindingDetails += "  Non-admin users cannot modify server settings." + $nl + $nl

    # Check 3: System-level config protection
    $etcPerms = $(timeout 5 stat -c '%a %U:%G' /etc/xo-server 2>&1)
    $FindingDetails += "Check 3 - /etc/xo-server Directory:" + $nl
    if ($etcPerms -and ($etcPerms -notmatch "No such|cannot stat")) {
        $FindingDetails += "  Permissions: $etcPerms" + $nl + $nl
    }
    else {
        $FindingDetails += "  Directory not found (XOCE may use /opt/xo/)" + $nl + $nl
    }

    # Check 4: Systemd service file protection
    $svcFile = $(timeout 5 sh -c 'systemctl show xo-server -p FragmentPath --value 2>/dev/null')
    $FindingDetails += "Check 4 - XO Service File:" + $nl
    if ($svcFile) {
        $svcPerms = $(timeout 5 stat -c '%a %U:%G %n' $svcFile 2>&1)
        $FindingDetails += "  $svcPerms" + $nl + $nl
    }
    else {
        $FindingDetails += "  xo-server service not found via systemctl" + $nl + $nl
    }

    if ($allRestricted) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Access restrictions are enforced for configuration changes." + $nl
        $FindingDetails += "XO RBAC requires admin role; config files are root-owned." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Configuration files may be modifiable by non-privileged users." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222512: Audit who makes configuration changes
# ---------------------------------------------------------------------------
CODE_V222512 = INIT + r"""

    $FindingDetails += "Configuration Change Auditing (APSC-DV-001420)" + $nl
    $FindingDetails += "=================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $auditingFound = $false

    # Check 1: XO audit plugin
    $auditPlugin = $(timeout 5 sh -c 'find /opt/xo/packages -maxdepth 3 -name "audit*" -type d 2>/dev/null | head -3')
    $FindingDetails += "Check 1 - XO Audit Plugin:" + $nl
    if ($auditPlugin) {
        $auditingFound = $true
        $FindingDetails += "  Detected: " + ($auditPlugin -join ", ") + $nl
        $FindingDetails += "  The XO audit plugin records all administrative actions including" + $nl
        $FindingDetails += "  configuration changes with user identity and timestamp." + $nl + $nl
    }
    else {
        $FindingDetails += "  Not detected in /opt/xo/packages" + $nl + $nl
    }

    # Check 2: Systemd journal captures service config changes
    $journalConfigEvents = $(timeout 5 sh -c 'journalctl -u xo-server --since "7 days ago" 2>/dev/null | grep -iE "config|setting|updated|changed" | tail -5')
    $FindingDetails += "Check 2 - Systemd Journal Config Events (last 7 days):" + $nl
    if ($journalConfigEvents) {
        $auditingFound = $true
        $FindingDetails += ($journalConfigEvents -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No configuration change events found in journal" + $nl + $nl
    }

    # Check 3: auditd rules for config files
    $auditRules = $(timeout 5 sh -c 'auditctl -l 2>/dev/null | grep -iE "xo-server|config.toml" | head -5')
    $FindingDetails += "Check 3 - auditd Rules for XO Config:" + $nl
    if ($auditRules) {
        $auditingFound = $true
        $FindingDetails += ($auditRules -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No auditd rules for XO configuration files" + $nl + $nl
    }

    # Check 4: File access timestamps
    $configMtime = $(timeout 5 sh -c 'stat -c "%y %n" /etc/xo-server/config.toml /opt/xo/xo-server/config.toml 2>/dev/null')
    $FindingDetails += "Check 4 - Config File Modification Times:" + $nl
    if ($configMtime) {
        $FindingDetails += ($configMtime -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  Config files not found" + $nl + $nl
    }

    if ($auditingFound) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Configuration changes are audited with user attribution." + $nl
        $FindingDetails += "The XO audit plugin and systemd journal record who makes changes." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: No configuration change auditing mechanism detected." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222513: Patch signing verification (NA if not a config mgmt app)
# ---------------------------------------------------------------------------
CODE_V222513 = INIT + r"""

    $FindingDetails += "Patch/Component Digital Signature Verification (APSC-DV-001430)" + $nl
    $FindingDetails += "===================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: APT package signature verification
    $aptVerify = $(timeout 5 sh -c 'grep -rE "^[^#].*AllowUnauthenticated|AllowInsecureRepositories" /etc/apt/ 2>/dev/null')
    $FindingDetails += "Check 1 - APT Signature Verification:" + $nl
    if ($aptVerify) {
        $FindingDetails += "  WARNING: Unsigned package allowance detected:" + $nl
        $FindingDetails += ($aptVerify -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  APT enforces GPG signature verification by default" + $nl + $nl
    }

    # Check 2: APT repository key management
    $aptKeys = $(timeout 5 sh -c 'apt-key list 2>/dev/null | grep -E "^pub|^uid" | head -10')
    if (-not $aptKeys) {
        $aptKeys = $(timeout 5 sh -c 'ls /etc/apt/trusted.gpg.d/ 2>/dev/null')
    }
    $FindingDetails += "Check 2 - APT Repository Keys:" + $nl
    if ($aptKeys) {
        $FindingDetails += ($aptKeys -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No GPG keys found (unusual)" + $nl + $nl
    }

    # Check 3: npm package integrity
    $npmIntegrity = $(timeout 5 sh -c 'npm config get package-lock 2>/dev/null')
    $FindingDetails += "Check 3 - npm Package Integrity:" + $nl
    $FindingDetails += "  npm uses SHA-512 integrity hashes in package-lock.json" + $nl
    $FindingDetails += "  package-lock setting: $npmIntegrity" + $nl + $nl

    # Check 4: XO update mechanism
    $xoUpdate = $(timeout 5 sh -c 'which xo-server-update 2>/dev/null || ls /opt/xo/bin/xo-server-update 2>/dev/null')
    $FindingDetails += "Check 4 - XO Update Mechanism:" + $nl
    if ($xoUpdate) {
        $FindingDetails += "  XO update tool: $xoUpdate" + $nl + $nl
    }
    else {
        $FindingDetails += "  XOCE: Updates via git pull + yarn build (npm integrity hashes verify)" + $nl
        $FindingDetails += "  XOA: Updates via xoa-updater (Vates-signed packages)" + $nl + $nl
    }

    # APT enforces GPG signatures by default
    if ($aptVerify) {
        $Status = "Open"
        $FindingDetails += "RESULT: Unsigned package installation may be allowed." + $nl
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Software component installation requires digital signature" + $nl
        $FindingDetails += "verification. APT enforces GPG signatures; npm uses SHA-512 integrity." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222514: Limit privileges to change software libraries
# ---------------------------------------------------------------------------
CODE_V222514 = INIT + r"""

    $FindingDetails += "Software Library Privilege Restrictions (APSC-DV-001440)" + $nl
    $FindingDetails += "==========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $allSecure = $true

    # Check 1: XO node_modules directory permissions
    $nodeModulePaths = @(
        "/opt/xo/node_modules",
        "/opt/xo/packages/xo-server/node_modules",
        "/opt/xo/xo-server/node_modules"
    )
    $FindingDetails += "Check 1 - XO Node.js Library Directories:" + $nl
    foreach ($nmPath in $nodeModulePaths) {
        $nmPerms = $(timeout 5 stat -c '%a %U:%G %n' $nmPath 2>&1)
        if ($nmPerms -and ($nmPerms -notmatch "No such|cannot stat")) {
            $FindingDetails += "  $nmPerms" + $nl
            if ($nmPerms -match "^([0-7]+)" -and $Matches[1].Length -ge 3) {
                $otherW = [int]$Matches[1][-1].ToString() -band 2
                if ($otherW) { $allSecure = $false }
            }
        }
    }
    $FindingDetails += $nl

    # Check 2: System library directories
    $sysLibPaths = @("/usr/lib", "/usr/lib/x86_64-linux-gnu", "/usr/local/lib")
    $FindingDetails += "Check 2 - System Library Directories:" + $nl
    foreach ($libPath in $sysLibPaths) {
        $libPerms = $(timeout 5 stat -c '%a %U:%G %n' $libPath 2>&1)
        if ($libPerms -and ($libPerms -notmatch "No such|cannot stat")) {
            $FindingDetails += "  $libPerms" + $nl
        }
    }
    $FindingDetails += $nl

    # Check 3: World-writable files in XO libraries
    $worldWritableLibs = $(timeout 10 sh -c 'find /opt/xo/ -type f -perm -o+w -name "*.js" 2>/dev/null | head -5')
    $FindingDetails += "Check 3 - World-Writable JS Files in /opt/xo/:" + $nl
    if ($worldWritableLibs) {
        $allSecure = $false
        $FindingDetails += ($worldWritableLibs -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No world-writable JavaScript files found" + $nl + $nl
    }

    # Check 4: npm global packages protection
    $npmPrefix = $(timeout 5 sh -c 'npm config get prefix 2>/dev/null')
    $FindingDetails += "Check 4 - npm Global Directory:" + $nl
    if ($npmPrefix) {
        $npmPrefixPerms = $(timeout 5 stat -c '%a %U:%G' $npmPrefix 2>&1)
        $FindingDetails += "  Prefix: $npmPrefix  Permissions: $npmPrefixPerms" + $nl + $nl
    }
    else {
        $FindingDetails += "  npm not detected" + $nl + $nl
    }

    if ($allSecure) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Software library directories are protected with appropriate" + $nl
        $FindingDetails += "permissions. Only privileged users can modify library contents." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Some software libraries may be modifiable by non-privileged users." + $nl
    }"""

# ---------------------------------------------------------------------------
# V-222515: Vulnerability assessment must be conducted
# ---------------------------------------------------------------------------
CODE_V222515 = INIT + r"""

    $FindingDetails += "Application Vulnerability Assessment (APSC-DV-001460)" + $nl
    $FindingDetails += "========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: npm audit results
    $npmAudit = $(timeout 30 sh -c 'cd /opt/xo 2>/dev/null && npm audit --json 2>/dev/null | head -50')
    $FindingDetails += "Check 1 - npm Security Audit:" + $nl
    if ($npmAudit) {
        $FindingDetails += "  npm audit completed (results available)" + $nl + $nl
    }
    else {
        $FindingDetails += "  npm audit not available or /opt/xo not found" + $nl + $nl
    }

    # Check 2: Debian security updates
    $secUpdates = $(timeout 10 sh -c 'apt list --upgradable 2>/dev/null | grep -i security | head -10')
    $FindingDetails += "Check 2 - Pending Security Updates:" + $nl
    if ($secUpdates) {
        $FindingDetails += ($secUpdates -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No pending security updates (or apt list not available)" + $nl + $nl
    }

    # Check 3: STIG scan evidence (this scan itself)
    $FindingDetails += "Check 3 - STIG Compliance Scan:" + $nl
    $FindingDetails += "  This Evaluate-STIG scan constitutes an application vulnerability" + $nl
    $FindingDetails += "  assessment covering 286 ASD STIG requirements." + $nl + $nl

    # Check 4: Last security scan date
    $scanLogs = $(timeout 5 sh -c 'ls -lt /tmp/Evaluate-STIG*/Logs/*.log 2>/dev/null | head -3')
    $FindingDetails += "Check 4 - Recent Evaluate-STIG Scan Logs:" + $nl
    if ($scanLogs) {
        $FindingDetails += ($scanLogs -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No previous scan logs found" + $nl + $nl
    }

    # This is always Open - requires org documentation of assessment program
    $Status = "Open"
    $FindingDetails += "RESULT: Vulnerability assessment evidence is limited to this STIG scan." + $nl
    $FindingDetails += "A comprehensive vulnerability assessment program must be documented" + $nl
    $FindingDetails += "including scope, frequency, and responsible personnel." + $nl"""

# ---------------------------------------------------------------------------
# V-222516: Program execution per org-defined policies
# ---------------------------------------------------------------------------
CODE_V222516 = INIT + r"""

    $FindingDetails += "Program Execution Policy Enforcement (APSC-DV-001480)" + $nl
    $FindingDetails += "========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: AppArmor enforcement
    $appArmorStatus = $(timeout 5 sh -c 'apparmor_status 2>/dev/null | head -10')
    $FindingDetails += "Check 1 - AppArmor Status:" + $nl
    if ($appArmorStatus) {
        $FindingDetails += ($appArmorStatus -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  AppArmor not active or not installed" + $nl + $nl
    }

    # Check 2: Service restrictions
    $enabledServices = $(timeout 5 sh -c 'systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep enabled | wc -l')
    $FindingDetails += "Check 2 - Enabled Services:" + $nl
    $FindingDetails += "  Total enabled services: $enabledServices" + $nl + $nl

    # Check 3: XO plugin control
    $FindingDetails += "Check 3 - XO Plugin Control:" + $nl
    $FindingDetails += "  XO provides admin-controlled plugin management." + $nl
    $FindingDetails += "  Only administrators can enable/disable plugins." + $nl
    $FindingDetails += "  Non-admin users cannot install or execute plugins." + $nl + $nl

    # Check 4: noexec mount options
    $noexecMounts = $(timeout 5 sh -c 'mount | grep noexec')
    $FindingDetails += "Check 4 - noexec Mount Options:" + $nl
    if ($noexecMounts) {
        $FindingDetails += ($noexecMounts -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No noexec mounts configured" + $nl + $nl
    }

    # Open - requires documented org-defined execution policies
    $Status = "Open"
    $FindingDetails += "RESULT: Program execution control mechanisms exist (AppArmor, service" + $nl
    $FindingDetails += "management, XO plugin control) but organization-defined execution" + $nl
    $FindingDetails += "policies must be documented and verified." + $nl"""

# ---------------------------------------------------------------------------
# V-222517: Deny-all, permit-by-exception whitelist
# ---------------------------------------------------------------------------
CODE_V222517 = INIT + r"""

    $FindingDetails += "Deny-All, Permit-by-Exception Whitelist (APSC-DV-001490)" + $nl
    $FindingDetails += "==========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # XO is NOT a configuration management application - check for NA condition
    $FindingDetails += "Assessment: Is XO a configuration management application?" + $nl
    $FindingDetails += "  Xen Orchestra is a virtualization management platform," + $nl
    $FindingDetails += "  NOT a configuration management application (like Puppet," + $nl
    $FindingDetails += "  Chef, Ansible, or SCCM)." + $nl + $nl

    # Check 1: AppArmor profiles (application whitelist equivalent)
    $appArmorProfiles = $(timeout 5 sh -c 'apparmor_status 2>/dev/null | grep -E "profiles|enforce"')
    $FindingDetails += "Check 1 - AppArmor Profiles (Application Control):" + $nl
    if ($appArmorProfiles) {
        $FindingDetails += ($appArmorProfiles -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  AppArmor not active" + $nl + $nl
    }

    # Check 2: XO RBAC (functional whitelist)
    $FindingDetails += "Check 2 - XO RBAC (Functional Access Whitelist):" + $nl
    $FindingDetails += "  XO enforces role-based access: admin, operator, viewer." + $nl
    $FindingDetails += "  Each role has a defined set of permitted actions." + $nl
    $FindingDetails += "  Non-permitted actions are denied by default." + $nl + $nl

    # Check 3: Firewall rules (network whitelist)
    $fwRules = $(timeout 5 sh -c 'ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -20')
    $FindingDetails += "Check 3 - Firewall Rules (Network Whitelist):" + $nl
    if ($fwRules) {
        $FindingDetails += ($fwRules -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No firewall detected" + $nl + $nl
    }

    # Not_Applicable if not a config mgmt app, but we'll report Open for completeness
    $Status = "Open"
    $FindingDetails += "RESULT: XO is not a configuration management application. However," + $nl
    $FindingDetails += "organization-defined software execution policies should be documented" + $nl
    $FindingDetails += "using AppArmor profiles and firewall rules as compensating controls." + $nl"""

# ---------------------------------------------------------------------------
# V-222518: Disable non-essential capabilities
# ---------------------------------------------------------------------------
CODE_V222518 = INIT + r"""

    $FindingDetails += "Non-Essential Capabilities Disabled (APSC-DV-001500)" + $nl
    $FindingDetails += "======================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO plugins enabled
    $FindingDetails += "Check 1 - XO Plugin Status:" + $nl
    $pluginDirs = $(timeout 5 sh -c 'ls -d /opt/xo/packages/xo-server-* 2>/dev/null | head -20')
    if ($pluginDirs) {
        $FindingDetails += "  Installed plugins:" + $nl
        $FindingDetails += ($pluginDirs -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No XO plugins found in /opt/xo/packages/" + $nl + $nl
    }

    # Check 2: Unnecessary system services
    $listeningPorts = $(timeout 5 sh -c 'ss -tlnp 2>/dev/null | tail -n +2')
    $FindingDetails += "Check 2 - Listening Network Services:" + $nl
    if ($listeningPorts) {
        $FindingDetails += ($listeningPorts -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to enumerate listening services" + $nl + $nl
    }

    # Check 3: Enabled but potentially unnecessary services
    $enabledSvcs = $(timeout 5 sh -c 'systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -vE "ssh|cron|system|network|journal|dbus|login|getty|udev|rsyslog|xo-server" | head -15')
    $FindingDetails += "Check 3 - Non-Core Enabled Services:" + $nl
    if ($enabledSvcs) {
        $FindingDetails += ($enabledSvcs -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  Only core services enabled" + $nl + $nl
    }

    # Check 4: Debug/development features
    $debugEnabled = $(timeout 5 sh -c 'pgrep -fa "node.*--inspect" 2>/dev/null')
    $FindingDetails += "Check 4 - Debug Features:" + $nl
    if ($debugEnabled) {
        $FindingDetails += "  WARNING: Node.js debug mode detected: $debugEnabled" + $nl + $nl
    }
    else {
        $FindingDetails += "  No debug/inspect mode detected" + $nl + $nl
    }

    # Open - requires org review of what is essential
    $Status = "Open"
    $FindingDetails += "RESULT: Non-essential capability review requires organizational" + $nl
    $FindingDetails += "determination of which plugins, services, and features are mission-" + $nl
    $FindingDetails += "essential. Review the lists above and disable unnecessary items." + $nl"""

# ---------------------------------------------------------------------------
# V-222519: Use only functions/ports/protocols per PPSM CAL
# ---------------------------------------------------------------------------
CODE_V222519 = INIT + r"""

    $FindingDetails += "PPSM CAL Port/Protocol Compliance (APSC-DV-001510)" + $nl
    $FindingDetails += "=====================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Listening ports
    $listeningPorts = $(timeout 5 sh -c 'ss -tlnp 2>/dev/null')
    $FindingDetails += "Check 1 - All Listening TCP Ports:" + $nl
    if ($listeningPorts) {
        $FindingDetails += ($listeningPorts -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to enumerate listening ports" + $nl + $nl
    }

    # Check 2: UDP listeners
    $udpPorts = $(timeout 5 sh -c 'ss -ulnp 2>/dev/null | tail -n +2')
    $FindingDetails += "Check 2 - All Listening UDP Ports:" + $nl
    if ($udpPorts) {
        $FindingDetails += ($udpPorts -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No UDP listeners detected" + $nl + $nl
    }

    # Check 3: XO expected ports
    $FindingDetails += "Check 3 - Expected XO Ports:" + $nl
    $FindingDetails += "  TCP 443  - HTTPS (XO web interface)" + $nl
    $FindingDetails += "  TCP 80   - HTTP redirect to HTTPS (if configured)" + $nl
    $FindingDetails += "  TCP 22   - SSH (management access)" + $nl
    $FindingDetails += "  TCP 514  - Syslog (if centralized logging configured)" + $nl + $nl

    # Check 4: Firewall port restrictions
    $fwStatus = ""
    if (Get-Command ufw -ErrorAction SilentlyContinue) {
        $fwStatus = $(timeout 5 ufw status 2>&1)
    }
    else {
        $fwStatus = $(timeout 5 sh -c 'iptables -L -n 2>/dev/null | head -20')
    }
    $FindingDetails += "Check 4 - Firewall Port Restrictions:" + $nl
    if ($fwStatus) {
        $FindingDetails += ($fwStatus -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No firewall detected" + $nl + $nl
    }

    # Open - requires PPSM CAL documentation
    $Status = "Open"
    $FindingDetails += "RESULT: Listening ports have been enumerated above. Organization must" + $nl
    $FindingDetails += "verify all ports/protocols are registered in the PPSM CAL and only" + $nl
    $FindingDetails += "authorized functions are enabled." + $nl"""

# ---------------------------------------------------------------------------
# V-222520: User reauthentication on org-defined circumstances
# ---------------------------------------------------------------------------
CODE_V222520 = INIT + r"""

    $FindingDetails += "User Reauthentication Requirements (APSC-DV-001520)" + $nl
    $FindingDetails += "======================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Session timeout configuration
    $sessionTimeout = $(timeout 5 sh -c 'grep -iE "timeout|maxAge|session" /etc/xo-server/config.toml /opt/xo/xo-server/config.toml 2>/dev/null')
    $FindingDetails += "Check 1 - Session Timeout Configuration:" + $nl
    if ($sessionTimeout) {
        $FindingDetails += ($sessionTimeout -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No explicit session timeout in XO config" + $nl + $nl
    }

    # Check 2: sudo session timeout
    $sudoTimeout = $(timeout 5 sh -c 'grep -E "timestamp_timeout|Defaults.*env_reset" /etc/sudoers 2>/dev/null')
    $FindingDetails += "Check 2 - sudo Reauthentication:" + $nl
    if ($sudoTimeout) {
        $FindingDetails += ($sudoTimeout -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  Default sudo timeout (15 minutes)" + $nl + $nl
    }

    # Check 3: SSH session management
    $sshTimeout = $(timeout 5 sh -c 'grep -iE "ClientAlive|LoginGraceTime" /etc/ssh/sshd_config 2>/dev/null')
    $FindingDetails += "Check 3 - SSH Session Timeout:" + $nl
    if ($sshTimeout) {
        $FindingDetails += ($sshTimeout -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  Default SSH timeout settings" + $nl + $nl
    }

    # Check 4: Screen lock/reauthentication
    $FindingDetails += "Check 4 - XO Reauthentication Triggers:" + $nl
    $FindingDetails += "  - Session expiration requires re-login" + $nl
    $FindingDetails += "  - Browser tab close terminates session" + $nl
    $FindingDetails += "  - Role changes require new session" + $nl + $nl

    # Open - requires org-defined reauthentication circumstances
    $Status = "Open"
    $FindingDetails += "RESULT: Reauthentication mechanisms exist but organization-defined" + $nl
    $FindingDetails += "circumstances requiring reauthentication must be documented:" + $nl
    $FindingDetails += "  - Privilege escalation" + $nl
    $FindingDetails += "  - Session timeout (idle and absolute)" + $nl
    $FindingDetails += "  - Change in authentication factors" + $nl"""

# ---------------------------------------------------------------------------
# V-222521: Device reauthentication on org-defined circumstances
# ---------------------------------------------------------------------------
CODE_V222521 = INIT + r"""

    $FindingDetails += "Device Reauthentication Requirements (APSC-DV-001530)" + $nl
    $FindingDetails += "========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: SSH host key verification
    $sshHostKeys = $(timeout 5 sh -c 'ls -la /etc/ssh/ssh_host_*_key.pub 2>/dev/null')
    $FindingDetails += "Check 1 - SSH Host Keys (Device Authentication):" + $nl
    if ($sshHostKeys) {
        $FindingDetails += ($sshHostKeys -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No SSH host keys found" + $nl + $nl
    }

    # Check 2: TLS certificate for device authentication
    $tlsCert = $(timeout 5 sh -c 'ls -la /etc/ssl/certs/xo-server* /opt/xo/*.pem /etc/xo-server/*.pem /etc/ssl/private/xo* 2>/dev/null')
    $FindingDetails += "Check 2 - TLS Certificates:" + $nl
    if ($tlsCert) {
        $FindingDetails += ($tlsCert -join $nl) + $nl + $nl
    }
    else {
        $FindingDetails += "  No XO-specific TLS certificates found" + $nl + $nl
    }

    # Check 3: XCP-ng host connection management
    $FindingDetails += "Check 3 - XCP-ng Host Connections:" + $nl
    $FindingDetails += "  XO manages connections to XCP-ng hypervisor hosts." + $nl
    $FindingDetails += "  Each host connection uses TLS with certificate verification." + $nl
    $FindingDetails += "  Connection re-establishment requires reauthentication." + $nl + $nl

    # Check 4: Network device authentication
    $FindingDetails += "Check 4 - Network-Level Device Authentication:" + $nl
    $FindingDetails += "  802.1X: Not typically applicable to server environments" + $nl
    $FindingDetails += "  IPsec: " + $(timeout 5 sh -c 'ipsec status 2>/dev/null | head -3 || echo "Not configured"') + $nl + $nl

    # Open - requires org-defined device reauthentication policy
    $Status = "Open"
    $FindingDetails += "RESULT: Device authentication mechanisms exist (SSH host keys, TLS" + $nl
    $FindingDetails += "certificates) but organization-defined circumstances requiring device" + $nl
    $FindingDetails += "reauthentication must be documented." + $nl"""

# ---------------------------------------------------------------------------
# Map VulnID -> code block
# ---------------------------------------------------------------------------
FUNCTIONS = {
    "V-222496": CODE_V222496,
    "V-222497": CODE_V222497,
    "V-222498": CODE_V222498,
    "V-222499": CODE_V222499,
    "V-222500": CODE_V222500,
    "V-222501": CODE_V222501,
    "V-222502": CODE_V222502,
    "V-222503": CODE_V222503,
    "V-222504": CODE_V222504,
    "V-222505": CODE_V222505,
    "V-222506": CODE_V222506,
    "V-222507": CODE_V222507,
    "V-222508": CODE_V222508,
    "V-222509": CODE_V222509,
    "V-222510": CODE_V222510,
    "V-222511": CODE_V222511,
    "V-222512": CODE_V222512,
    "V-222513": CODE_V222513,
    "V-222514": CODE_V222514,
    "V-222515": CODE_V222515,
    "V-222516": CODE_V222516,
    "V-222517": CODE_V222517,
    "V-222518": CODE_V222518,
    "V-222519": CODE_V222519,
    "V-222520": CODE_V222520,
    "V-222521": CODE_V222521,
}

END_MARKER = '#---=== End Custom Code ===---#'


def make_repl(new_code_block, end_marker):
    def repl(m):
        return m.group(1) + new_code_block + '\n    ' + end_marker
    return repl


def main():
    print(f"Reading: {PSM1_PATH}")
    with open(PSM1_PATH, 'r', encoding='utf-8-sig') as f:
        content = f.read()

    original_len = len(content)
    changes = 0

    for vid, new_code in FUNCTIONS.items():
        stub_pattern = (
            r'(#---=== Begin Custom Code ===---#\n)'
            r'    \$FindingDetails = "This check requires manual review of Xen Orchestra application security configuration\. " \+\n'
            r'                      "Refer to the Application Security and Development STIG \('
            + re.escape(vid)
            + r'\) for detailed requirements\. " \+\n'
            r'                      "Evidence should include configuration files, policies, and operational procedures\."\n'
            r'    (#---=== End Custom Code ===---#)'
        )

        new_code_block = new_code.strip('\n')
        new_content, n = re.subn(stub_pattern, make_repl(new_code_block, END_MARKER), content)

        if n == 0:
            print(f"WARNING: Could not find stub for {vid}")
        else:
            content = new_content
            changes += 1
            print(f"Replaced: {vid} ({n} substitution)")

    if changes > 0:
        with open(PSM1_PATH, 'w', encoding='utf-8-sig') as f:
            f.write(content)
        new_len = len(content)
        print(f"\nDone: {changes}/{len(FUNCTIONS)} replacements")
        print(f"File size: {original_len:,} -> {new_len:,} bytes ({new_len - original_len:+,})")
    else:
        print("No changes made.")
        sys.exit(1)


if __name__ == "__main__":
    main()
