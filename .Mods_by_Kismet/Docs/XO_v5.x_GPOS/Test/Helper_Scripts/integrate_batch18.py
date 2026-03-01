#!/usr/bin/env python3
"""Batch 18 integration — replaces 10 remaining stubs with implementations.

V-203621 (CAT II) — Audit privilege access attempts (XO Audit Plugin Category A)
V-203700 (CAT III) — Audit storage capacity (1 week minimum)
V-203701 (CAT III) — Offload audit records to different system
V-203702 (CAT III) — Notify SA/ISSO at 75% audit storage
V-203704 (CAT III) — Audit reduction on-demand
V-203705 (CAT III) — Audit reduction after-the-fact
V-203706 (CAT III) — Report generation on-demand
V-203707 (CAT III) — Report generation on-demand requirements
V-203708 (CAT III) — Report generation after-the-fact
V-203714 (CAT III) — Timestamps mappable to UTC
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

# ---------- implementations ----------

IMPLEMENTATIONS = {}

# V-203621 — Audit records when privilege access attempts occur (Category A — XO Audit Plugin compensates)
IMPLEMENTATIONS["V-203621"] = {
    "stig_id": "SRG-OS-000064-GPOS-00033",
    "rule_id": "SV-203621r958446_rule",
    "rule_title": "The operating system must generate audit records when successful/unsuccessful attempts to access privileges occur.",
    "discuss_md5": "54b117448d2d37375c1440c2f61bb02a",
    "check_md5": "d0cee44c137e88f3fbdca667ac3851cc",
    "fix_md5": "6703a881a425728055359852719833c4",
    "body": r'''
    $nl = [Environment]::NewLine
    $auditIssues = 0

    $FindingDetails += "CHECK 1: auditd Service Status" + $nl
    $FindingDetails += "------------------------------" + $nl
    $auditdStatus = $(timeout 5 systemctl is-active auditd 2>&1)
    $FindingDetails += "Service active: $auditdStatus" + $nl
    if ($auditdStatus -ne "active") {
        $auditIssues++
        $FindingDetails += "FAIL: auditd is not active" + $nl
    }
    else {
        $FindingDetails += "PASS: auditd is running" + $nl
    }

    $FindingDetails += $nl + "CHECK 2: Audit Rules for Privilege Access" + $nl
    $FindingDetails += "-----------------------------------------" + $nl
    $auditRules = $(timeout 5 auditctl -l 2>&1)
    if ($auditRules -and ($auditRules -notmatch "No rules")) {
        $privRules = (($auditRules -split $nl) | Where-Object { $_ -match "execve" -or $_ -match "-F perm=x" -or $_ -match "privileged" -or $_ -match "sudo|su |passwd|chsh|chfn|newgrp|gpasswd" })
        $pCount = ($privRules | Measure-Object).Count
        $FindingDetails += "Privilege access rules found: $pCount" + $nl
        if ($pCount -gt 0) {
            $FindingDetails += "PASS: Audit rules monitor privilege access attempts" + $nl
            foreach ($r in ($privRules | Select-Object -First 5)) {
                $FindingDetails += "  $r" + $nl
            }
        }
        else {
            $auditIssues++
            $FindingDetails += "FAIL: No audit rules for privilege access" + $nl
        }
    }
    else {
        $auditIssues++
        $FindingDetails += "FAIL: No audit rules loaded" + $nl
    }

    $FindingDetails += $nl + "CHECK 3: Privilege Access Audit Events in Log" + $nl
    $FindingDetails += "----------------------------------------------" + $nl
    $privEvents = $(timeout 5 grep -c -E "type=SYSCALL.*execve|type=USER_CMD|sudo:" /var/log/audit/audit.log 2>&1)
    if ($privEvents -match "^\d+$" -and [int]$privEvents -gt 0) {
        $FindingDetails += "Privilege access events: $privEvents" + $nl
        $FindingDetails += "PASS: Audit log contains privilege access records" + $nl
    }
    else {
        $FindingDetails += "Privilege events: 0 or log not accessible" + $nl
        $auditIssues++
    }

    # Check 4: XO Audit Plugin (Application-Layer Auditing)
    $FindingDetails += $nl + "--- Check 4: XO Audit Plugin ---" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE" + $nl
        $FindingDetails += "  Recent audit records: $($xoAuditInfo.RecordCount)" + $nl
        $FindingDetails += "  Hash chain integrity: $($xoAuditInfo.HasIntegrity)" + $nl
        $FindingDetails += "  Token source: $($xoAuditInfo.TokenSource)" + $nl
        $FindingDetails += "  [PASS] XO Audit Plugin provides application-layer privilege access recording via authenticated admin action tracking in audit records" + $nl
        $xoAuditCompensates = $true
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
        $FindingDetails += "  Reason: $($xoAuditInfo.Details)" + $nl
        $FindingDetails += "  [INFO] No application-layer audit compensation available" + $nl
        $xoAuditCompensates = $false
    }
    $FindingDetails += $nl

    if ($auditIssues -eq 0) {
        $Status = "NotAFinding"
    }
    elseif ($xoAuditCompensates) {
        $Status = "NotAFinding"
        $FindingDetails += "COMPENSATING CONTROL: While auditd is not active, the XO Audit Plugin" + $nl
        $FindingDetails += "provides application-layer auditing with hash chain integrity that" + $nl
        $FindingDetails += "satisfies this requirement for the Xen Orchestra application." + $nl
    }
'''
}

# V-203700 — Audit storage capacity (1 week minimum)
IMPLEMENTATIONS["V-203700"] = {
    "stig_id": "SRG-OS-000341-GPOS-00132",
    "rule_id": "SV-203700r958752_rule",
    "rule_title": "The operating system must allocate audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility.",
    "discuss_md5": "29cc73b5cd4801ac006e1c2002b2edec",
    "check_md5": "be0bce28d0b9e9288eecf0aec28f52e6",
    "fix_md5": "ab5df7ae5a259006470db751dc25b5cd",
    "body": r'''
    $nl = [Environment]::NewLine
    $auditIssues = 0

    $FindingDetails += "CHECK 1: /var/log Partition Space" + $nl
    $FindingDetails += "--------------------------------" + $nl
    $dfOutput = $(timeout 5 df -h /var/log 2>&1)
    if ($dfOutput) {
        $FindingDetails += ($dfOutput -split $nl | Select-Object -Last 1) + $nl
        $availLine = ($dfOutput -split $nl | Select-Object -Last 1)
        if ($availLine -match "(\d+)%") {
            $usedPct = [int]$matches[1]
            $FindingDetails += "Usage: ${usedPct}%" + $nl
            if ($usedPct -lt 90) {
                $FindingDetails += "PASS: Adequate space available for audit storage" + $nl
            }
            else {
                $auditIssues++
                $FindingDetails += "FAIL: Disk usage at ${usedPct}% - insufficient capacity" + $nl
            }
        }
    }
    else {
        $auditIssues++
        $FindingDetails += "FAIL: Unable to check /var/log disk space" + $nl
    }

    $FindingDetails += $nl + "CHECK 2: Journal Persistent Storage" + $nl
    $FindingDetails += "-----------------------------------" + $nl
    $journalConf = $(timeout 5 grep -E "^Storage=" /etc/systemd/journald.conf 2>&1)
    if ($journalConf -match "persistent") {
        $FindingDetails += "Journal storage: persistent" + $nl
        $FindingDetails += "PASS: Journal configured for persistent storage" + $nl
    }
    else {
        $FindingDetails += "Journal storage: $journalConf" + $nl
        $journalDir = $(timeout 5 ls -la /var/log/journal/ 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $FindingDetails += "PASS: /var/log/journal/ directory exists (implicit persistent)" + $nl
        }
        else {
            $auditIssues++
            $FindingDetails += "FAIL: Journal not configured for persistent storage" + $nl
        }
    }

    $FindingDetails += $nl + "CHECK 3: Log Rotation Configuration" + $nl
    $FindingDetails += "------------------------------------" + $nl
    $logrotateConf = $(timeout 5 grep -E "rotate |weekly|daily|maxsize" /etc/logrotate.conf 2>&1)
    if ($logrotateConf) {
        foreach ($line in ($logrotateConf -split $nl | Select-Object -First 5)) {
            $FindingDetails += "  $line" + $nl
        }
        if ($logrotateConf -match "rotate\s+(\d+)") {
            $rotateCount = [int]$matches[1]
            $FindingDetails += "Rotation count: $rotateCount" + $nl
            if ($rotateCount -ge 4) {
                $FindingDetails += "PASS: Log rotation retains at least 4 rotations" + $nl
            }
            else {
                $auditIssues++
                $FindingDetails += "FAIL: Rotation count $rotateCount is less than 4" + $nl
            }
        }
    }
    else {
        $auditIssues++
        $FindingDetails += "FAIL: logrotate configuration not found" + $nl
    }

    if ($auditIssues -eq 0) {
        $Status = "NotAFinding"
    }
'''
}

# V-203701 — Offload audit records onto a different system
IMPLEMENTATIONS["V-203701"] = {
    "stig_id": "SRG-OS-000342-GPOS-00133",
    "rule_id": "SV-203701r958754_rule",
    "rule_title": "The operating system must offload audit records onto a different system or media from the system being audited.",
    "discuss_md5": "70944557094cf5c2cbca167073bdd4b1",
    "check_md5": "4fa7b1ca17e229c958b97b688beb3418",
    "fix_md5": "9a6025fd40cc61bd0d500cf5716600a4",
    "body": r'''
    $nl = [Environment]::NewLine
    $auditIssues = 0

    $FindingDetails += "CHECK 1: rsyslog Remote Forwarding" + $nl
    $FindingDetails += "----------------------------------" + $nl
    $rsyslogConf = $(timeout 5 grep -r "@@\|action.*type=" /etc/rsyslog.conf /etc/rsyslog.d/ 2>&1)
    if ($rsyslogConf -and $rsyslogConf -notmatch "No such file") {
        $remoteLines = ($rsyslogConf -split $nl) | Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^#" -and ($_ -match "@@" -or $_ -match "action.*type=") }
        $rCount = ($remoteLines | Measure-Object).Count
        $FindingDetails += "Remote forwarding rules: $rCount" + $nl
        foreach ($r in ($remoteLines | Select-Object -First 5)) {
            $FindingDetails += "  $r" + $nl
        }
        if ($rCount -gt 0) {
            $FindingDetails += "PASS: rsyslog configured to offload records" + $nl
        }
        else {
            $auditIssues++
            $FindingDetails += "FAIL: No remote forwarding in rsyslog" + $nl
        }
    }
    else {
        $auditIssues++
        $FindingDetails += "rsyslog remote forwarding: Not configured" + $nl
    }

    $FindingDetails += $nl + "CHECK 2: systemd-journal-upload" + $nl
    $FindingDetails += "-------------------------------" + $nl
    $journalUpload = $(timeout 5 systemctl is-active systemd-journal-upload 2>&1)
    $FindingDetails += "systemd-journal-upload: $journalUpload" + $nl
    if ($journalUpload -eq "active") {
        $FindingDetails += "PASS: Journal upload service is active" + $nl
    }
    else {
        $FindingDetails += "INFO: Journal upload service not active" + $nl
    }

    $FindingDetails += $nl + "CHECK 3: audisp-remote Plugin" + $nl
    $FindingDetails += "-----------------------------" + $nl
    $audispConf = $(timeout 5 cat /etc/audisp/audisp-remote.conf 2>&1)
    if ($LASTEXITCODE -eq 0 -and $audispConf -match "remote_server") {
        $serverLine = ($audispConf -split $nl) | Where-Object { $_ -match "remote_server" -and $_ -notmatch "^#" }
        $FindingDetails += "audisp-remote: $serverLine" + $nl
        $FindingDetails += "PASS: audisp configured for remote audit" + $nl
    }
    else {
        $FindingDetails += "audisp-remote: Not configured or not found" + $nl
    }

    # If no remote offloading detected at all
    if ($auditIssues -gt 0 -and $journalUpload -ne "active") {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No audit record offloading mechanism detected." + $nl
    }
    else {
        $Status = "NotAFinding"
    }
'''
}

# V-203702 — Notify SA/ISSO at 75% audit storage
IMPLEMENTATIONS["V-203702"] = {
    "stig_id": "SRG-OS-000343-GPOS-00134",
    "rule_id": "SV-203702r971542_rule",
    "rule_title": "The operating system must immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.",
    "discuss_md5": "dc95ad86be604b1f625fc835e4af8813",
    "check_md5": "28c0214bc080a7265273e1c1988401e8",
    "fix_md5": "1e6f59c0627eb0692d915a8b7ca63706",
    "body": r'''
    $nl = [Environment]::NewLine
    $auditIssues = 0

    $FindingDetails += "CHECK 1: auditd Space-Left Configuration" + $nl
    $FindingDetails += "----------------------------------------" + $nl
    $auditdConf = $(timeout 5 cat /etc/audit/auditd.conf 2>&1)
    if ($LASTEXITCODE -eq 0 -and $auditdConf) {
        $spaceLine = ($auditdConf -split $nl) | Where-Object { $_ -match "^space_left\s*=" }
        $actionLine = ($auditdConf -split $nl) | Where-Object { $_ -match "^space_left_action\s*=" }
        $adminLine = ($auditdConf -split $nl) | Where-Object { $_ -match "^admin_space_left_action\s*=" }
        $FindingDetails += "space_left: $spaceLine" + $nl
        $FindingDetails += "space_left_action: $actionLine" + $nl
        $FindingDetails += "admin_space_left_action: $adminLine" + $nl
        if ($actionLine -match "email|exec|syslog") {
            $FindingDetails += "PASS: Notification action configured" + $nl
        }
        else {
            $auditIssues++
            $FindingDetails += "FAIL: No notification action for space_left" + $nl
        }
    }
    else {
        $auditIssues++
        $FindingDetails += "auditd.conf: Not found or not readable" + $nl
    }

    $FindingDetails += $nl + "CHECK 2: action_mail_acct Configuration" + $nl
    $FindingDetails += "---------------------------------------" + $nl
    if ($auditdConf) {
        $mailAcct = ($auditdConf -split $nl) | Where-Object { $_ -match "^action_mail_acct\s*=" }
        $FindingDetails += "action_mail_acct: $mailAcct" + $nl
        if ($mailAcct -match "root|admin") {
            $FindingDetails += "PASS: Email notification target configured" + $nl
        }
        else {
            $FindingDetails += "INFO: Email notification may not be configured" + $nl
        }
    }

    $FindingDetails += $nl + "CHECK 3: Disk Space Monitoring" + $nl
    $FindingDetails += "------------------------------" + $nl
    $dfOutput = $(timeout 5 df -h /var/log 2>&1)
    if ($dfOutput) {
        $FindingDetails += ($dfOutput -split $nl | Select-Object -Last 1) + $nl
        $useLine = ($dfOutput -split $nl | Select-Object -Last 1)
        if ($useLine -match "(\d+)%") {
            $usedPct = [int]$matches[1]
            $FindingDetails += "Current usage: ${usedPct}%" + $nl
            if ($usedPct -ge 75) {
                $FindingDetails += "WARNING: Disk usage at ${usedPct}% - exceeds 75% threshold" + $nl
            }
        }
    }

    if ($auditIssues -eq 0) {
        $Status = "NotAFinding"
    }
'''
}

# Helper for audit reduction / report generation (V-203704 through V-203708)
def _make_audit_tool_impl(vid, rule_id, stig_id, discuss_md5, check_md5, fix_md5, rule_title, check_type, check_desc):
    """Generate implementation for audit reduction / report generation checks."""
    return {
        "stig_id": stig_id,
        "rule_id": rule_id,
        "rule_title": rule_title,
        "discuss_md5": discuss_md5,
        "check_md5": check_md5,
        "fix_md5": fix_md5,
        "body": r'''
    $nl = [Environment]::NewLine
    $toolsFound = 0

    $FindingDetails += "CHECK 1: aureport Utility" + $nl
    $FindingDetails += "-------------------------" + $nl
    $aureportPath = $(which aureport 2>&1)
    if ($LASTEXITCODE -eq 0 -and $aureportPath -match "/aureport") {
        $FindingDetails += "aureport: AVAILABLE ($aureportPath)" + $nl
        $FindingDetails += "  Supports ''' + check_type + r''' for ''' + check_desc + r'''" + $nl
        $toolsFound++
    }
    else {
        $FindingDetails += "aureport: NOT FOUND" + $nl
    }

    $FindingDetails += $nl + "CHECK 2: ausearch Utility" + $nl
    $FindingDetails += "-------------------------" + $nl
    $ausearchPath = $(which ausearch 2>&1)
    if ($LASTEXITCODE -eq 0 -and $ausearchPath -match "/ausearch") {
        $FindingDetails += "ausearch: AVAILABLE ($ausearchPath)" + $nl
        $FindingDetails += "  Supports search and filtering of audit records" + $nl
        $toolsFound++
    }
    else {
        $FindingDetails += "ausearch: NOT FOUND" + $nl
    }

    $FindingDetails += $nl + "CHECK 3: journalctl Capability" + $nl
    $FindingDetails += "------------------------------" + $nl
    $journalctlPath = $(which journalctl 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "journalctl: AVAILABLE" + $nl
        $FindingDetails += "  Supports time-based queries (--since/--until)" + $nl
        $FindingDetails += "  Supports priority filtering (--priority)" + $nl
        $FindingDetails += "  Supports output formats (json, verbose, short-iso)" + $nl
        $toolsFound++
    }
    else {
        $FindingDetails += "journalctl: NOT FOUND" + $nl
    }

    # Check 4: XO Audit Plugin
    $FindingDetails += $nl + "--- Check 4: XO Audit Plugin ---" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE" + $nl
        $FindingDetails += "  REST API provides search and filtering at /rest/v0/plugins/audit/records" + $nl
        $FindingDetails += "  Records: $($xoAuditInfo.RecordCount) recent entries" + $nl
        $FindingDetails += "  [PASS] XO Audit Plugin provides application-layer ''' + check_type + r'''" + $nl
        $toolsFound++
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
        $FindingDetails += "  Reason: $($xoAuditInfo.Details)" + $nl
    }
    $FindingDetails += $nl

    if ($toolsFound -ge 1) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: $toolsFound ''' + check_type + r''' tool(s) available for ''' + check_desc + r'''." + $nl
    }
    else {
        $FindingDetails += "RESULT: No ''' + check_type + r''' tools detected." + $nl
    }
'''
    }

IMPLEMENTATIONS["V-203704"] = _make_audit_tool_impl(
    "V-203704", "SV-203704r958766_rule", "SRG-OS-000348-GPOS-00136",
    "fcbe41fc9b84face96567d3a6c0bdf85", "1fa4677fc1a85835a5679e09b8be3bd8", "4b511b6aec9be0fd4d006f44de62d5c9",
    "The operating system must provide an audit reduction capability that supports on-demand audit review and analysis.",
    "audit reduction", "on-demand audit review and analysis"
)

IMPLEMENTATIONS["V-203705"] = _make_audit_tool_impl(
    "V-203705", "SV-203705r958768_rule", "SRG-OS-000349-GPOS-00137",
    "bffa24953e8d5a6eca9da316e16bb092", "437aa94aa0154845179e343f31c3a922", "4dac99619a954868c6bcc9a08a18803a",
    "The operating system must provide an audit reduction capability that supports after-the-fact investigations of security incidents.",
    "audit reduction", "after-the-fact investigation of security incidents"
)

IMPLEMENTATIONS["V-203706"] = _make_audit_tool_impl(
    "V-203706", "SV-203706r958770_rule", "SRG-OS-000350-GPOS-00138",
    "7e437bbe2ea4350c4b0ab2aaafbb266d", "f2ac10ea966e0429c8c77e6eceebf776", "f412d97e4b66cae6a5446ff79acc13fc",
    "The operating system must provide a report generation capability that supports on-demand audit review and analysis.",
    "report generation", "on-demand audit review and analysis"
)

IMPLEMENTATIONS["V-203707"] = _make_audit_tool_impl(
    "V-203707", "SV-203707r958772_rule", "SRG-OS-000351-GPOS-00139",
    "aa7f8b04bcfcfb018abf19516c3556e7", "cf45b1ff89b5e87d79786b66d8723cf3", "db82a04ea8fd2126a33f5567d0901d5a",
    "The operating system must provide a report generation capability that supports on-demand reporting requirements.",
    "report generation", "on-demand reporting requirements"
)

IMPLEMENTATIONS["V-203708"] = _make_audit_tool_impl(
    "V-203708", "SV-203708r958774_rule", "SRG-OS-000352-GPOS-00140",
    "478f6e5569d39bf28f728f1c1e486951", "0f988c1f7f692d9afd2aa2644c877c9b", "d48398051d702d9bd3add2bd1f0965ed",
    "The operating system must provide a report generation capability that supports after-the-fact investigations of security incidents.",
    "report generation", "after-the-fact investigation of security incidents"
)

# V-203714 — Timestamps mappable to UTC
IMPLEMENTATIONS["V-203714"] = {
    "stig_id": "SRG-OS-000359-GPOS-00146",
    "rule_id": "SV-203714r958788_rule",
    "rule_title": "The operating system must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).",
    "discuss_md5": "05e0521723c26e924165487459b87cb0",
    "check_md5": "dd1e719d63cc7418e6d0640929eccb6d",
    "fix_md5": "31f17fde4abe096ce6e12599032b4993",
    "body": r'''
    $nl = [Environment]::NewLine
    $auditIssues = 0

    $FindingDetails += "CHECK 1: System Timezone Configuration" + $nl
    $FindingDetails += "--------------------------------------" + $nl
    $timectl = $(timeout 5 timedatectl 2>&1)
    if ($timectl) {
        $tzLine = ($timectl -split $nl) | Where-Object { $_ -match "Time zone" }
        $utcLine = ($timectl -split $nl) | Where-Object { $_ -match "Universal time" }
        $FindingDetails += "  $($tzLine.Trim())" + $nl
        $FindingDetails += "  $($utcLine.Trim())" + $nl
        if ($tzLine -match "UTC|GMT|Etc/UTC|Etc/GMT") {
            $FindingDetails += "PASS: System timezone is UTC/GMT" + $nl
        }
        else {
            $FindingDetails += "INFO: System timezone is not UTC but timestamps can be mapped to UTC" + $nl
        }
    }
    else {
        $FindingDetails += "timedatectl: not available" + $nl
    }

    $FindingDetails += $nl + "CHECK 2: NTP Synchronization Active" + $nl
    $FindingDetails += "------------------------------------" + $nl
    $ntpSync = $(timeout 5 timedatectl show -p NTPSynchronized --value 2>&1)
    $FindingDetails += "NTP synchronized: $ntpSync" + $nl
    if ($ntpSync -eq "yes") {
        $FindingDetails += "PASS: NTP sync ensures UTC mapping accuracy" + $nl
    }
    else {
        $auditIssues++
        $FindingDetails += "FAIL: NTP synchronization not active" + $nl
    }

    $FindingDetails += $nl + "CHECK 3: Audit Log Timestamp Format" + $nl
    $FindingDetails += "------------------------------------" + $nl
    $auditSample = $(timeout 5 tail -5 /var/log/audit/audit.log 2>&1)
    if ($LASTEXITCODE -eq 0 -and $auditSample -match "msg=audit\((\d+\.\d+)") {
        $FindingDetails += "Audit log uses epoch timestamps (UTC-based): $($matches[1])" + $nl
        $FindingDetails += "PASS: Epoch timestamps are inherently UTC-mappable" + $nl
    }
    else {
        $FindingDetails += "audit.log: Not accessible or empty" + $nl
    }

    $FindingDetails += $nl + "CHECK 4: Journal Timestamp UTC Capability" + $nl
    $FindingDetails += "-----------------------------------------" + $nl
    $journalUtc = $(timeout 5 journalctl --utc -n 1 --no-pager 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "journalctl --utc: Available" + $nl
        $FindingDetails += "  Sample: $(($journalUtc -split $nl | Select-Object -Last 1).Substring(0, [Math]::Min(80, ($journalUtc -split $nl | Select-Object -Last 1).Length)))" + $nl
        $FindingDetails += "PASS: Journal supports UTC timestamp output" + $nl
    }
    else {
        $FindingDetails += "journalctl --utc: Not available" + $nl
    }

    # XO Audit Plugin timestamps
    $FindingDetails += $nl + "--- Check 5: XO Audit Plugin ---" + $nl
    $xoAuditInfo = Get-XOAuditPluginInfo
    if ($xoAuditInfo.Enabled) {
        $FindingDetails += "  XO Audit Plugin: ACTIVE" + $nl
        $FindingDetails += "  Uses Unix millisecond timestamps (inherently UTC)" + $nl
        $FindingDetails += "  [PASS] XO audit timestamps are UTC-mappable" + $nl
    }
    else {
        $FindingDetails += "  XO Audit Plugin: NOT DETECTED" + $nl
    }
    $FindingDetails += $nl

    if ($auditIssues -eq 0) {
        $Status = "NotAFinding"
    }
'''
}


def build_function(vid, impl):
    """Build a complete PowerShell function block."""
    func_name = vid.replace("-", "")
    return f'''Function Get-{func_name} {{
    <#
    .DESCRIPTION
        Vuln ID    : {vid}
        STIG ID    : {impl["stig_id"]}
        Rule ID    : {impl["rule_id"]}
        Rule Title : {impl["rule_title"]}
        DiscussMD5 : {impl["discuss_md5"]}
        CheckMD5   : {impl["check_md5"]}
        FixMD5     : {impl["fix_md5"]}
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
    $VulnID = "{vid}"
    $RuleID = "{impl["rule_id"]}"
    $Status = "Open"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
{impl["body"]}
    #---=== End Custom Code ===---#

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
        ResultHash       = $ResultHash
        HeadHash         = $null
        HeadInstance     = $null
        HeadDatabase     = $null
        HeadSite         = $null
    }}
    return Send-CheckResult @SendCheckParams
}}
'''


def main():
    with open(MODULE_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    replaced = 0
    for vid, impl in IMPLEMENTATIONS.items():
        func_name = vid.replace("-", "")
        # Find the existing stub function
        pattern = re.compile(
            r'(Function Get-' + func_name + r'\s*\{.*?\n\})',
            re.DOTALL | re.IGNORECASE
        )
        match = pattern.search(content)
        if match:
            new_func = build_function(vid, impl)
            content = content[:match.start()] + new_func + content[match.end():]
            replaced += 1
            print(f"  [OK] {vid} — replaced stub with implementation")
        else:
            print(f"  [WARN] {vid} — function not found in module")

    with open(MODULE_PATH, "w", encoding="utf-8-sig") as f:
        f.write(content)

    print(f"\nReplaced {replaced}/10 stubs")

    # Validate module parse
    import subprocess
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command",
         f"Import-Module '.\\{MODULE_PATH.replace(chr(92), '/')}' -Force -ErrorAction Stop; "
         "(Get-Command -Module Scan-XO_GPOS_Debian12_Checks).Count"],
        capture_output=True, text=True, cwd="."
    )
    if result.returncode == 0:
        count = result.stdout.strip()
        print(f"Module validation: {count} functions exported")
    else:
        print(f"Module validation FAILED: {result.stderr[:500]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
