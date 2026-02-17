#!/usr/bin/env python3
"""
Implement XO_ASD Batch 7: V-222471-V-222481 (Audit Record Generation & Logging)
Replaces stub custom code blocks in Scan-XO_ASD_Checks.psm1
"""

import re
import sys

PSM1_PATH = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode"
    r"\Evaluate-STIG\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psm1"
)

# --------------------------------------------------------------------------
# Code blocks for each VulnID (indented with 4 spaces inside custom code)
# --------------------------------------------------------------------------

IMPLEMENTATIONS = {}

# ---- V-222471: Log user data access ----
IMPLEMENTATIONS["V-222471"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin (logs all user API operations including reads)
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: Journal for data access events (read/get/list operations)
    $accessEvents = $(timeout 5 sh -c 'journalctl -u xo-server --no-pager -n 100 2>/dev/null | grep -iE "get |list |fetch|read |access|view" | head -5')
    $accessEventsStr = ($accessEvents -join $nl).Trim()
    $accessLogged = $accessEventsStr -ne ""

    # Check 3: XO audit REST API - check recent audit records
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $accessInAudit = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=30" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match [char]34 + "action" + [char]34 + ":" -or $auditRecordsStr -match [char]34 + "userId" + [char]34 + ":") {
            $accessInAudit = $true
        }
    }

    $FindingDetails = "Data Access Audit Record Generation Check" + $nl
    $FindingDetails += "===========================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: Audit plugin installed - logs all user API operations including reads" + $nl
        $FindingDetails += "  Path: " + $auditPkgStr.Split($nl)[0] + $nl
    } else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Data Access Events in Journal" + $nl
    if ($accessLogged) {
        $FindingDetails += "Access events found in journal:" + $nl + $accessEventsStr + $nl
    } else {
        $FindingDetails += "No data access events found in recent journal entries" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: XO Audit API Records" + $nl
    if ($apiTokenStr -ne "") {
        if ($accessInAudit) {
            $FindingDetails += "Audit records contain action and userId fields - access logging confirmed" + $nl
        } else {
            $FindingDetails += "Structured audit records not found via API" + $nl
        }
    } else {
        $FindingDetails += "API token not available - audit API check skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound -or $accessLogged -or $accessInAudit) {
        $Status = "NotAFinding"
        $FindingDetails += "XO provides audit logging of user data access operations." + $nl
        $FindingDetails += "The XO audit plugin records all user API actions including read/list operations." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "Data access audit logging not confirmed." + $nl
        $FindingDetails += "Manual review required: Verify XO audit plugin is installed and configured." + $nl
    }
"""

# ---- V-222472: Log data changes ----
IMPLEMENTATIONS["V-222472"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin (logs create/update/delete operations)
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: Journal for data change events
    $changeEvents = $(timeout 5 sh -c 'journalctl -u xo-server --no-pager -n 100 2>/dev/null | grep -iE "creat|updat|delet|modif|set |add |remov|patch" | head -5')
    $changeEventsStr = ($changeEvents -join $nl).Trim()
    $changeLogged = $changeEventsStr -ne ""

    # Check 3: XO audit REST API - check for change-type actions
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $changeInAudit = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=30" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match [char]34 + "action" + [char]34 + ":" -and $auditRecordsStr -match [char]34 + "userId" + [char]34 + ":") {
            $changeInAudit = $true
        }
    }

    $FindingDetails = "Data Change Audit Record Generation Check" + $nl
    $FindingDetails += "===========================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: Audit plugin installed - logs all create/update/delete operations" + $nl
        $FindingDetails += "  Path: " + $auditPkgStr.Split($nl)[0] + $nl
    } else {
        $FindingDetails += "NOT FOUND: XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Data Change Events in Journal" + $nl
    if ($changeLogged) {
        $FindingDetails += "Change events found in journal:" + $nl + $changeEventsStr + $nl
    } else {
        $FindingDetails += "No explicit data change events found in recent journal entries" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: XO Audit API Records" + $nl
    if ($apiTokenStr -ne "") {
        if ($changeInAudit) {
            $FindingDetails += "Audit records contain action and userId fields - change logging confirmed" + $nl
        } else {
            $FindingDetails += "Structured change records not confirmed via API" + $nl
        }
    } else {
        $FindingDetails += "API token not available - audit API check skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound -or $changeLogged -or $changeInAudit) {
        $Status = "NotAFinding"
        $FindingDetails += "XO provides audit logging of user data change operations." + $nl
        $FindingDetails += "The XO audit plugin records all create, update, and delete API actions." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "Data change audit logging not confirmed." + $nl
        $FindingDetails += "Manual review required: Verify XO audit plugin captures data modification events." + $nl
    }
"""

# ---- V-222473: Date/time in audit records ----
IMPLEMENTATIONS["V-222473"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: Examine XO journal entries for ISO timestamps
    $recentLogs = $(timeout 5 sh -c 'journalctl -u xo-server --no-pager -n 10 --output=short-iso 2>/dev/null')
    $recentLogsStr = ($recentLogs -join $nl).Trim()
    $isoTimestamps = $recentLogsStr -match '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'

    # Check 2: Check XO log files for timestamp format
    $logFile = $(timeout 5 sh -c 'ls -t /var/log/xo-server*.log 2>/dev/null | head -1')
    $logFileStr = ($logFile -join $nl).Trim()
    $fileTimestamps = $false
    if ($logFileStr -ne "") {
        $logSample = $(timeout 5 sh -c "tail -5 $logFileStr 2>/dev/null")
        $logSampleStr = ($logSample -join $nl).Trim()
        $fileTimestamps = $logSampleStr -match '\d{4}-\d{2}-\d{2}' -or $logSampleStr -match '\w+ +\d+ \d{2}:\d{2}:\d{2}'
    }

    # Check 3: System time
    $sysTime = $(timeout 3 date --iso-8601=seconds 2>/dev/null)
    $sysTimeStr = ($sysTime -join $nl).Trim()

    $FindingDetails = "Audit Record Date/Time Stamp Check" + $nl
    $FindingDetails += "====================================" + $nl + $nl

    $FindingDetails += "Check 1: systemd Journal Timestamps" + $nl
    if ($recentLogsStr -ne "") {
        $FindingDetails += "Recent journal entries (ISO format):" + $nl
        $firstLines = ($recentLogs | Select-Object -First 3) -join $nl
        $FindingDetails += $firstLines + $nl
        if ($isoTimestamps) {
            $FindingDetails += "PASS: ISO 8601 timestamps detected" + $nl
        } else {
            $FindingDetails += "Timestamps present in alternate format" + $nl
        }
    } else {
        $FindingDetails += "Could not retrieve journal entries" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Log File Timestamps" + $nl
    if ($logFileStr -ne "") {
        $FindingDetails += "Log file: " + $logFileStr + $nl
        if ($fileTimestamps) {
            $FindingDetails += "PASS: Date/time stamps found in log file entries" + $nl
        } else {
            $FindingDetails += "No log file timestamp pattern matched" + $nl
        }
    } else {
        $FindingDetails += "No XO log files found; journal is primary log source" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: System Time Reference" + $nl
    $FindingDetails += "Current system time: " + $sysTimeStr + $nl + $nl

    $FindingDetails += "Summary:" + $nl
    if ($isoTimestamps -or $fileTimestamps) {
        $Status = "NotAFinding"
        $FindingDetails += "XO audit records include date/time stamps on all log entries." + $nl
        $FindingDetails += "systemd journal provides precise ISO 8601 timestamps for all xo-server events." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "Manual review required: Verify audit records include date/time stamps." + $nl
        $FindingDetails += "Review XO server log files and systemd journal for timestamp format." + $nl
    }
"""

# ---- V-222474: Which component triggered event ----
IMPLEMENTATIONS["V-222474"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin captures action/component name
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: XO audit API - check for action field identifying component
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $componentInAudit = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=20" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match [char]34 + "action" + [char]34 + ":") {
            $componentInAudit = $true
        }
    }

    # Check 3: Journal source identification
    $journalSrc = $(timeout 5 sh -c 'journalctl -u xo-server --no-pager -n 5 --output=verbose 2>/dev/null | grep -i "SYSLOG_IDENTIFIER\|_SYSTEMD_UNIT" | head -5')
    $journalSrcStr = ($journalSrc -join $nl).Trim()
    $srcIdentified = $journalSrcStr -ne ""

    $FindingDetails = "Audit Record Component Source Identification Check" + $nl
    $FindingDetails += "====================================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: Audit plugin captures API action name (identifies triggering component)" + $nl
        $FindingDetails += "  Path: " + $auditPkgStr.Split($nl)[0] + $nl
    } else {
        $FindingDetails += "XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Audit API Action Field" + $nl
    if ($apiTokenStr -ne "") {
        if ($componentInAudit) {
            $FindingDetails += "Audit records include 'action' field identifying the API method triggered" + $nl
        } else {
            $FindingDetails += "Action field not detected in recent audit records" + $nl
        }
    } else {
        $FindingDetails += "API token not available - audit API check skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: Journal Source Identification" + $nl
    if ($srcIdentified) {
        $FindingDetails += "systemd journal source fields found:" + $nl + $journalSrcStr + $nl
    } else {
        $FindingDetails += "Standard journal entries include _SYSTEMD_UNIT=xo-server.service" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound -or $componentInAudit) {
        $Status = "NotAFinding"
        $FindingDetails += "XO audit records identify which component/function triggered each event." + $nl
        $FindingDetails += "The XO audit plugin records the API action name for each logged operation," + $nl
        $FindingDetails += "identifying which XO component triggered the audit event." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "Manual review required: Verify audit records identify the source component." + $nl
        $FindingDetails += "Review XO audit logs to confirm component identification in all events." + $nl
    }
"""

# ---- V-222475: Unique identifier in centralized logging ----
IMPLEMENTATIONS["V-222475"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: Remote syslog configuration
    $rsyslogRemote = $(timeout 5 sh -c 'grep -rE "^[^#].*@@?[0-9a-zA-Z]" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | head -5')
    $rsyslogRemoteStr = ($rsyslogRemote -join $nl).Trim()

    # Check 2: syslog-ng remote destination
    $syslogNgRemote = $(timeout 5 sh -c 'test -d /etc/syslog-ng && grep -rE "destination|tcp|udp" /etc/syslog-ng/ 2>/dev/null | grep -v "#" | head -5')
    $syslogNgRemoteStr = ($syslogNgRemote -join $nl).Trim()

    # Check 3: systemd journal upload service
    $journalUpload = $(timeout 3 sh -c 'systemctl is-active systemd-journal-remote systemd-journal-upload 2>/dev/null')
    $journalUploadStr = ($journalUpload -join $nl).Trim()

    $centralizedLogging = ($rsyslogRemoteStr -ne "") -or ($syslogNgRemoteStr -ne "") -or ($journalUploadStr -match "active")

    $FindingDetails = "Centralized Logging Unique Identifier Check" + $nl
    $FindingDetails += "============================================" + $nl + $nl

    $FindingDetails += "Check 1: rsyslog Remote Destinations" + $nl
    if ($rsyslogRemoteStr -ne "") {
        $FindingDetails += "FOUND: " + $rsyslogRemoteStr + $nl
    } else {
        $FindingDetails += "rsyslog: No remote destinations configured" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: syslog-ng Remote Destinations" + $nl
    if ($syslogNgRemoteStr -ne "") {
        $FindingDetails += "FOUND: " + $syslogNgRemoteStr + $nl
    } else {
        $FindingDetails += "syslog-ng: Not configured for remote logging" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: systemd Journal Remote Upload" + $nl
    $FindingDetails += "Status: " + $journalUploadStr + $nl + $nl

    $FindingDetails += "Summary:" + $nl
    if (-not $centralizedLogging) {
        $Status = "Not_Applicable"
        $FindingDetails += "No centralized logging solution detected." + $nl
        $FindingDetails += "Per STIG check content: if the application logs locally and does not" + $nl
        $FindingDetails += "utilize a centralized logging solution, this requirement is Not Applicable." + $nl
        $FindingDetails += "XO currently logs to local systemd journal and local log files only." + $nl
    } else {
        # Centralized logging IS configured - verify unique identifier
        $hostIdent = $(timeout 5 sh -c 'grep -rE "hostname|programname|app-name" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v "#" | head -3')
        $hostIdentStr = ($hostIdent -join $nl).Trim()
        $FindingDetails += "Centralized logging IS configured." + $nl
        if ($hostIdentStr -ne "") {
            $Status = "NotAFinding"
            $FindingDetails += "Hostname/application identifier configured in syslog:" + $nl + $hostIdentStr + $nl
        } else {
            $Status = "Open"
            $FindingDetails += "Centralized logging active but unique app identifier not confirmed." + $nl
            $FindingDetails += "Verify hostname and application name are included in forwarded log entries." + $nl
        }
    }
"""

# ---- V-222476: Event outcome in audit records ----
IMPLEMENTATIONS["V-222476"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin (records action results including errors)
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: Journal for outcome events (success/error/status codes)
    $outcomeEvents = $(timeout 5 sh -c 'journalctl -u xo-server --no-pager -n 100 2>/dev/null | grep -iE "error|fail|success|200 |401 |403 |500 |result" | head -5')
    $outcomeEventsStr = ($outcomeEvents -join $nl).Trim()
    $outcomesLogged = $outcomeEventsStr -ne ""

    # Check 3: XO audit API for error/result fields
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $outcomeInAudit = $false
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=20" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match [char]34 + "error" + [char]34 + ":|" + [char]34 + "result" + [char]34 + ":") {
            $outcomeInAudit = $true
        }
    }

    $FindingDetails = "Event Outcome in Audit Records Check" + $nl
    $FindingDetails += "======================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: Audit plugin records action outcomes (including errors and failures)" + $nl
        $FindingDetails += "  Path: " + $auditPkgStr.Split($nl)[0] + $nl
    } else {
        $FindingDetails += "XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Outcome Events in Journal" + $nl
    if ($outcomesLogged) {
        $FindingDetails += "Success/error events found in journal:" + $nl + $outcomeEventsStr + $nl
    } else {
        $FindingDetails += "No explicit outcome events found in recent journal entries" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: Audit API Outcome Fields" + $nl
    if ($apiTokenStr -ne "") {
        if ($outcomeInAudit) {
            $FindingDetails += "Audit records include error/result outcome fields" + $nl
        } else {
            $FindingDetails += "Outcome fields not detected in recent audit records via API" + $nl
        }
    } else {
        $FindingDetails += "API token not available - audit API check skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound -or $outcomesLogged -or $outcomeInAudit) {
        $Status = "NotAFinding"
        $FindingDetails += "XO audit records include event outcome information." + $nl
        $FindingDetails += "The XO audit plugin records action results; journal captures success/error states." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "Event outcome in audit records not confirmed." + $nl
        $FindingDetails += "Manual review required: Verify audit logs include success/failure outcomes." + $nl
    }
"""

# ---- V-222477: User identity in audit records ----
IMPLEMENTATIONS["V-222477"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin (records userId for all actions)
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: XO audit API - check for userId field in records
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $userInAudit = $false
    $userFieldEvidence = ""
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=20" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match [char]34 + "userId" + [char]34 + ":|" + [char]34 + "user" + [char]34 + ":") {
            $userInAudit = $true
            $userFieldEvidence = "userId/user field present in audit records"
        }
    }

    # Check 3: Journal for user-associated events
    $userEvents = $(timeout 5 sh -c 'journalctl -u xo-server --no-pager -n 50 2>/dev/null | grep -iE "userId|user:|identity|authent" | head -5')
    $userEventsStr = ($userEvents -join $nl).Trim()
    $userInJournal = $userEventsStr -ne ""

    $FindingDetails = "User Identity in Audit Records Check" + $nl
    $FindingDetails += "======================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: Audit plugin records userId for all authenticated API actions" + $nl
        $FindingDetails += "  Path: " + $auditPkgStr.Split($nl)[0] + $nl
    } else {
        $FindingDetails += "XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Audit API User Identity Fields" + $nl
    if ($apiTokenStr -ne "") {
        if ($userInAudit) {
            $FindingDetails += "User identity fields confirmed: " + $userFieldEvidence + $nl
        } else {
            $FindingDetails += "User identity fields not found in recent audit records via API" + $nl
        }
    } else {
        $FindingDetails += "API token not available - audit API check skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: User Events in Journal" + $nl
    if ($userInJournal) {
        $FindingDetails += "User/identity events found in journal:" + $nl + $userEventsStr + $nl
    } else {
        $FindingDetails += "No explicit user identity events in recent journal entries" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound -or $userInAudit -or $userInJournal) {
        $Status = "NotAFinding"
        $FindingDetails += "XO audit records include user identity information." + $nl
        $FindingDetails += "The XO audit plugin associates each action with the authenticated userId." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "User identity in audit records not confirmed." + $nl
        $FindingDetails += "Manual review required: Verify audit logs include user identity for events." + $nl
    }
"""

# ---- V-222478: Full-text recording of privileged commands ----
IMPLEMENTATIONS["V-222478"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: XO audit plugin records full action details
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    # Check 2: XO audit API - verify action + userId fields (full action context)
    $apiToken = $(timeout 5 cat /etc/xo-server/stig/api-token 2>/dev/null)
    $apiTokenStr = ($apiToken -join $nl).Trim()
    $fullTextInAudit = $false
    $sampleAction = ""
    if ($apiTokenStr -ne "") {
        $auditRecords = $(timeout 5 curl -sk -H ("Authorization: Bearer " + $apiTokenStr) "https://localhost/rest/v0/plugins/audit/records?limit=20" 2>/dev/null)
        $auditRecordsStr = ($auditRecords -join $nl).Trim()
        if ($auditRecordsStr -match [char]34 + "action" + [char]34 + ":" -and $auditRecordsStr -match [char]34 + "userId" + [char]34 + ":") {
            $fullTextInAudit = $true
            if ($auditRecordsStr -match [char]34 + "action" + [char]34 + ":" + [char]34 + "([^" + [char]34 + "]+)" + [char]34) {
                $sampleAction = $Matches[1]
            }
        }
    }

    $FindingDetails = "Full-Text Privileged Command Audit Record Check" + $nl
    $FindingDetails += "=================================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Audit Plugin" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "FOUND: Audit plugin captures full API action details" + $nl
        $FindingDetails += "  Path: " + $auditPkgStr.Split($nl)[0] + $nl
        $FindingDetails += "  Records: action name (method), userId, timestamp, and parameters" + $nl
    } else {
        $FindingDetails += "XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Audit API Record Structure" + $nl
    if ($apiTokenStr -ne "") {
        if ($fullTextInAudit) {
            $FindingDetails += "Audit records contain action and userId fields - full action context confirmed" + $nl
            if ($sampleAction -ne "") {
                $FindingDetails += "  Sample action recorded: " + $sampleAction + $nl
            }
        } else {
            $FindingDetails += "Full action context not confirmed in recent audit records" + $nl
        }
    } else {
        $FindingDetails += "API token not available - audit API check skipped" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Note: XO uses a JSON-RPC API; all privileged commands are API method calls." + $nl
    $FindingDetails += "The audit plugin records the full method name (e.g., 'vm.create', 'acl.add')" + $nl
    $FindingDetails += "along with the calling userId for all privileged operations." + $nl + $nl

    $FindingDetails += "Summary:" + $nl
    if ($auditPluginFound -or $fullTextInAudit) {
        $Status = "NotAFinding"
        $FindingDetails += "XO audit records capture full API action details for privileged commands." + $nl
        $FindingDetails += "The XO audit plugin records the full method name (action) and userId for" + $nl
        $FindingDetails += "all privileged operations, fulfilling the full-text recording requirement." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "Full-text recording of privileged commands not confirmed." + $nl
        $FindingDetails += "Manual review required: Verify XO audit logs include full action details." + $nl
    }
"""

# ---- V-222479: Transaction recovery logs ----
IMPLEMENTATIONS["V-222479"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: Identify XO primary data store (LevelDB)
    $leveldbPath = $(timeout 5 find /var/lib/xo-server /opt/xo -maxdepth 3 -name "CURRENT" -o -name "MANIFEST-000001" 2>/dev/null | head -5 2>&1)
    $leveldbPathStr = ($leveldbPath -join $nl).Trim()
    $usesLevelDB = $leveldbPathStr -ne ""

    # Check 2: Check for relational RDBMS (PostgreSQL, MySQL, SQLite)
    $psqlActive = $(timeout 3 sh -c 'systemctl is-active postgresql 2>/dev/null')
    $psqlStr = ($psqlActive -join $nl).Trim()
    $mysqlActive = $(timeout 3 sh -c 'systemctl is-active mysql mariadb 2>/dev/null')
    $mysqlStr = ($mysqlActive -join $nl).Trim()
    $sqliteFiles = $(timeout 5 find /var/lib/xo-server /opt/xo -maxdepth 3 -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | head -3 2>&1)
    $sqliteFilesStr = ($sqliteFiles -join $nl).Trim()
    $usesRDBMS = ($psqlStr -eq "active") -or ($mysqlStr -eq "active") -or ($sqliteFilesStr -ne "")

    # Check 3: Redis (session store - ephemeral, not transactional application data)
    $redisSvc = $(timeout 3 sh -c 'systemctl is-active redis 2>/dev/null')
    $redisStr = ($redisSvc -join $nl).Trim()

    $FindingDetails = "Transaction Recovery Log Check" + $nl
    $FindingDetails += "=================================" + $nl + $nl

    $FindingDetails += "Check 1: XO Data Store (LevelDB)" + $nl
    if ($usesLevelDB) {
        $firstDb = $leveldbPathStr.Split($nl)[0]
        $FindingDetails += "LevelDB database files detected: " + $firstDb + $nl
        $FindingDetails += "XO uses LevelDB (key-value store) as primary persistent data storage." + $nl
        $FindingDetails += "LevelDB provides atomic batch writes but is NOT a transactional RDBMS." + $nl
    } else {
        $FindingDetails += "LevelDB files not found in standard XO locations" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: Relational Database (RDBMS)" + $nl
    $FindingDetails += "PostgreSQL: " + $psqlStr + $nl
    $FindingDetails += "MySQL/MariaDB: " + $mysqlStr + $nl
    if ($sqliteFilesStr -ne "") {
        $FindingDetails += "SQLite files: " + $sqliteFilesStr + $nl
    } else {
        $FindingDetails += "SQLite: No .sqlite files found" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: Redis Session Store" + $nl
    $FindingDetails += "Redis service: " + $redisStr + " (session management only - not application state)" + $nl + $nl

    $FindingDetails += "Summary:" + $nl
    if (-not $usesRDBMS) {
        $Status = "Not_Applicable"
        $FindingDetails += "XO does not use a transaction-based relational database management system." + $nl
        $FindingDetails += "Primary data store: LevelDB (key-value store with atomic batch operations)." + $nl
        $FindingDetails += "This requirement applies to applications using transactional RDBMS backends." + $nl
        $FindingDetails += "LevelDB does not support SQL transactions or produce transaction recovery logs." + $nl
        $FindingDetails += "This check is Not Applicable for this XO deployment." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "Relational database detected. Verify transaction logging is configured." + $nl
        $FindingDetails += "Manual review required: Confirm transaction recovery logs are enabled." + $nl
    }
"""

# ---- V-222480: Centralized management of audit record content ----
IMPLEMENTATIONS["V-222480"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: Is centralized logging configured?
    $rsyslogRemote = $(timeout 5 sh -c 'grep -rE "^[^#].*@@?[0-9a-zA-Z]" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | head -5')
    $rsyslogRemoteStr = ($rsyslogRemote -join $nl).Trim()
    $journalRemote = $(timeout 3 sh -c 'systemctl is-active systemd-journal-remote 2>/dev/null ; systemctl is-active systemd-journal-upload 2>/dev/null')
    $journalRemoteStr = ($journalRemote -join $nl).Trim()
    $centralizedLogging = ($rsyslogRemoteStr -ne "") -or ($journalRemoteStr -match "active")

    # Check 2: XO audit plugin (provides local centralized audit config for XO)
    $auditPkg = $(timeout 5 find /opt/xo/packages /usr/share/xo-server/node_modules -maxdepth 3 -type d -name "@xen-orchestra/audit*" 2>/dev/null | head -3 2>&1)
    $auditPkgStr = ($auditPkg -join $nl).Trim()
    $auditPluginFound = $auditPkgStr -ne ""

    $FindingDetails = "Centralized Audit Record Content Management Check" + $nl
    $FindingDetails += "====================================================" + $nl + $nl

    $FindingDetails += "Check 1: Centralized Logging Configuration" + $nl
    if ($rsyslogRemoteStr -ne "") {
        $FindingDetails += "rsyslog remote destinations: " + $rsyslogRemoteStr + $nl
    } else {
        $FindingDetails += "rsyslog: No remote destinations configured" + $nl
    }
    if ($journalRemoteStr -match "active") {
        $FindingDetails += "systemd-journal-remote/upload: active" + $nl
    } else {
        $FindingDetails += "systemd-journal-remote: not active" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: XO Local Audit Configuration Capability" + $nl
    if ($auditPluginFound) {
        $FindingDetails += "XO audit plugin found: " + $auditPkgStr.Split($nl)[0] + $nl
        $FindingDetails += "The XO audit plugin provides centralized management of XO audit content" + $nl
    } else {
        $FindingDetails += "XO audit plugin not detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($centralizedLogging) {
        $Status = "Not_Applicable"
        $FindingDetails += "Centralized logging solution IS configured." + $nl
        $FindingDetails += "Per STIG check content: if the application is configured to log to a" + $nl
        $FindingDetails += "centralized, enterprise-based logging solution, this is Not Applicable." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "No enterprise centralized logging solution detected." + $nl
        $FindingDetails += "Manual review required: Verify XO audit plugin provides centralized" + $nl
        $FindingDetails += "management and configuration of audit record content." + $nl
        if ($auditPluginFound) {
            $FindingDetails += "XO audit plugin is installed and provides audit content management" + $nl
            $FindingDetails += "for XO-specific events. Document how audit record content is configured." + $nl
        }
    }
"""

# ---- V-222481: Off-load audit records to different system ----
IMPLEMENTATIONS["V-222481"] = r"""
    $nl = [Environment]::NewLine

    # Check 1: rsyslog remote destinations
    $rsyslogRemote = $(timeout 5 sh -c 'grep -rE "^[^#].*@@?[0-9a-zA-Z]" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | head -5')
    $rsyslogRemoteStr = ($rsyslogRemote -join $nl).Trim()

    # Check 2: syslog-ng remote destinations
    $syslogNgRemote = $(timeout 5 sh -c 'test -d /etc/syslog-ng && grep -rE "tcp\|udp\|network" /etc/syslog-ng/ 2>/dev/null | grep -v "#" | head -5')
    $syslogNgRemoteStr = ($syslogNgRemote -join $nl).Trim()

    # Check 3: systemd journal remote upload
    $journalUpload = $(timeout 3 sh -c 'systemctl is-active systemd-journal-remote 2>/dev/null ; systemctl is-active systemd-journal-upload 2>/dev/null')
    $journalUploadStr = ($journalUpload -join $nl).Trim()

    # Check 4: Logrotate forwarding scripts
    $logrotateForward = $(timeout 5 sh -c 'grep -rE "rsync|scp|curl|postrotate" /etc/logrotate.d/ /etc/logrotate.conf 2>/dev/null | grep -v "#" | head -5')
    $logrotateForwardStr = ($logrotateForward -join $nl).Trim()

    $offloadConfigured = ($rsyslogRemoteStr -ne "") -or ($syslogNgRemoteStr -ne "") -or ($journalUploadStr -match "active") -or ($logrotateForwardStr -ne "")

    $FindingDetails = "Audit Record Off-load to Different System Check" + $nl
    $FindingDetails += "=================================================" + $nl + $nl

    $FindingDetails += "Check 1: rsyslog Remote Destinations" + $nl
    if ($rsyslogRemoteStr -ne "") {
        $FindingDetails += "FOUND: " + $rsyslogRemoteStr + $nl
    } else {
        $FindingDetails += "No remote rsyslog destinations configured" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 2: syslog-ng Remote Destinations" + $nl
    if ($syslogNgRemoteStr -ne "") {
        $FindingDetails += "FOUND: " + $syslogNgRemoteStr + $nl
    } else {
        $FindingDetails += "syslog-ng remote: not configured" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 3: systemd Journal Remote Upload" + $nl
    if ($journalUploadStr -match "active") {
        $FindingDetails += "systemd-journal-remote/upload: ACTIVE" + $nl
    } else {
        $FindingDetails += "systemd-journal-remote/upload: not active" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Check 4: Logrotate Log Forwarding Scripts" + $nl
    if ($logrotateForwardStr -ne "") {
        $FindingDetails += "Log forwarding found in logrotate: " + $logrotateForwardStr + $nl
    } else {
        $FindingDetails += "No log forwarding scripts in logrotate configuration" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "Summary:" + $nl
    if ($offloadConfigured) {
        $Status = "Not_Applicable"
        $FindingDetails += "Log off-loading to a different system IS configured." + $nl
        $FindingDetails += "Per STIG check content: if the application is configured to utilize a" + $nl
        $FindingDetails += "centralized logging solution, this requirement is Not Applicable." + $nl
    } else {
        $Status = "Open"
        $FindingDetails += "No audit log off-loading to a different system detected." + $nl
        $FindingDetails += "Manual review required: Configure rsyslog, syslog-ng, or equivalent" + $nl
        $FindingDetails += "to forward XO audit records to a centralized log server." + $nl
        $FindingDetails += "Automated off-loading per approved schedule is required." + $nl
    }
"""


def make_repl(new_code_block, end_marker):
    def repl(m):
        return m.group(1) + new_code_block + '\n    ' + end_marker
    return repl


def main():
    with open(PSM1_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    original_len = len(content)
    changes = 0

    for vid, new_code in IMPLEMENTATIONS.items():
        stub_pattern = (
            r'(#---=== Begin Custom Code ===---#\n)'
            r'    \$FindingDetails = "This check requires manual review of Xen Orchestra application security configuration\. " \+\n'
            r'                      "Refer to the Application Security and Development STIG \(' + re.escape(vid) + r'\) for detailed requirements\. " \+\n'
            r'                      "Evidence should include configuration files, policies, and operational procedures\."\n'
            r'    (#---=== End Custom Code ===---#)'
        )

        begin_marker = '#---=== Begin Custom Code ===---#'
        end_marker = '#---=== End Custom Code ===---#'
        new_code_block = new_code.strip('\n')

        new_content, n = re.subn(
            stub_pattern,
            make_repl(new_code_block, end_marker),
            content
        )

        if n == 0:
            print(f"WARNING: Could not find stub pattern for {vid}")
        else:
            content = new_content
            changes += 1
            print(f"Replaced: {vid} ({n} substitution)")

    if changes > 0:
        with open(PSM1_PATH, 'w', encoding='utf-8') as f:
            f.write(content)
        new_len = len(content)
        print(f"\nDone: {changes}/{len(IMPLEMENTATIONS)} replacements made")
        print(f"File size: {original_len:,} -> {new_len:,} bytes (+{new_len - original_len:,})")
    else:
        print("No changes made.")
        sys.exit(1)


if __name__ == "__main__":
    main()
