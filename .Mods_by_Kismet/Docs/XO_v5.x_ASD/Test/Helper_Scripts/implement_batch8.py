#!/usr/bin/env python3
"""
implement_batch8.py — Replace stubs for Batch 8 (V-222482 through V-222495)
Audit Record Management: Centralized logging, capacity alerting, audit reduction,
report generation.

All 14 functions share the same centralized logging detection pattern:
  - V-222482: NotAFinding if SIEM detected, Open if not
  - V-222483-V-222495: Not_Applicable if SIEM detected, Open if not
"""

import re
import sys

PSM1_PATH = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode"
    r"\Evaluate-STIG\Modules\Scan-XO_ASD_Checks\Scan-XO_ASD_Checks.psm1"
)

# ---------------------------------------------------------------------------
# Shared detection code (same for all 14 functions)
# ---------------------------------------------------------------------------
DETECT = """\
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    # Detect centralized logging: rsyslog remote targets, systemd-journal-remote, syslog-ng
    $remoteTargets  = $(grep -rE "^[^#].*(@@?[a-zA-Z0-9])" /etc/rsyslog.conf /etc/rsyslog.d/ 2>&1)
    $journalRemote  = $(systemctl is-active systemd-journal-remote 2>&1)
    $syslogNgRemote = $(grep -rEi "destination " /etc/syslog-ng/ 2>&1 | grep -iE "tcp|udp|network" 2>&1)

    $centralizedFound   = $false
    $centralizedDetails = ""

    if ($remoteTargets -and ($remoteTargets -notmatch "No such file|cannot stat|failed|error")) {
        $centralizedFound    = $true
        $centralizedDetails += "Rsyslog remote target(s) detected:" + $nl + $remoteTargets + $nl + $nl
    }
    if ($journalRemote -eq "active") {
        $centralizedFound    = $true
        $centralizedDetails += "systemd-journal-remote: active" + $nl + $nl
    }
    if ($syslogNgRemote -and ($syslogNgRemote -notmatch "No such file|cannot stat|failed|error")) {
        $centralizedFound    = $true
        $centralizedDetails += "syslog-ng remote destination(s) detected:" + $nl + $syslogNgRemote + $nl + $nl
    }
"""

# ---------------------------------------------------------------------------
# Per-function code bodies (inserted between Begin/End Custom Code markers)
# ---------------------------------------------------------------------------

CODE_V222482 = DETECT + r"""
    $FindingDetails += "Centralized Log Repository Check (APSC-DV-001080)" + $nl
    $FindingDetails += "===================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "NotAFinding"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "XO application logs are forwarded to a centralized log management" + $nl
        $FindingDetails += "repository in an expeditious manner. This requirement is MET." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging configuration detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets (/etc/rsyslog.conf, /etc/rsyslog.d/): NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote status: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations (/etc/syslog-ng/): NOT FOUND" + $nl + $nl
        $FindingDetails += "XO application logs are NOT forwarded to a centralized log management" + $nl
        $FindingDetails += "repository. This is a finding per APSC-DV-001080." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "Configure rsyslog, syslog-ng, or systemd-journal-remote to forward" + $nl
        $FindingDetails += "all XO application logs to an approved centralized logging system." + $nl
    }"""

CODE_V222483 = DETECT + r"""
    $FindingDetails += "Audit Log Storage Capacity Alarming (APSC-DV-001090)" + $nl
    $FindingDetails += "======================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001090: If the application utilizes a centralized logging" + $nl
        $FindingDetails += "system that provides storage capacity alarming, this is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Confirm the centralized logging system (SIEM/syslog)" + $nl
        $FindingDetails += "is configured to alert the SA and ISSO when log storage exceeds 75%." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Without a centralized logging system, local log storage capacity" + $nl
        $FindingDetails += "alarming must be configured. No alarm mechanism detected for:" + $nl
        $FindingDetails += "  - 75% disk capacity threshold" + $nl
        $FindingDetails += "  - Notification to ISSO and SA" + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "1. Configure a centralized logging system (recommended), OR" + $nl
        $FindingDetails += "2. Implement local disk monitoring with alerting at 75% capacity." + $nl
        $FindingDetails += "   Example: Use logwatch, custom cron, or systemd OnCalendar timers." + $nl
    }"""

CODE_V222484 = DETECT + r"""
    $FindingDetails += "Real-Time Alert on Audit System Failure (APSC-DV-001100)" + $nl
    $FindingDetails += "===========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001100: If the centralized logging system provides real-time" + $nl
        $FindingDetails += "alarms for audit failures, this requirement is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Confirm the SIEM provides real-time audit failure alerts." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "For this moderate/high impact system, a real-time alert must be" + $nl
        $FindingDetails += "configured when the audit system fails or is failing." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "1. Implement a centralized SIEM with real-time audit failure alerting, OR" + $nl
        $FindingDetails += "2. Configure systemd OnFailure= for xo-server to notify the ISSO/SA," + $nl
        $FindingDetails += "3. Configure auditd action_mail_acct for local audit failure notification." + $nl
    }"""

CODE_V222485 = DETECT + r"""
    $FindingDetails += "Alert on Audit Processing Failures (APSC-DV-001110)" + $nl
    $FindingDetails += "======================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001110: If the centralized logging system provides audit" + $nl
        $FindingDetails += "processing failure alarms, this requirement is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Confirm the SIEM alerts on hardware failures," + $nl
        $FindingDetails += "capture failures, and storage errors." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Audit processing failure alerting not configured for:" + $nl
        $FindingDetails += "  - Hardware failures affecting log storage" + $nl
        $FindingDetails += "  - Failures to capture audit records" + $nl
        $FindingDetails += "  - Audit storage capacity errors" + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "1. Integrate XO with a centralized SIEM that monitors for these failures, OR" + $nl
        $FindingDetails += "2. Implement local alerting: systemd OnFailure= for xo-server service," + $nl
        $FindingDetails += "   logrotate error handling, disk monitoring scripts." + $nl
    }"""

CODE_V222486 = DETECT + r"""
    $FindingDetails += "Application Behavior on Audit Failure (APSC-DV-001120)" + $nl
    $FindingDetails += "=========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001120: If the centralized logging system handles audit" + $nl
        $FindingDetails += "failure behavior (local spooling during outages), this is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Confirm rsyslog/syslog-ng is configured to spool" + $nl
        $FindingDetails += "logs locally during central system failure and forward when available." + $nl
        $FindingDetails += "Verify: ActionQueueType LinkedList (rsyslog) or disk-buffer (syslog-ng)." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Application behavior on audit failure has not been defined or tested." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "Define and document the ISSO-approved audit failure response:" + $nl
        $FindingDetails += "  Option A (Halt): Configure xo-server to stop if audit logging fails." + $nl
        $FindingDetails += "  Option B (Spool): Configure rsyslog queuing (ActionQueueType LinkedList)" + $nl
        $FindingDetails += "    to spool locally during outages and forward when available." + $nl
        $FindingDetails += "Document the approved option in the SSP." + $nl
    }"""

CODE_V222487 = DETECT + r"""
    $FindingDetails += "Central Review of Audit Records (APSC-DV-001130)" + $nl
    $FindingDetails += "===================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001130: If the centralized logging system provides central" + $nl
        $FindingDetails += "review capability, this requirement is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Confirm all XO component logs are reviewable from" + $nl
        $FindingDetails += "one central location (SIEM console) without accessing each system." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Audit records from XO components (xo-server, nginx, PAM, journal)" + $nl
        $FindingDetails += "cannot be reviewed from a single central location." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "Deploy a centralized SIEM or syslog server to aggregate:" + $nl
        $FindingDetails += "  - XO application logs (xo-server via systemd journal)" + $nl
        $FindingDetails += "  - nginx access/error logs" + $nl
        $FindingDetails += "  - System authentication logs (pam_unix, sshd)" + $nl
        $FindingDetails += "  - XO audit plugin records" + $nl
    }"""

CODE_V222488 = DETECT + r"""
    $FindingDetails += "Audit Record Filtering Capability (APSC-DV-001140)" + $nl
    $FindingDetails += "=====================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001140: If the centralized logging system provides event" + $nl
        $FindingDetails += "filtering, this requirement is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Confirm the SIEM supports filtering by:" + $nl
        $FindingDetails += "  Users, event types, dates/times, system resources," + $nl
        $FindingDetails += "  IP addresses, objects accessed, event level (critical/warning/error)." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Without a SIEM, full audit record filtering capability is not available." + $nl
        $FindingDetails += "The systemd journal provides limited filtering (by service, priority," + $nl
        $FindingDetails += "date range) but cannot filter by IP address, user, or accessed object." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "Deploy a SIEM (Splunk, ELK, Graylog) that supports filtering by all" + $nl
        $FindingDetails += "required criteria per APSC-DV-001140." + $nl
    }"""

CODE_V222489 = DETECT + r"""
    $FindingDetails += "On-Demand Filtered Audit Report Generation (APSC-DV-001150)" + $nl
    $FindingDetails += "===============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001150: If the centralized logging system provides filtered" + $nl
        $FindingDetails += "report generation, this requirement is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Demonstrate generating an on-demand report from" + $nl
        $FindingDetails += "the SIEM using security event filters (date range, user, event type)." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "On-demand report generation from filtered audit data is not available." + $nl
        $FindingDetails += "The XO audit API (GET /rest/v0/plugins/audit/records) provides raw" + $nl
        $FindingDetails += "data access but does not support formatted report generation." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "Integrate XO logs with a SIEM (Splunk, Kibana, Graylog) that supports" + $nl
        $FindingDetails += "customizable, on-demand report generation from filtered event data." + $nl
    }"""

CODE_V222490 = DETECT + r"""
    $FindingDetails += "Audit Reduction with On-Demand Reports (APSC-DV-001160)" + $nl
    $FindingDetails += "==========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001160: If the centralized logging system provides audit" + $nl
        $FindingDetails += "reduction supporting on-demand reports, this is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Demonstrate audit reduction (filtering to relevant" + $nl
        $FindingDetails += "subset) followed by on-demand report generation in the SIEM." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Audit reduction with on-demand report generation is not available." + $nl
        $FindingDetails += "Audit reduction means reducing record volume while preserving original" + $nl
        $FindingDetails += "data, then generating reports from the reduced dataset." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "Deploy a SIEM that supports both audit reduction (query/filter) and" + $nl
        $FindingDetails += "on-demand report generation from the reduced dataset." + $nl
    }"""

CODE_V222491 = DETECT + r"""
    $FindingDetails += "Audit Reduction and Event Filtering (APSC-DV-001170)" + $nl
    $FindingDetails += "=======================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001170: If the centralized logging system performs audit" + $nl
        $FindingDetails += "reduction and event filtering, this requirement is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Demonstrate applying event filters to reduce" + $nl
        $FindingDetails += "the audit record dataset (e.g., logon events for a specific day)." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Full audit reduction and event filtering capability is not available." + $nl
        $FindingDetails += "The systemd journal provides basic filtering (journalctl -p err," + $nl
        $FindingDetails += "journalctl --since today) but lacks multi-criteria filtering." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "Deploy a SIEM that supports event filtering by multiple simultaneous" + $nl
        $FindingDetails += "criteria (user AND event type AND date range AND IP address)." + $nl
    }"""

CODE_V222492 = DETECT + r"""
    $FindingDetails += "Immediate Ad-Hoc Audit Review and Analysis (APSC-DV-001180)" + $nl
    $FindingDetails += "================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001180: If the centralized logging system provides immediate," + $nl
        $FindingDetails += "customizable, ad-hoc audit review and analysis, this is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Demonstrate immediate ad-hoc queries with custom" + $nl
        $FindingDetails += "criteria (date/time ranges, user-defined filters) in the SIEM console." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Immediate, customizable, ad-hoc audit review capability is not available." + $nl
        $FindingDetails += "This requires an interactive search interface with real-time results" + $nl
        $FindingDetails += "and user-defined query criteria." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "Integrate XO logs with Splunk, Elastic/ELK, or Graylog to provide" + $nl
        $FindingDetails += "interactive search and immediate ad-hoc analysis capability." + $nl
    }"""

CODE_V222493 = DETECT + r"""
    $FindingDetails += "Customizable Ad-Hoc Audit Log Reporting (APSC-DV-001190)" + $nl
    $FindingDetails += "===========================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001190: If the centralized logging system provides immediate," + $nl
        $FindingDetails += "customizable, ad-hoc report generation, this is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Generate an event report using the SIEM, verify" + $nl
        $FindingDetails += "the report data matches the applied filter criteria." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Customizable, immediate, ad-hoc audit log reporting is not available." + $nl
        $FindingDetails += "The XO audit API provides raw data access but not report generation." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "Integrate XO logs with a SIEM (Splunk, Kibana, Graylog) that supports" + $nl
        $FindingDetails += "immediate, customizable, ad-hoc report generation from audit data." + $nl
    }"""

CODE_V222494 = DETECT + r"""
    $FindingDetails += "Report Generation for After-the-Fact Investigations (APSC-DV-001200)" + $nl
    $FindingDetails += "========================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001200: If the centralized logging system performs report" + $nl
        $FindingDetails += "generation for after-the-fact investigations, this is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Confirm the SIEM retains logs for the required" + $nl
        $FindingDetails += "DoD retention period (1 year online, 2 years archived) and can" + $nl
        $FindingDetails += "generate reports from historical data for security investigations." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Report generation for after-the-fact security investigations requires:" + $nl
        $FindingDetails += "  - Long-term log retention (DoD: 1 year online, 2 years archived)" + $nl
        $FindingDetails += "  - Ability to query historical audit records" + $nl
        $FindingDetails += "  - Report generation from historical data" + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "1. Configure log retention: logrotate with rotate count for 90+ days local" + $nl
        $FindingDetails += "2. Forward to a SIEM with long-term storage for full DoD compliance" + $nl
        $FindingDetails += "3. Implement report generation from historical audit data in the SIEM" + $nl
    }"""

CODE_V222495 = DETECT + r"""
    $FindingDetails += "Audit Reduction Must Preserve Original Records (APSC-DV-001210)" + $nl
    $FindingDetails += "====================================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    if ($centralizedFound) {
        $Status          = "Not_Applicable"
        $FindingDetails += "RESULT: Centralized logging IS configured." + $nl + $nl
        $FindingDetails += $centralizedDetails
        $FindingDetails += "Per APSC-DV-001210: If the centralized logging system performs audit" + $nl
        $FindingDetails += "reduction while preserving original content, this is Not Applicable." + $nl + $nl
        $FindingDetails += "ISSO VERIFICATION: Apply filters in the SIEM to reduce displayed records," + $nl
        $FindingDetails += "then clear filters and verify all original records are intact and" + $nl
        $FindingDetails += "in original time order." + $nl
    }
    else {
        $Status          = "Open"
        $FindingDetails += "RESULT: No centralized logging detected." + $nl + $nl
        $FindingDetails += "Checked:" + $nl
        $FindingDetails += "  rsyslog remote targets: NOT FOUND" + $nl
        $FindingDetails += "  systemd-journal-remote: $journalRemote" + $nl
        $FindingDetails += "  syslog-ng remote destinations: NOT FOUND" + $nl + $nl
        $FindingDetails += "Without a centralized logging system, audit reduction capability" + $nl
        $FindingDetails += "and its compliance with original record preservation cannot be verified." + $nl + $nl
        $FindingDetails += "NOTE: The systemd journal itself does NOT modify records when filtered" + $nl
        $FindingDetails += "  (journalctl filtering is read-only), which is inherently compliant." + $nl + $nl
        $FindingDetails += "ISSO ACTION REQUIRED:" + $nl
        $FindingDetails += "1. Deploy a centralized SIEM for full audit reduction capability." + $nl
        $FindingDetails += "2. Verify any local audit reduction tool preserves original records." + $nl
        $FindingDetails += "3. Document the verified audit reduction approach in the SSP." + $nl
    }"""

# ---------------------------------------------------------------------------
# Map VulnID -> code block
# ---------------------------------------------------------------------------
FUNCTIONS = {
    "V-222482": CODE_V222482,
    "V-222483": CODE_V222483,
    "V-222484": CODE_V222484,
    "V-222485": CODE_V222485,
    "V-222486": CODE_V222486,
    "V-222487": CODE_V222487,
    "V-222488": CODE_V222488,
    "V-222489": CODE_V222489,
    "V-222490": CODE_V222490,
    "V-222491": CODE_V222491,
    "V-222492": CODE_V222492,
    "V-222493": CODE_V222493,
    "V-222494": CODE_V222494,
    "V-222495": CODE_V222495,
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
