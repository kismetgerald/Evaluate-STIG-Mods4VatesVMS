#!/usr/bin/env python3
"""Batch 18 answer file integration — adds 2-index entries for 10 VulnIDs."""

import sys

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

ENTRIES = {
    "V-203621": {
        "nf_comment": "DOCUMENTATION: Audit records for privilege access attempts are generated on this system. The XO Audit Plugin records all authenticated admin actions including permission changes, role assignments, and elevated operations with hash chain integrity. The plugin REST API at /rest/v0/plugins/audit/records provides searchable access to privilege-related audit events. For systems with auditd, audit rules monitor execve syscalls, sudo usage, passwd, chsh, chfn, newgrp, and gpasswd commands. Systemd journal captures privilege escalation events with _SYSTEMD_UNIT and _COMM fields. These mechanisms collectively satisfy the requirement for auditing privilege access attempts.",
        "open_comment": "FINDING: Audit records for privilege access attempts may not be fully generated. REMEDIATION: 1) Install and enable auditd: apt install auditd &amp;&amp; systemctl enable --now auditd. 2) Add privilege access rules: auditctl -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged. 3) Add rules for passwd, chsh, chfn, newgrp, gpasswd similarly. 4) Enable the XO Audit Plugin for application-layer privilege tracking. 5) Verify audit records: ausearch -k privileged or journalctl _COMM=sudo.",
    },
    "V-203700": {
        "nf_comment": "DOCUMENTATION: Audit record storage capacity is allocated to store at least one week of records. The /var/log partition has adequate free space (below 90% utilization). Systemd journal is configured for persistent storage in /var/log/journal/. Log rotation via logrotate retains at least 4 rotations of log files ensuring multi-week retention. These configurations ensure audit records are preserved for the minimum one-week retention period required by the STIG.",
        "open_comment": "FINDING: Audit storage capacity may not be sufficient for one week of records. REMEDIATION: 1) Check disk space: df -h /var/log. 2) Configure persistent journal: set Storage=persistent in /etc/systemd/journald.conf. 3) Ensure logrotate retains sufficient rotations: review /etc/logrotate.conf (rotate 4 or higher with weekly rotation). 4) Consider a dedicated /var/log partition with at least 2GB. 5) Monitor disk usage and set alerts at 75% threshold.",
    },
    "V-203701": {
        "nf_comment": "DOCUMENTATION: Audit records are offloaded to a different system from the one being audited. Remote syslog forwarding is configured via rsyslog with remote server targets (using @@ for TCP or @ for UDP). Alternatively, systemd-journal-upload or audisp-remote may be used for secure log forwarding. Centralized logging to a SIEM or syslog server ensures audit records survive local system compromise and support enterprise-wide correlation and analysis.",
        "open_comment": "FINDING: Audit record offloading is not configured. REMEDIATION: 1) Configure rsyslog remote forwarding: add '*.* @@syslog-server:514' to /etc/rsyslog.conf. 2) Restart rsyslog: systemctl restart rsyslog. 3) Alternatively, enable systemd-journal-upload: systemctl enable --now systemd-journal-upload. 4) For auditd, configure audisp-remote with the remote server address. 5) Verify log receipt on the central syslog/SIEM server. 6) Document the centralized audit architecture in the System Security Plan.",
    },
    "V-203702": {
        "nf_comment": "DOCUMENTATION: The system is configured to notify SAs and ISSOs when audit storage reaches 75% capacity. The auditd configuration in /etc/audit/auditd.conf includes space_left and space_left_action settings that trigger notification (email, syslog, or exec) when storage thresholds are reached. The action_mail_acct parameter directs email notifications to the root account or designated administrator. Disk space monitoring tools provide additional alerting capability for the /var/log partition.",
        "open_comment": "FINDING: Notification at 75% audit storage capacity is not fully configured. REMEDIATION: 1) Install auditd: apt install auditd. 2) Configure /etc/audit/auditd.conf: set space_left = 25% of partition size, space_left_action = email, admin_space_left_action = halt or single. 3) Set action_mail_acct = root (or admin email). 4) Ensure mail utility is installed for email delivery. 5) Consider additional monitoring (Nagios, Zabbix, Prometheus) for disk space alerting. 6) Test alert delivery by filling log space to threshold.",
    },
    "V-203704": {
        "nf_comment": "DOCUMENTATION: The system provides audit reduction capability for on-demand audit review and analysis. The aureport utility generates summary reports from audit log data with filtering by user, type, date range, and event category. The ausearch utility provides granular search and filtering of audit records. Journalctl supports time-based queries, priority filtering, and multiple output formats (json, verbose, short-iso). The XO Audit Plugin REST API at /rest/v0/plugins/audit/records provides application-layer search and filtering. These tools collectively satisfy the on-demand audit reduction requirement.",
        "open_comment": "FINDING: Audit reduction tools are not available for on-demand review. REMEDIATION: 1) Install auditd tools: apt install auditd. 2) Verify aureport is available: which aureport. 3) Verify ausearch is available: which ausearch. 4) Verify journalctl is available: which journalctl. 5) Enable the XO Audit Plugin for application-layer audit reduction. 6) Document audit reduction procedures in the System Security Plan including tool usage examples and standard operating procedures.",
    },
    "V-203705": {
        "nf_comment": "DOCUMENTATION: The system provides audit reduction capability for after-the-fact investigation of security incidents. The aureport utility can generate retrospective reports from historical audit data. The ausearch utility supports searching archived audit logs with time-bounded queries. Journalctl provides historical log access with filtering by boot, time range, unit, and priority. The XO Audit Plugin maintains hash chain integrity for tamper detection, supporting forensic investigation. These tools enable after-the-fact security incident investigation.",
        "open_comment": "FINDING: Audit reduction tools for after-the-fact investigation are not available. REMEDIATION: 1) Install auditd tools: apt install auditd. 2) Verify aureport: which aureport. 3) Verify ausearch: which ausearch. 4) Configure journal persistence for historical access: Storage=persistent in journald.conf. 5) Enable the XO Audit Plugin for application-layer forensic capability. 6) Document incident investigation procedures including audit log analysis steps.",
    },
    "V-203706": {
        "nf_comment": "DOCUMENTATION: The system provides report generation capability for on-demand audit review and analysis. The aureport utility generates formatted summary reports including login/logout reports, authentication events, and anomaly reports. Journalctl supports structured output in JSON and verbose formats suitable for report generation. The XO Audit Plugin REST API provides programmatic access to audit data for custom report generation. These tools satisfy the on-demand report generation requirement.",
        "open_comment": "FINDING: Report generation tools are not available for on-demand audit review. REMEDIATION: 1) Install auditd tools: apt install auditd. 2) Verify aureport: which aureport (generates formatted reports). 3) Verify journalctl: which journalctl (supports --output=json for structured reports). 4) Enable the XO Audit Plugin for application-layer reporting. 5) Document report generation procedures and standard report templates in the System Security Plan.",
    },
    "V-203707": {
        "nf_comment": "DOCUMENTATION: The system provides report generation capability that supports on-demand reporting requirements. The aureport utility provides multiple report types: summary, authentication, login, anomaly, and event reports on demand. Ausearch enables targeted queries for specific report content. Journalctl supports time-bounded and priority-filtered output in multiple formats. The XO Audit Plugin REST API enables on-demand queries with filtering parameters. These tools collectively meet on-demand reporting requirements.",
        "open_comment": "FINDING: On-demand reporting capability is not available. REMEDIATION: 1) Install auditd tools: apt install auditd. 2) Verify aureport: which aureport. 3) Verify ausearch: which ausearch. 4) Verify journalctl: which journalctl. 5) Enable the XO Audit Plugin for application-layer reporting. 6) Create standard report templates and document reporting procedures for periodic security reviews and on-demand information requests.",
    },
    "V-203708": {
        "nf_comment": "DOCUMENTATION: The system provides report generation capability for after-the-fact investigation of security incidents. The aureport utility generates historical reports from archived audit data supporting incident timeline reconstruction. Ausearch provides forensic search capabilities across historical records. Journalctl accesses persistent journal entries for post-incident analysis. The XO Audit Plugin maintains tamper-evident hash chain records supporting forensic investigation. These tools enable comprehensive after-the-fact incident investigation reporting.",
        "open_comment": "FINDING: Report generation for after-the-fact investigation is not available. REMEDIATION: 1) Install auditd tools: apt install auditd. 2) Verify aureport: which aureport. 3) Configure log retention for historical access (logrotate with sufficient rotations). 4) Configure journal persistence: Storage=persistent in journald.conf. 5) Enable the XO Audit Plugin for application-layer forensic reporting. 6) Document incident investigation reporting procedures including evidence preservation requirements.",
    },
    "V-203714": {
        "nf_comment": "DOCUMENTATION: Audit record timestamps can be mapped to Coordinated Universal Time (UTC). NTP synchronization is active via systemd-timesyncd, chronyd, or ntpd ensuring accurate timekeeping. Audit logs use epoch timestamps (Unix time) which are inherently UTC-based and directly mappable. Systemd journal supports UTC output via journalctl --utc flag. The XO Audit Plugin records timestamps as Unix milliseconds (UTC). Even when the system timezone is not UTC, all timestamp formats used by audit subsystems can be mathematically converted to UTC, satisfying the requirement for UTC-mappable timestamps.",
        "open_comment": "FINDING: Audit timestamps may not be mappable to UTC. REMEDIATION: 1) Enable NTP synchronization: systemctl enable --now systemd-timesyncd (or chronyd/ntpd). 2) Configure authoritative time sources in /etc/systemd/timesyncd.conf. 3) Optionally set system timezone to UTC: timedatectl set-timezone UTC. 4) Verify NTP sync: timedatectl show -p NTPSynchronized. 5) Verify audit log timestamps: tail /var/log/audit/audit.log (epoch format). 6) Verify journal UTC capability: journalctl --utc -n 1.",
    },
}


def main():
    with open(AF_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    insertion_point = content.rfind("</STIGComments>")
    if insertion_point == -1:
        print("ERROR: Could not find </STIGComments> tag")
        sys.exit(1)

    new_entries = ""
    for vuln_id, comments in ENTRIES.items():
        new_entries += f'''
  <Vuln ID="{vuln_id}">
    <AnswerKey Name="XO">
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{comments["nf_comment"]}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{comments["open_comment"]}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>
'''

    content = content[:insertion_point] + new_entries + content[insertion_point:]

    with open(AF_PATH, "w", encoding="utf-8-sig") as f:
        f.write(content)

    print(f"Integrated {len(ENTRIES)} answer file entries")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(AF_PATH)
        print("XML validation: PASSED")
    except ET.ParseError as e:
        print(f"XML validation: FAILED - {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
