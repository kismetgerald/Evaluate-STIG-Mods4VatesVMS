"""
update_batch8_answerfile.py
Replace GUI-generated stub entries for V-222482–V-222495 with
full implementation entries (2 indices each).

V-222482:  Index1=NotAFinding (SIEM detected)   + Index2=Open (no SIEM)
V-222483–V-222495: Index1=Open (no SIEM)         + Index2=Not_Applicable (SIEM detected)
"""

import re
import os

ANSWER_FILE = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode"
    r"\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml"
)

# ── Stub pattern (one per VulnID block) ──────────────────────────────────────
# Matches the entire AnswerKey block that contains only a single NR stub index.
def make_stub_pattern(vid):
    """Return a regex that matches the GUI-generated stub for the given VulnID."""
    return re.compile(
        r'(<Vuln ID="' + re.escape(vid) + r'">\s*'
        r'<!--RuleTitle:[^<]*-->\s*)'
        r'<AnswerKey Name="XO">.*?</AnswerKey>\s*'
        r'(</Vuln>)',
        re.DOTALL,
    )


def make_repl(new_answer_key):
    """Return a replacement callable that avoids backslash issues."""
    def _repl(m):
        return m.group(1) + new_answer_key + "\n  " + m.group(2)
    return _repl


# ── Helper: build AnswerKey XML ───────────────────────────────────────────────
def answer_key(comment, idx1_status, idx1_comment, idx2_status, idx2_comment):
    """Build a two-index <AnswerKey Name="XO"> block."""
    return (
        '<AnswerKey Name="XO">\n'
        '      <!--Updated by implement-stig-check for Batch 8-->\n'
        f'      <Answer Index="1" ExpectedStatus="{idx1_status}" Hostname="" Instance="" Database="" Site="" ResultHash="">\n'
        '        <ValidationCode></ValidationCode>\n'
        f'        <ValidTrueStatus>{idx1_status}</ValidTrueStatus>\n'
        f'        <ValidTrueComment>{idx1_comment}</ValidTrueComment>\n'
        '        <ValidFalseStatus></ValidFalseStatus>\n'
        '        <ValidFalseComment></ValidFalseComment>\n'
        '      </Answer>\n'
        f'      <Answer Index="2" ExpectedStatus="{idx2_status}" Hostname="" Instance="" Database="" Site="" ResultHash="">\n'
        '        <ValidationCode></ValidationCode>\n'
        f'        <ValidTrueStatus>{idx2_status}</ValidTrueStatus>\n'
        f'        <ValidTrueComment>{idx2_comment}</ValidTrueComment>\n'
        '        <ValidFalseStatus></ValidFalseStatus>\n'
        '        <ValidFalseComment></ValidFalseComment>\n'
        '      </Answer>\n'
        '    </AnswerKey>'
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222482 — Centralized log repository
#   NF if SIEM/rsyslog-remote detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222482 = answer_key(
    comment="V-222482",
    idx1_status="NotAFinding",
    idx1_comment="""\
XO application logs are being forwarded to a centralized log repository. \
Rsyslog remote target(s), systemd-journal-remote, or syslog-ng remote destination(s) \
were detected, indicating that audit records are being transmitted to a centralized \
log management system.

ISSO VERIFICATION:
1. Confirm the centralized destination is an approved enterprise logging solution
2. Verify XO audit plugin records (via /rest/v0/plugins/audit/records) are included \
in forwarded logs
3. Confirm log forwarding is encrypted (@@hostname = TLS-wrapped rsyslog, or equivalent)
4. Document the centralized logging architecture in the SSP
5. Retain audit records per organizational policy (minimum 1 year for DoD)""",
    idx2_status="Open",
    idx2_comment="""\
No centralized log repository configuration was detected. XO audit records are \
currently stored only on the local system and are not being forwarded to an \
enterprise centralized logging solution.

REMEDIATION STEPS:
1. Configure rsyslog to forward logs to a centralized syslog server:
   Add to /etc/rsyslog.conf: *.* @@siem-server.domain:514
   For TLS: *.* @@(o)siem-server.domain:6514
2. Alternatively, configure systemd-journal-remote to forward journal entries
3. Enterprise SIEM options: Splunk, ELK/Elasticsearch, IBM QRadar, Graylog
4. Restart rsyslog after configuration: systemctl restart rsyslog
5. Verify forwarding: tail -f /var/log/syslog and confirm SIEM receives entries

NOTE: The XO audit plugin writes to /var/log/xo-server/ locally. Configure \
the SIEM to ingest these log files in addition to syslog forwarding.""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222483 — 75% capacity warning
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222483 = answer_key(
    comment="V-222483",
    idx1_status="Open",
    idx1_comment="""\
No centralized logging solution was detected that provides audit storage capacity \
monitoring. XO does not natively alert on audit log storage reaching 75% capacity.

REMEDIATION STEPS:
1. Configure disk usage monitoring on the log partition:
   - logwatch or logcheck with disk threshold alerts
   - Custom cron job: du -sh /var/log | awk '{if($1+0 > threshold) send_alert}'
2. Configure systemd journal size limits in /etc/systemd/journald.conf:
   SystemMaxUse=2G (set based on available disk space)
   SystemKeepFree=500M
3. Implement enterprise monitoring: Nagios, Zabbix, Prometheus + Alertmanager
4. Configure alerting to SA and ISSO email addresses
5. Document the capacity monitoring procedure in the SSP

ALTERNATIVE: Deploy a centralized logging solution (rsyslog + SIEM) that \
provides storage capacity monitoring and automated alerting.""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides audit record storage capacity monitoring.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized logging solution has capacity monitoring enabled
2. Verify alerts are configured for 75% threshold notifications to SA and ISSO
3. Document the centralized logging capacity monitoring configuration in the SSP
4. Test the alerting mechanism to confirm SA and ISSO receive notifications""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222484 — Real-time alert for audit failure events (moderate/high impact)
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222484 = answer_key(
    comment="V-222484",
    idx1_status="Open",
    idx1_comment="""\
No centralized logging solution was detected that provides real-time audit failure \
alerting. XO does not natively send immediate real-time alerts for audit failure events.

REMEDIATION STEPS:
1. Monitor XO service health for audit-related failures:
   journalctl -u xo-server -f | grep -i "audit\|error\|fail"
2. Configure systemd service failure alerting:
   Create /etc/systemd/system/xo-server.service.d/alert.conf with OnFailure= directive
3. Implement log monitoring with immediate alerting:
   - Logcheck or OSSEC for real-time log analysis and alerting
   - Configure to send immediate email/SMS to SA and ISSO on audit failures
4. Set XO_AUDIT_FAILURE alert in SIEM or monitoring platform
5. Document the audit failure alerting procedure in the SSP

NOTE: This applies to applications with moderate or high categorization. \
XO managing virtualized resources should be classified at minimum moderate impact.""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides real-time audit failure alerting.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized logging/SIEM solution has real-time alerting configured
2. Verify audit failure events trigger immediate notifications to SA and ISSO
3. Document the audit failure alerting configuration in the SSP
4. Test the alerting by simulating an audit failure and confirming notifications""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222485 — Alert ISSO and SA on audit processing failure
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222485 = answer_key(
    comment="V-222485",
    idx1_status="Open",
    idx1_comment="""\
No alerting mechanism was detected to notify ISSO and SA when audit processing \
fails. XO does not natively send alerts when the audit plugin or logging subsystem \
encounters a processing failure.

REMEDIATION STEPS:
1. Configure systemd service monitoring for xo-server:
   Set up OnFailure= in xo-server.service to trigger notification on crash
2. Monitor audit plugin status via XO web UI (Settings &gt; Plugins &gt; Audit)
3. Implement Nagios/Zabbix/Prometheus check for XO service availability
4. Configure log monitoring to detect audit-related errors:
   grep -i "audit\|plugin.*error\|winston.*error" /var/log/xo-server/
5. Set up automated email/SMS alerting to SA and ISSO on detection
6. Document the alerting procedure in the Incident Response Plan

TESTING: Simulate audit failure by temporarily disabling audit plugin and \
verify SA/ISSO receive notification within acceptable timeframe.""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides audit processing failure alerting to SA and ISSO.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized SIEM/logging solution monitors audit processing health
2. Verify alerts are routed to SA and ISSO when audit failures occur
3. Document the notification chain and escalation procedures in the SSP
4. Conduct periodic testing of audit failure alerting (at minimum annually)""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222486 — Shut down by default upon audit failure
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222486 = answer_key(
    comment="V-222486",
    idx1_status="Open",
    idx1_comment="""\
XO does not natively shut down upon audit failure. XO will continue to operate \
even if the audit plugin is disabled or encounters errors. This behavior is by design \
to maintain hypervisor management availability, but requires documented compensating controls.

REMEDIATION/COMPENSATING CONTROLS:
1. Document the availability-override justification in the SSP:
   XO manages virtualized infrastructure; shutdown on audit failure could impact \
   all hosted VMs and services (availability overrides this requirement per STIG)
2. Implement compensating controls:
   a. Audit log monitoring with immediate alerting (see V-222485)
   b. Centralized logging to prevent single-point audit failure
   c. Redundant audit mechanisms (systemd journal + XO audit plugin)
3. Configure systemd watchdog for xo-server to restart on crashes:
   Add WatchdogSec=30 to xo-server.service
4. Document in POA&amp;M if full shutdown-on-failure cannot be implemented

NOTE: For hypervisor management applications, availability is typically an \
overriding concern. This finding should be documented with availability override \
justification in the system security plan.""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured, \
providing an alternative audit mechanism that prevents the need for application shutdown \
upon local audit failure.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm centralized logging provides continuous audit capability even if local logging fails
2. Verify the centralized solution has high availability configuration
3. Document why centralized logging satisfies this requirement in the SSP
4. Confirm organizational risk acceptance for this control based on availability requirements""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222487 — Centrally review and analyze audit records from multiple components
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222487 = answer_key(
    comment="V-222487",
    idx1_status="Open",
    idx1_comment="""\
No centralized logging solution was detected that enables central review and \
analysis of audit records from multiple XO components. XO audit records from \
xo-server, systemd journal, and nginx (if present) are stored separately locally.

REMEDIATION STEPS:
1. Deploy a centralized log management solution:
   - ELK Stack (Elasticsearch, Logstash, Kibana) for search and analysis
   - Splunk Enterprise for correlation and centralized review
   - Graylog as open-source alternative
2. Configure log forwarding from all XO components:
   a. xo-server logs: /var/log/xo-server/ -&gt; SIEM
   b. systemd journal: rsyslog + systemd-journald forwarding
   c. Authentication logs: /var/log/auth.log -&gt; SIEM
3. Create dashboards for centralized audit record review
4. Document the centralized review capability in the SSP""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides the capability to centrally review and analyze audit records from \
multiple XO components.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm all XO log sources are forwarded to the centralized solution:
   - xo-server application logs
   - systemd journal (authentication, service events)
   - Audit plugin records
2. Verify the centralized solution provides search and analysis capabilities
3. Confirm authorized personnel can access centralized audit records for review
4. Document the centralized logging architecture in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222488 — Filter audit records by organization-defined criteria
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222488 = answer_key(
    comment="V-222488",
    idx1_status="Open",
    idx1_comment="""\
No centralized logging solution was detected that provides audit record filtering \
capability. XO does not natively provide audit record filtering by organization-defined \
criteria without a supporting SIEM or log management platform.

REMEDIATION STEPS:
1. Deploy a log management solution that supports filtering:
   - Kibana (ELK Stack): create saved searches and filters
   - Splunk: use SPL queries for organization-defined criteria
   - Graylog: create streams and filters
2. Define organization-specific filtering criteria:
   - Authentication failures, privilege escalation attempts
   - VM creation/deletion events
   - Configuration changes
   - Failed API calls
3. Implement grep-based filtering for immediate review:
   journalctl -u xo-server | grep -E "error|fail|unauthorized"
4. Document filtering criteria in the Audit Policy""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides the capability to filter audit records based on organization-defined \
criteria.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized solution supports filtering by organization-defined criteria
2. Verify filter configurations are documented and cover DoD-required event types
3. Test filtering capability: confirm specific event types can be isolated on demand
4. Document approved filtering criteria in the Audit Policy and SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222489 — Audit reduction supporting on-demand reporting
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222489 = answer_key(
    comment="V-222489",
    idx1_status="Open",
    idx1_comment="""\
No audit reduction capability was detected that supports on-demand reporting. \
XO does not natively provide audit reduction tools without a supporting SIEM or \
log management platform.

REMEDIATION STEPS:
1. Implement an audit reduction solution:
   - Splunk: saved reports and scheduled reports
   - ELK Kibana: dashboards with on-demand reporting
   - Graylog: reports and dashboards
2. Use command-line tools for on-demand reduction:
   journalctl --since "7 days ago" -u xo-server | grep -i "audit" | sort | uniq -c
3. Configure logrotate with compression for manageable report sizes
4. Create organization-defined report templates covering:
   - Authentication and authorization events
   - VM lifecycle operations
   - Administrative actions
5. Document reporting procedures in the SSP""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides audit reduction capability supporting on-demand reporting.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized solution has on-demand report generation capability
2. Verify reports can be generated for any date range without modifying source records
3. Test by generating an on-demand report for a specific time period or event type
4. Document available report types and generation procedures in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222490 — Audit reduction supporting on-demand review and analysis
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222490 = answer_key(
    comment="V-222490",
    idx1_status="Open",
    idx1_comment="""\
No audit reduction capability was detected that supports on-demand audit review \
and analysis. XO does not natively provide audit reduction and analysis tools \
without a supporting SIEM or log management platform.

REMEDIATION STEPS:
1. Implement an audit reduction and analysis solution:
   - Elasticsearch + Kibana for full-text search and analysis
   - Splunk for correlation and anomaly detection
   - OSSEC or Wazuh for host-based audit analysis
2. For immediate capability: use systemd journal analysis tools:
   journalctl -u xo-server --output=json | python3 -c "import json,sys; [print(json.dumps(json.loads(l))) for l in sys.stdin]"
3. Configure log parsing rules to extract structured data from XO logs
4. Define analysis use cases:
   - Failed authentication correlation
   - Privilege escalation patterns
   - Unusual VM operations
5. Document analysis procedures in the Incident Response Plan""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides audit reduction capability supporting on-demand audit review and analysis.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized solution supports on-demand audit record review
2. Verify analysis tools (search, correlation, aggregation) are available
3. Confirm authorized personnel can perform ad-hoc analysis of XO audit records
4. Document analysis procedures and available tool capabilities in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222491 — Audit reduction supporting after-the-fact investigations
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222491 = answer_key(
    comment="V-222491",
    idx1_status="Open",
    idx1_comment="""\
No audit reduction capability was detected that supports after-the-fact security \
incident investigations. XO audit records are stored locally without a dedicated \
investigation and forensics capability.

REMEDIATION STEPS:
1. Implement log retention and audit reduction for forensic capability:
   - Configure log retention for minimum 1 year (DoD requirement)
   - logrotate: rotate monthly, retain=12
   - Centralized SIEM with long-term storage (cold tier for older records)
2. Establish forensic investigation procedures:
   - Preserve log integrity: use immutable storage or write-once media
   - Configure chattr +a on log directories to prevent deletion
3. Implement chain of custody procedures for audit records
4. Document the forensic investigation capability in the Incident Response Plan
5. Conduct periodic tabletop exercises to validate investigation capability

CRITICAL: After-the-fact investigation capability requires log records be \
preserved without modification. Configure append-only logging.""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides audit reduction capability supporting after-the-fact security incident \
investigations.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm centralized log retention meets DoD minimum (1 year for most systems)
2. Verify audit records cannot be deleted or modified after collection
3. Confirm the investigation process is documented in the Incident Response Plan
4. Test the forensic capability by performing a mock incident investigation""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222492 — Report generation supporting on-demand review and analysis
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222492 = answer_key(
    comment="V-222492",
    idx1_status="Open",
    idx1_comment="""\
No report generation capability was detected that supports on-demand audit review \
and analysis. XO does not include a built-in audit report generation tool.

REMEDIATION STEPS:
1. Implement a report generation solution:
   - Kibana (ELK): create and save audit dashboards as reports
   - Splunk: scheduled reports and dashboard exports
   - Custom scripts: parse XO logs and generate structured reports
2. Develop standard report templates for:
   - Weekly authentication summary report
   - VM lifecycle change report
   - Administrative action audit report
   - Security event summary
3. Implement report scheduling:
   - Cron-based: 0 8 * * 1 /usr/local/bin/generate_xo_audit_report.sh
4. Configure report distribution to ISSO and SA
5. Document report generation capability in the SSP""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides report generation capability supporting on-demand audit review and analysis.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized solution has report generation capability
2. Verify reports can be generated on-demand without specialized access
3. Confirm report output includes all required audit record fields
4. Document available report types and access procedures in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222493 — Report generation supporting on-demand reporting requirements
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222493 = answer_key(
    comment="V-222493",
    idx1_status="Open",
    idx1_comment="""\
No report generation capability was detected that supports on-demand reporting \
requirements. XO does not include built-in compliance or security reporting tools.

REMEDIATION STEPS:
1. Implement report generation capability:
   - Deploy Splunk, ELK, or Graylog with reporting features
   - Create custom audit report scripts using XO REST API:
     curl -sk -H "Authorization: Bearer TOKEN" https://xo/rest/v0/plugins/audit/records
2. Define organizational reporting requirements:
   - Frequency: daily summary, weekly trend, monthly compliance
   - Scope: all users, privileged users only, specific event types
   - Format: CSV, JSON, PDF for management review
3. Automate report distribution to ISSO, SA, and management
4. Implement compliance reporting tied to STIG requirements
5. Document reporting schedule and distribution list in SSP""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides report generation capability supporting on-demand reporting requirements.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized solution can generate on-demand reports
2. Verify report content covers organization-defined reporting requirements
3. Confirm reports are accessible to ISSO and SA without special access
4. Document report generation procedures and schedule in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222494 — Report generation supporting after-the-fact investigations
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222494 = answer_key(
    comment="V-222494",
    idx1_status="Open",
    idx1_comment="""\
No report generation capability was detected that supports after-the-fact security \
incident investigations. Without a dedicated forensic reporting tool, investigating \
security incidents requires manual log analysis.

REMEDIATION STEPS:
1. Implement forensic report generation capability:
   - SIEM correlation rules for incident reconstruction
   - Log analysis scripts that can reconstruct event timelines
   - Audit record export in forensically sound formats
2. Create incident investigation report templates:
   - Timeline reconstruction report
   - User activity trace report
   - Access pattern anomaly report
3. Configure long-term log retention for forensic availability:
   - Minimum 1 year online/accessible retention
   - Archive to write-once media for chain of custody
4. Train SA and ISSO on generating forensic reports
5. Document forensic reporting procedures in Incident Response Plan

LEGAL CONSIDERATION: Ensure forensic report generation meets requirements \
for potential legal proceedings (chain of custody, integrity verification).""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides report generation capability supporting after-the-fact security incident \
investigations.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized solution supports forensic-quality report generation
2. Verify audit records are preserved with integrity for investigation use
3. Confirm reports can span the full incident timeline across all XO components
4. Document the forensic investigation and reporting procedures in the IRP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222495 — Audit reduction that does not alter original content or ordering
#   NA if SIEM detected; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222495 = answer_key(
    comment="V-222495",
    idx1_status="Open",
    idx1_comment="""\
No audit reduction capability was detected that preserves original audit record \
content and time ordering. Manual log review of XO logs is susceptible to \
accidental modification without protective controls.

REMEDIATION STEPS:
1. Protect original log files from modification:
   chattr +a /var/log/xo-server/  # append-only
   chattr +i /var/log/xo-server/archived-logs/  # immutable after archival
2. Configure audit reduction to use read-only access to source logs:
   - Mount log directory read-only for analysis: mount --bind -o ro /var/log/xo-server /mnt/ro-logs
   - Use log shipping to separate analysis system
3. Implement integrity verification:
   - Compute checksums of original logs before analysis: sha256sum /var/log/xo-server/*
   - Store checksums in a separate tamper-evident location
4. Configure SIEM to ingest logs as read-only copies
5. Document the audit reduction integrity preservation procedure in the SSP

CRITICAL: Audit reduction tools must never modify timestamps or reorder events \
in source audit records.""",
    idx2_status="Not_Applicable",
    idx2_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides audit reduction without altering original audit record content or \
time ordering.

Per ASD STIG check content: if the application uses a centralized logging \
mechanism provided by the platform, this requirement is Not Applicable.

ISSO VERIFICATION:
1. Confirm the centralized solution maintains original record integrity during reduction
2. Verify the SIEM/log management solution does not modify timestamps or reorder events
3. Confirm source log integrity is preserved (checksums, append-only storage)
4. Document the audit reduction integrity controls in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Main: apply all replacements
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPLACEMENTS = [
    ("V-222482", AK_222482),
    ("V-222483", AK_222483),
    ("V-222484", AK_222484),
    ("V-222485", AK_222485),
    ("V-222486", AK_222486),
    ("V-222487", AK_222487),
    ("V-222488", AK_222488),
    ("V-222489", AK_222489),
    ("V-222490", AK_222490),
    ("V-222491", AK_222491),
    ("V-222492", AK_222492),
    ("V-222493", AK_222493),
    ("V-222494", AK_222494),
    ("V-222495", AK_222495),
]

def main():
    print(f"Reading: {ANSWER_FILE}")
    with open(ANSWER_FILE, "r", encoding="utf-8") as fh:
        content = fh.read()

    original_size = len(content.encode("utf-8"))
    success = 0

    for vid, ak in REPLACEMENTS:
        pattern = make_stub_pattern(vid)
        new_content, n = pattern.subn(make_repl(ak), content)
        if n == 1:
            print(f"Replaced: {vid} (1 substitution)")
            content = new_content
            success += 1
        elif n == 0:
            print(f"WARNING: {vid} — pattern not found (already updated?)")
        else:
            print(f"WARNING: {vid} — {n} substitutions (expected 1)")

    with open(ANSWER_FILE, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)

    new_size = len(content.encode("utf-8"))
    print(f"\nDone: {success}/{len(REPLACEMENTS)} replacements")
    print(f"File size: {original_size:,} -> {new_size:,} bytes (+{new_size - original_size:,})")


if __name__ == "__main__":
    main()
