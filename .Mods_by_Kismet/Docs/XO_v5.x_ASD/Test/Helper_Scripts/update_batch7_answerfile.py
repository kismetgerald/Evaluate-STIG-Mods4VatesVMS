#!/usr/bin/env python3
"""
Update XO_v5.x_ASD_AnswerFile.xml for Batch 7: V-222471-V-222481
Replaces stub answer file entries with proper 2- or 3-index entries.
"""

import re
import sys

AF_PATH = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode"
    r"\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml"
)


def xml_esc(s):
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))


def build_nf_open_block(vid, nf_comment, open_comment):
    """Two-index block: Index 1=NotAFinding, Index 2=Open"""
    return f"""  <Vuln ID="{vid}">
    <!--RuleTitle: See XCCDF for rule title.-->
    <AnswerKey Name="XO">
      <!--Updated by implement-stig-check for Batch 7-->
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{xml_esc(nf_comment)}</ValidTrueComment>
        <ValidFalseStatus></ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{xml_esc(open_comment)}</ValidTrueComment>
        <ValidFalseStatus></ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>"""


def build_nf_open_na_block(vid, nf_comment, open_comment, na_comment):
    """Three-index block: Index 1=NotAFinding, Index 2=Open, Index 3=Not_Applicable"""
    return f"""  <Vuln ID="{vid}">
    <!--RuleTitle: See XCCDF for rule title.-->
    <AnswerKey Name="XO">
      <!--Updated by implement-stig-check for Batch 7-->
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{xml_esc(nf_comment)}</ValidTrueComment>
        <ValidFalseStatus></ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{xml_esc(open_comment)}</ValidTrueComment>
        <ValidFalseStatus></ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="3" ExpectedStatus="Not_Applicable" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Not_Applicable</ValidTrueStatus>
        <ValidTrueComment>{xml_esc(na_comment)}</ValidTrueComment>
        <ValidFalseStatus></ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>"""


def build_open_na_block(vid, open_comment, na_comment):
    """Two-index block: Index 1=Open, Index 2=Not_Applicable"""
    return f"""  <Vuln ID="{vid}">
    <!--RuleTitle: See XCCDF for rule title.-->
    <AnswerKey Name="XO">
      <!--Updated by implement-stig-check for Batch 7-->
      <Answer Index="1" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{xml_esc(open_comment)}</ValidTrueComment>
        <ValidFalseStatus></ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Not_Applicable" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Not_Applicable</ValidTrueStatus>
        <ValidTrueComment>{xml_esc(na_comment)}</ValidTrueComment>
        <ValidFalseStatus></ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>"""


# --------------------------------------------------------------------------
# Answer content per VulnID
# --------------------------------------------------------------------------

ENTRIES = {}

# V-222471: NF if audit plugin found, Open otherwise
ENTRIES["V-222471"] = build_nf_open_block(
    "V-222471",
    nf_comment=(
        "XO provides audit logging of user data access operations. "
        "The XO audit plugin (@xen-orchestra/audit) is installed and records all user API operations, "
        "including read/list/get actions that constitute data access. "
        "Each audit record includes the action name (API method), userId of the authenticated user, "
        "and timestamp. All data access is performed via the XO JSON-RPC API, and the audit plugin "
        "intercepts all API calls at the middleware layer.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Confirm XO audit plugin is enabled in XO web UI (Settings > Plugins > Audit)\n"
        "2. Review audit records via API: GET /rest/v0/plugins/audit/records\n"
        "3. Verify read-type actions (vm.list, host.get, etc.) are present in audit records\n"
        "4. Confirm audit records are retained per organizational policy (minimum 1 year for DoD)"
    ),
    open_comment=(
        "XO audit logging of user data access operations was not confirmed. "
        "The XO audit plugin may not be installed or enabled.\n\n"
        "REMEDIATION STEPS:\n"
        "1. Install XO audit plugin: In XO web UI, go to Settings > Plugins\n"
        "2. Find '@xen-orchestra/audit' or 'audit' plugin and enable it\n"
        "3. For XOCE: npm install @xen-orchestra/audit in the XO packages directory\n"
        "4. Verify the plugin logs user data access events after enabling\n"
        "5. Test by performing a data access operation and reviewing audit records\n\n"
        "ALTERNATIVE: If using a SIEM or external logging solution that captures all XO API calls, "
        "provide documentation showing data access events are captured and attributed to users."
    )
)

# V-222472: NF if audit plugin found, Open otherwise
ENTRIES["V-222472"] = build_nf_open_block(
    "V-222472",
    nf_comment=(
        "XO provides audit logging of user data change operations. "
        "The XO audit plugin (@xen-orchestra/audit) records all create, update, and delete API operations. "
        "Each modification action (vm.create, vm.set, vm.delete, acl.add, acl.remove, etc.) is logged "
        "with the full action name, authenticated userId, and timestamp.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Confirm XO audit plugin is enabled in XO web UI (Settings > Plugins > Audit)\n"
        "2. Perform a change operation (e.g., start a VM, modify a setting)\n"
        "3. Verify the change appears in audit records: GET /rest/v0/plugins/audit/records\n"
        "4. Confirm the record includes: action name, userId, and timestamp\n"
        "5. Retain audit records per organizational policy (minimum 1 year for DoD)"
    ),
    open_comment=(
        "XO audit logging of user data change operations was not confirmed. "
        "The XO audit plugin may not be installed or enabled.\n\n"
        "REMEDIATION STEPS:\n"
        "1. Install and enable XO audit plugin via XO web UI (Settings > Plugins)\n"
        "2. For XOCE deployments: install @xen-orchestra/audit package\n"
        "3. Verify change operations (create/update/delete) are captured in audit records\n"
        "4. Test by creating or modifying a resource and checking audit log\n\n"
        "If application design documents specify protected data elements, verify those specific "
        "elements' changes are also captured. Consult XO documentation for audit plugin configuration."
    )
)

# V-222473: NF (timestamps always present in systemd journal), Open as fallback
ENTRIES["V-222473"] = build_nf_open_block(
    "V-222473",
    nf_comment=(
        "XO audit records include date and time stamps on all log entries. "
        "systemd journal provides precise ISO 8601 timestamps (YYYY-MM-DDTHH:MM:SS+TZ) for all "
        "xo-server events as a function of the journald service. "
        "Timestamps are added at the kernel level and cannot be disabled without disabling journald.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Run: journalctl -u xo-server --no-pager -n 10 --output=short-iso\n"
        "2. Confirm each line has an ISO 8601 timestamp prefix\n"
        "3. If using file-based logging: tail -5 /var/log/xo-server.log\n"
        "4. Note: Per V-222425, timestamps should use UTC/GMT for DoD compliance\n"
        "   (local timezone detected as non-UTC - separate finding)"
    ),
    open_comment=(
        "Date/time stamps in XO audit records could not be confirmed by automated check. "
        "Manual verification is required.\n\n"
        "VERIFICATION STEPS:\n"
        "1. Access the system: ssh root@xo1\n"
        "2. Review journal: journalctl -u xo-server --no-pager -n 20 --output=short-iso\n"
        "3. Verify each audit entry has a date/time stamp\n"
        "4. Review log files if file-based logging is configured\n\n"
        "If timestamps are absent, configure application or application server to include "
        "date and time in all audit log entries."
    )
)

# V-222474: NF if audit plugin found (action field = component ID), Open otherwise
ENTRIES["V-222474"] = build_nf_open_block(
    "V-222474",
    nf_comment=(
        "XO audit records identify which component, feature, or function triggered each audit event. "
        "The XO audit plugin records the API action name (e.g., 'vm.create', 'acl.add', 'user.set') "
        "for each logged event. This action name identifies the specific XO component and operation "
        "that triggered the audit record. The systemd journal additionally tags all entries with "
        "_SYSTEMD_UNIT=xo-server.service as the source component.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Review audit records: GET /rest/v0/plugins/audit/records?limit=10\n"
        "2. Verify each record includes an 'action' field (e.g., 'vm.start', 'host.get')\n"
        "3. Confirm the action name identifies the XO feature/function that triggered the event\n"
        "4. Document key XO components: web server (express), API server (xo-server), "
        "   database (LevelDB), session store (Redis)"
    ),
    open_comment=(
        "XO audit records identifying the triggering component/function were not confirmed. "
        "Manual review of application documentation and logs is required.\n\n"
        "VERIFICATION STEPS:\n"
        "1. Obtain architecture documentation identifying XO components:\n"
        "   - Web/API server: xo-server (Node.js/Express)\n"
        "   - Data store: LevelDB at /var/lib/xo-server\n"
        "   - Session store: Redis\n"
        "   - Authentication: local + optional LDAP/SAML plugins\n"
        "2. Access audit logs and verify component identification in entries\n"
        "3. If XO audit plugin is not installed, install it to enable structured audit records\n"
        "   with action names identifying the triggering component/function"
    )
)

# V-222475: NA if no centralized logging, NF/Open if centralized logging found
ENTRIES["V-222475"] = build_nf_open_na_block(
    "V-222475",
    nf_comment=(
        "XO is configured with centralized logging AND includes a unique application identifier "
        "in forwarded log entries. The hostname and application name (xo-server) are included "
        "in all log entries forwarded to the centralized logging solution.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Verify centralized logging configuration: grep -rE '@@?' /etc/rsyslog.conf /etc/rsyslog.d/\n"
        "2. Confirm forwarded entries include hostname: check rsyslog template or default format\n"
        "3. Verify application name (xo-server) is identifiable in centralized log entries\n"
        "4. Test by reviewing a sample of centralized log entries for XO source identification"
    ),
    open_comment=(
        "XO is configured with centralized logging but a unique application identifier was not "
        "confirmed in the forwarded log entries.\n\n"
        "REMEDIATION STEPS:\n"
        "1. Configure rsyslog/syslog-ng to include hostname and program name in all log entries\n"
        "2. Example rsyslog template: $template CustomFormat,\"%HOSTNAME% %programname% %msg%\\n\"\n"
        "3. Verify xo-server is identifiable as the application in centralized log storage\n"
        "4. Coordinate with SIEM team to confirm XO logs are distinguishable from other sources"
    ),
    na_comment=(
        "This requirement is Not Applicable. XO is not configured to use a centralized logging solution. "
        "Per STIG check content: if the application logs locally and does not utilize a centralized "
        "logging solution, this requirement is Not Applicable.\n\n"
        "XO currently logs to the local systemd journal and/or local log files only. "
        "No remote syslog, syslog-ng, or systemd-journal-upload destinations are configured.\n\n"
        "NOTE: For DoD environments, configuring centralized audit log forwarding is strongly "
        "recommended to satisfy V-222481 (off-load audit records) and support SIEM integration. "
        "See VATES_COMPLIANCE_BLOCKERS.md for implementation guidance."
    )
)

# V-222476: NF if audit plugin found, Open otherwise
ENTRIES["V-222476"] = build_nf_open_block(
    "V-222476",
    nf_comment=(
        "XO audit records include event outcome information. "
        "The XO audit plugin records action results, including error conditions. "
        "The systemd journal captures success/error states for xo-server operations. "
        "Successful API calls are logged by the audit plugin; errors are logged by both "
        "the audit plugin and the application-level error handlers.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Review audit records for outcome fields: GET /rest/v0/plugins/audit/records\n"
        "2. Check for error records: journalctl -u xo-server -n 50 | grep -i 'error\\|fail'\n"
        "3. Verify successful operations are also captured (implied by default per STIG)\n"
        "4. Document that success events may be implied if documented as organizational baseline"
    ),
    open_comment=(
        "Event outcome information in XO audit records was not confirmed. "
        "Manual verification of audit log format is required.\n\n"
        "VERIFICATION STEPS:\n"
        "1. Perform both a successful and a failed operation in XO\n"
        "2. Review audit records and confirm both outcomes are captured\n"
        "3. Verify the audit plugin records error conditions and success states\n\n"
        "REMEDIATION: Install/enable XO audit plugin to capture structured audit records "
        "that include event outcomes. Configure application error handlers to log failure details."
    )
)

# V-222477: NF if audit plugin found, Open otherwise
ENTRIES["V-222477"] = build_nf_open_block(
    "V-222477",
    nf_comment=(
        "XO audit records include user identity information for all events. "
        "The XO audit plugin records the authenticated userId (XO user account ID) for every "
        "API action. This userId is the primary identity associated with each audit event, "
        "establishing accountability for all privileged and non-privileged operations.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Review audit records: GET /rest/v0/plugins/audit/records?limit=10\n"
        "2. Verify each record includes a 'userId' field with the authenticated user's ID\n"
        "3. Cross-reference userId with XO user accounts: GET /rest/v0/users\n"
        "4. For LDAP/AD users, verify userId maps to the AD account identity\n"
        "5. Confirm system-level processes are identified differently from user actions"
    ),
    open_comment=(
        "User identity in XO audit records was not confirmed by automated check. "
        "Manual review is required.\n\n"
        "VERIFICATION STEPS:\n"
        "1. Log into XO as a test user and perform an action\n"
        "2. Review audit records: GET /rest/v0/plugins/audit/records\n"
        "3. Verify the action record includes the userId of the test account\n\n"
        "REMEDIATION: Install/enable XO audit plugin. Without the audit plugin, XO does not "
        "produce structured per-user audit records. The audit plugin is required for DoD compliance."
    )
)

# V-222478: NF if audit plugin found, Open otherwise
ENTRIES["V-222478"] = build_nf_open_block(
    "V-222478",
    nf_comment=(
        "XO audit records capture the full API action details for all privileged commands. "
        "XO uses a JSON-RPC API architecture where all privileged commands are API method calls "
        "(e.g., 'vm.create', 'vm.delete', 'acl.add', 'host.set'). "
        "The XO audit plugin records the complete method name (action) along with the authenticated "
        "userId for every privileged operation, fulfilling the full-text recording requirement.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Perform a privileged operation (create VM, modify ACL, add user)\n"
        "2. Review audit records: GET /rest/v0/plugins/audit/records\n"
        "3. Verify the record includes the full action name and userId\n"
        "4. Confirm privileged commands (admin operations) are distinguishable from user actions\n"
        "5. For group account scenarios: verify individual userId is always recorded (no shared accounts)"
    ),
    open_comment=(
        "Full-text recording of privileged commands in XO audit records was not confirmed. "
        "Manual verification is required.\n\n"
        "VERIFICATION STEPS:\n"
        "1. Perform privileged operations as an admin user\n"
        "2. Review audit records and verify full action details are captured\n"
        "3. Confirm each record includes: action name, userId, timestamp, and relevant parameters\n\n"
        "REMEDIATION: Install/enable XO audit plugin. This is the only mechanism in XO that "
        "provides structured full-text recording of privileged API commands with user attribution."
    )
)

# V-222479: NA (no RDBMS) or Open (RDBMS found without transaction logs)
ENTRIES["V-222479"] = build_open_na_block(
    "V-222479",
    open_comment=(
        "A relational database was detected but transaction recovery logging configuration "
        "was not confirmed. Manual review of database transaction logging settings is required.\n\n"
        "VERIFICATION STEPS:\n"
        "1. Identify the database being used by XO\n"
        "2. For PostgreSQL: verify WAL (Write-Ahead Logging) is enabled\n"
        "   SELECT name, setting FROM pg_settings WHERE name LIKE 'wal%';\n"
        "3. For MySQL/MariaDB: verify binary logging is enabled\n"
        "   SHOW VARIABLES LIKE 'log_bin';\n"
        "4. Document transaction log retention settings\n\n"
        "REMEDIATION: Configure database transaction logging appropriate for the RDBMS in use. "
        "Ensure transaction logs are retained per organizational data retention policy."
    ),
    na_comment=(
        "This requirement is Not Applicable. XO does not use a transaction-based relational "
        "database management system.\n\n"
        "XO's primary data store is LevelDB (a key-value store), not an RDBMS. LevelDB provides "
        "atomic batch writes (all-or-nothing operations) but does not produce SQL transaction logs "
        "or support BEGIN/COMMIT/ROLLBACK transactions.\n\n"
        "DATA STORE SUMMARY:\n"
        "- Primary: LevelDB at /var/lib/xo-server (key-value, no transaction logs)\n"
        "- Sessions: Redis (ephemeral session data, in-memory)\n"
        "- No PostgreSQL, MySQL, MariaDB, or SQLite detected\n\n"
        "This check applies to transaction-based applications using RDBMS backends with "
        "SQL transaction logging requirements. XO's LevelDB architecture is not in scope."
    )
)

# V-222480: NA if centralized logging, Open otherwise
ENTRIES["V-222480"] = build_open_na_block(
    "V-222480",
    open_comment=(
        "No enterprise centralized logging solution was detected. "
        "Manual review of XO audit configuration management capability is required.\n\n"
        "VERIFICATION STEPS:\n"
        "1. Review XO audit plugin configuration in XO web UI (Settings > Plugins > Audit)\n"
        "2. Verify the audit plugin provides centralized configuration of audit record content\n"
        "3. Document what audit events are captured and how content is managed\n"
        "4. If a SIEM or centralized log management system is used (even if not detected by "
        "   automated check), provide documentation to satisfy this requirement\n\n"
        "REMEDIATION: Configure rsyslog or syslog-ng to forward XO logs to an enterprise "
        "centralized logging solution. Enterprise SIEM tools (Splunk, ELK, QRadar) provide "
        "centralized management of audit record content collection and configuration."
    ),
    na_comment=(
        "This requirement is Not Applicable. XO is configured to log to an enterprise centralized "
        "logging solution that meets this requirement.\n\n"
        "Per STIG check content: if the application is configured to log application event entries "
        "to a centralized, enterprise-based logging solution, this requirement is Not Applicable.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Confirm the centralized logging destination is an approved enterprise solution\n"
        "2. Verify XO audit records are being forwarded to the centralized system\n"
        "3. Document the centralized logging architecture (rsyslog/syslog-ng target server)\n"
        "4. Confirm the centralized solution provides configuration management of audit content"
    )
)

# V-222481: NA if off-load configured, Open otherwise
ENTRIES["V-222481"] = build_open_na_block(
    "V-222481",
    open_comment=(
        "No audit log off-loading to a different system was detected. "
        "XO audit records are currently stored only on the local system.\n\n"
        "REMEDIATION STEPS:\n"
        "1. Configure rsyslog to forward XO logs to a centralized audit server:\n"
        "   echo '*.* @@audit-server.example.com:514' >> /etc/rsyslog.d/90-xo-remote.conf\n"
        "   systemctl restart rsyslog\n"
        "2. For journal-based forwarding: configure systemd-journal-upload to forward to\n"
        "   a systemd-journal-remote server\n"
        "3. Alternatively, configure logrotate postrotate scripts to rsync/scp logs to\n"
        "   a designated log archive server\n"
        "4. Verify automated tasks run per approved schedule to transfer audit records\n\n"
        "Obtain risk acceptance documentation if off-loading cannot be implemented immediately. "
        "Document compensating controls (e.g., daily backup to separate media)."
    ),
    na_comment=(
        "This requirement is Not Applicable. XO is configured to utilize a centralized logging "
        "solution that off-loads audit records to a different system.\n\n"
        "Per STIG check content: if the application is configured to utilize a centralized "
        "logging solution, this requirement is Not Applicable.\n\n"
        "ISSO VERIFICATION:\n"
        "1. Confirm audit records are being forwarded to a separate centralized log server\n"
        "2. Verify the receiving system is different from the XO host being audited\n"
        "3. Review log forwarding configuration: /etc/rsyslog.d/ or syslog-ng destinations\n"
        "4. Confirm forwarding occurs per the approved schedule or in real-time\n"
        "5. Verify receiving system has adequate capacity for log retention (DoD: 1+ year)"
    )
)


def main():
    with open(AF_PATH, 'r', encoding='utf-8-sig') as f:
        content = f.read()

    original_len = len(content)
    changes = 0

    for vid, new_block in ENTRIES.items():
        # Match the stub entry for this VulnID (original GUI-generated format)
        stub_pattern = (
            r'  <Vuln ID="' + re.escape(vid) + r'">\n'
            r'    <!--RuleTitle:[^\n]*-->\n'
            r'    <AnswerKey Name="XO">\n'
            r'      <!--AnswerKey[^\n]*-->\n'
            r'      <Answer Index="1" ExpectedStatus="Not_Reviewed"[^>]*>\n'
            r'        <!--Index[^\n]*-->\n'
            r'        <ValidationCode></ValidationCode>\n'
            r'        <ValidTrueStatus></ValidTrueStatus>\n'
            r'        <ValidTrueComment></ValidTrueComment>\n'
            r'        <ValidFalseStatus></ValidFalseStatus>\n'
            r'        <ValidFalseComment></ValidFalseComment>\n'
            r'      </Answer>\n'
            r'    </AnswerKey>\n'
            r'  </Vuln>'
        )

        new_content, n = re.subn(stub_pattern, new_block, content)
        if n == 0:
            print(f"WARNING: Could not find stub entry for {vid}")
        else:
            content = new_content
            changes += 1
            print(f"Updated: {vid} ({n} substitution)")

    if changes > 0:
        with open(AF_PATH, 'w', encoding='utf-8-sig') as f:
            f.write(content)
        new_len = len(content)
        print(f"\nDone: {changes}/{len(ENTRIES)} entries updated")
        print(f"File size: {original_len:,} -> {new_len:,} bytes (+{new_len - original_len:,})")
    else:
        print("No changes made.")
        sys.exit(1)


if __name__ == "__main__":
    main()
