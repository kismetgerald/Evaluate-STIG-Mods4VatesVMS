import re

AF_PATH = r'd:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml'

with open(AF_PATH, 'r', encoding='utf-8') as f:
    content = f.read()

entries = {
    "V-222436": {
        "nf": "Automated check detected DoD mandatory notice and consent banner content on the XO login page. "
              "The banner includes required DoD keywords. "
              "ISSO action: Verify the full banner text matches the DoD Standard Mandatory Notice and Consent Banner exactly. "
              "Document the banner source (nginx consent page, reverse proxy redirect, or application-level splash page).",
        "open": "No DoD mandatory notice and consent banner was detected on the XO login page. "
                "Xen Orchestra does not include a native pre-login banner mechanism. "
                "ISSO action: Implement a DoD consent banner via one of the following methods: "
                "(1) Nginx reverse proxy consent page before forwarding to XO; "
                "(2) XO customization via GUI/branding plugin; "
                "(3) Network access point banner (router/firewall warning). "
                "The banner must include: unauthorized use is prohibited, activities are monitored, "
                "evidence of unauthorized use may result in criminal prosecution. "
                "Reference VATES_COMPLIANCE_BLOCKERS.md BANNER-001 for implementation guidance.",
    },
    "V-222437": {
        "nf": "Automated check detected last successful logon display on the XO application. "
              "The application presents the time/date of the user's last successful logon after authentication. "
              "ISSO action: Verify the last logon display is visible to users immediately after login and "
              "includes at minimum the date and time of the previous successful authentication.",
        "open": "Xen Orchestra does not display the time and date of the user's last successful logon. "
                "ISSO action: Implement last logon display via one of the following: "
                "(1) XO custom plugin that queries audit records for last login event; "
                "(2) Nginx/reverse proxy post-login redirect with last logon information; "
                "(3) LDAP/AD integration that surfaces last logon from directory services. "
                "Document this as an accepted risk or submit a waiver if implementation is not feasible. "
                "Reference VATES_COMPLIANCE_BLOCKERS.md BANNER-001 for related guidance.",
    },
    "V-222438": {
        "nf": "Automated check confirmed XO provides non-repudiation through user-attributed audit records. "
              "The XO audit plugin captures each action with userId, action type, and timestamp. "
              "ISSO action: Verify audit records cannot be modified or deleted by users whose actions are recorded. "
              "Document the audit record retention policy and integrity protection mechanisms.",
        "open": "Non-repudiation for XO user actions requires manual verification. "
                "XO audit plugin records user actions with userId attribution but does not cryptographically sign individual records. "
                "ISSO action: (1) Verify XO audit plugin is active and recording all user actions; "
                "(2) Verify audit records are protected from modification (immutable storage or SIEM forwarding); "
                "(3) Verify records contain sufficient attribution (userId, timestamp, action, target); "
                "(4) Consider forwarding audit records to a SIEM for integrity protection. "
                "Document the non-repudiation controls as compensating measures in the ATO package.",
    },
    "V-222439": {
        "nf": "System clock is synchronized via NTP/Chrony. "
              "XO audit records use the synchronized system clock for timestamping, enabling time-correlated "
              "aggregation with audit records from other systems. "
              "ISSO action: Verify NTP is synchronized to an authoritative government time source. "
              "Document the NTP server configuration and synchronization frequency.",
        "open": "NTP time synchronization not confirmed for this system. "
                "Without synchronized clocks, audit records from multiple systems cannot be reliably correlated. "
                "ISSO action: (1) Configure chronyd or systemd-timesyncd to use DoD-approved NTP servers; "
                "(2) Verify synchronization: timedatectl show | grep NTPSynchronized; "
                "(3) Set polling interval appropriate for the organization tolerance level; "
                "(4) Document the authoritative time source in the system security plan.",
    },
    "V-222441": {
        "nf": "XO generates audit records when session IDs are created (user login). "
              "The XO audit plugin records authentication events including user login, which creates a new session. "
              "Journal logs confirm session creation events are captured with user identity and timestamp. "
              "ISSO action: Verify audit records for session creation include: user ID, source IP, timestamp, and outcome.",
        "open": "Session ID creation audit record generation requires manual verification. "
                "ISSO action: (1) Verify XO audit plugin is installed and active; "
                "(2) Perform a test login and verify an audit record was created; "
                "(3) Confirm the audit record includes: userId, action=session.signIn, timestamp, IP address; "
                "(4) Verify audit records are retained per the organization retention policy.",
    },
    "V-222442": {
        "nf": "XO generates audit records when session IDs are destroyed (user logout). "
              "The XO audit plugin records logout events (session.signOut) with user identity and timestamp. "
              "Session destruction events are captured when users explicitly log out or tokens expire. "
              "ISSO action: Verify audit records for session destruction include: user ID, timestamp, and session identifier.",
        "open": "Session ID destruction audit record generation requires manual verification. "
                "ISSO action: (1) Verify XO audit plugin is installed and active; "
                "(2) Perform a test logout and verify an audit record was created; "
                "(3) Confirm the audit record includes: userId, action=session.signOut, timestamp; "
                "(4) Verify session expiration (timeout) also generates an audit record.",
    },
    "V-222443": {
        "nf": "XO generates audit records when session IDs are renewed. "
              "Session renewal or token refresh events are captured in the audit trail. "
              "ISSO action: Verify the audit plugin captures token renewal events and confirm the records "
              "include userId, session identifier, and timestamp.",
        "open": "Session ID renewal audit record generation requires manual verification. "
                "XO may use rolling session tokens without explicit renewal audit records. "
                "ISSO action: (1) Review XO session management configuration (config.toml session settings); "
                "(2) Verify whether token renewal generates an audit event; "
                "(3) If no renewal audit exists, document as accepted risk or implement via custom logging middleware; "
                "(4) Consider enabling rolling session logging in the XO configuration.",
    },
    "V-222444": {
        "nf": "No sensitive data (passwords, credentials, tokens) detected in XO application logs. "
              "XO Winston logger does not record authentication credentials or session tokens in log output. "
              "ISSO action: Periodically review logs to confirm no sensitive data is written. "
              "Verify the Winston log level is set to exclude debug-level password data in production.",
        "open": "Possible sensitive data detected in XO application logs. "
                "ISSO action: (1) Review the flagged log files for actual sensitive data exposure; "
                "(2) Verify NODE_ENV=production is set (suppresses verbose debug logging); "
                "(3) Review Winston logger configuration for log level and format settings; "
                "(4) Ensure authentication middleware does not log passwords or tokens; "
                "(5) Implement log scrubbing if sensitive data is confirmed in logs.",
    },
    "V-222445": {
        "nf": "XO generates audit records when sessions time out. "
              "Session timeout events are captured in the audit trail with user identity and timestamp. "
              "ISSO action: Verify audit records for session timeouts include: userId, session identifier, "
              "and the reason for termination (timeout vs explicit logout).",
        "open": "Session timeout audit record generation requires manual verification. "
                "Session timeout events may not generate distinct audit records in XO. "
                "ISSO action: (1) Configure session timeout in XO (config.toml or environment variables); "
                "(2) Test session timeout and verify an audit/log event is generated; "
                "(3) If no timeout audit exists, implement via session expiration middleware; "
                "(4) Document as compensating control if session timeout logging is not natively supported.",
    },
    "V-222446": {
        "nf": "XO audit records include timestamps for all events. "
              "systemd journal entries have system timestamps; XO audit plugin uses Unix millisecond timestamps. "
              "Winston logger produces ISO 8601 formatted timestamps. "
              "ISSO action: Verify all audit record sources (journal, XO audit, nginx access log) "
              "include timestamps with sufficient granularity (seconds or better).",
        "open": "Timestamp recording in XO audit records requires manual verification. "
                "ISSO action: (1) Retrieve a sample audit record: GET /rest/v0/plugins/audit/records?limit=5; "
                "(2) Verify each record has a time field in Unix milliseconds; "
                "(3) Verify systemd journal entries include system timestamps; "
                "(4) Verify Winston log format includes timestamp configuration.",
    },
    "V-222447": {
        "nf": "XO generates audit records that include HTTP headers (User-Agent, method, path). "
              "Nginx access logs are configured to capture User-Agent, Referer, and HTTP method. "
              "ISSO action: Verify the nginx combined log format is active and access logs are retained "
              "per the organization audit log retention policy.",
        "open": "HTTP header audit record generation requires manual verification. "
                "ISSO action: (1) Verify nginx access_log is enabled with combined format (includes User-Agent, Referer); "
                "(2) Verify the log_format includes: $remote_addr, $request, $status, $http_user_agent, $http_referer; "
                "(3) If XO is accessed directly (no nginx), verify XO/Express.js logs HTTP headers via morgan middleware; "
                "(4) Retain nginx access logs per organizational policy (minimum 1 year for DoD systems).",
    },
    "V-222448": {
        "nf": "XO generates audit records that include connecting system IP addresses. "
              "Nginx access logs capture client IP ($remote_addr) and X-Forwarded-For headers. "
              "ISSO action: Verify client IP addresses are accurately recorded even when behind a load balancer "
              "or reverse proxy (trust proxy setting may be required in Express.js).",
        "open": "Connecting system IP address audit record generation requires manual verification. "
                "ISSO action: (1) Verify nginx access_log captures $remote_addr for each request; "
                "(2) If behind a load balancer, configure nginx real_ip_header to capture original client IP; "
                "(3) Verify XO audit plugin records the requesting IP address in each audit record; "
                "(4) Test with a known client IP and confirm it appears in access logs.",
    },
    "V-222449": {
        "nf": "XO audit records include the username/user ID for each event. "
              "The XO audit plugin records the userId for every action in the audit trail. "
              "ISSO action: Verify each audit record includes a non-null userId field. "
              "Confirm that unauthenticated actions (failed logins) record the attempted username.",
        "open": "Username/user ID in audit records requires manual verification. "
                "ISSO action: (1) Retrieve a sample audit record: GET /rest/v0/plugins/audit/records?limit=5; "
                "(2) Verify each record has a userId or subject field identifying the user; "
                "(3) Perform a test action and verify the audit record contains your user ID; "
                "(4) Verify failed authentication attempts also record the attempted username.",
    },
    "V-222450": {
        "nf": "XO generates audit records for privilege grant attempts. "
              "The XO audit plugin logs ACL changes, role assignments, and permission modifications. "
              "Both successful and unsuccessful privilege grant attempts are captured with userId and timestamp. "
              "ISSO action: Verify audit records for privilege changes include: granting user ID, "
              "target user ID, privilege granted, and outcome.",
        "open": "Privilege grant attempt audit record generation requires manual verification. "
                "ISSO action: (1) Verify XO audit plugin is active and logging ACL/permission changes; "
                "(2) Test: assign a role to a user and verify an audit record is created; "
                "(3) Confirm the audit record includes: userId (granter), targetUserId, action, privilege level; "
                "(4) Verify failed privilege escalation attempts also generate audit records.",
    },
    "V-222451": {
        "nf": "XO generates audit records for security object access attempts. "
              "The XO audit plugin logs all user interactions with security objects (VMs, hosts, storage, networks). "
              "Both successful and unsuccessful access attempts are recorded with userId and timestamp. "
              "ISSO action: Verify audit records for security object access include: userId, "
              "object type/ID, action performed, and outcome (success/failure).",
        "open": "Security object access audit record generation requires manual verification. "
                "ISSO action: (1) Verify XO audit plugin is active and logging resource access events; "
                "(2) Test: access a VM and verify an audit record is created; "
                "(3) Test: attempt access to a resource without permission and verify audit record is created; "
                "(4) Confirm audit records include: userId, objectType, objectId, action, outcome.",
    },
    "V-222452": {
        "nf": "XO generates audit records for security level access attempts. "
              "XO uses RBAC (Admin, Operator, Viewer roles) rather than MAC security levels. "
              "The XO audit plugin logs all actions with role context, capturing access attempts at different privilege levels. "
              "ISSO action: Verify audit records reflect the user role level and capture both "
              "authorized and unauthorized access attempts across privilege boundaries.",
        "open": "Security level access audit record generation requires manual verification. "
                "ISSO action: (1) Verify XO audit plugin is active and logging RBAC role-based access events; "
                "(2) Test: attempt an admin-only action with a viewer account and verify audit record is created; "
                "(3) Confirm audit records capture cross-role access attempts; "
                "(4) Document XO RBAC model as the mechanism satisfying security level access control audit requirement.",
    },
}


def xml_esc(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


changes = 0
for vid, data in entries.items():
    vuln_pattern = r'(<Vuln ID="' + re.escape(vid) + r'">.*?</Vuln>)'
    m = re.search(vuln_pattern, content, re.DOTALL)
    if not m:
        print(f"NOT FOUND: {vid}")
        continue

    old_block = m.group(1)

    rt_match = re.search(r'<!--RuleTitle:.*?-->', old_block, re.DOTALL)
    rt_comment = rt_match.group() if rt_match else ''

    ak_match = re.search(r'<AnswerKey Name="([^"]+)">', old_block)
    ak_name = ak_match.group(1) if ak_match else 'XO'

    nf_comment = xml_esc(data['nf'])
    open_comment = xml_esc(data['open'])

    new_block = (
        f'<Vuln ID="{vid}">\n'
        f'    {rt_comment}\n'
        f'    <AnswerKey Name="{ak_name}">\n'
        f'      <!--Updated by implement-stig-check for Batch 5-->\n'
        f'      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">\n'
        f'        <ValidationCode></ValidationCode>\n'
        f'        <ValidTrueStatus>NotAFinding</ValidTrueStatus>\n'
        f'        <ValidTrueComment>{nf_comment}</ValidTrueComment>\n'
        f'        <ValidFalseStatus></ValidFalseStatus>\n'
        f'        <ValidFalseComment></ValidFalseComment>\n'
        f'      </Answer>\n'
        f'      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">\n'
        f'        <ValidationCode></ValidationCode>\n'
        f'        <ValidTrueStatus>Open</ValidTrueStatus>\n'
        f'        <ValidTrueComment>{open_comment}</ValidTrueComment>\n'
        f'        <ValidFalseStatus></ValidFalseStatus>\n'
        f'        <ValidFalseComment></ValidFalseComment>\n'
        f'      </Answer>\n'
        f'    </AnswerKey>\n'
        f'  </Vuln>'
    )

    content = content.replace(old_block, new_block, 1)
    changes += 1

print(f"Updated {changes} entries")

with open(AF_PATH, 'w', encoding='utf-8') as f:
    f.write(content)

print("Written successfully")
