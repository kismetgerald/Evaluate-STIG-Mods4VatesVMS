"""
Update answer file for Batch 6: V-222453 through V-222470
"""
import re

AF_PATH = r'd:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml'

with open(AF_PATH, 'r', encoding='utf-8') as f:
    content = f.read()


def xml_esc(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


# Not_Applicable entries (single index)
NA_ENTRIES = {
    "V-222453": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.",
        "na": "Xen Orchestra does not implement data classification categories, MAC security labels, or compartmentalized data protection. XO is a virtualization management platform that uses RBAC (Admin/Operator/Viewer roles) — not data classification levels. The STIG check explicitly states this requirement is not applicable when the application does not require compartmentalized data and data protection. This condition applies to XO deployments.",
    },
    "V-222455": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to modify security objects occur.",
        "na": "Xen Orchestra does not implement classified security objects or data elements with privilege/classification designations. XO manages virtual infrastructure resources (VMs, hosts, storage, networks) using RBAC access controls, not object-level security classification labels. This requirement for security object modification auditing does not apply to XO deployments.",
    },
    "V-222456": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to modify security levels occur.",
        "na": "Xen Orchestra uses RBAC (Admin/Operator/Viewer) and does not implement MAC security levels, security domains, or multilevel security (MLS) classifications. RBAC role changes (privilege modifications) are audited under V-222454. This MAC-specific security level modification requirement does not apply to XO deployments.",
    },
    "V-222457": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.",
        "na": "Xen Orchestra does not store or process classified information and does not implement data classification categories or compartmentalized data protection. The STIG check explicitly states this requirement is not applicable when the application does not require compartmentalized data protection. This condition applies to XO deployments.",
    },
    "V-222459": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to delete security levels occur.",
        "na": "Xen Orchestra uses RBAC (Admin/Operator/Viewer) and does not implement MAC security levels or multilevel security domains. The deletion of security level permissions is not a supported operation in XO. RBAC role removals (privilege deletions) are audited under V-222458. This MAC-specific requirement does not apply to XO deployments.",
    },
    "V-222460": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur.",
        "na": "Xen Orchestra stores its state in LevelDB (a key-value store) and does not implement a relational database with security-labeled objects or data elements. XO does not support compartmentalized data classification for database records. This database security object deletion requirement does not apply to XO deployments.",
    },
    "V-222461": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.",
        "na": "Xen Orchestra does not store classified or categorized information and does not implement data classification categories. The STIG check explicitly states this requirement is not applicable when the application does not require compartmentalized data and data protection. This condition applies to XO deployments.",
    },
    "V-222466": {
        "rt": "The application must generate audit records for all direct access to the information system.",
        "na": "Xen Orchestra is a web-based virtualization management application. Users interact with XO exclusively via HTTPS web UI and REST API. XO does not expose terminal emulators, command shells, file system browsers, or direct OS command execution interfaces to authenticated users. The STIG check explicitly states this requirement is not applicable when the application does not provide direct access to the system. This condition applies to XO deployments.",
    },
}

# Technical entries with NotAFinding + Open (and optionally Not_Applicable)
TECH_ENTRIES = {
    "V-222454": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to modify privileges occur.",
        "nf": "Automated check detected the XO audit plugin is active. The XO audit plugin records all ACL and role modification events (addAcl, removeAcl, setAcl) which constitute privilege modification attempts in XO's RBAC model. Both successful and unsuccessful privilege modification attempts are captured with userId, action type, timestamp, and target object.\nISSO action: Verify audit records include the granting user ID, target user/object, privilege modified, and outcome. Confirm audit records are retained per the organization retention policy.",
        "open": "Automated check could not confirm the XO audit plugin is active. Privilege modification audit records may not be generated.\nISSO action: (1) Install and activate the @xen-orchestra/audit plugin; (2) Test: assign and revoke a role for a test user; (3) Verify audit records capture: userId (admin performing change), targetUserId, action (addAcl/removeAcl), privilege level, and outcome; (4) Verify failed privilege modification attempts also generate audit records.",
    },
    "V-222458": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to delete privileges occur.",
        "nf": "Automated check detected the XO audit plugin is active. The XO audit plugin records all ACL and role deletion events (removeAcl, deleteAcl operations) which constitute privilege deletion attempts in XO's RBAC model. Both successful and unsuccessful privilege deletion attempts are captured with userId, action type, timestamp, and target.\nISSO action: Verify audit records include the user performing the deletion, the target user/object, the privilege deleted, and the outcome. Confirm audit records are retained per the organization retention policy.",
        "open": "Automated check could not confirm the XO audit plugin is active. Privilege deletion audit records may not be generated.\nISSO action: (1) Install and activate the @xen-orchestra/audit plugin; (2) Test: remove a role from a test user; (3) Verify audit records capture: userId (admin), targetUserId, action (removeAcl), privilege level, and outcome; (4) Verify failed deletion attempts also generate audit records.",
    },
    "V-222462": {
        "rt": "The application must generate audit records when successful and unsuccessful logon attempts occur.",
        "nf": "Automated check detected the XO audit plugin is active. XO records session.signIn events for all authentication attempts. The audit plugin captures: userId, action (session.signIn), timestamp, source IP address, and outcome. Failed authentication attempts are also recorded. systemd journal provides additional authentication event logging.\nISSO action: Verify audit records include successful logins (userId + timestamp) and failed login attempts (attempted username + reason). Confirm records are retained per the organization retention policy.",
        "open": "Automated check could not confirm the XO audit plugin is active. Logon attempt audit records may not be generated.\nISSO action: (1) Install and activate the @xen-orchestra/audit plugin; (2) Perform a successful login and verify session.signIn audit record was created; (3) Perform a failed login and verify it is recorded; (4) Confirm records include: userId, action=session.signIn, timestamp, source IP, outcome.",
    },
    "V-222463": {
        "rt": "The application must generate audit records for privileged activities or other system-level access.",
        "nf": "Automated check detected the XO audit plugin is active. XO audit plugin captures all privileged activities including: VM lifecycle operations (start/stop/snapshot/migrate), host management (patch/reboot/maintenance), user management, ACL changes, server configuration, and pool operations. All records include userId, action, target object ID, and timestamp.\nISSO action: Verify audit records capture the full range of admin operations. Test by performing a VM snapshot as admin and confirm the audit record shows your userId, the action, and the VM ID.",
        "open": "Automated check could not confirm the XO audit plugin is active. Privileged activity audit records may not be generated.\nISSO action: (1) Install and activate the @xen-orchestra/audit plugin; (2) Perform a privileged action (start a VM, add a user, change an ACL); (3) Verify audit record includes: userId, action type, target object, timestamp; (4) Verify system-level access events (host management, pool operations) are captured.",
    },
    "V-222464": {
        "rt": "The application must generate audit records showing the starting and ending time for user access to the system.",
        "nf": "Automated check detected the XO audit plugin is active. XO records session.signIn (session start) and session.signOut (session end) events with Unix millisecond timestamps for each user session. Session start and end times are available in the XO audit trail via the REST API.\nISSO action: Query the audit API: GET /rest/v0/plugins/audit/records?limit=10 and verify records include 'time' field in Unix milliseconds. Confirm session.signIn and session.signOut pairs are present for the same userId.",
        "open": "Automated check could not confirm the XO audit plugin is active. Session start/end time audit records may not be generated.\nISSO action: (1) Install and activate the @xen-orchestra/audit plugin; (2) Perform a login and logout; (3) Verify audit records for session.signIn and session.signOut exist with timestamps; (4) Confirm timestamps have millisecond granularity and are in UTC.",
    },
    "V-222465": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to access objects occur.",
        "nf": "Automated check detected the XO audit plugin is active. XO audit plugin records all object access events including VM operations (start/stop/snapshot/migrate/console), host management, storage repository access, network configuration, and pool membership changes. Both successful and authorized operations are recorded. Unauthorized access attempts return errors which are logged by the application.\nISSO action: Test object access logging by accessing a VM and verifying the audit record includes: userId, action, objectType (vm/host/sr/network), objectId, and timestamp.",
        "open": "Automated check could not confirm the XO audit plugin is active. Object access audit records may not be generated.\nISSO action: (1) Install and activate the @xen-orchestra/audit plugin; (2) Access a VM (start or view console); (3) Verify audit record includes: userId, action, object type, object ID, timestamp; (4) Test unauthorized access (attempt restricted action) and verify the failed attempt is also recorded.",
    },
    "V-222467": {
        "rt": "The application must generate audit records when successful/unsuccessful attempts to create, modify, disable/deactivate, or delete accounts occur.",
        "nf": "Automated check detected the XO audit plugin is active and XO is not configured with LDAP enterprise authentication. XO audit plugin records user account lifecycle events: user.create, user.set (modify), and user.delete operations are captured with userId (admin performing action), target userId, action type, and timestamp.\nISSO action: Test account lifecycle logging: (1) Create a test user and verify audit record; (2) Modify the user and verify; (3) Delete the user and verify. Confirm each event includes: adminUserId, targetUserId, action, and timestamp.",
        "open": "Automated check could not confirm the XO audit plugin is active or account lifecycle events are logged. Account lifecycle audit records may not be generated.\nISSO action: (1) Install and activate the @xen-orchestra/audit plugin; (2) Create, modify, and delete a test user account; (3) Verify audit records for each lifecycle event are created; (4) Confirm records include: performing user ID, target user ID, action, and timestamp.",
        "na": "XO is configured to use LDAP/AD enterprise authentication. The STIG states this requirement is not applicable when the application uses a STIG-compliant enterprise user management capability. Account lifecycle events (create/modify/disable/terminate) are managed and audited by the enterprise directory (AD/LDAP) system. Verify the enterprise directory STIG compliance and confirm account lifecycle audit records exist in the directory audit logs.",
    },
    "V-222468": {
        "rt": "The application must initiate session auditing upon startup.",
        "nf": "Automated check confirmed the XO audit plugin is present and the XO service is active under systemd. The audit plugin is loaded with the XO application on startup. Winston logger initializes with the application and begins logging from the first event. systemd journals service start events capturing the startup sequence.\nISSO action: Verify session auditing begins on startup by reviewing systemd journal entries: journalctl -u xo-server --since 'last reboot' | head -20. Confirm log entries begin immediately upon service start.",
        "open": "Automated check could not confirm the XO audit plugin is active or that session auditing begins on startup.\nISSO action: (1) Install and activate the @xen-orchestra/audit plugin; (2) Restart the xo-server service: systemctl restart xo-server; (3) Review logs immediately after restart: journalctl -u xo-server -f; (4) Verify the first log entries appear immediately upon service start; (5) Confirm the audit plugin logs a startup event.",
    },
    "V-222469": {
        "rt": "The application must log application shutdown events.",
        "nf": "Automated check confirmed the XO service runs under systemd which records all service stop/shutdown events in the system journal. systemd logs both graceful shutdown (systemctl stop xo-server) and unexpected termination events with timestamps. This provides comprehensive shutdown event logging.\nISSO action: Review recent shutdown events: journalctl -u xo-server | grep -i 'stop\\|shut\\|deactiv' | tail -10. Verify shutdown events are captured with timestamp and reason.",
        "open": "Automated check could not confirm systemd manages the XO service or that shutdown events are logged.\nISSO action: (1) Verify xo-server runs as a systemd service: systemctl status xo-server; (2) Stop and start the service to generate shutdown events; (3) Verify: journalctl -u xo-server | grep -i stopped; (4) Confirm shutdown events include: timestamp, service name, and exit status; (5) If not systemd-managed, configure XO to log shutdown events via Winston.",
    },
    "V-222470": {
        "rt": "The application must log the destination IP addresses of outbound network connections.",
        "nf": "Automated check detected the XO audit plugin is active and XO configuration references outbound connections to XCP-ng hosts. XO audit records include source IP (connecting client) and target object references (host IDs which map to destination IPs). Outbound connections to XCP-ng hosts via XAPI are logged per-operation in XO audit records.\nISSO action: Verify destination IP logging by checking audit records for host operations: GET /rest/v0/plugins/audit/records?limit=20. Confirm records reference the destination XCP-ng host by ID (which can be resolved to IP via server list).",
        "open": "Automated check could not confirm the XO audit plugin is active or that destination IP addresses are logged for outbound connections.\nISSO action: (1) Install and activate the @xen-orchestra/audit plugin; (2) Perform an operation on a VM hosted on a specific XCP-ng host; (3) Verify the audit record references the target host (which maps to the destination IP); (4) Check nginx access logs for upstream proxy destination logging; (5) Review syslog for outbound connection destination IPs to DNS, LDAP, and XCP-ng hosts.",
    },
}


def build_na_block(vid, rt, na_comment):
    rt_escaped = xml_esc(rt)
    na_esc = xml_esc(na_comment)
    return (
        f'  <Vuln ID="{vid}">\n'
        f'    <!--RuleTitle: {rt_escaped}-->\n'
        f'    <AnswerKey Name="XO">\n'
        f'      <!--Updated by update_batch6_answerfile.py for Batch 6-->\n'
        f'      <Answer Index="1" ExpectedStatus="Not_Applicable" Hostname="" Instance="" Database="" Site="" ResultHash="">\n'
        f'        <ValidationCode></ValidationCode>\n'
        f'        <ValidTrueStatus>Not_Applicable</ValidTrueStatus>\n'
        f'        <ValidTrueComment>{na_esc}</ValidTrueComment>\n'
        f'        <ValidFalseStatus></ValidFalseStatus>\n'
        f'        <ValidFalseComment></ValidFalseComment>\n'
        f'      </Answer>\n'
        f'    </AnswerKey>\n'
        f'  </Vuln>'
    )


def build_tech_block(vid, rt, nf_comment, open_comment, na_comment=None):
    rt_escaped = xml_esc(rt)
    nf_esc = xml_esc(nf_comment)
    open_esc = xml_esc(open_comment)
    block = (
        f'  <Vuln ID="{vid}">\n'
        f'    <!--RuleTitle: {rt_escaped}-->\n'
        f'    <AnswerKey Name="XO">\n'
        f'      <!--Updated by update_batch6_answerfile.py for Batch 6-->\n'
        f'      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">\n'
        f'        <ValidationCode></ValidationCode>\n'
        f'        <ValidTrueStatus>NotAFinding</ValidTrueStatus>\n'
        f'        <ValidTrueComment>{nf_esc}</ValidTrueComment>\n'
        f'        <ValidFalseStatus></ValidFalseStatus>\n'
        f'        <ValidFalseComment></ValidFalseComment>\n'
        f'      </Answer>\n'
        f'      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">\n'
        f'        <ValidationCode></ValidationCode>\n'
        f'        <ValidTrueStatus>Open</ValidTrueStatus>\n'
        f'        <ValidTrueComment>{open_esc}</ValidTrueComment>\n'
        f'        <ValidFalseStatus></ValidFalseStatus>\n'
        f'        <ValidFalseComment></ValidFalseComment>\n'
        f'      </Answer>\n'
    )
    if na_comment:
        na_esc = xml_esc(na_comment)
        block += (
            f'      <Answer Index="3" ExpectedStatus="Not_Applicable" Hostname="" Instance="" Database="" Site="" ResultHash="">\n'
            f'        <ValidationCode></ValidationCode>\n'
            f'        <ValidTrueStatus>Not_Applicable</ValidTrueStatus>\n'
            f'        <ValidTrueComment>{na_esc}</ValidTrueComment>\n'
            f'        <ValidFalseStatus></ValidFalseStatus>\n'
            f'        <ValidFalseComment></ValidFalseComment>\n'
            f'      </Answer>\n'
        )
    block += f'    </AnswerKey>\n  </Vuln>'
    return block


changes = 0

# Replace N/A stubs
for vid, data in NA_ENTRIES.items():
    vuln_pattern = r'(<Vuln ID="' + re.escape(vid) + r'">.*?</Vuln>)'
    m = re.search(vuln_pattern, content, re.DOTALL)
    if not m:
        print(f"NOT FOUND: {vid}")
        continue
    new_block = build_na_block(vid, data['rt'], data['na'])
    content = content.replace(m.group(1), new_block, 1)
    changes += 1
    print(f"Updated N/A: {vid}")

# Replace technical stubs
for vid, data in TECH_ENTRIES.items():
    vuln_pattern = r'(<Vuln ID="' + re.escape(vid) + r'">.*?</Vuln>)'
    m = re.search(vuln_pattern, content, re.DOTALL)
    if not m:
        print(f"NOT FOUND: {vid}")
        continue
    na_c = data.get('na')
    new_block = build_tech_block(vid, data['rt'], data['nf'], data['open'], na_c)
    content = content.replace(m.group(1), new_block, 1)
    changes += 1
    print(f"Updated tech: {vid}")

print(f"\nTotal updated: {changes}/18")

with open(AF_PATH, 'w', encoding='utf-8') as f:
    f.write(content)

print("Written successfully")
