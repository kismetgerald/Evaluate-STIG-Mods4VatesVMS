#!/usr/bin/env python3
"""Replace stub answer file entries for Batch 12 with proper 2-index entries."""

import re
import sys

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

def escape_xml(text):
    """Escape XML special characters."""
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text

ENTRIES = {
    "V-203685": {
        "NF": """System displays explicit logoff message indicating reliable termination of authenticated sessions.

Automated scan verified:
- SSH logout scripts configured with explicit logoff messaging
- /etc/bash.bash_logout or profile.d logout scripts contain echo/printf/wall commands
- PAM session close modules configured for session termination notification
- SSH ClientAliveInterval/ClientAliveCountMax provide connection termination signaling

On Debian 12 systems running Xen Orchestra, SSH provides implicit connection closed messages. Custom logout scripts in /etc/bash.bash_logout or /etc/profile.d/ can display explicit logoff messages.

ISSO/ISSM: Verify organizational logoff message requirements and that session termination is reliably communicated to users.""",
        "O": """System does not display an explicit logoff message to users upon session termination.

Automated scan found:
- No explicit logoff message configured in logout scripts
- /etc/bash.bash_logout does not contain echo/printf/wall commands
- No custom session termination notification configured

Remediation steps:
1. Create or edit /etc/bash.bash_logout to include a logoff message:
   echo "Session terminated. You have been logged out."
2. Alternatively, create /etc/profile.d/logout.sh with session close messaging
3. Configure PAM session close notification if required
4. Verify SSH ClientAliveInterval is set for reliable session termination

ISSO/ISSM: Document organizational logoff message requirements and verify implementation."""
    },
    "V-203691": {
        "NF": """System notifies SAs and ISSOs when accounts are enabled or created.

Automated scan verified:
- auditd rules configured for account-related file monitoring (/etc/passwd, /etc/shadow, /etc/group)
- Syslog forwarding configured for auth/authpriv facility to remote logging server
- XO Audit Plugin active with hash chain integrity for application-layer account event recording
- Mail system or alerting mechanism available for automated notifications

Account enabling actions are captured by audit rules and forwarded to centralized logging for SA/ISSO review.

ISSO/ISSM: Verify that account enabling notifications reach designated SAs and ISSOs within the required timeframe.""",
        "O": """System does not notify SAs and ISSOs of account enabling actions.

Automated scan found:
- auditd not active or account-related audit rules not configured
- No syslog forwarding for auth events to remote server
- No automated email or alerting mechanism for account changes

Remediation steps:
1. Install and enable auditd: apt install auditd &amp;&amp; systemctl enable --now auditd
2. Add audit rules for account files:
   -w /etc/passwd -p wa -k identity
   -w /etc/shadow -p wa -k identity
   -w /etc/group -p wa -k identity
3. Configure rsyslog to forward auth events: auth.* @siem-server:514
4. Install mail utilities for alert notifications: apt install mailutils
5. Configure auditd space_left_action = email

ISSO/ISSM: Document notification procedures and verify SA/ISSO receipt of account enabling alerts."""
    },
    "V-203692": {
        "NF": """Operating system allows administrators to pass information to other admins and users.

Automated scan verified:
- wall command available for broadcast messaging to all logged-in users
- write command available for direct user-to-user messaging
- Mail system available for email-based communication
- sudo installed with administrative group configuration

Linux provides native inter-user communication tools (wall, write, mail) that satisfy the requirement for admin-to-admin and admin-to-user information passing.

ISSO/ISSM: Verify organizational communication procedures are documented and that administrators have access to messaging tools.""",
        "O": """Operating system does not provide adequate tools for administrators to pass information.

Automated scan found:
- wall command not available or not properly configured
- write/mesg commands not available
- No mail system installed for email communication

Remediation steps:
1. Install bsd-mailx or mailutils: apt install bsd-mailx
2. Verify wall command is available: which wall
3. Verify write command permissions allow admin use
4. Configure mesg for terminal messaging: mesg y

ISSO/ISSM: Document organizational communication requirements and verify admin communication tools are available."""
    },
    "V-203693": {
        "NF": """Operating system allows administrators to grant their privileges to other administrators.

Automated scan verified:
- sudo installed and configured with privilege delegation groups
- Administrative groups (sudo, admin, root) configured in /etc/group
- usermod and gpasswd available for group membership management
- sudoers.d directory available for granular privilege delegation rules

Linux sudo infrastructure provides comprehensive privilege delegation capabilities allowing administrators to grant specific or full privileges to other administrators.

ISSO/ISSM: Verify privilege delegation policies are documented and that sudo configurations follow least-privilege principles.""",
        "O": """Operating system does not adequately allow administrators to grant privileges to other administrators.

Automated scan found:
- sudo not installed or not properly configured
- No administrative group configuration for privilege delegation
- sudoers file does not contain privilege delegation rules

Remediation steps:
1. Install sudo: apt install sudo
2. Configure administrative groups: usermod -aG sudo username
3. Create sudoers.d rules for granular delegation
4. Verify /etc/sudoers syntax: visudo -c

ISSO/ISSM: Document privilege delegation policies and verify sudo configuration follows organizational requirements."""
    },
    "V-203694": {
        "NF": """Operating system allows administrators to change security attributes on users, the OS, or its components.

Automated scan verified:
- User attribute modification tools available (usermod, chown, chmod, chattr, setfacl)
- sudo installed with administrative access for privilege escalation
- AppArmor available for mandatory access control management
- sysctl available for kernel security parameter modification

Linux provides comprehensive security attribute management tools for users, files, kernel parameters, and mandatory access controls.

ISSO/ISSM: Verify security attribute change procedures are documented and follow organizational change management processes.""",
        "O": """Operating system does not provide adequate tools for administrators to change security attributes.

Automated scan found:
- Essential security tools missing (usermod, chown, chmod, etc.)
- sudo not installed for administrative privilege escalation
- Insufficient tools for security attribute management

Remediation steps:
1. Install sudo: apt install sudo
2. Verify coreutils provides chmod/chown: dpkg -l coreutils
3. Install ACL tools: apt install acl
4. Verify AppArmor tools: apt install apparmor-utils
5. Verify sysctl is available for kernel parameter management

ISSO/ISSM: Document security attribute management procedures and verify all required tools are available."""
    },
    "V-203698": {
        "NF": """System automatically locks accounts after three unsuccessful logon attempts until released by an administrator.

Automated scan verified:
- PAM pam_faillock configured in /etc/pam.d/common-auth
- /etc/security/faillock.conf has deny threshold set to 3 or fewer
- unlock_time set to 0 (administrator must manually unlock)
- fail_interval configured for 15-minute window
- faillock command available for account management

The combination of deny=3, unlock_time=0, and fail_interval=900 ensures accounts lock after 3 failed attempts within 15 minutes and require administrator intervention to unlock.

ISSO/ISSM: Verify account lockout policy is documented and that SA/ISSO procedures exist for unlocking accounts.""",
        "O": """System does not automatically lock accounts after three unsuccessful logon attempts with admin-only release.

Automated scan found:
- PAM pam_faillock not configured or deny threshold exceeds 3
- unlock_time not set to 0 (auto-unlock enabled instead of admin-only)
- /etc/security/faillock.conf missing or incomplete

Remediation steps:
1. Install libpam-modules if needed: apt install libpam-modules
2. Configure /etc/security/faillock.conf:
   deny = 3
   unlock_time = 0
   fail_interval = 900
3. Add pam_faillock to /etc/pam.d/common-auth:
   auth required pam_faillock.so preauth
   auth [default=die] pam_faillock.so authfail
4. Add pam_faillock to /etc/pam.d/common-account:
   account required pam_faillock.so
5. Test with: faillock --user testuser

ISSO/ISSM: Document account lockout policy and verify procedures for administrator account unlock."""
    },
    "V-203699": {
        "NF": """System provides capability for IMOs/ISSOs to change auditing configuration in near real time.

Automated scan verified:
- auditd service active and enabled
- auditctl command available for real-time audit rule changes
- Audit rules configuration files present in /etc/audit/rules.d/
- Administrative access to audit tools via sudo or root

auditctl allows authorized administrators to add, modify, or remove audit rules without service restart, providing near-real-time audit configuration capability.

ISSO/ISSM: Verify IMO/ISSO procedures for audit configuration changes are documented and that designated personnel have appropriate access.""",
        "O": """System does not provide near-real-time audit configuration capability.

Automated scan found:
- auditd service not active or not installed
- auditctl command not available
- No mechanism for real-time audit rule changes

Remediation steps:
1. Install audit framework: apt install auditd audispd-plugins
2. Enable and start auditd: systemctl enable --now auditd
3. Verify auditctl is available: which auditctl
4. Configure base audit rules in /etc/audit/rules.d/
5. Test real-time rule addition: auditctl -w /etc/passwd -p wa -k identity

ISSO/ISSM: Document audit configuration change procedures and verify IMO/ISSO access to auditctl."""
    },
    "V-203703": {
        "NF": """System provides immediate real-time alert to SA and ISSO for audit failure events.

Automated scan verified:
- auditd configured with space_left_action = email (or syslog/exec)
- action_mail_acct configured for alert delivery
- Disk full and disk error actions configured for failure handling
- Syslog forwarding configured for audit events to centralized server
- Mail system installed for email-based alerting

auditd failure actions combined with syslog forwarding ensure SA/ISSO receive real-time notification of audit system failures.

ISSO/ISSM: Verify alert recipients are documented and that test alerts have been validated.""",
        "O": """System does not provide real-time alerting for audit failure events.

Automated scan found:
- auditd not configured for failure alerting (space_left_action not set to email/syslog)
- No mail system installed for email alerts
- No syslog forwarding for audit events

Remediation steps:
1. Configure /etc/audit/auditd.conf:
   space_left_action = email
   admin_space_left_action = halt
   disk_full_action = halt
   disk_error_action = halt
   action_mail_acct = root
2. Install mail system: apt install postfix mailutils
3. Configure syslog forwarding: local6.* @siem-server:514
4. Restart auditd: systemctl restart auditd
5. Test alerting: fill audit log partition to trigger space_left_action

ISSO/ISSM: Document alert recipients and verify notification delivery for audit failures."""
    },
    "V-203709": {
        "NF": """System does not alter original content or time ordering when providing audit reduction capability.

Automated scan verified:
- ausearch available for read-only audit record queries
- aureport available for read-only report generation
- systemd journalctl provides read-only filtering and search
- XO Audit Plugin uses hash chain integrity preventing content alteration
- Audit log files have restrictive permissions preventing unauthorized modification

Linux audit tools (ausearch, aureport, journalctl) perform read-only operations on original audit data, preserving content integrity and chronological ordering.

ISSO/ISSM: Verify audit reduction procedures are documented and that original audit data is preserved.""",
        "O": """System may alter original audit content during audit reduction operations.

Automated scan found:
- ausearch and aureport tools not available
- journalctl not available as alternative
- No audit reduction tools that guarantee content preservation

Remediation steps:
1. Install audit tools: apt install auditd
2. Verify ausearch and aureport are available
3. Configure journald for persistent storage: Storage=persistent in /etc/systemd/journald.conf
4. Set audit log permissions to prevent modification: chmod 600 /var/log/audit/audit.log
5. Consider enabling immutable attribute: chattr +a /var/log/audit/audit.log

ISSO/ISSM: Document audit reduction procedures and verify tools do not modify original records."""
    },
    "V-203710": {
        "NF": """System does not alter original content or time ordering when providing report generation capability.

Automated scan verified:
- aureport available for read-only report generation from audit data
- systemd journalctl supports time-based and priority-based filtering for reports
- Audit log files have restrictive permissions preventing unauthorized modification
- XO Audit Plugin hash chain prevents content alteration during report generation
- Report tools use read-only access to original audit records

Linux report generation tools (aureport, journalctl) create reports from original data without modifying the source records, preserving both content and chronological ordering.

ISSO/ISSM: Verify report generation procedures are documented and that original audit records remain unaltered.""",
        "O": """System may alter original audit content during report generation.

Automated scan found:
- aureport not available for read-only report generation
- journalctl not available as alternative reporting tool
- No report generation tools that guarantee content preservation

Remediation steps:
1. Install audit tools: apt install auditd
2. Verify aureport is available: which aureport
3. Configure journald for persistent storage
4. Set audit log permissions: chmod 600 /var/log/audit/audit.log
5. Test report generation: aureport --summary

ISSO/ISSM: Document report generation procedures and verify tools preserve original audit records."""
    },
}


def build_entry(vid, data):
    nf = escape_xml(data["NF"])
    o = escape_xml(data["O"])
    return f'''  <Vuln ID="{vid}">
    <AnswerKey Name="XO">
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{o}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>'''


def main():
    with open(AF_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    changes = 0
    for vid, data in ENTRIES.items():
        # Find existing Vuln block
        pattern = rf'(\s*<Vuln ID="{re.escape(vid)}">.*?</Vuln>)'
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            print(f"WARNING: {vid} not found in answer file")
            continue

        old_block = match.group(1)
        new_block = "\n" + build_entry(vid, data)
        content = content.replace(old_block, new_block)
        changes += 1
        print(f"OK: Replaced {vid} stub with 2-index entry")

    with open(AF_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nReplaced {changes}/10 entries")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(AF_PATH)
        print("XML validation: PASSED")
    except ET.ParseError as e:
        print(f"XML validation: FAILED - {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
