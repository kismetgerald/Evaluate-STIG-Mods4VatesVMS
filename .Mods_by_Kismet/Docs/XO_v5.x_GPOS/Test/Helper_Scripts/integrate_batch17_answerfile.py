#!/usr/bin/env python3
"""Batch 17 answer file integration — adds 2-index entries for 10 VulnIDs."""

import sys

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

ENTRIES = {
    "V-203651": {
        "nf_comment": "DOCUMENTATION: Audit reduction and report generation capability is provided on this system. The aureport utility from the audit package generates formatted reports from audit log data. Additional tools include ausearch for searching audit records, aulast for login/logout reports, and journalctl for systemd journal queries. The XO Audit Plugin provides application-layer audit records with built-in search and filtering capabilities via the REST API. These tools collectively satisfy the requirement for audit reduction and report generation.",
        "open_comment": "FINDING: Audit reduction and report generation tools are not fully available on this system. REMEDIATION: 1) Install auditd: apt install auditd. 2) Verify aureport is available: which aureport. 3) Verify ausearch is available: which ausearch. 4) Enable the XO Audit Plugin for application-layer audit records. 5) Configure log aggregation to a centralized SIEM for enterprise-level audit reduction. 6) Document audit reduction procedures in the System Security Plan.",
    },
    "V-203671": {
        "nf_comment": "DOCUMENTATION: Audit records contain information identifying the source of audited events. The auditd system records the source process, UID, GID, terminal, and executable path for all audited events. Systemd journal captures the _COMM, _EXE, _CMDLINE, _PID, and _SYSTEMD_UNIT fields that identify the source of each event. The XO Audit Plugin records the userId, subject name, and action endpoint for application-layer events. Together these provide comprehensive event source identification.",
        "open_comment": "FINDING: Audit records may not contain sufficient source identification. REMEDIATION: 1) Install and enable auditd: apt install auditd &amp;&amp; systemctl enable --now auditd. 2) Verify audit rules include source identification: auditctl -l. 3) Enable the XO Audit Plugin for application-layer source tracking. 4) Verify systemd journal is capturing _COMM and _EXE fields: journalctl -o verbose. 5) Document event source identification requirements in the audit policy.",
    },
    "V-203675": {
        "nf_comment": "DOCUMENTATION: Privileges to change software resident within software libraries are limited to authorized personnel. System package management (apt/dpkg) requires root privileges. Critical directories (/usr/lib, /usr/bin, /usr/sbin) are owned by root with appropriate permissions. The sudoers configuration restricts privilege escalation to authorized administrators only. No unauthorized SUID/SGID binaries were found that could allow unprivileged software modification.",
        "open_comment": "FINDING: Software library permissions may allow unauthorized modification. REMEDIATION: 1) Verify ownership of critical directories: stat -c '%U:%G %a %n' /usr/lib /usr/bin /usr/sbin. 2) Fix any incorrect ownership: chown root:root /usr/lib /usr/bin /usr/sbin. 3) Set correct permissions: chmod 755 /usr/lib /usr/bin /usr/sbin. 4) Audit SUID/SGID files: find / -perm /6000 -type f. 5) Remove unnecessary SUID/SGID bits. 6) Restrict sudo access to authorized administrators only.",
    },
    "V-203677": {
        "nf_comment": "DOCUMENTATION: The system preserves operating system state information in the event of a system failure. Systemd journal persistence is configured with Storage=persistent in /etc/systemd/journald.conf, ensuring journal data survives reboots. Kernel crash dump capabilities are available (kdump/systemd-coredump). The filesystem uses ext4/xfs journaling for data integrity. Audit logs are stored on persistent storage. These mechanisms collectively preserve system state information through failures.",
        "open_comment": "FINDING: System state preservation may not be fully configured. REMEDIATION: 1) Enable persistent journald: set Storage=persistent in /etc/systemd/journald.conf. 2) Restart journald: systemctl restart systemd-journald. 3) Install crash dump tools: apt install kdump-tools or systemd-coredump. 4) Verify journal persistence: ls -la /var/log/journal/. 5) Ensure audit logs are on persistent filesystem. 6) Document system failure recovery procedures in the contingency plan.",
    },
    "V-203678": {
        "nf_comment": "DOCUMENTATION: The system is configured to notify system administrators and ISSOs when accounts are created. PAM configuration includes pam_exec or pam_script modules for account creation notification. Auditd rules monitor /etc/passwd, /etc/shadow, and /etc/group for modifications via -w watch rules. The XO Audit Plugin records user account creation events at the application layer. Email notification or SIEM alerting is configured for account creation events per organizational security policy.",
        "open_comment": "FINDING: Account creation notification is not fully configured. REMEDIATION: 1) Add audit rules for account files: auditctl -w /etc/passwd -p wa -k identity &amp;&amp; auditctl -w /etc/shadow -p wa -k identity &amp;&amp; auditctl -w /etc/group -p wa -k identity. 2) Configure email alerts via auditd: set action_mail_acct = root in /etc/audit/auditd.conf. 3) Enable the XO Audit Plugin for application-layer notifications. 4) Configure SIEM integration for real-time alerting. 5) Document notification procedures in the security plan.",
    },
    "V-203679": {
        "nf_comment": "DOCUMENTATION: The system is configured to notify system administrators and ISSOs when accounts are modified. PAM configuration includes notification modules for account modification events. Auditd rules monitor /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow for write access and attribute changes. The XO Audit Plugin records user permission and role modification events at the application layer. Centralized logging forwards modification events to SIEM for alerting.",
        "open_comment": "FINDING: Account modification notification is not fully configured. REMEDIATION: 1) Add audit rules for account files: auditctl -w /etc/passwd -p wa -k identity &amp;&amp; auditctl -w /etc/shadow -p wa -k identity &amp;&amp; auditctl -w /etc/group -p wa -k identity &amp;&amp; auditctl -w /etc/gshadow -p wa -k identity. 2) Configure email alerts via auditd action_mail_acct. 3) Enable the XO Audit Plugin for application-layer notifications. 4) Integrate with SIEM for real-time modification alerts.",
    },
    "V-203680": {
        "nf_comment": "DOCUMENTATION: The system is configured to notify system administrators and ISSOs when accounts are disabled. PAM configuration includes notification modules for account disabling events. Auditd rules monitor /etc/shadow for attribute changes that indicate account locking (password field changes). The XO Audit Plugin records account status change events at the application layer. The passwd -l and usermod -L commands generate audit events when accounts are locked.",
        "open_comment": "FINDING: Account disabling notification is not fully configured. REMEDIATION: 1) Add audit rules for shadow file: auditctl -w /etc/shadow -p wa -k identity. 2) Monitor for account lock events: ausearch -k identity -i. 3) Configure email alerts via auditd action_mail_acct. 4) Enable the XO Audit Plugin for application-layer account status tracking. 5) Configure SIEM alerts for account disable/lock events. 6) Document account disabling notification procedures in the security plan.",
    },
    "V-203681": {
        "nf_comment": "DOCUMENTATION: The system is configured to notify system administrators and ISSOs when accounts are removed. PAM configuration includes notification modules for account removal events. Auditd rules monitor /etc/passwd and /etc/shadow for write access, capturing userdel operations. The XO Audit Plugin records user account deletion events at the application layer. Centralized logging forwards account removal events to SIEM for alerting and compliance tracking.",
        "open_comment": "FINDING: Account removal notification is not fully configured. REMEDIATION: 1) Add audit rules for account files: auditctl -w /etc/passwd -p wa -k identity &amp;&amp; auditctl -w /etc/shadow -p wa -k identity. 2) Configure email alerts via auditd action_mail_acct. 3) Monitor userdel events: ausearch -k identity -i | grep userdel. 4) Enable the XO Audit Plugin for application-layer account removal tracking. 5) Configure SIEM alerts for account removal events. 6) Document procedures in the security plan.",
    },
    "V-263660": {
        "nf_comment": "DOCUMENTATION: Cryptographic keys used on this system are stored in protected locations with appropriate file permissions. Private keys in /etc/ssl/private/ are restricted to root access only (permissions 0700 for directory, 0600 for files). SSH host keys in /etc/ssh/ have permissions of 0600 for private keys. No private keys were found with world-readable permissions. The filesystem provides integrity protection for key storage locations.",
        "open_comment": "FINDING: Cryptographic key storage may not be adequately protected. REMEDIATION: 1) Restrict /etc/ssl/private/ permissions: chmod 0700 /etc/ssl/private &amp;&amp; chmod 0600 /etc/ssl/private/*. 2) Restrict SSH key permissions: chmod 0600 /etc/ssh/ssh_host_*_key. 3) Verify key ownership: chown root:root /etc/ssl/private/* /etc/ssh/ssh_host_*_key. 4) Check for keys in non-standard locations: find / -name '*.key' -o -name '*.pem' | xargs ls -la. 5) Implement key management procedures per NIST SP 800-57.",
    },
    "V-263661": {
        "nf_comment": "DOCUMENTATION: Internal system clocks are synchronized with an authoritative time source. The system uses systemd-timesyncd, chronyd, or ntpd for time synchronization. Time sources are configured to use authorized NTP servers (DoD or organizational time servers). Time synchronization is active and the system clock is within acceptable drift tolerance. Accurate time synchronization supports audit log correlation and forensic analysis across systems.",
        "open_comment": "FINDING: System clock synchronization may not be properly configured. REMEDIATION: 1) Enable time synchronization: systemctl enable --now systemd-timesyncd (or chronyd/ntpd). 2) Configure authoritative time sources in /etc/systemd/timesyncd.conf or /etc/chrony/chrony.conf. 3) Use DoD-approved NTP servers where available. 4) Verify synchronization: timedatectl show-timesync or chronyc sources. 5) Ensure NTP traffic (UDP 123) is allowed through the firewall. 6) Document time synchronization requirements in the security plan.",
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
