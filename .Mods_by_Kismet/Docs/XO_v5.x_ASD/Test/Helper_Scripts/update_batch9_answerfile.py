"""
update_batch9_answerfile.py
Replace GUI-generated stub entries for V-222496 through V-222521 with
full implementation entries (2 indices each).

26 functions covering audit info protection, software/config controls,
vulnerability &amp; execution controls.
"""

import re

ANSWER_FILE = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode"
    r"\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml"
)


def make_stub_pattern(vid):
    return re.compile(
        r'(<Vuln ID="' + re.escape(vid) + r'">\s*'
        r'<!--RuleTitle:[^<]*-->\s*)'
        r'<AnswerKey Name="XO">.*?</AnswerKey>\s*'
        r'(</Vuln>)',
        re.DOTALL,
    )


def make_repl(new_answer_key):
    def _repl(m):
        return m.group(1) + new_answer_key + "\n  " + m.group(2)
    return _repl


def answer_key(idx1_status, idx1_comment, idx2_status, idx2_comment):
    return (
        '<AnswerKey Name="XO">\n'
        '      <!--Updated by implement-stig-check for Batch 9-->\n'
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
# V-222496 — Report generation preserving original content
# Not_Applicable if SIEM; Open if no SIEM
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222496 = answer_key(
    idx1_status="Not_Applicable",
    idx1_comment="""\
This requirement is Not Applicable. A centralized logging solution is configured \
that provides report generation preserving original audit record content and time ordering.

ISSO VERIFICATION:
1. Confirm the SIEM generates reports without modifying source audit records
2. Verify reports maintain chronological ordering of events
3. Document the centralized report generation capability in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
No centralized logging solution was detected that provides report generation \
preserving original content and time ordering.

REMEDIATION STEPS:
1. Deploy a centralized SIEM (Splunk, ELK, Graylog) with report generation
2. Verify report generation does not alter source audit records
3. Configure read-only access to source logs during report generation
4. Document the report generation integrity controls in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222497 — Internal system clocks for timestamps
# NF if NTP active; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222497 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
The system uses internal system clocks synchronized via NTP/chrony/timesyncd \
for generating audit record timestamps. XO (Node.js) uses the system clock \
(Date.now()) for all timestamp generation.

ISSO VERIFICATION:
1. Confirm NTP synchronization is active and configured to DoD time sources
2. Verify XO audit plugin timestamps align with system clock
3. Document the NTP configuration in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
No active NTP synchronization was detected. The system clock may not be \
reliable for audit timestamp generation.

REMEDIATION STEPS:
1. Install and configure chrony or ntp:
   apt install chrony
   systemctl enable --now chronyd
2. Configure DoD-approved NTP sources in /etc/chrony/chrony.conf
3. Verify synchronization: chronyc sources
4. Document NTP configuration in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222498 — Timestamps mappable to UTC
# NF always (timezone offset allows UTC mapping)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222498 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit timestamps can be mapped to UTC. The system timezone offset is known, \
systemd journal natively supports UTC output, and Node.js Date objects store \
time internally as UTC milliseconds.

ISSO VERIFICATION:
1. Confirm timezone is configured correctly (timedatectl)
2. Verify log timestamps include timezone offset or are in UTC
3. For UTC-only requirement, configure: timedatectl set-timezone UTC""",
    idx2_status="Open",
    idx2_comment="""\
Audit timestamps cannot be reliably mapped to UTC. The system timezone \
configuration may be incorrect or log timestamps lack timezone information.

REMEDIATION STEPS:
1. Set the system timezone to UTC for DoD compliance:
   timedatectl set-timezone UTC
2. Configure XO to use UTC timestamps in logging
3. Verify journal output with: journalctl --output=short-iso
4. Document the timezone configuration in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222499 — Timestamp granularity >= 1 second
# NF always (subsecond precision available)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222499 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit timestamps exceed the minimum 1-second granularity requirement. \
Systemd journal provides microsecond precision. XO audit plugin records \
timestamps as Unix milliseconds (Date.now()).

ISSO VERIFICATION:
1. Verify journal timestamp precision: journalctl --output=short-precise
2. Confirm XO audit records contain millisecond timestamps
3. Document the timestamp precision in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Audit timestamps do not meet the minimum 1-second granularity requirement.

REMEDIATION STEPS:
1. Verify systemd journal is configured for persistent storage
2. Check XO logging configuration for timestamp format
3. Ensure Node.js Date.now() is used (not truncated to seconds)
4. Document the timestamp granularity in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222500 — Protect audit info from unauthorized read
# NF if permissions secure; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222500 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit information is protected from unauthorized read access. Log directories \
are owned by root with restricted permissions. Systemd journal access is \
controlled by the systemd-journal group membership.

ISSO VERIFICATION:
1. Verify log directory permissions: stat /var/log/xo-server /var/log/journal
2. Confirm no world-readable log files exist
3. Review systemd-journal group membership for authorized users only""",
    idx2_status="Open",
    idx2_comment="""\
Audit information may be accessible to unauthorized readers. World-readable \
log files or overly permissive directory permissions were detected.

REMEDIATION STEPS:
1. Fix log directory permissions:
   chmod 750 /var/log/xo-server
   chown root:adm /var/log/xo-server
2. Fix individual log file permissions:
   chmod 640 /var/log/xo-server/*.log
3. Review and restrict systemd-journal group membership
4. Document the access control configuration in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222501 — Protect audit info from unauthorized modification
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222501 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit information is protected from unauthorized modification. Log files are \
owned by root with no world-write permissions. Systemd journal uses a binary \
format with built-in integrity checking.

ISSO VERIFICATION:
1. Verify no world-writable log files exist
2. Confirm log directory ownership is root
3. Consider enabling append-only attributes: chattr +a /var/log/xo-server/""",
    idx2_status="Open",
    idx2_comment="""\
Audit information may be modifiable by unauthorized users. World-writable \
log files or insufficient directory permissions were detected.

REMEDIATION STEPS:
1. Remove world-write permissions:
   chmod -R o-w /var/log/xo-server/
2. Set append-only attribute: chattr +a /var/log/xo-server/*.log
3. Configure logrotate to maintain proper permissions on rotated files
4. Document the modification protection controls in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222502 — Protect audit info from unauthorized deletion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222502 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit information is protected from unauthorized deletion. Log directories \
are owned by root with restricted permissions. Only root can delete log files.

ISSO VERIFICATION:
1. Verify log directory ownership: ls -la /var/log/xo-server/
2. Confirm only root has delete permissions on log files
3. Consider setting immutable attributes on archived logs""",
    idx2_status="Open",
    idx2_comment="""\
Audit information may be deletable by unauthorized users.

REMEDIATION STEPS:
1. Restrict log directory permissions:
   chmod 750 /var/log/xo-server
   chown root:adm /var/log/xo-server
2. Set immutable attribute on archived logs: chattr +i /var/log/xo-server/archived/
3. Forward logs to a centralized SIEM for off-system preservation
4. Document the deletion protection controls in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222503 — Protect audit tools from unauthorized access
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222503 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit tools are protected from unauthorized access. System audit tools \
(journalctl, logger, aureport, ausearch) are owned by root with standard \
permissions managed by the dpkg package manager.

ISSO VERIFICATION:
1. Verify audit tool permissions: stat /usr/bin/journalctl /usr/sbin/aureport
2. Confirm tools are owned by root
3. Document the audit tool access controls in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Some audit tools may have overly permissive access settings.

REMEDIATION STEPS:
1. Reset audit tool permissions to package defaults:
   apt install --reinstall coreutils systemd
2. Verify permissions after reset: dpkg --verify coreutils systemd
3. Restrict access to sensitive audit tools (aureport, ausearch)
4. Document the remediation in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222504 — Protect audit tools from unauthorized modification
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222504 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit tools are protected from unauthorized modification. System audit tools \
are managed by the dpkg package manager which maintains cryptographic hashes. \
Only root can modify files in /usr/bin and /usr/sbin.

ISSO VERIFICATION:
1. Verify package integrity: dpkg --verify coreutils systemd
2. Confirm no group/other write permissions on audit tools
3. Document the modification protection controls in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Some audit tools may be modifiable by non-root users.

REMEDIATION STEPS:
1. Remove group/other write permissions:
   chmod go-w /usr/bin/journalctl /usr/sbin/aureport /usr/sbin/ausearch
2. Verify package integrity: dpkg --verify coreutils systemd
3. Install AIDE for ongoing integrity monitoring: apt install aide
4. Document the remediation in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222505 — Protect audit tools from unauthorized deletion
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222505 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit tools are protected from unauthorized deletion. Tool directories \
(/usr/bin, /usr/sbin) are owned by root and not world-writable. Package \
management (dpkg/apt) requires root for removal.

ISSO VERIFICATION:
1. Verify directory permissions: stat /usr/bin /usr/sbin
2. Confirm only root can remove packages: apt requires sudo
3. Document the deletion protection controls in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Audit tool directories may allow unauthorized deletion.

REMEDIATION STEPS:
1. Fix directory permissions:
   chmod 755 /usr/bin /usr/sbin
   chown root:root /usr/bin /usr/sbin
2. Verify no unauthorized users have sudo access to apt/dpkg
3. Consider immutable attributes on critical audit tools
4. Document the remediation in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222506 — Back up audit records every 7 days
# NF if centralized; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222506 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit records are backed up via centralized logging which forwards logs \
in real-time, exceeding the 7-day backup requirement.

ISSO VERIFICATION:
1. Confirm centralized logging is actively forwarding all XO audit records
2. Verify the centralized system retains logs per organizational policy
3. Confirm backup frequency exceeds the 7-day minimum requirement
4. Document the audit record backup configuration in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
No verified backup mechanism for audit records to a separate system. \
Local logrotate provides archival but not off-system backup.

REMEDIATION STEPS:
1. Configure rsyslog to forward logs to centralized syslog server:
   Add to /etc/rsyslog.conf: *.* @@siem-server:514
2. Alternatively, configure scheduled backup:
   cron job: 0 0 * * 0 rsync -a /var/log/xo-server/ backup-server:/backup/xo-logs/
3. Configure systemd-journal-remote for journal forwarding
4. Verify backup occurs at minimum every 7 days
5. Document the backup configuration in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222507 — Cryptographic integrity protection for audit info
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222507 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Cryptographic mechanisms are in use to protect audit information integrity. \
This may include systemd journal Forward Secure Sealing (FSS), AIDE file \
integrity monitoring, or TLS-protected log transmission.

ISSO VERIFICATION:
1. Confirm the cryptographic integrity mechanism is active and configured
2. Verify audit records cannot be modified without detection
3. Document the integrity protection mechanism in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
No cryptographic integrity protection detected for audit records.

REMEDIATION STEPS:
1. Enable systemd journal Forward Secure Sealing:
   Set Seal=yes in /etc/systemd/journald.conf
   systemctl restart systemd-journald
2. Install AIDE for file integrity monitoring:
   apt install aide
   aideinit
3. Configure TLS for remote log transmission (rsyslog with TLS)
4. Document the integrity protection in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222508 — Audit tools must be cryptographically hashed
# NF always (dpkg provides hashing)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222508 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit tools are cryptographically hashed through the dpkg package management \
system, which maintains MD5 checksums for all installed package files. \
dpkg --verify validates current file state against stored checksums.

ISSO VERIFICATION:
1. Run dpkg --verify for audit tool packages
2. Verify no unauthorized modifications are reported
3. Document the package integrity verification in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Audit tool cryptographic hashing verification has failed or is not available.

REMEDIATION STEPS:
1. Verify dpkg integrity checking is functional: dpkg --verify coreutils systemd
2. Reinstall modified packages: apt install --reinstall [package]
3. Install debsums for additional integrity checking: apt install debsums
4. Document the remediation in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222509 — Validate audit tool integrity by checking hash changes
# NF if validation found; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222509 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Audit tool integrity is validated through cryptographic hash checking. \
Mechanisms may include AIDE scheduled checks, debsums verification, \
dpkg --verify, or journalctl --verify.

ISSO VERIFICATION:
1. Confirm integrity checking is scheduled (cron/systemd timer)
2. Verify the checking mechanism runs at organization-defined frequency
3. Document the integrity validation schedule in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
No automated audit tool integrity validation mechanism was detected.

REMEDIATION STEPS:
1. Install AIDE: apt install aide &amp;&amp; aideinit
2. Configure daily AIDE check: add to /etc/cron.daily/aide
3. Install debsums: apt install debsums
4. Configure scheduled integrity validation
5. Document the validation schedule and procedures in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222510 — Prohibit user software installation without privileges
# NF always (apt requires root)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222510 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Software installation requires privileged (root/sudo) access. The apt/dpkg \
package managers enforce root-level permissions for software installation, \
modification, and removal by default on Debian 12.

ISSO VERIFICATION:
1. Confirm apt/dpkg require root or sudo for installation
2. Review sudo configuration for authorized software installers
3. Document the software installation policy in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Non-privileged users may be able to install software.

REMEDIATION STEPS:
1. Review sudo configuration: visudo
2. Remove unnecessary sudo permissions for package management
3. Restrict polkit policies for package installation
4. Document the software installation restrictions in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222511 — Enforce access restrictions for config changes
# NF if restricted; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222511 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Access restrictions are enforced for configuration changes. XO RBAC requires \
admin role for configuration modifications. Config files are root-owned with \
restricted permissions.

ISSO VERIFICATION:
1. Verify XO admin role is required for configuration changes
2. Confirm config file permissions are restricted (600 or 640)
3. Document the configuration change access controls in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Configuration files may be modifiable by non-privileged users.

REMEDIATION STEPS:
1. Fix config file permissions:
   chmod 600 /etc/xo-server/config.toml
   chown root:root /etc/xo-server/config.toml
2. Verify XO RBAC is enforced (admin role required for settings)
3. Restrict systemd service file permissions
4. Document the access restriction configuration in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222512 — Audit who makes config changes
# NF if auditing found; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222512 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Configuration changes are audited with user attribution. The XO audit plugin \
records all administrative actions including configuration changes with user \
identity and timestamp. Systemd journal records service configuration events.

ISSO VERIFICATION:
1. Verify the XO audit plugin is enabled and recording events
2. Confirm configuration change events include user identity
3. Document the configuration auditing capability in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
No configuration change auditing mechanism was detected.

REMEDIATION STEPS:
1. Enable the XO audit plugin in Settings &gt; Plugins
2. Configure auditd rules for XO config files:
   auditctl -w /etc/xo-server/config.toml -p wa -k xo-config
3. Verify auditing captures user identity for all config changes
4. Document the auditing configuration in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222513 — Patch signing verification
# NF if GPG enforced; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222513 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Software component installation requires digital signature verification. APT \
enforces GPG signature verification by default. npm uses SHA-512 integrity \
hashes in package-lock.json.

ISSO VERIFICATION:
1. Confirm APT signature verification is not disabled
2. Verify GPG keys are from trusted sources
3. Confirm npm integrity checking is enabled (package-lock)
4. Document the signature verification configuration in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Unsigned package installation may be allowed or signature verification \
is disabled.

REMEDIATION STEPS:
1. Remove any AllowUnauthenticated settings from APT config:
   grep -r AllowUnauthenticated /etc/apt/
2. Verify GPG keys: apt-key list
3. Enable npm package-lock: npm config set package-lock true
4. Document the signature verification configuration in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222514 — Limit privileges to change software libraries
# NF if secure; Open if not
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222514 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Software library directories are protected with appropriate permissions. Only \
privileged users can modify library contents. XO node_modules, system libraries, \
and npm global packages are root-owned.

ISSO VERIFICATION:
1. Verify no world-writable files in /opt/xo/ or /usr/lib/
2. Confirm library directories are root-owned
3. Document the library protection configuration in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Some software libraries may be modifiable by non-privileged users.

REMEDIATION STEPS:
1. Fix permissions on XO libraries:
   chown -R root:root /opt/xo/node_modules
   chmod -R o-w /opt/xo/
2. Fix system library permissions:
   chmod -R o-w /usr/lib/ /usr/local/lib/
3. Verify npm global directory permissions
4. Document the library protection in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222515 — Vulnerability assessment
# Open always (org documentation required)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222515 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
An application vulnerability assessment program is in place. This includes \
STIG compliance scanning via Evaluate-STIG, npm security audits, and Debian \
security update monitoring.

ISSO VERIFICATION:
1. Confirm regular vulnerability assessments are conducted
2. Verify assessment scope covers all application components
3. Document the assessment program in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Vulnerability assessment evidence is limited. A comprehensive vulnerability \
assessment program must be documented.

REMEDIATION STEPS:
1. Establish a vulnerability assessment program:
   - Define scope (XO application, OS, dependencies)
   - Define frequency (quarterly minimum)
   - Assign responsible personnel
2. Run regular npm audits: npm audit
3. Monitor Debian security updates: apt list --upgradable
4. Schedule STIG compliance scans with Evaluate-STIG
5. Document the assessment program in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222516 — Program execution per org policies
# Open always (org policies required)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222516 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Program execution control mechanisms are in place including AppArmor profiles, \
systemd service management, XO plugin control, and noexec mount options.

ISSO VERIFICATION:
1. Confirm organization-defined execution policies are documented
2. Verify AppArmor enforcement mode for applicable profiles
3. Document the execution control configuration in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Program execution control mechanisms exist but organization-defined execution \
policies must be documented and verified.

REMEDIATION STEPS:
1. Document organization-defined software execution policies
2. Enable AppArmor enforcement for XO-related profiles
3. Disable unnecessary services: systemctl disable [service]
4. Configure noexec on /tmp and /var/tmp mount points
5. Document the execution control policies in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222517 — Deny-all, permit-by-exception whitelist
# Open always (org policies required)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222517 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
A deny-all, permit-by-exception approach is implemented through XO RBAC, \
AppArmor profiles, and firewall rules. XO enforces role-based access where \
non-permitted actions are denied by default.

ISSO VERIFICATION:
1. Confirm XO RBAC is configured with least-privilege roles
2. Verify AppArmor or similar application control is enforcing
3. Document the whitelist/exception-based policy in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Organization-defined software execution policies using deny-all, permit-by- \
exception approach must be documented and verified.

REMEDIATION STEPS:
1. Document the authorized software whitelist
2. Configure AppArmor profiles for XO components
3. Implement firewall deny-all with specific allow rules
4. Configure XO RBAC with minimum necessary permissions
5. Document the deny-all, permit-by-exception policy in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222518 — Disable non-essential capabilities
# Open always (org determination required)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222518 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Non-essential capabilities have been reviewed and disabled. Only mission- \
essential services, plugins, and features are enabled.

ISSO VERIFICATION:
1. Review enabled services and confirm all are mission-essential
2. Review XO plugins and confirm all are required
3. Confirm no debug/development features are enabled in production
4. Document the capability review in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Non-essential capability review requires organizational determination of \
which plugins, services, and features are mission-essential.

REMEDIATION STEPS:
1. Review and document mission-essential services
2. Disable unnecessary XO plugins in Settings &gt; Plugins
3. Disable non-essential system services: systemctl disable [service]
4. Ensure Node.js debug mode is disabled (no --inspect flags)
5. Document the capability review and disabled items in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222519 — PPSM CAL ports/protocols
# Open always (PPSM documentation required)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222519 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
All ports/protocols in use are registered in the PPSM CAL and only authorized \
functions are enabled. Firewall rules restrict to approved ports only.

ISSO VERIFICATION:
1. Verify all listening ports are registered in the PPSM CAL
2. Confirm firewall rules match PPSM CAL approved ports
3. Document the PPSM CAL registration in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Listening ports have been enumerated. Organization must verify all ports/ \
protocols are registered in the PPSM CAL.

REMEDIATION STEPS:
1. Document all required ports/protocols:
   TCP 443 (HTTPS), TCP 22 (SSH), TCP 80 (HTTP redirect)
2. Register all ports in the PPSM CAL
3. Configure firewall to allow only PPSM-approved ports
4. Disable any services using unregistered ports
5. Document the PPSM CAL compliance in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222520 — User reauthentication
# Open always (org-defined circumstances required)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222520 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
User reauthentication is required for organization-defined circumstances \
including session timeout, privilege escalation, and authentication factor changes.

ISSO VERIFICATION:
1. Confirm reauthentication triggers are documented
2. Verify session timeout forces re-login
3. Document the reauthentication policy in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Reauthentication mechanisms exist but organization-defined circumstances \
requiring reauthentication must be documented.

REMEDIATION STEPS:
1. Document organization-defined reauthentication circumstances:
   - Session timeout (idle and absolute)
   - Privilege escalation (role change)
   - Authentication factor changes
2. Configure XO session timeout in config.toml
3. Configure sudo timeout: Defaults timestamp_timeout=5
4. Document the reauthentication policy in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V-222521 — Device reauthentication
# Open always (org-defined circumstances required)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AK_222521 = answer_key(
    idx1_status="NotAFinding",
    idx1_comment="""\
Device reauthentication mechanisms are in place including SSH host key \
verification, TLS certificate authentication, and XCP-ng host connection \
management requiring reauthentication on reconnection.

ISSO VERIFICATION:
1. Confirm device reauthentication triggers are documented
2. Verify TLS certificate validation on device connections
3. Document the device reauthentication policy in the SSP""",
    idx2_status="Open",
    idx2_comment="""\
Device authentication mechanisms exist (SSH host keys, TLS certificates) but \
organization-defined circumstances requiring device reauthentication must be \
documented.

REMEDIATION STEPS:
1. Document organization-defined device reauthentication circumstances:
   - Network reconnection
   - Certificate expiration/renewal
   - Security posture changes
2. Configure XO to validate XCP-ng host certificates
3. Enable SSH host key verification: StrictHostKeyChecking yes
4. Document the device reauthentication policy in the SSP""",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Main: apply all replacements
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPLACEMENTS = [
    ("V-222496", AK_222496),
    ("V-222497", AK_222497),
    ("V-222498", AK_222498),
    ("V-222499", AK_222499),
    ("V-222500", AK_222500),
    ("V-222501", AK_222501),
    ("V-222502", AK_222502),
    ("V-222503", AK_222503),
    ("V-222504", AK_222504),
    ("V-222505", AK_222505),
    ("V-222506", AK_222506),
    ("V-222507", AK_222507),
    ("V-222508", AK_222508),
    ("V-222509", AK_222509),
    ("V-222510", AK_222510),
    ("V-222511", AK_222511),
    ("V-222512", AK_222512),
    ("V-222513", AK_222513),
    ("V-222514", AK_222514),
    ("V-222515", AK_222515),
    ("V-222516", AK_222516),
    ("V-222517", AK_222517),
    ("V-222518", AK_222518),
    ("V-222519", AK_222519),
    ("V-222520", AK_222520),
    ("V-222521", AK_222521),
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
            print(f"WARNING: {vid} - pattern not found (already updated?)")
        else:
            print(f"WARNING: {vid} - {n} substitutions (expected 1)")

    with open(ANSWER_FILE, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)

    new_size = len(content.encode("utf-8"))
    print(f"\nDone: {success}/{len(REPLACEMENTS)} replacements")
    print(f"File size: {original_size:,} -> {new_size:,} bytes (+{new_size - original_size:,})")


if __name__ == "__main__":
    main()
