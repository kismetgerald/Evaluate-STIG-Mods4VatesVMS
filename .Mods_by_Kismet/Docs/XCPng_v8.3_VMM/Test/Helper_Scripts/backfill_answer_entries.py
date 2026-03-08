#!/usr/bin/env python3
"""
Backfill VMM answer file entries for Batches 1-4 + original 3 implemented functions.
Replaces single-index NR stubs with proper 2-index NotAFinding/Open entries.
"""
import re
import sys
import xml.etree.ElementTree as ET

ANSWER_FILE = 'Evaluate-STIG/AnswerFiles/XCP-ng_v8.3_VMM_AnswerFile.xml'

# ---- Entry definitions ----
# Format: VulnID -> (batch_label, nf_comment, open_comment)
# 11 placeholder functions (V-207339-207341, V-207343-207350) are EXCLUDED - they keep NR stubs

entries = {}

# === Original 3 functions that properly flip status ===

entries['V-207338'] = (
    'Pre-existing: RBAC account management via xe role-list/subject-list',
    'XCP-ng provides automated account management through XAPI Role-Based Access Control (RBAC).\n\n'
    'The automated check verified: (1) RBAC roles are available via xe role-list (pool-admin, pool-operator, vm-power-admin, vm-admin, vm-operator, read-only), (2) RBAC subjects (users/groups) can be listed via xe subject-list showing external authentication integration, (3) Non-admin roles can be assigned to segregate privileges.\n\n'
    'XAPI RBAC provides automated mechanisms for creating, modifying, and managing user accounts and access permissions on the hypervisor. This meets the VMM SRG requirement for automated account management functions.',
    'XCP-ng RBAC is not properly configured to support automated account management. The automated check found issues with RBAC role availability or subject configuration. Without properly configured RBAC, account management relies on manual root SSH access without role segregation.\n\n'
    'Remediation:\n'
    '1. Enable external authentication: xe pool-enable-external-auth auth-type=AD service-name=domain.com\n'
    '2. Add RBAC subjects: xe subject-add subject-name=user role-name=vm-operator\n'
    '3. Verify RBAC roles: xe role-list\n'
    '4. Verify subjects: xe subject-list\n'
    '5. Assign least-privilege roles per DoD policy\n\n'
    'Contact the system administrator and ISSO to configure XAPI RBAC.'
)

entries['V-207342'] = (
    'Pre-existing: PAM faillock for login attempt limiting',
    'XCP-ng Dom0 enforces login attempt limits through PAM faillock configuration.\n\n'
    'The automated check verified: (1) pam_faillock.so is configured in /etc/pam.d/system-auth and/or /etc/pam.d/password-auth, (2) deny parameter is set to 3 or fewer attempts, (3) fail_interval is set to 900 seconds (15 minutes) or more, (4) unlock_time is configured per organizational policy.\n\n'
    'PAM faillock automatically locks accounts after the specified number of failed authentication attempts within the configured time window. This meets the VMM SRG requirement for limiting consecutive invalid logon attempts.',
    'XCP-ng Dom0 does not properly enforce login attempt limits. The automated check found that pam_faillock.so is not configured or parameters do not meet requirements.\n\n'
    'Remediation:\n'
    '1. Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth to include:\n'
    '   auth required pam_faillock.so preauth deny=3 fail_interval=900 unlock_time=never\n'
    '   auth required pam_faillock.so authfail deny=3 fail_interval=900 unlock_time=never\n'
    '2. Verify: faillock --user testuser\n'
    '3. Test by attempting 4 failed logins and confirming lockout\n\n'
    'Contact the system administrator to configure PAM faillock.'
)

entries['V-207351'] = (
    'Pre-existing: SSH encryption and XAPI TLS for remote access',
    'XCP-ng Dom0 uses DoD-approved encryption for remote access session confidentiality.\n\n'
    'The automated check verified: (1) SSH is configured with FIPS-approved encryption algorithms (AES-256, AES-128 in CTR or GCM modes), (2) XAPI communicates over HTTPS/TLS providing encrypted API sessions, (3) No weak or deprecated ciphers (DES, 3DES, RC4) are enabled for SSH.\n\n'
    'All remote management of XCP-ng occurs via encrypted SSH sessions or XAPI HTTPS connections, ensuring confidentiality of management data in transit. This meets the VMM SRG requirement for DoD-approved encryption of remote access sessions.',
    'XCP-ng Dom0 does not use DoD-approved encryption for all remote access sessions. The automated check found weak or non-FIPS-approved ciphers in SSH configuration, or XAPI HTTPS is not properly configured.\n\n'
    'Remediation:\n'
    '1. Edit /etc/ssh/sshd_config to set approved ciphers:\n'
    '   Ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com\n'
    '2. Restart SSH: systemctl restart sshd\n'
    '3. Verify XAPI TLS: openssl s_client -connect localhost:443\n'
    '4. Remove any non-encrypted remote access methods\n\n'
    'Contact the system administrator to harden SSH encryption.'
)

# === Batch 1: Audit Configuration (V-207352..V-207367, skip V-207359 phantom) ===

audit_open_generic = (
    'The automated check found that auditd is not active, not properly configured, or required audit rules are missing.\n\n'
    'Remediation:\n'
    '1. Install auditd if missing: yum install audit\n'
    '2. Enable and start: systemctl enable auditd; service auditd start\n'
    '3. Configure required audit rules in /etc/audit/rules.d/\n'
    '4. Reload rules: augenrules --load\n'
    '5. Verify: auditctl -l\n\n'
    'Contact the system administrator to configure the audit subsystem.'
)

entries['V-207352'] = ('Batch 1: auditd event type fields in audit records',
    'XCP-ng Dom0 produces audit records containing event type information.\n\nThe automated check verified that auditd is active and audit records contain type= fields (SYSCALL, PATH, CWD, EXECVE, USER_LOGIN, etc.) establishing what type of events occurred. The Linux audit subsystem automatically classifies each event by type. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not produce audit records with event type information.\n\n' + audit_open_generic)

entries['V-207353'] = ('Batch 1: auditd timestamp fields in audit records',
    'XCP-ng Dom0 produces audit records with date/time timestamps.\n\nThe automated check verified that auditd is active and records contain msg=audit(EPOCH:SERIAL) timestamps providing precise date and time for each event. The kernel audit subsystem generates timestamps from the system clock. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not produce properly timestamped audit records.\n\n' + audit_open_generic)

entries['V-207354'] = ('Batch 1: auditd location fields in audit records',
    'XCP-ng Dom0 produces audit records establishing where events occurred.\n\nThe automated check verified that auditd is active and records contain hostname/node information and file path details (name= field) establishing the location of each event on the system. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not produce audit records with location information.\n\n' + audit_open_generic)

entries['V-207355'] = ('Batch 1: auditd source fields (exe, pid) in audit records',
    'XCP-ng Dom0 produces audit records establishing the source of events.\n\nThe automated check verified that auditd is active and records contain exe= (executable path) and pid= (process ID) fields identifying the source process for each event. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not produce audit records with source information.\n\n' + audit_open_generic)

entries['V-207356'] = ('Batch 1: auditd outcome fields (success/exit) in audit records',
    'XCP-ng Dom0 produces audit records establishing event outcomes.\n\nThe automated check verified that auditd is active and records contain success= and exit= fields establishing whether each event succeeded or failed. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not produce audit records with outcome information.\n\n' + audit_open_generic)

entries['V-207357'] = ('Batch 1: Privileged command audit logging',
    'XCP-ng Dom0 generates audit records for privileged commands.\n\nThe automated check verified that auditd rules exist for setuid/setgid binaries (sudo, su, passwd, etc.) capturing the full command text and individual user identity. This meets the VMM SRG requirement for privileged command recording.',
    'XCP-ng Dom0 does not fully audit privileged commands.\n\n' + audit_open_generic)

entries['V-207358'] = ('Batch 1: auditd failure alerting via action_mail_acct',
    'XCP-ng Dom0 alerts administrators on audit processing failures.\n\nThe automated check verified that /etc/audit/auditd.conf contains action_mail_acct, space_left_action, and admin_space_left_action settings to alert the SA and ISSO when audit processing fails (disk full, daemon crash). This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not properly alert on audit processing failures.\n\nThe automated check found that auditd.conf does not configure failure alerting.\n\nRemediation:\n1. Edit /etc/audit/auditd.conf:\n   action_mail_acct = root\n   space_left_action = email\n   admin_space_left_action = halt\n2. Restart auditd: service auditd restart\n3. Configure mail forwarding to ISSO/SA\n\nContact the system administrator to configure audit failure alerting.')

entries['V-207360'] = ('Batch 1: Centralized audit review via aureport/ausearch',
    'XCP-ng Dom0 supports centralized audit record review and analysis.\n\nThe automated check verified that aureport and ausearch tools are available, providing capability to review, correlate, and analyze audit records from all system components. These tools support multiple output formats and cross-component analysis. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not support centralized audit review capability.\n\n' + audit_open_generic)

entries['V-207361'] = ('Batch 1: ausearch filtering by all audit fields',
    'XCP-ng Dom0 supports filtering audit records by all fields.\n\nThe automated check verified that ausearch supports filtering by user (-ua), type (-m), syscall (-sc), key (-k), time range (-ts/-te), and all other audit fields within records. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not support audit record filtering.\n\n' + audit_open_generic)

entries['V-207362'] = ('Batch 1: System clock for audit timestamps (chronyd/ntpd)',
    'XCP-ng Dom0 uses internal system clocks for audit record timestamps.\n\nThe automated check verified that auditd timestamps are generated from the system clock, and time synchronization is configured via chronyd or ntpd to maintain accurate time. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not properly use system clocks for audit timestamps.\n\nThe automated check found that time synchronization (chronyd/ntpd) is not configured or not active.\n\nRemediation:\n1. Install chronyd: yum install chrony\n2. Configure NTP servers in /etc/chrony.conf\n3. Enable: systemctl enable chronyd; systemctl start chronyd\n4. Verify: chronyc sources\n\nContact the system administrator to configure time synchronization.')

entries['V-207363'] = ('Batch 1: Audit log read permissions (600 root:root)',
    'XCP-ng Dom0 protects audit information from unauthorized read access.\n\nThe automated check verified that /var/log/audit/ files have permissions 600 or more restrictive, owned by root. Only the root account can read audit log files. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not protect audit information from unauthorized read access.\n\nThe automated check found audit log files with overly permissive read access.\n\nRemediation:\n1. Set audit log permissions: chmod 600 /var/log/audit/audit.log\n2. Set ownership: chown root:root /var/log/audit/audit.log\n3. Configure auditd.conf: log_group = root\n4. Verify: stat -c "%a %U %G" /var/log/audit/*\n\nContact the system administrator to restrict audit log permissions.')

entries['V-207364'] = ('Batch 1: Audit log write permissions (root-only)',
    'XCP-ng Dom0 protects audit information from unauthorized modification.\n\nThe automated check verified that /var/log/audit/ files have no group or world write permissions, and are owned by root. Only the auditd process (running as root) can write to audit logs. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not protect audit information from unauthorized modification.\n\nThe automated check found audit log files with group or world write permissions.\n\nRemediation:\n1. Remove unauthorized write: chmod go-w /var/log/audit/audit.log\n2. Set ownership: chown root:root /var/log/audit/audit.log\n3. Verify: stat -c "%a %U %G" /var/log/audit/*\n\nContact the system administrator to restrict audit log write permissions.')

entries['V-207365'] = ('Batch 1: Audit log deletion protection',
    'XCP-ng Dom0 protects audit information from unauthorized deletion.\n\nThe automated check verified that the /var/log/audit/ directory is owned by root with restricted permissions, preventing non-root users from deleting audit log files. auditd manages log rotation (max_log_file_action) to ensure controlled log lifecycle. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not protect audit information from unauthorized deletion.\n\nThe automated check found /var/log/audit/ directory permissions allow unauthorized deletion.\n\nRemediation:\n1. Set directory permissions: chmod 700 /var/log/audit\n2. Set ownership: chown root:root /var/log/audit\n3. Configure log retention in auditd.conf: max_log_file_action = keep_logs\n4. Verify: stat -c "%a %U %G" /var/log/audit\n\nContact the system administrator to protect audit logs from deletion.')

entries['V-207367'] = ('Batch 1: Audit rule management restricted to root/ISSM',
    'XCP-ng Dom0 restricts audit event selection to the ISSM (or authorized individuals).\n\nThe automated check verified that audit rule configuration files in /etc/audit/rules.d/ are owned by root with permissions restricting write access to root only. Only root (the ISSM-appointed administrator) can select which events are audited. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not properly restrict audit event configuration to authorized administrators.\n\nThe automated check found audit rule files with overly permissive access.\n\nRemediation:\n1. Set permissions: chmod 640 /etc/audit/rules.d/*.rules\n2. Set ownership: chown root:root /etc/audit/rules.d/*.rules\n3. Verify: ls -la /etc/audit/rules.d/\n\nContact the ISSO to review audit rule management access.')

# === Batch 2: Authentication & Password (V-207366, V-207368..V-207379, V-207381) ===

entries['V-207366'] = ('Batch 2: auditd generation for all VMM component events',
    'XCP-ng Dom0 provides audit record generation for all VMM components.\n\nThe automated check verified that auditd is configured with rules covering system calls, file access, user authentication, privilege escalation, and administrative commands across all VMM components (XAPI, Xen, Dom0 services). This meets the VMM SRG requirement for comprehensive audit generation.',
    'XCP-ng Dom0 does not generate audit records for all VMM component events.\n\n' + audit_open_generic)

entries['V-207368'] = ('Batch 2: Audit privilege access attempts',
    'XCP-ng Dom0 generates audit records for privilege access attempts.\n\nThe automated check verified that auditd rules monitor privilege escalation events (sudo, su, setuid binaries) capturing both successful and unsuccessful attempts. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not audit privilege access attempts.\n\n' + audit_open_generic)

entries['V-207369'] = ('Batch 2: PKI certificate path validation to trust anchor',
    'XCP-ng validates PKI certificates by constructing certification paths to accepted trust anchors.\n\nThe automated check verified that the system CA certificate bundle (/etc/pki/tls/certs/ca-bundle.crt) is present and contains DoD Root CA certificates. OpenSSL and XAPI use this bundle for certificate validation. This meets the VMM SRG requirement.',
    'XCP-ng does not properly validate PKI certificates to an accepted trust anchor.\n\nThe automated check found the CA certificate bundle is missing or does not contain required DoD Root CA certificates.\n\nRemediation:\n1. Install DoD Root CA certificates: cp DoD_Root_CA.pem /etc/pki/ca-trust/source/anchors/\n2. Update CA trust: update-ca-trust\n3. Verify: openssl verify -CAfile /etc/pki/tls/certs/ca-bundle.crt /path/to/cert.pem\n\nContact the PKI administrator to install DoD Root CA certificates.')

entries['V-207370'] = ('Batch 2: PKI private key access control',
    'XCP-ng enforces authorized access to PKI private keys.\n\nThe automated check verified that XAPI private key (/etc/xensource/xapi-ssl.pem) and SSH host keys (/etc/ssh/ssh_host_*_key) are owned by root with permissions 600 or more restrictive, preventing unauthorized access. This meets the VMM SRG requirement.',
    'XCP-ng does not properly protect PKI private keys.\n\nThe automated check found private key files with overly permissive access.\n\nRemediation:\n1. Set XAPI key permissions: chmod 600 /etc/xensource/xapi-ssl.pem; chown root:root /etc/xensource/xapi-ssl.pem\n2. Set SSH key permissions: chmod 600 /etc/ssh/ssh_host_*_key; chown root:root /etc/ssh/ssh_host_*_key\n3. Verify: stat -c "%a %U" /etc/xensource/xapi-ssl.pem /etc/ssh/ssh_host_*_key\n\nContact the system administrator to restrict private key access.')

entries['V-207371'] = ('Batch 2: PKI-to-account identity mapping',
    'XCP-ng maps PKI-authenticated identities to user/group accounts.\n\nThe automated check verified that SSH is configured to use PKI certificates for authentication (AuthorizedKeysFile configured, PubkeyAuthentication enabled) and that certificate-based identities map to local or LDAP/AD user accounts. This meets the VMM SRG requirement.',
    'XCP-ng does not properly map PKI-authenticated identities to accounts.\n\nThe automated check found that PKI-based authentication mapping is not configured.\n\nRemediation:\n1. Enable public key authentication in /etc/ssh/sshd_config: PubkeyAuthentication yes\n2. Configure authorized keys: AuthorizedKeysFile .ssh/authorized_keys\n3. For AD integration, configure SSSD with certificate mapping\n4. Restart sshd: systemctl restart sshd\n\nContact the system administrator and PKI administrator to configure identity mapping.')

entries['V-207372'] = ('Batch 2: Password complexity - uppercase character',
    'XCP-ng Dom0 enforces password complexity requiring at least one uppercase character.\n\nThe automated check verified that PAM pwquality/pam_cracklib is configured with ucredit=-1 (or lower) in /etc/security/pwquality.conf or /etc/pam.d/system-auth. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not require uppercase characters in passwords.\n\nThe automated check found ucredit is not set to -1 or lower.\n\nRemediation:\n1. Edit /etc/security/pwquality.conf: ucredit = -1\n2. Verify: grep ucredit /etc/security/pwquality.conf\n\nContact the system administrator to configure password complexity.')

entries['V-207373'] = ('Batch 2: Password complexity - lowercase character',
    'XCP-ng Dom0 enforces password complexity requiring at least one lowercase character.\n\nThe automated check verified that PAM pwquality/pam_cracklib is configured with lcredit=-1 (or lower) in /etc/security/pwquality.conf or /etc/pam.d/system-auth. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not require lowercase characters in passwords.\n\nThe automated check found lcredit is not set to -1 or lower.\n\nRemediation:\n1. Edit /etc/security/pwquality.conf: lcredit = -1\n2. Verify: grep lcredit /etc/security/pwquality.conf\n\nContact the system administrator to configure password complexity.')

entries['V-207374'] = ('Batch 2: Password complexity - numeric character',
    'XCP-ng Dom0 enforces password complexity requiring at least one numeric character.\n\nThe automated check verified that PAM pwquality/pam_cracklib is configured with dcredit=-1 (or lower) in /etc/security/pwquality.conf or /etc/pam.d/system-auth. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not require numeric characters in passwords.\n\nThe automated check found dcredit is not set to -1 or lower.\n\nRemediation:\n1. Edit /etc/security/pwquality.conf: dcredit = -1\n2. Verify: grep dcredit /etc/security/pwquality.conf\n\nContact the system administrator to configure password complexity.')

entries['V-207375'] = ('Batch 2: Password change - minimum 8 characters changed',
    'XCP-ng Dom0 requires at least 8 characters to change when passwords are modified.\n\nThe automated check verified that PAM pwquality is configured with difok=8 (or higher) in /etc/security/pwquality.conf. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not require sufficient character changes in new passwords.\n\nThe automated check found difok is not set to 8 or higher.\n\nRemediation:\n1. Edit /etc/security/pwquality.conf: difok = 8\n2. Verify: grep difok /etc/security/pwquality.conf\n\nContact the system administrator to configure password change requirements.')

entries['V-207376'] = ('Batch 2: Encrypted password storage (shadow file)',
    'XCP-ng Dom0 stores only encrypted representations of passwords.\n\nThe automated check verified that /etc/shadow contains hashed passwords (SHA-512 $6$ prefix or similar), no plaintext passwords exist, and /etc/passwd does not contain password hashes (x placeholder used). This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not properly encrypt stored passwords.\n\nThe automated check found plaintext or weakly hashed passwords.\n\nRemediation:\n1. Ensure SHA-512 hashing: authconfig --passalgo=sha512 --update\n2. Verify shadow entries use $6$ prefix: grep "^root" /etc/shadow\n3. Force password changes for affected accounts: chage -d 0 username\n\nContact the system administrator to configure password hashing.')

entries['V-207377'] = ('Batch 2: Encrypted password transmission (SSH/TLS)',
    'XCP-ng Dom0 transmits only encrypted representations of passwords.\n\nThe automated check verified that SSH encrypts all authentication traffic, XAPI uses HTTPS/TLS for API authentication, and no unencrypted authentication protocols (telnet, FTP, HTTP) are enabled. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 may transmit passwords in unencrypted form.\n\nThe automated check found unencrypted services or protocols that could transmit passwords in cleartext.\n\nRemediation:\n1. Disable telnet: systemctl disable telnet.socket; systemctl stop telnet.socket\n2. Disable FTP: systemctl disable vsftpd; systemctl stop vsftpd\n3. Ensure SSH is the only remote access method\n4. Verify XAPI uses HTTPS only\n\nContact the system administrator to disable unencrypted authentication protocols.')

entries['V-207378'] = ('Batch 2: Minimum 24-hour password lifetime',
    'XCP-ng Dom0 enforces a 24-hour minimum password lifetime.\n\nThe automated check verified that /etc/login.defs contains PASS_MIN_DAYS set to 1 or greater, preventing users from changing passwords more than once per day. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not enforce a minimum password lifetime.\n\nThe automated check found PASS_MIN_DAYS is not set to 1 or greater in /etc/login.defs.\n\nRemediation:\n1. Edit /etc/login.defs: PASS_MIN_DAYS 1\n2. Apply to existing accounts: chage --mindays 1 username\n3. Verify: grep PASS_MIN_DAYS /etc/login.defs\n\nContact the system administrator to configure password lifetime.')

entries['V-207379'] = ('Batch 2: Maximum 60-day password lifetime',
    'XCP-ng Dom0 enforces a 60-day maximum password lifetime.\n\nThe automated check verified that /etc/login.defs contains PASS_MAX_DAYS set to 60 or less. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not enforce a maximum password lifetime.\n\nThe automated check found PASS_MAX_DAYS is not set to 60 or less in /etc/login.defs.\n\nRemediation:\n1. Edit /etc/login.defs: PASS_MAX_DAYS 60\n2. Apply to existing accounts: chage --maxdays 60 username\n3. Verify: grep PASS_MAX_DAYS /etc/login.defs\n\nContact the system administrator to configure password expiration.')

entries['V-207381'] = ('Batch 2: Minimum 15-character password length',
    'XCP-ng Dom0 enforces a minimum 15-character password length.\n\nThe automated check verified that PAM pwquality is configured with minlen=15 (or higher) in /etc/security/pwquality.conf or /etc/pam.d/system-auth. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not enforce a 15-character minimum password length.\n\nThe automated check found minlen is not set to 15 or higher.\n\nRemediation:\n1. Edit /etc/security/pwquality.conf: minlen = 15\n2. Verify: grep minlen /etc/security/pwquality.conf\n\nContact the system administrator to configure password length requirements.')

# === Batch 3: Auth, Access Control, MFA, Replay Resistance (V-207382..V-207395) ===

entries['V-207382'] = ('Batch 3: Authentication feedback obscuring',
    'XCP-ng Dom0 obscures authentication feedback during the authentication process.\n\nThe automated check verified that SSH is configured to not display password characters during entry, and PAM does not echo credentials. The terminal does not display typed password characters, preventing shoulder-surfing attacks. This meets the VMM SRG requirement.',
    'XCP-ng Dom0 does not properly obscure authentication feedback.\n\nThe automated check found configuration issues that may expose authentication information during the login process.\n\nRemediation:\n1. Verify SSH does not echo passwords (default behavior)\n2. Check PAM configuration does not include pam_echo modules\n3. Verify console login obscures password entry\n\nContact the system administrator to verify authentication feedback handling.')

entries['V-207383'] = ('Batch 3: RBAC-enforced logical access control',
    'XCP-ng enforces approved authorizations for logical access via XAPI RBAC.\n\nThe automated check verified: (1) RBAC roles are defined and available via xe role-list, (2) Access to XAPI functions is controlled by role assignment, (3) Non-admin roles (vm-operator, read-only) provide least-privilege access. XAPI RBAC enforces authorization policies for all management operations. This meets the VMM SRG requirement.',
    'XCP-ng does not properly enforce logical access authorizations.\n\nThe automated check found RBAC is not configured or all users have pool-admin access.\n\nRemediation:\n1. Configure RBAC roles: xe role-list\n2. Assign least-privilege roles: xe subject-add subject-name=user role-name=vm-operator\n3. Remove unnecessary pool-admin access\n4. Verify: xe subject-list\n\nContact the ISSO to review and approve RBAC role assignments.')

entries['V-207384'] = ('Batch 3: Non-essential capabilities disabled',
    'XCP-ng is configured to disable non-essential capabilities.\n\nThe automated check verified that unnecessary services are disabled on Dom0, non-essential network ports are not listening, and only required XAPI/SSH services are active. This meets the VMM SRG requirement.',
    'XCP-ng has non-essential capabilities enabled.\n\nThe automated check found unnecessary services running or non-essential ports listening on Dom0.\n\nRemediation:\n1. List active services: systemctl list-units --type=service --state=running\n2. Disable non-essential services: systemctl disable SERVICE; systemctl stop SERVICE\n3. Review listening ports: ss -tlnp\n4. Document required services in the System Security Plan\n\nContact the system administrator to disable non-essential services.')

entries['V-207385'] = ('Batch 3: Prohibited ports/protocols/services restricted',
    'XCP-ng is configured to restrict functions, ports, protocols, and services per PPSM CAL.\n\nThe automated check verified that Dom0 listening ports are limited to essential services (SSH/22, XAPI/443, XAPI/80-redirect), and iptables/firewall rules restrict unauthorized access. This meets the VMM SRG requirement.',
    'XCP-ng does not properly restrict ports, protocols, and services.\n\nThe automated check found unauthorized ports listening or insufficient firewall rules.\n\nRemediation:\n1. Review listening ports: ss -tlnp\n2. Configure iptables to restrict access to authorized ports only\n3. Disable unnecessary services\n4. Document authorized ports in POA&amp;M per PPSM CAL\n\nContact the ISSO to review authorized ports and protocols.')

entries['V-207386'] = ('Batch 3: Unique user identification and authentication',
    'XCP-ng uniquely identifies and authenticates organizational users.\n\nThe automated check verified that each user has a unique account (no shared accounts detected), UID 0 is limited to root only, and PAM enforces authentication for all user sessions. This meets the VMM SRG requirement.',
    'XCP-ng does not properly enforce unique user identification.\n\nThe automated check found shared accounts, duplicate UIDs, or authentication bypass.\n\nRemediation:\n1. Review accounts: cat /etc/passwd | awk -F: "{print $3}" | sort | uniq -d\n2. Remove shared accounts and create individual accounts\n3. Ensure only root has UID 0\n4. Configure PAM to require authentication\n\nContact the system administrator to implement unique user accounts.')

entries['V-207387'] = ('Batch 3: MFA for network access to privileged accounts',
    'XCP-ng uses multifactor authentication for network access to privileged accounts.\n\nThe automated check verified the configuration of SSH key-based authentication combined with password/token authentication, or external AD/LDAP integration providing MFA. This meets the VMM SRG requirement when properly configured.',
    'XCP-ng does not implement multifactor authentication for network privileged access.\n\nThe automated check found that MFA is not configured for privileged network access. XCP-ng Dom0 relies on single-factor SSH password authentication by default.\n\nRemediation:\n1. Configure SSH key-based authentication as the first factor\n2. Integrate with AD/LDAP for centralized MFA: xe pool-enable-external-auth\n3. Consider RADIUS/TACACS+ integration for MFA\n4. Document MFA implementation in the System Security Plan\n\nContact the ISSO and system administrator to implement MFA for privileged access.')

entries['V-207388'] = ('Batch 3: MFA for network access to non-privileged accounts',
    'XCP-ng uses multifactor authentication for network access to non-privileged accounts.\n\nThe automated check verified MFA configuration for non-privileged network access via SSH key-based authentication or external AD/LDAP integration. This meets the VMM SRG requirement when properly configured.',
    'XCP-ng does not implement MFA for network non-privileged access.\n\nThe automated check found that MFA is not configured for non-privileged network access.\n\nRemediation:\n1. Configure SSH key + password for all accounts\n2. Integrate with AD/LDAP: xe pool-enable-external-auth\n3. Ensure non-privileged RBAC subjects use MFA\n\nContact the ISSO to implement MFA for non-privileged access.')

entries['V-207389'] = ('Batch 3: MFA for local access to privileged accounts',
    'XCP-ng uses multifactor authentication for local access to privileged accounts.\n\nThe automated check verified MFA configuration for local console access to privileged accounts. This meets the VMM SRG requirement when properly configured.',
    'XCP-ng does not implement MFA for local privileged access.\n\nThe automated check found that MFA is not configured for local console access to privileged accounts. Physical console access typically uses single-factor password authentication.\n\nRemediation:\n1. Configure PAM for local MFA (smart card or token)\n2. Restrict physical console access\n3. Implement compensating controls (physical security, CCTV)\n4. Document in POA&amp;M if MFA is not feasible for local console\n\nContact the ISSO to implement or document MFA for local access.')

entries['V-207390'] = ('Batch 3: MFA for local access to non-privileged accounts',
    'XCP-ng uses multifactor authentication for local access to non-privileged accounts.\n\nThe automated check verified MFA configuration for local access to non-privileged accounts. This meets the VMM SRG requirement when properly configured.',
    'XCP-ng does not implement MFA for local non-privileged access.\n\nThe automated check found MFA is not configured for local non-privileged access.\n\nRemediation:\n1. Configure PAM for local MFA\n2. Integrate with organizational MFA solution\n3. Document in POA&amp;M if not feasible\n\nContact the ISSO to implement MFA for local non-privileged access.')

entries['V-207391'] = ('Batch 3: Individual auth before group authenticator',
    'XCP-ng requires individual authentication before group authenticator use.\n\nThe automated check verified that PAM configuration requires individual user authentication (password or key) before any group-based access is granted. Users must authenticate individually before accessing shared or group resources. This meets the VMM SRG requirement.',
    'XCP-ng does not require individual authentication before group authenticator use.\n\nThe automated check found that group access may be granted without prior individual authentication.\n\nRemediation:\n1. Ensure PAM requires individual authentication first\n2. Remove any group-only authentication paths\n3. Verify sudo requires password: grep NOPASSWD /etc/sudoers (should be empty or justified)\n\nContact the system administrator to enforce individual authentication.')

entries['V-207392'] = ('Batch 3: Replay-resistant auth for network privileged access',
    'XCP-ng implements replay-resistant authentication for network privileged access.\n\nThe automated check verified that SSH uses protocol 2 with challenge-response or public key authentication, both of which are inherently replay-resistant. XAPI sessions use unique tokens that cannot be replayed. This meets the VMM SRG requirement.',
    'XCP-ng does not implement replay-resistant authentication for network privileged access.\n\nThe automated check found authentication mechanisms that may be vulnerable to replay attacks.\n\nRemediation:\n1. Ensure SSH Protocol 2 only: Protocol 2 in sshd_config\n2. Use SSH key-based authentication\n3. Disable legacy protocols vulnerable to replay\n4. Verify XAPI uses session tokens with timeout\n\nContact the system administrator to configure replay-resistant authentication.')

entries['V-207393'] = ('Batch 3: Replay-resistant auth for network non-privileged access',
    'XCP-ng implements replay-resistant authentication for network non-privileged access.\n\nThe automated check verified that SSH protocol 2 is used for all network authentication, providing inherent replay resistance through cryptographic nonces and session keys. This meets the VMM SRG requirement.',
    'XCP-ng does not implement replay-resistant authentication for network non-privileged access.\n\nThe automated check found authentication mechanisms vulnerable to replay.\n\nRemediation:\n1. Ensure SSH Protocol 2: Protocol 2 in sshd_config\n2. Disable password-only authentication where possible\n3. Use key-based authentication\n\nContact the system administrator to configure replay-resistant authentication.')

entries['V-207394'] = ('Batch 3: Peripheral identification before connection',
    'XCP-ng uniquely identifies peripherals before establishing connections.\n\nThe automated check verified that XAPI manages all device assignments and Dom0 identifies devices by PCI bus address, USB vendor/product ID, or similar unique identifiers before allowing VM connections. This meets the VMM SRG requirement.',
    'XCP-ng does not properly identify peripherals before establishing connections.\n\nThe automated check found that device identification is not properly enforced before VM assignment.\n\nRemediation:\n1. Review device assignments: xe pusb-list; xe pci-list\n2. Ensure all device passthrough is explicitly authorized\n3. Document authorized devices in the System Security Plan\n\nContact the system administrator to review peripheral identification.')

entries['V-207395'] = ('Batch 3: Disable inactive accounts after 35 days',
    'XCP-ng disables local account identifiers after 35 days of inactivity.\n\nThe automated check verified that /etc/default/useradd INACTIVE is set to 35 or less, and existing accounts have appropriate inactivity limits configured via chage. This meets the VMM SRG requirement.',
    'XCP-ng does not disable inactive accounts after 35 days.\n\nThe automated check found INACTIVE is not set to 35 or less in /etc/default/useradd, or existing accounts lack inactivity limits.\n\nRemediation:\n1. Set default: useradd -D -f 35\n2. Apply to existing accounts: chage -I 35 username\n3. Verify: useradd -D | grep INACTIVE; chage -l username\n\nContact the system administrator to configure account inactivity limits.')

# === Batch 4: Encryption, Sessions, Integrity, Errors (V-207396..V-207411, skip V-207400,V-207408) ===

entries['V-207396'] = ('Batch 4: FIPS cryptographic module authentication',
    'XCP-ng uses mechanisms meeting federal requirements for authentication to a cryptographic module.\n\nThe automated check verified the status of FIPS mode on the system (crypto-policies or /proc/sys/crypto/fips_enabled). This meets the VMM SRG requirement when FIPS mode is enabled.',
    'XCP-ng does not meet federal cryptographic module authentication requirements.\n\nThe automated check found FIPS mode is not enabled. XCP-ng (CentOS 7-based) may not fully support FIPS 140-2 validated cryptographic modules.\n\nRemediation:\n1. Enable FIPS mode: fips-mode-setup --enable (if supported)\n2. Verify: cat /proc/sys/crypto/fips_enabled (should be 1)\n3. If FIPS mode is not supported, document as a compliance gap in POA&amp;M\n4. Use FIPS-validated crypto libraries where available\n\nContact the ISSO to document FIPS compliance status.')

entries['V-207397'] = ('Batch 4: Audit reduction and on-demand reporting',
    'XCP-ng supports audit reduction and on-demand reporting.\n\nThe automated check verified that aureport provides summary reports (--summary, --auth, --login, --event) and ausearch provides on-demand queries with flexible filtering. These tools meet the VMM SRG requirement for audit reduction and reporting capability.',
    'XCP-ng does not support audit reduction and on-demand reporting.\n\nThe automated check found that audit reporting tools are not available or functional.\n\nRemediation:\n1. Install audit tools: yum install audit\n2. Verify aureport: aureport --summary\n3. Verify ausearch: ausearch -m USER_LOGIN\n4. Configure scheduled reports if required\n\nContact the system administrator to install audit reporting tools.')

entries['V-207398'] = ('Batch 4: Emergency account auto-removal after 72 hours',
    'XCP-ng automatically removes or disables emergency accounts after the crisis is resolved or within 72 hours.\n\nThe automated check verified that emergency/temporary accounts have expiration dates set via chage, and /etc/default/useradd EXPIRE is configured for automatic account expiration. This meets the VMM SRG requirement.',
    'XCP-ng does not automatically remove or disable emergency accounts within 72 hours.\n\nThe automated check found accounts without expiration dates or emergency account policies not enforced.\n\nRemediation:\n1. Set expiration on emergency accounts: chage -E $(date -d "+3 days" +%Y-%m-%d) emergency_user\n2. Configure default expiration: useradd -D -e DATE\n3. Create procedures for emergency account lifecycle\n4. Review accounts regularly: chage -l username\n\nContact the ISSO to establish emergency account procedures.')

entries['V-207399'] = ('Batch 4: Strong authenticators for nonlocal maintenance',
    'XCP-ng employs strong authenticators for nonlocal maintenance and diagnostic sessions.\n\nThe automated check verified that SSH uses strong authentication (key-based or password with complexity requirements) for all remote maintenance sessions, and XAPI requires authenticated HTTPS sessions. This meets the VMM SRG requirement.',
    'XCP-ng does not employ strong authenticators for nonlocal maintenance.\n\nThe automated check found weak authentication for remote maintenance sessions.\n\nRemediation:\n1. Configure SSH key-based authentication: PubkeyAuthentication yes\n2. Disable password-only auth for maintenance: PasswordAuthentication no\n3. Ensure strong password policy via PAM\n4. Verify XAPI uses HTTPS with authentication\n\nContact the system administrator to strengthen remote maintenance authentication.')

entries['V-207401'] = ('Batch 4: Dom0/DomU user-management separation',
    'XCP-ng separates user functionality from VMM management functionality.\n\nThe automated check verified that Dom0 (management domain) is isolated from DomU (guest VMs) by the Xen hypervisor. User workloads run in DomU while VMM management occurs exclusively in Dom0. The Xen architecture inherently provides this separation through hardware-enforced privilege rings. This meets the VMM SRG requirement.',
    'XCP-ng does not properly separate user and management functionality.\n\nThe automated check found potential issues with Dom0/DomU isolation.\n\nRemediation:\n1. Verify no user workloads run in Dom0\n2. Ensure all user applications run in DomU guest VMs\n3. Restrict Dom0 access to authorized administrators only\n4. Review Dom0 services: systemctl list-units --type=service\n\nContact the system administrator to verify Dom0/DomU separation.')

entries['V-207402'] = ('Batch 4: Security function isolation from non-security',
    'XCP-ng isolates security functions from non-security functions.\n\nThe automated check verified that the Xen hypervisor provides hardware-enforced isolation between security functions (Dom0, XAPI, authentication) and non-security functions (DomU guest workloads). Security-critical processes run in the privileged Dom0 domain. This meets the VMM SRG requirement.',
    'XCP-ng does not properly isolate security functions.\n\nThe automated check found security functions may not be adequately isolated from non-security functions.\n\nRemediation:\n1. Ensure security services run only in Dom0\n2. Do not install non-essential software in Dom0\n3. Restrict Dom0 to management functions only\n4. Document security function isolation in the System Security Plan\n\nContact the ISSO to review security function isolation.')

entries['V-207403'] = ('Batch 4: Shared resource information transfer prevention',
    'XCP-ng prevents unauthorized information transfer via shared system resources.\n\nThe automated check verified that the Xen hypervisor enforces memory isolation between VMs, CPU cache flushing mitigations are applied, and shared storage is access-controlled via XAPI. Dom0 mediates all shared resource access. This meets the VMM SRG requirement.',
    'XCP-ng does not prevent unauthorized information transfer via shared resources.\n\nThe automated check found potential shared resource isolation issues.\n\nRemediation:\n1. Verify Xen security patches are current: yum update xen\n2. Enable CPU side-channel mitigations in GRUB: spec-ctrl=yes\n3. Review shared storage access: xe sr-list; xe vdi-list\n4. Ensure VMs do not share memory pages unintentionally\n\nContact the system administrator to verify shared resource isolation.')

entries['V-207404'] = ('Batch 4: DoS protection - capacity and bandwidth management',
    'XCP-ng manages excess capacity to limit DoS attack effects.\n\nThe automated check verified that TCP SYN cookies are enabled (net.ipv4.tcp_syncookies=1), connection tracking limits are configured, and XCP-ng resource management (memory/CPU limits per VM) prevents individual VMs from consuming all host resources. This meets the VMM SRG requirement.',
    'XCP-ng does not properly manage capacity for DoS protection.\n\nThe automated check found TCP SYN cookies are not enabled, reducing flood protection.\n\nRemediation:\n1. Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1\n2. Make persistent: echo "net.ipv4.tcp_syncookies = 1" &gt;&gt; /etc/sysctl.d/99-dos.conf\n3. Configure connection tracking: sysctl -w net.netfilter.nf_conntrack_max=65536\n4. Set VM resource limits via XO or xe CLI\n\nContact the system administrator to configure DoS protection.')

entries['V-207405'] = ('Batch 4: Session termination (10min privileged, 15min user)',
    'XCP-ng terminates network sessions after specified inactivity periods.\n\nThe automated check verified SSH session timeout configuration (ClientAliveInterval and ClientAliveCountMax in sshd_config) and XAPI session timeout settings. Privileged sessions terminate after 10 minutes and user sessions after 15 minutes of inactivity. This meets the VMM SRG requirement.',
    'XCP-ng does not terminate sessions after the required inactivity periods.\n\nThe automated check found SSH or XAPI session timeouts are not properly configured.\n\nRemediation:\n1. Edit /etc/ssh/sshd_config:\n   ClientAliveInterval 600\n   ClientAliveCountMax 0\n2. Restart sshd: systemctl restart sshd\n3. Configure XAPI session timeout in XO settings\n\nContact the system administrator to configure session timeouts.')

entries['V-207406'] = ('Batch 4: Fail-secure on initialization/shutdown/abort failure',
    'XCP-ng fails to a secure state on system initialization, shutdown, or abort failures.\n\nThe automated check verified that kernel panic behavior is configured (kernel.panic sysctl), Dom0 crash dump settings capture failure state, and Xen watchdog is configured to handle hypervisor failures. This meets the VMM SRG requirement.',
    'XCP-ng does not properly fail to a secure state.\n\nThe automated check found that fail-secure behavior is not fully configured.\n\nRemediation:\n1. Configure panic behavior: sysctl -w kernel.panic=10\n2. Enable kdump for crash analysis: systemctl enable kdump\n3. Configure Xen watchdog timeout\n4. Verify: sysctl kernel.panic; systemctl is-enabled kdump\n\nContact the system administrator to configure fail-secure behavior.')

entries['V-207407'] = ('Batch 4: Data-at-rest confidentiality and integrity',
    'XCP-ng protects the confidentiality and integrity of information at rest.\n\nThe automated check verified LUKS/dm-crypt disk encryption status, file system permissions on sensitive directories, and XCP-ng storage repository access controls. This meets the VMM SRG requirement when encryption is properly configured.',
    'XCP-ng does not fully protect data at rest.\n\nThe automated check found that disk encryption is not enabled or file system permissions are insufficient.\n\nRemediation:\n1. Enable LUKS encryption for storage repositories\n2. Verify file permissions on /etc/xensource/, /var/xapi/\n3. Configure encrypted storage for VM disk images\n4. Document encryption status in the System Security Plan\n\nContact the system administrator and ISSO to implement data-at-rest encryption.')

entries['V-207409'] = ('Batch 4: Input validation for data inputs',
    'XCP-ng checks the validity of data inputs.\n\nThe automated check verified that XAPI validates API inputs through its type system and parameter validation, SSH enforces protocol-level input validation, and web-facing services sanitize inputs. This meets the VMM SRG requirement.',
    'XCP-ng does not properly validate data inputs.\n\nThe automated check found potential input validation gaps.\n\nRemediation:\n1. Ensure XAPI is current with security patches: yum update xapi\n2. Configure SSH to reject invalid inputs\n3. Review any custom scripts for input validation\n4. Apply vendor security updates\n\nContact the system administrator to verify input validation controls.')

entries['V-207410'] = ('Batch 4: Error messages with corrective info, no exploitation data',
    'XCP-ng generates error messages with corrective action information without revealing exploitable data.\n\nThe automated check verified that system error messages provide sufficient information for corrective action (log files, error codes) without exposing internal system details, stack traces, or configuration paths to unauthorized users. This meets the VMM SRG requirement.',
    'XCP-ng error messages may reveal exploitable information.\n\nThe automated check found error messages that expose internal system details.\n\nRemediation:\n1. Configure sshd LogLevel to INFO (not DEBUG): LogLevel INFO in sshd_config\n2. Review XAPI error handling configuration\n3. Ensure error pages do not expose stack traces or paths\n4. Restart affected services after changes\n\nContact the system administrator to review error message configuration.')

entries['V-207411'] = ('Batch 4: Error messages restricted to authorized users',
    'XCP-ng reveals system error messages only to authorized users.\n\nThe automated check verified that system logs are readable only by root (permissions 600 on /var/log/messages, /var/log/secure), XAPI error details require authenticated sessions, and console error output is restricted to logged-in administrators. This meets the VMM SRG requirement.',
    'XCP-ng may reveal system error messages to unauthorized users.\n\nThe automated check found log files or error outputs accessible to non-authorized users.\n\nRemediation:\n1. Set log permissions: chmod 600 /var/log/messages /var/log/secure\n2. Ensure XAPI requires authentication for error details\n3. Review console access restrictions\n4. Verify: stat -c "%a %U" /var/log/messages /var/log/secure\n\nContact the system administrator to restrict error message access.')


# ---- Read the answer file ----
with open(ANSWER_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

# ---- Now do the replacements ----
count = 0
for vuln_id, (batch_label, nf_comment, open_comment) in entries.items():
    # Build the NR stub pattern
    old_pattern = (
        f'  <Vuln ID="{vuln_id}">\n'
        f'    <!--RuleTitle: '
    )

    # Find the full old block
    start = content.find(f'  <Vuln ID="{vuln_id}">')
    if start == -1:
        print(f"WARNING: {vuln_id} not found in answer file!")
        continue

    end = content.find('  </Vuln>', start) + len('  </Vuln>')
    old_block = content[start:end]

    # Check if already implemented (has NotAFinding or Open)
    if 'ExpectedStatus="NotAFinding"' in old_block or 'ExpectedStatus="Open"' in old_block:
        print(f"SKIP: {vuln_id} already has implemented entries")
        continue

    # Extract the RuleTitle from the existing block
    title_match = re.search(r'<!--RuleTitle: (.+?)-->', old_block)
    rule_title = title_match.group(1) if title_match else 'Unknown'

    # Build the new 2-index entry
    new_block = f'''  <Vuln ID="{vuln_id}">
    <!--RuleTitle: {rule_title}-->
    <AnswerKey Name="XCP-ng">
      <!--{batch_label}-->
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{open_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>This answer index should not normally be used.</ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>'''

    content = content[:start] + new_block + content[end:]
    count += 1

# Write the updated file
with open(ANSWER_FILE, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"\nDone! Updated {count} answer file entries.")
print(f"Entries defined: {len(entries)}")
