#!/usr/bin/env python3
"""Integrate Batch 14 answer file entries into XO GPOS Debian12 answer file.

Batch 14: Kernel and Memory Protection / Auth & PKI (10 functions)
"""

import sys

ANSWER_FILE = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Each entry: (VulnID, NF_comment, Open_comment)
ENTRIES = [
    (
        "V-203723",
        # NotAFinding comment
        """The operating system requires users to reauthenticate for privilege escalation.

Automated scan verified:
- sudo configuration requires password authentication (no NOPASSWD entries found)
- su requires PAM authentication (/etc/pam.d/su configured)
- sudo timestamp_timeout limits credential caching (default 5 minutes)
- polkit (pkexec) provides additional authentication for GUI escalation

All privilege escalation mechanisms enforce re-authentication before granting elevated privileges.

ISSO/ISSM: Verify that any NOPASSWD entries in sudoers are justified and documented for service accounts only.""",
        # Open comment
        """The operating system may not require users to reauthenticate for privilege escalation.

Automated scan found:
- NOPASSWD entries detected in /etc/sudoers or /etc/sudoers.d/
- Users may escalate privileges without re-authentication

Remediation steps:
1. Review sudoers entries: visudo or files in /etc/sudoers.d/
2. Remove NOPASSWD from user entries: replace with PASSWD (default)
3. Retain NOPASSWD only for documented service accounts that cannot prompt
4. Verify su requires PAM authentication: check /etc/pam.d/su
5. Set sudo timestamp_timeout appropriately: Defaults timestamp_timeout=5

ISSO/ISSM: Review and document justification for any remaining NOPASSWD entries."""
    ),
    (
        "V-203724",
        # NotAFinding
        """The operating system requires users to reauthenticate when changing roles.

Automated scan verified:
- sudo enforces timeout-based re-authentication (timestamp_timeout)
- su requires PAM authentication for role changes between users
- XO application role changes require authenticated admin session
- No mechanism allows role changes without authentication

Role transitions through sudo, su, or XO admin interface all require active authentication.

ISSO/ISSM: Verify organizational role change procedures are documented and enforced.""",
        # Open
        """The operating system may not require users to reauthenticate when changing roles.

Automated scan found:
- sudo credential caching may allow role changes without re-authentication
- Unable to verify re-authentication enforcement for all role transitions

Remediation steps:
1. Configure sudo timestamp_timeout: Defaults timestamp_timeout=5
2. Ensure su requires PAM authentication: check /etc/pam.d/su
3. Verify XO admin role changes require active session authentication
4. Document organizational role change procedures
5. Consider setting timestamp_timeout=0 for immediate re-auth on each sudo

ISSO/ISSM: Verify and document role change re-authentication procedures."""
    ),
    (
        "V-203725",
        # NotAFinding
        """The operating system requires users to reauthenticate when changing authenticators.

Automated scan verified:
- passwd command requires current password before setting new one (PAM enforced)
- PAM password modules (pam_unix, pam_pwquality) configured in /etc/pam.d/common-password
- SSH authorized_keys files have restrictive permissions (root access required for changes)
- Non-root users cannot modify authenticators without providing current credentials

All authenticator change mechanisms enforce re-authentication before allowing modifications.

ISSO/ISSM: No additional action required - PAM enforces re-authentication for authenticator changes.""",
        # Open
        """The operating system may not require users to reauthenticate when changing authenticators.

Automated scan found:
- PAM password module configuration may be incomplete
- Authenticator change re-authentication cannot be fully verified

Remediation steps:
1. Verify /etc/pam.d/common-password includes pam_unix and pam_pwquality
2. Ensure passwd requires current password: check PAM configuration
3. Restrict SSH authorized_keys file permissions: chmod 600 ~/.ssh/authorized_keys
4. Verify root is required to modify system-level authenticators
5. Document authenticator change procedures

ISSO/ISSM: Verify PAM enforces current password requirement for all authenticator changes."""
    ),
    (
        "V-203730",
        # NotAFinding
        """The operating system authenticates peripherals before establishing a connection.

Automated scan verified:
- USBGuard is installed and active with device authorization policies
- USB device authorization framework controls peripheral connections
- System may be a virtual machine with limited physical peripheral exposure
- Kernel USB authorization defaults restrict unauthorized device connections

Peripheral authentication is enforced through USBGuard policies or equivalent device authorization controls.

ISSO/ISSM: Verify USBGuard policies are appropriate for the environment and reviewed periodically.""",
        # Open
        """The operating system may not authenticate peripherals before establishing a connection.

Automated scan found:
- USBGuard is not installed or not active
- No device authorization framework detected
- Peripherals may connect without authentication

Remediation steps:
1. Install USBGuard: apt install usbguard
2. Generate initial policy: usbguard generate-policy &gt; /etc/usbguard/rules.conf
3. Enable USBGuard: systemctl enable --now usbguard
4. Review and customize policy: usbguard list-rules
5. For VMs: document that hypervisor controls peripheral passthrough
6. Set kernel USB authorization default: echo 0 &gt; /sys/bus/usb/devices/usb1/authorized_default

ISSO/ISSM: Implement peripheral authentication controls appropriate for the deployment model (physical vs VM)."""
    ),
    (
        "V-203731",
        # NotAFinding
        """The operating system authenticates all endpoint devices using bidirectional cryptographic authentication.

Automated scan verified:
- SSH host keys provide server-to-client authentication (host key verification)
- TLS certificate on port 443 authenticates XO server to connecting clients
- Client authentication via password or public key over encrypted SSH channel
- XO authentication (username/password or LDAP/SAML) over encrypted TLS channel

Bidirectional cryptographic authentication is implemented: servers authenticate to clients via SSH host keys and TLS certificates, clients authenticate to servers via credentials over encrypted channels.

ISSO/ISSM: Verify SSH host keys and TLS certificates are from trusted sources and properly maintained.""",
        # Open
        """The operating system may not authenticate endpoint devices using bidirectional cryptographic authentication.

Automated scan found:
- SSH host keys may not be properly configured
- TLS certificate verification could not be confirmed
- Bidirectional authentication cannot be fully verified

Remediation steps:
1. Verify SSH host keys exist: ls -la /etc/ssh/ssh_host_*_key.pub
2. Regenerate if needed: ssh-keygen -A
3. Ensure XO uses HTTPS with valid TLS certificate
4. Configure client authentication requirements in sshd_config
5. Implement LDAP/SAML for enterprise authentication (DoD PKI)
6. Verify StrictHostKeyChecking is enabled for outbound SSH

ISSO/ISSM: Verify bidirectional cryptographic authentication for all remote connections."""
    ),
    (
        "V-203733",
        # NotAFinding
        """The operating system prohibits the use of cached authenticators after one day.

Automated scan verified:
- Sudo credential cache: 5 minutes (well within 1-day/86400-second requirement)
- SSSD is either not configured or has appropriate cache expiration settings
- PAM timestamp module has appropriate expiration or is not configured
- Kerberos ticket lifetime is either not configured or within 1-day limit

All cached authenticator mechanisms expire well within the one-day (86400 second) maximum. Sudo default of 5 minutes is the primary caching mechanism and is fully compliant.

ISSO/ISSM: If SSSD or Kerberos is deployed, verify offline_credentials_expiration and ticket_lifetime are within 1 day.""",
        # Open
        """The operating system may allow cached authenticators to persist beyond one day.

Automated scan found:
- Cached authenticator expiration settings may exceed one day
- SSSD or Kerberos cache lifetimes could not be verified

Remediation steps:
1. Verify sudo timestamp_timeout (default 5 min is compliant): grep timestamp_timeout /etc/sudoers
2. For SSSD: set offline_credentials_expiration = 1 in /etc/sssd/sssd.conf [pam] section
3. For Kerberos: set ticket_lifetime = 24h in /etc/krb5.conf [libdefaults]
4. For PAM timestamp: verify timeout in /etc/security/pam_timestamp.conf
5. Restart services after changes: systemctl restart sssd

ISSO/ISSM: Verify all cached authenticator mechanisms expire within 86400 seconds (1 day)."""
    ),
    (
        "V-203734",
        # NotAFinding
        """The operating system implements a local cache of PKI revocation data for path discovery and validation.

Automated scan verified:
- CA trust store is present and properly maintained (/etc/ssl/certs/ca-certificates.crt)
- Local CRL files may be cached for offline revocation checking
- OpenSSL configuration includes CRL/OCSP settings
- LDAP TLS certificate verification is configured with trusted CA paths

PKI revocation data caching supports certificate validation when network access to CRL/OCSP is unavailable.

ISSO/ISSM: Verify CRL distribution points are configured and local cache is periodically updated.""",
        # Open
        """The operating system may not implement a local cache of PKI revocation data.

Automated scan found:
- No local CRL files detected in standard locations
- OCSP stapling may not be configured
- PKI revocation caching infrastructure requires organizational implementation

Remediation steps:
1. Install DoD PKI CA certificates: download from https://militarycac.com/maccerts
2. Update CA trust store: update-ca-certificates
3. Configure CRL download: create cron job to fetch CRL files periodically
4. Store CRL files in /etc/ssl/crl/ or /etc/pki/tls/crl/
5. Configure OpenSSL to use local CRL: update /etc/ssl/openssl.cnf
6. For LDAP: set TLS_CACERT in /etc/ldap/ldap.conf

ISSO/ISSM: Implement PKI revocation data caching with periodic CRL updates from DoD PKI sources."""
    ),
    (
        "V-203735",
        # NotAFinding
        """The operating system audits all activities performed during nonlocal maintenance and diagnostic sessions.

Automated scan verified:
- SSH session logging is active (sshd LogLevel INFO or higher)
- systemd journal captures SSH session events (start, authentication, termination)
- /var/log/auth.log records authentication and session activity
- XO Audit Plugin records user actions with hash chain integrity

Nonlocal maintenance sessions via SSH and XO web interface are fully audited through multiple logging mechanisms.

ISSO/ISSM: Verify audit logs are reviewed regularly and retained per organizational requirements.""",
        # Open
        """The operating system may not audit all activities during nonlocal maintenance sessions.

Automated scan found:
- SSH logging level may not capture sufficient detail
- Session audit trail may be incomplete
- XO Audit Plugin may not be active

Remediation steps:
1. Set SSH log level: LogLevel INFO (or VERBOSE) in /etc/ssh/sshd_config
2. Restart SSH: systemctl restart ssh
3. Verify journal captures SSH: journalctl -u ssh -n 10
4. Ensure /var/log/auth.log exists with proper permissions (640 root:adm)
5. Enable XO Audit Plugin for application-layer audit trail
6. Configure log forwarding to centralized SIEM

ISSO/ISSM: Verify all nonlocal maintenance and diagnostic sessions are captured in audit records."""
    ),
    (
        "V-203738",
        # NotAFinding
        """The operating system verifies remote disconnection at the termination of nonlocal maintenance and diagnostic sessions.

Automated scan verified:
- SSH ClientAliveInterval and ClientAliveCountMax configured for session keepalive
- SSH TCPKeepAlive enabled for connection state detection
- systemd-logind tracks session lifecycle (creation and termination)
- SSH logs session disconnect events in journal and auth.log

Remote session termination is verified through SSH keepalive mechanisms, systemd session tracking, and comprehensive disconnect logging.

ISSO/ISSM: Verify ClientAliveInterval is set appropriately for the environment (recommend 600 seconds or less).""",
        # Open
        """The operating system may not verify remote disconnection at session termination.

Automated scan found:
- SSH ClientAliveInterval may not be configured (default 0 = disabled)
- Session termination verification may be incomplete
- TCPKeepAlive settings may not detect stale connections

Remediation steps:
1. Set ClientAliveInterval in /etc/ssh/sshd_config: ClientAliveInterval 600
2. Set ClientAliveCountMax: ClientAliveCountMax 3
3. Ensure TCPKeepAlive yes (default) in sshd_config
4. Restart SSH: systemctl restart ssh
5. Verify session tracking: loginctl list-sessions
6. Confirm disconnect logging: journalctl -u ssh | grep -i disconnect

ISSO/ISSM: Verify SSH session timeout and disconnect verification are properly configured."""
    ),
    (
        "V-203744",
        # NotAFinding
        """The operating system only allows DoD PKI-established certificate authorities for authentication in protected sessions.

Automated scan verified:
- System CA trust store contains DoD/DISA root CA certificates
- XO TLS certificate is issued by a DoD PKI-established CA
- LDAP/AD TLS configuration references DoD-approved CA trust paths
- Non-DoD CA certificates are documented and justified

Only DoD PKI-established certificate authorities are used for authentication in protected sessions.

ISSO/ISSM: Periodically verify the CA trust store contains only authorized DoD and justified non-DoD CAs.""",
        # Open
        """The operating system may allow non-DoD PKI certificate authorities for authentication.

Automated scan found:
- DoD root CA certificates may not be installed in system trust store
- XO TLS certificate may be self-signed or from non-DoD CA
- CA trust store may contain unauthorized certificate authorities

Remediation steps:
1. Download DoD PKI CA certificates from DISA or https://militarycac.com
2. Install DoD root CAs: copy to /usr/local/share/ca-certificates/ with .crt extension
3. Update trust store: update-ca-certificates
4. Replace self-signed XO certificate with DoD PKI-issued certificate
5. Remove unauthorized non-DoD CAs from trust store (document justified exceptions)
6. Configure LDAP TLS_CACERT to reference DoD CA bundle

ISSO/ISSM: Verify only DoD PKI-established CAs are in the trust store. Document and justify any non-DoD CA exceptions."""
    ),
]


def main():
    with open(ANSWER_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    # Build the XML entries
    new_entries = []
    for vuln_id, nf_comment, open_comment in ENTRIES:
        entry = f"""  <Vuln ID="{vuln_id}">
    <AnswerKey Name="XO">
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{open_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>"""
        new_entries.append(entry)

    all_entries = "\n".join(new_entries) + "\n"

    # Insert before closing </STIGComments>
    closing_tag = "  </STIGComments>"
    if closing_tag not in content:
        print("ERROR: </STIGComments> not found")
        return 1

    content = content.replace(closing_tag, all_entries + closing_tag)

    with open(ANSWER_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Integrated {len(ENTRIES)} answer file entries")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(ANSWER_FILE)
        print("XML validation: PASSED")
    except Exception as e:
        print(f"XML validation: FAILED - {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
