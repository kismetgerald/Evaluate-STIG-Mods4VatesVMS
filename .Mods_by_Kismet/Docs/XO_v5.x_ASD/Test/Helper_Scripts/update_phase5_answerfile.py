#!/usr/bin/env python3
"""
update_phase5_answerfile.py — Replace stub answer file entries for Phase 5
(V-222546 through V-222580, 28 functions).

Each entry has 2 Answer indices with all 5 required schema children:
  ValidationCode, ValidTrueStatus, ValidTrueComment, ValidFalseStatus, ValidFalseComment

Lesson from Phase 4: Missing schema elements causes framework validation failure.
"""

import re
import sys

ANSWER_FILE = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode"
    r"\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml"
)

# ---------------------------------------------------------------------------
# Answer file entry definitions
# Each tuple: (VulnID, primary_status, primary_comment, secondary_status, secondary_comment)
# primary = most likely status; secondary = fallback
# ---------------------------------------------------------------------------

ENTRIES = [
    # ===== BATCH 12 =====
    ("V-222546", "Open", """\
STIG Requirement: The application must prohibit password reuse for a minimum of five generations (APSC-DV-001680).

The automated check examined PAM configuration for the 'remember' parameter in pam_unix/pam_pwhistory
modules and searched for LDAP/AD delegation. No password reuse prevention meeting the 5-generation
minimum was detected.

Remediation options:
1. Configure PAM password history: Add 'remember=5' to pam_unix in /etc/pam.d/common-password.
2. If using LDAP/AD authentication, verify the directory enforces password history of 5+ generations.
3. Document the password history enforcement method in the SSP.

Reference: APSC-DV-001680. The AO must accept this finding or implement password history enforcement.""",
     "NotAFinding", """\
STIG Requirement: The application must prohibit password reuse for a minimum of five generations (APSC-DV-001680).

PAM is configured with remember=5 or greater in /etc/pam.d/common-password, enforcing password history
for at least 5 generations. Alternatively, LDAP/AD password policy delegation is verified to enforce
the required password history. This satisfies APSC-DV-001680."""),

    ("V-222547", "Open", """\
STIG Requirement: The application must allow the use of a temporary password with an immediate change to a permanent password (APSC-DV-001690).

XO does not natively enforce forced password change on first logon. The automated check verified that
the chage command is available for system-level forced password changes, but XO application-level
temporary password enforcement is not built in.

Remediation options:
1. Use LDAP/AD integration where AD supports 'User must change password at next logon' attribute.
2. For local accounts, use 'chage -d 0 username' to force password change at next system login.
3. Establish an organizational procedure for temporary password issuance and forced change.
4. Document the temporary password procedure in the SSP.

Reference: APSC-DV-001690.""",
     "NotAFinding", """\
STIG Requirement: Temporary password with immediate change (APSC-DV-001690).

Temporary password enforcement is provided through LDAP/AD integration or organizational procedures.
ISSO has verified that temporary passwords require immediate change upon first use."""),

    ("V-222548", "NotAFinding", """\
STIG Requirement: Password changes restricted to administrator or associated user (APSC-DV-001700).

XO enforces password change restrictions through its role-based access model:
- Administrator users can change any user's password via the web UI.
- Regular users can only change their own password via profile settings.
- Non-admin users cannot modify other users' passwords.
- System-level password files (/etc/shadow) are protected with appropriate permissions.

This satisfies APSC-DV-001700.""",
     "Open", """\
STIG Requirement: Password changes restricted to administrator or associated user (APSC-DV-001700).

The automated check could not fully verify password change restrictions. Manual verification steps:
1. Log in as a non-admin user and confirm you cannot change other users' passwords.
2. Verify /etc/shadow permissions are 640 or more restrictive.
3. Confirm XO admin panel restricts password management to authorized users."""),

    ("V-222549", "Open", """\
STIG Requirement: The application must terminate existing sessions upon account deletion (APSC-DV-001710).

XO validates session tokens against the user database on each authenticated request. When a user account
is deleted, subsequent requests with that user's session token should be rejected. However, immediate
session invalidation upon deletion cannot be confirmed without destructive testing.

Manual verification steps:
1. Create a test user account in XO.
2. Log in as the test user in a separate browser session.
3. Delete the test user account from the admin panel.
4. Verify the test user's session is immediately terminated (should receive authentication error).

Reference: APSC-DV-001710.""",
     "NotAFinding", """\
STIG Requirement: Session termination on account deletion (APSC-DV-001710).

ISSO has verified that deleting a user account in XO immediately terminates all active sessions
for that user. Session tokens referencing deleted users are rejected on the next API request."""),

    ("V-222552", "Open", """\
STIG Requirement: Map authenticated identity to user/group for PKI-based authentication (APSC-DV-001800).

XO does not natively support PKI certificate-to-user mapping. No client certificate authentication
settings were found in the XO configuration.

Remediation options:
1. Configure LDAP/AD integration with certificate mapping via altSecurityIdentities attribute.
2. Implement client certificate authentication in a reverse proxy (nginx) fronting XO.
3. Use SAML federation with a PKI-enabled identity provider.
4. Document the PKI authentication architecture in the SSP.

Reference: APSC-DV-001800.""",
     "NotAFinding", """\
STIG Requirement: PKI certificate mapping (APSC-DV-001800).

PKI-based authentication with certificate-to-user mapping is configured through LDAP/AD integration
or a PKI-enabled identity provider. ISSO has verified the mapping configuration."""),

    ("V-222553", "Open", """\
STIG Requirement: Local CRL cache for PKI path discovery and validation (APSC-DV-001810).

No local CRL cache or OCSP stapling configuration was detected. PKI certificate revocation checking
requires configuration of CRL distribution points or OCSP responders.

Remediation options:
1. Configure OCSP stapling in the web server or reverse proxy.
2. Maintain a local CRL cache updated on a schedule from the PKI CRL distribution point.
3. If using LDAP/AD with certificate authentication, verify AD performs CRL/OCSP checking.
4. Document the certificate revocation checking architecture in the SSP.

Reference: APSC-DV-001810.""",
     "NotAFinding", """\
STIG Requirement: CRL caching for PKI validation (APSC-DV-001810).

Local CRL cache or OCSP responder is configured for PKI path validation. Certificate revocation
checking is operational for offline and online scenarios."""),

    ("V-222556", "Open", """\
STIG Requirement: Uniquely identify and authenticate non-organizational users (APSC-DV-001820).

XO enforces unique user identification through unique email addresses and internal UUIDs. However,
verification that non-organizational users have individual accounts and are not sharing credentials
requires organizational policy review.

Manual verification steps:
1. Review XO user accounts for any shared or generic accounts used by external users.
2. Verify each non-organizational user has an individual account with unique email.
3. Confirm authentication method (local, LDAP, SAML) for external user accounts.
4. Document non-organizational user management procedures in the SSP.

Reference: APSC-DV-001820.""",
     "NotAFinding", """\
STIG Requirement: Non-organizational user unique authentication (APSC-DV-001820).

ISSO has verified that all non-organizational users have individual accounts with unique
identification. No shared or generic accounts exist for external users."""),

    ("V-222557", "Open", """\
STIG Requirement: Accept PIV credentials from other federal agencies (APSC-DV-001830).

XO does not natively support PIV/smartcard credential acceptance. No client certificate authentication,
PKCS#11 modules, or PIV-enabled identity provider integration was detected.

Remediation options:
1. Configure LDAP/AD integration with PIV certificate-to-account mapping.
2. Implement SAML federation with a PIV-enabled identity provider (e.g., ADFS with smartcard auth).
3. Configure client certificate authentication via a reverse proxy.
4. Deploy PKCS#11 middleware for PIV card reader integration.

Reference: APSC-DV-001830.""",
     "NotAFinding", """\
STIG Requirement: Accept PIV credentials (APSC-DV-001830).

PIV credential acceptance is configured through LDAP/AD or SAML federation with a PIV-enabled IdP.
ISSO has verified interoperability with other federal agency PIV credentials."""),

    ("V-222558", "Open", """\
STIG Requirement: Electronically verify PIV credentials from other agencies (APSC-DV-001840).

Electronic PIV verification requires DoD CA certificates in the system trust store, OCSP/CRL checking,
and integration with a certificate-aware identity provider. The automated check found the system CA
bundle but could not confirm DoD-specific CA certificates or active certificate chain validation.

Remediation options:
1. Install DoD CA certificates in the system trust store (/etc/ssl/certs/).
2. Configure OCSP responder or CRL distribution point for certificate revocation checking.
3. Integrate with AD that performs certificate chain validation for PIV credentials.
4. Document the PKI trust chain architecture in the SSP.

Reference: APSC-DV-001840.""",
     "NotAFinding", """\
STIG Requirement: Verify PIV credentials electronically (APSC-DV-001840).

DoD CA certificates are installed and certificate chain validation with revocation checking is
configured. PIV credentials from other agencies are electronically verified."""),

    ("V-222559", "Open", """\
STIG Requirement: Accept FICAM-approved third-party credentials (APSC-DV-001850).

FICAM credential acceptance requires federation with a FICAM-approved identity provider using
SAML 2.0 or OpenID Connect. The automated check searched for SAML, OIDC, and LDAP plugins.

Remediation options:
1. Configure SAML federation with a FICAM-approved identity provider.
2. Deploy the auth-oidc plugin and connect to a FICAM-approved OIDC provider.
3. Use LDAP/AD as a FICAM bridge for credential acceptance.
4. Verify FICAM approval status of the connected identity provider.

Reference: APSC-DV-001850.""",
     "NotAFinding", """\
STIG Requirement: Accept FICAM credentials (APSC-DV-001850).

FICAM-approved credential acceptance is configured through SAML/OIDC federation with an approved
identity provider. ISSO has verified the IdP's FICAM approval status."""),

    ("V-222560", "Open", """\
STIG Requirement: Conform to FICAM-issued profiles (APSC-DV-001860).

FICAM profile conformance requires organizational configuration of identity federation using approved
protocols (SAML 2.0 or OIDC 1.0) with specific attribute schemas and trust framework requirements.

Remediation options:
1. Configure SAML 2.0 assertions to include FICAM-required attributes.
2. Verify OIDC claims mapping conforms to FICAM technical profiles.
3. Establish trust agreements with FICAM-approved identity providers.
4. Document FICAM conformance in the SSP.

Reference: APSC-DV-001860.""",
     "NotAFinding", """\
STIG Requirement: Conform to FICAM profiles (APSC-DV-001860).

XO's identity federation configuration conforms to FICAM-issued technical profiles. ISSO has verified
protocol compliance and attribute schema requirements."""),

    # ===== BATCH 13 =====
    ("V-222561", "NotAFinding", """\
STIG Requirement: Audit non-local maintenance and diagnostic sessions (APSC-DV-001870).

Non-local maintenance sessions are audited through multiple mechanisms:
- SSH sessions: Logged by systemd journal (journalctl -u sshd) including login/logout events,
  source IP, username, and authentication method.
- PAM session logging: Records in /var/log/auth.log for session open/close events.
- XO web sessions: XO audit plugin records user actions through the web interface.

SSH LogLevel is configured to capture authentication and session events.
This satisfies APSC-DV-001870.""",
     "Open", """\
STIG Requirement: Audit non-local maintenance sessions (APSC-DV-001870).

The automated check could not verify SSH audit logging. Manual verification steps:
1. Run 'journalctl -u sshd -n 20' and confirm session events are recorded.
2. Check /var/log/auth.log for PAM session entries.
3. Verify XO audit plugin is enabled for web-based maintenance tracking.
4. Confirm SSH LogLevel is INFO or higher in sshd_config."""),

    ("V-222562", "NotAFinding", """\
STIG Requirement: Cryptographic integrity for non-local maintenance communications (APSC-DV-001880).

Non-local maintenance uses SSH and HTTPS, both providing cryptographic integrity:
- SSH: HMAC algorithms (hmac-sha2-256, hmac-sha2-512) verify message integrity.
- HTTPS/TLS: Message authentication codes protect web session integrity.

Both protocols use FIPS-approved integrity algorithms when available.
This satisfies APSC-DV-001880.""",
     "Open", """\
STIG Requirement: Cryptographic integrity for maintenance (APSC-DV-001880).

The automated check could not verify SSH MAC configuration. Manual verification steps:
1. Run 'sshd -T | grep macs' and confirm approved MAC algorithms are configured.
2. Verify TLS connection to XO uses approved cipher suites with integrity protection.
3. Document the cryptographic integrity mechanisms in the SSP."""),

    ("V-222563", "NotAFinding", """\
STIG Requirement: Cryptographic confidentiality for non-local maintenance communications (APSC-DV-001890).

Non-local maintenance communications are encrypted:
- SSH: AES encryption (aes256-ctr, aes128-gcm) for terminal sessions.
- HTTPS/TLS: TLS 1.2/1.3 encryption for web-based access.

Both protocols provide confidentiality protection for maintenance sessions.
This satisfies APSC-DV-001890.""",
     "Open", """\
STIG Requirement: Cryptographic confidentiality for maintenance (APSC-DV-001890).

The automated check could not verify encryption configuration. Manual verification steps:
1. Run 'sshd -T | grep ciphers' and confirm approved encryption algorithms.
2. Verify TLS 1.2+ is enforced for HTTPS access to XO.
3. Document the encryption mechanisms in the SSP."""),

    ("V-222564", "NotAFinding", """\
STIG Requirement: Verify remote disconnection at maintenance termination (APSC-DV-001900).

Remote disconnection verification is provided through:
- SSH: TCP keep-alive and ClientAlive mechanisms detect and terminate stale connections.
- HTTPS: Standard TCP FIN/RST handshake ensures connection cleanup.
- XO web sessions: Token expiration terminates inactive web sessions.

These mechanisms ensure that remote maintenance connections are properly terminated.
This satisfies APSC-DV-001900.""",
     "Open", """\
STIG Requirement: Verify remote disconnection (APSC-DV-001900).

The automated check could not verify disconnection mechanisms. Manual verification steps:
1. Check SSH ClientAliveInterval and ClientAliveCountMax in sshd_config.
2. Verify XO session timeout configuration.
3. Test disconnection by terminating a session and confirming cleanup."""),

    ("V-222565", "Open", """\
STIG Requirement: Strong authenticators for non-local maintenance sessions (APSC-DV-001910).

SSH supports public key authentication (a strong authenticator), but multi-factor authentication
for maintenance sessions is not configured. No PAM MFA modules (pam_google, pam_oath, pam_yubico,
pam_duo) were detected in the SSH PAM configuration.

Remediation options:
1. Configure SSH key-based authentication and disable password authentication.
2. Deploy PAM MFA module (e.g., pam_google_authenticator, pam_duo) for SSH.
3. Require certificate-based authentication for maintenance access.
4. Document the strong authentication requirements in the SSP.

Reference: APSC-DV-001910.""",
     "NotAFinding", """\
STIG Requirement: Strong authenticators for maintenance (APSC-DV-001910).

Multi-factor or certificate-based authentication is configured for non-local maintenance sessions.
ISSO has verified that strong authenticators are enforced for all maintenance access."""),

    ("V-222566", "Open", """\
STIG Requirement: Terminate all sessions and network connections when maintenance is completed (APSC-DV-001920).

The automated check examined SSH idle timeout (ClientAliveInterval) and shell TMOUT settings.

Remediation options:
1. Configure SSH ClientAliveInterval (e.g., 600 seconds) and ClientAliveCountMax (e.g., 0) in sshd_config.
2. Set TMOUT=600 in /etc/profile.d/ for shell session timeout.
3. Establish organizational procedures for terminating maintenance sessions upon completion.
4. Document session termination procedures in the SSP.

Reference: APSC-DV-001920.""",
     "NotAFinding", """\
STIG Requirement: Terminate sessions after maintenance (APSC-DV-001920).

SSH idle timeout and/or shell TMOUT are configured to automatically terminate inactive maintenance
sessions. Organizational procedures require explicit session termination upon completion."""),

    ("V-222567", "Open", """\
STIG Requirement: The application must not be vulnerable to race conditions (APSC-DV-001930).

Node.js uses a single-threaded event loop model that inherently prevents many traditional race
conditions found in multi-threaded applications. XO uses LevelDB with file-level locking for data
storage. However, comprehensive code review is required to verify all shared resources are properly
serialized.

Manual verification steps:
1. Review XO source code for concurrent access to shared resources.
2. Verify database operations use proper locking mechanisms.
3. Check for asynchronous file operations without proper serialization.
4. Document the race condition analysis in the SSP.

Reference: APSC-DV-001930.""",
     "NotAFinding", """\
STIG Requirement: Race condition prevention (APSC-DV-001930).

Code review confirms Node.js single-threaded event loop and LevelDB file locking prevent race
conditions. All shared resources are properly serialized."""),

    ("V-222568", "NotAFinding", """\
STIG Requirement: Terminate all network connections at end of session (APSC-DV-001940).

Network connections are properly terminated at session end:
- TCP keep-alive settings detect and close stale connections.
- HTTP/HTTPS connections follow standard TCP FIN/RST lifecycle.
- Browser close triggers TCP connection termination.
- Server-side session token expiration invalidates abandoned sessions.

Node.js HTTP server uses standard socket cleanup on connection close.
This satisfies APSC-DV-001940.""",
     "Open", """\
STIG Requirement: Network connection termination (APSC-DV-001940).

The automated check could not verify network connection cleanup. Manual verification steps:
1. Check TCP keep-alive settings in /proc/sys/net/ipv4/.
2. Verify XO session timeout configuration.
3. Test that closing a browser properly terminates the server-side session."""),

    ("V-222570", "Open", """\
STIG Requirement: Use FIPS-validated cryptographic modules for signing (APSC-DV-001950).

System FIPS mode is not enabled (/proc/sys/crypto/fips_enabled = 0). Node.js crypto module is not
operating in FIPS mode. Cryptographic signing operations may not use FIPS-validated modules.

Remediation options:
1. Enable FIPS mode: Install fips-related packages and configure the kernel boot parameter fips=1.
2. Configure Node.js with --force-fips flag for FIPS-compliant crypto operations.
3. If FIPS mode cannot be enabled, document as a compensating control with the AO.
4. Delegate signing operations to a FIPS-validated HSM or TPM.

Reference: APSC-DV-001950. See VATES_COMPLIANCE_BLOCKERS.md.""",
     "NotAFinding", """\
STIG Requirement: FIPS crypto for signing (APSC-DV-001950).

System FIPS mode is enabled and Node.js crypto module operates in FIPS mode. Cryptographic
signing operations use FIPS-validated modules."""),

    ("V-222571", "Open", """\
STIG Requirement: Use FIPS-validated cryptographic modules for hashing (APSC-DV-001960).

XO uses bcrypt for password hashing, which is NOT a FIPS 140-2 validated algorithm. System FIPS
mode is not enabled. FIPS-approved hash alternatives include SHA-256/384/512 and PBKDF2.

Remediation options:
1. Delegate authentication to LDAP/AD which uses FIPS-validated hashing algorithms.
2. Replace bcrypt with PBKDF2 (NIST SP 800-132) in XO source code (requires Vates action).
3. Enable system FIPS mode for all non-application hashing operations.
4. Document as a known compliance gap in the SSP and POA&amp;M.

Reference: APSC-DV-001960. See VATES_COMPLIANCE_BLOCKERS.md for bcrypt FIPS status.""",
     "NotAFinding", """\
STIG Requirement: FIPS crypto for hashing (APSC-DV-001960).

Authentication is delegated to LDAP/AD with FIPS-validated hashing. System FIPS mode is enabled
for all cryptographic hashing operations."""),

    ("V-222572", "Open", """\
STIG Requirement: Use FIPS-validated cryptographic modules for data protection (APSC-DV-001970).

System FIPS mode is not enabled. TLS encryption is active for data in transit but may not use
FIPS-validated modules. No disk encryption (LUKS/dm-crypt) detected for data at rest.

Remediation options:
1. Enable system FIPS mode for all cryptographic operations.
2. Configure LUKS/dm-crypt for data at rest encryption.
3. Verify TLS cipher suites use only FIPS-approved algorithms.
4. Configure Node.js with --force-fips flag.

Reference: APSC-DV-001970. See VATES_COMPLIANCE_BLOCKERS.md.""",
     "NotAFinding", """\
STIG Requirement: FIPS crypto for data protection (APSC-DV-001970).

System FIPS mode is enabled. LUKS encryption protects data at rest. TLS uses FIPS-approved cipher
suites for data in transit protection."""),

    ("V-222573", "Not_Applicable", """\
STIG Requirement: SAML assertions must use FIPS-approved random numbers for SessionIndex (APSC-DV-001980).

SAML is not configured or active on this XO instance. This requirement applies only to applications
making SAML assertions. Since XO is not configured as a SAML identity provider or service provider,
this control is Not Applicable.

If SAML is enabled in the future, verify that the auth-saml plugin uses crypto.randomBytes()
(Node.js CSPRNG) for generating SessionIndex values in AuthnStatement elements.""",
     "Open", """\
STIG Requirement: SAML FIPS SessionIndex (APSC-DV-001980).

SAML is configured on this system. Verify that the auth-saml plugin generates SessionIndex values
using FIPS-approved CSPRNG (crypto.randomBytes in Node.js). If FIPS mode is not enabled, the random
number generator may not be FIPS-validated.

Manual verification steps:
1. Review auth-saml plugin source for SessionIndex generation method.
2. Verify Node.js crypto module FIPS mode status.
3. Document SAML SessionIndex generation in the SSP."""),

    ("V-222574", "NotAFinding", """\
STIG Requirement: UI must be separated from data storage and management interfaces (APSC-DV-001990).

XO follows a client-server architecture with clear separation:
- Web UI: React/Vue.js single-page application runs entirely in the browser (client-side).
- REST API: Node.js/Express.js server handles business logic and authentication.
- Data Store: LevelDB stores data on the server, accessed only by the xo-server process.

The web UI communicates with the server exclusively through authenticated REST API calls.
LevelDB is not directly exposed to the network or user interface. This satisfies APSC-DV-001990.""",
     "Open", """\
STIG Requirement: UI/management interface separation (APSC-DV-001990).

The automated check could not fully verify interface separation. Manual verification steps:
1. Confirm XO web UI communicates only via REST API (no direct database access from client).
2. Verify LevelDB is not exposed on any network port.
3. Check that management interfaces (API) require authentication."""),

    ("V-222575", "NotAFinding", """\
STIG Requirement: Set HTTPOnly flag on session cookies (APSC-DV-002000).

XO session cookies use the HTTPOnly flag, which prevents client-side JavaScript from accessing
session tokens. This mitigates cross-site scripting (XSS) attacks targeting session cookies.

Express.js (the Node.js web framework used by XO) sets HTTPOnly=true by default for session
cookies. The automated check verified the cookie configuration through HTTP response headers
and application configuration. This satisfies APSC-DV-002000.""",
     "Open", """\
STIG Requirement: HTTPOnly flag on session cookies (APSC-DV-002000).

The automated check could not verify the HTTPOnly flag on session cookies. Manual verification steps:
1. Use browser developer tools to inspect Set-Cookie headers after authentication.
2. Verify the HTTPOnly attribute is present on session cookies.
3. Check XO configuration for cookie settings."""),

    ("V-222576", "NotAFinding", """\
STIG Requirement: Set Secure flag on session cookies (APSC-DV-002010).

XO serves over HTTPS and session cookies include the Secure flag, ensuring they are only transmitted
over encrypted connections. This prevents session token interception via unencrypted HTTP.

The automated check verified HTTPS enforcement on port 443 and the presence of the Secure
attribute on session cookies. This satisfies APSC-DV-002010.""",
     "Open", """\
STIG Requirement: Secure flag on session cookies (APSC-DV-002010).

The automated check could not verify the Secure flag on session cookies. Manual verification steps:
1. Use browser developer tools to inspect Set-Cookie headers.
2. Verify the Secure attribute is present on session cookies.
3. Confirm HTTPS is enforced (no HTTP fallback)."""),

    ("V-222579", "NotAFinding", """\
STIG Requirement: Use system-generated session identifiers protecting against session fixation (APSC-DV-002060).

XO generates cryptographically random session tokens server-side upon successful authentication using
Node.js crypto.randomBytes(). Session tokens are:
- Generated only by the server (not accepted from client input).
- Created fresh on each authentication (not reusing pre-authentication tokens).
- Stored server-side in the session store (memory or Redis).

Pre-authentication session tokens are not accepted, preventing session fixation attacks.
This satisfies APSC-DV-002060.""",
     "Open", """\
STIG Requirement: Session fixation protection (APSC-DV-002060).

The automated check could not fully verify session fixation protection. Manual verification steps:
1. Verify that a new session token is issued after successful authentication.
2. Confirm pre-authentication tokens are not accepted for authenticated sessions.
3. Test by setting a known session token before login and verifying it changes after login."""),

    ("V-222580", "NotAFinding", """\
STIG Requirement: The application must validate session identifiers (APSC-DV-002070).

XO validates session identifiers server-side on every API request:
- Each request includes the authentication token in the Cookie header.
- The server verifies the token against the session store before processing.
- Invalid, expired, or tampered tokens are rejected with HTTP 401.
- Only tokens matching a valid server-side session are accepted.

XO uses opaque tokens (not JWT) validated by server-side lookup, preventing forged tokens.
This satisfies APSC-DV-002070.""",
     "Open", """\
STIG Requirement: Session ID validation (APSC-DV-002070).

The automated check could not fully verify session validation. Manual verification steps:
1. Send an API request with an invalid/forged authentication token.
2. Verify the server rejects it with HTTP 401.
3. Confirm session tokens are validated on every request, not just at login."""),
]


def build_vuln_entry(vid, status1, comment1, status2, comment2):
    """Build a complete Vuln XML entry with 2 Answer indices and all 5 schema elements."""
    return f"""  <Vuln ID="{vid}">

    <AnswerKey Name="XO">
      <Answer Index="1" ExpectedStatus="{status1}" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode />
        <ValidTrueStatus>{status1}</ValidTrueStatus>
        <ValidTrueComment>
{comment1}
        </ValidTrueComment>
        <ValidFalseStatus />
        <ValidFalseComment />
      </Answer>
      <Answer Index="2" ExpectedStatus="{status2}" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode />
        <ValidTrueStatus>{status2}</ValidTrueStatus>
        <ValidTrueComment>
{comment2}
        </ValidTrueComment>
        <ValidFalseStatus />
        <ValidFalseComment />
      </Answer>
    </AnswerKey>
  </Vuln>"""


def main():
    print(f"Reading: {ANSWER_FILE}")
    with open(ANSWER_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    original_len = len(content)
    changes = 0

    for vid, status1, comment1, status2, comment2 in ENTRIES:
        # Build the replacement entry
        new_entry = build_vuln_entry(vid, status1, comment1, status2, comment2)

        # Pattern to match the existing stub entry
        stub_pattern = (
            r'  <Vuln ID="' + re.escape(vid) + r'">\s*'
            r'<AnswerKey Name="XO">\s*'
            r'<Answer Index="1" ExpectedStatus="Not_Reviewed"[^>]*>\s*'
            r'<ValidationCode\s*/>\s*'
            r'<ValidTrueStatus\s*/>\s*'
            r'<ValidTrueComment\s*/>\s*'
            r'<ValidFalseStatus\s*/>\s*'
            r'<ValidFalseComment\s*/>\s*'
            r'</Answer>\s*'
            r'</AnswerKey>\s*'
            r'</Vuln>'
        )

        new_content, n = re.subn(stub_pattern, new_entry, content)

        if n == 0:
            print(f"WARNING: Could not find stub for {vid}")
        else:
            content = new_content
            changes += 1
            print(f"Replaced: {vid} ({n} substitution)")

    if changes > 0:
        with open(ANSWER_FILE, 'w', encoding='utf-8') as f:
            f.write(content)
        new_len = len(content)
        print(f"\nDone: {changes}/{len(ENTRIES)} replacements")
        print(f"File size: {original_len:,} -> {new_len:,} bytes ({new_len - original_len:+,})")
    else:
        print("No changes made.")
        sys.exit(1)


if __name__ == "__main__":
    main()
