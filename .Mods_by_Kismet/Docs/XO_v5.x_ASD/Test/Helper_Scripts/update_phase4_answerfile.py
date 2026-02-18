#!/usr/bin/env python3
"""
Phase 4 Answer File Update Script — Batches 10-11 (20 functions)
Replaces stub answer file entries with proper 2-index entries for each VulnID.
"""

import re
import os

AF_PATH = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..',
                       'Evaluate-STIG', 'AnswerFiles', 'XO_v5.x_ASD_AnswerFile.xml')
AF_PATH = os.path.normpath(AF_PATH)

# ============================================================================
# Answer file entries for each VulnID
# Key: VulnID
# Value: dict with 'title', 'nf_comment', 'open_comment', 'na_comment' (optional)
# ============================================================================

ENTRIES = {}

# --- Batch 10: Authentication Methods ---

ENTRIES['V-222523'] = {
    'title': 'The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.',
    'nf_comment': '''Xen Orchestra privileged account access has been verified for MFA/Alt Token compliance.

Enterprise authentication integration (LDAP/AD with smart card or SAML with MFA-enabled IdP) is configured, providing multifactor authentication for privileged network access to the XO management console.

Evidence examined:
- Authentication plugin configuration (auth-ldap or auth-saml)
- TLS client certificate settings
- Privileged user account enumeration via REST API

The organization has implemented MFA through directory services integration, meeting DoD requirements for privileged network access authentication.''',
    'open_comment': '''Xen Orchestra does not natively enforce multifactor authentication for privileged network access.

Current state: XO uses local username/password authentication by default. No MFA/Alt Token enforcement detected for admin accounts.

Remediation actions:
1. Configure LDAP/AD integration with smart card (CAC/PIV) authentication
2. Or configure SAML/OIDC integration with MFA-enabled Identity Provider
3. Ensure all admin accounts require MFA before network access
4. Document MFA enforcement in the system security plan

Reference: VATES_COMPLIANCE_BLOCKERS.md - MFA/2FA not built into XO''',
}

ENTRIES['V-222524'] = {
    'title': 'The application must accept Personal Identity Verification (PIV) credentials.',
    'nf_comment': '''PIV credential acceptance has been verified for Xen Orchestra.

The system is configured to accept PIV credentials through TLS client certificate authentication or LDAP/AD integration with smart card support. PKCS#11 packages are installed on the host system.

Evidence examined:
- TLS client certificate configuration
- PKCS#11/smart card package installation
- Authentication plugin configuration''',
    'open_comment': '''Xen Orchestra does not natively accept PIV credentials.

Current state: XO uses local username/password or token-based authentication. No PIV/CAC credential acceptance configured.

Remediation actions:
1. Install PKCS#11 packages (opensc, p11-kit, pam-pkcs11)
2. Configure TLS client certificate authentication in XO
3. Or integrate with LDAP/AD that supports smart card authentication
4. Test PIV credential acceptance with DoD CAC cards''',
}

ENTRIES['V-222525'] = {
    'title': 'The application must electronically verify Personal Identity Verification (PIV) credentials.',
    'nf_comment': '''PIV credential electronic verification has been confirmed for Xen Orchestra.

The system validates PIV credentials through OCSP/CRL certificate revocation checking and TLS client certificate verification.

Evidence examined:
- OCSP/CRL revocation checking configuration
- TLS client certificate verification settings
- Certificate chain validation''',
    'open_comment': '''PIV credential electronic verification is not configured for Xen Orchestra.

Current state: No OCSP or CRL revocation checking configured for client certificates. Certificate chain validation is limited to server-side TLS.

Remediation actions:
1. Configure OCSP stapling or CRL distribution point checking
2. Enable TLS client certificate verification with revocation checking
3. Configure certificate chain validation against DoD PKI trust anchors
4. Test credential verification with revoked certificates''',
}

ENTRIES['V-222526'] = {
    'title': 'The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.',
    'nf_comment': '''MFA for non-privileged network access has been verified for Xen Orchestra.

Enterprise authentication (LDAP/AD or SAML) with MFA capability is configured for all user accounts, including non-privileged users.

Evidence examined:
- Authentication plugin configuration
- Non-privileged user account enumeration
- MFA enforcement settings''',
    'open_comment': '''MFA is not enforced for non-privileged network access to Xen Orchestra.

Current state: Non-privileged users authenticate with username/password only. No MFA enforcement for standard user accounts.

Remediation actions:
1. Configure LDAP/AD integration with CAC/PIV for all users
2. Or configure SAML/OIDC with MFA-enabled IdP
3. Ensure MFA applies to both privileged and non-privileged accounts
4. Document MFA enforcement in access control policy''',
}

ENTRIES['V-222527'] = {
    'title': 'The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.',
    'nf_comment': '''MFA for local privileged access has been verified for Xen Orchestra.

PAM MFA modules or SSH multi-factor authentication is configured for local privileged access to the XO server.

Evidence examined:
- PAM configuration (pam_pkcs11, pam_u2f, pam_google_authenticator)
- SSH AuthenticationMethods configuration
- Local console access controls''',
    'open_comment': '''MFA is not enforced for local privileged access to the Xen Orchestra server.

Current state: Local access uses standard password authentication without additional factors.

Remediation actions:
1. Configure PAM MFA module (pam_pkcs11 for smart card, pam_u2f for FIDO2)
2. Configure SSH AuthenticationMethods to require publickey and password
3. Restrict local console access to authorized administrators
4. Document local access MFA requirements''',
}

ENTRIES['V-222528'] = {
    'title': 'The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged accounts.',
    'nf_comment': '''MFA for local nonprivileged access has been verified for Xen Orchestra.

PAM MFA modules or SAML integration provides multifactor authentication for all local user access.

Evidence examined:
- PAM MFA configuration
- SAML/OIDC authentication settings
- Web interface authentication methods''',
    'open_comment': '''MFA is not enforced for local nonprivileged access to Xen Orchestra.

Current state: Local nonprivileged users authenticate with username/password only.

Remediation actions:
1. Configure PAM MFA module for system-level authentication
2. Configure SAML/OIDC with MFA-enabled IdP for web access
3. Ensure MFA applies to all user types
4. Document authentication requirements for nonprivileged users''',
}

ENTRIES['V-222529'] = {
    'title': 'The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.',
    'nf_comment': '''Individual authentication before group access has been verified for Xen Orchestra.

All XO user accounts use individual email/username credentials. No shared or group accounts were detected in the XO user database. Each user must authenticate individually before accessing any shared resources.

Evidence examined:
- XO user account listing via REST API
- Shared/group account detection
- Recent login activity analysis''',
    'open_comment': '''Individual authentication before group access requires verification for Xen Orchestra.

Current state: Possible shared or group accounts detected in XO user database. Individual authentication before shared access must be verified.

Remediation actions:
1. Review all XO user accounts for shared/generic credentials
2. Convert shared accounts to individual accounts
3. If shared accounts are required, implement individual login first
4. Document shared account usage and individual authentication procedures''',
}

ENTRIES['V-222530'] = {
    'title': 'The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.',
    'nf_comment': '''Replay-resistant authentication for privileged access has been verified for Xen Orchestra.

XO uses session-based authentication over TLS 1.2+. TLS encryption prevents credential interception and replay. Session tokens are unique per session and time-limited.

Evidence examined:
- TLS version and cipher configuration
- Session token management
- CSRF protection headers''',
    'open_comment': '''Replay-resistant authentication for privileged access cannot be fully verified.

Current state: TLS configuration may not fully prevent replay attacks.

Remediation actions:
1. Ensure TLS 1.2+ is the minimum supported version
2. Verify session tokens are cryptographically random and time-limited
3. Enable CSRF protection tokens
4. Disable TLS session resumption if replay is a concern''',
}

ENTRIES['V-222531'] = {
    'title': 'The application must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.',
    'nf_comment': '''Replay-resistant authentication for nonprivileged access has been verified for Xen Orchestra.

The same TLS 1.2+ session-based authentication mechanism applies to all user accounts (both privileged and nonprivileged), providing replay protection through encrypted transport and unique session tokens.

Evidence examined:
- TLS encryption active for all connections
- Uniform authentication mechanism for all users''',
    'open_comment': '''Replay-resistant authentication for nonprivileged access cannot be fully verified.

Remediation: Ensure TLS 1.2+ is enforced for all connections. Verify session tokens are cryptographically random and time-limited for all user accounts.''',
}

ENTRIES['V-222532'] = {
    'title': 'The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoD policy or by the data owner.',
    'nf_comment': '''Mutual authentication for non-repudiation has been verified for Xen Orchestra.

Mutual TLS (mTLS) is configured, providing both server and client certificate verification. This ensures device-level non-repudiation for management operations.

Evidence examined:
- TLS client certificate configuration
- Server certificate verification
- Mutual authentication settings''',
    'open_comment': '''Mutual authentication (mTLS) is not configured for Xen Orchestra.

Current state: Server-side TLS only. No client certificate authentication configured.

Remediation actions:
1. Configure TLS client certificate requirements in XO config
2. Deploy client certificates to authorized management endpoints
3. Configure certificate chain validation against DoD PKI
4. Document mutual authentication requirements and implementation''',
}

ENTRIES['V-222533'] = {
    'title': 'The application must authenticate all network connected endpoint devices before establishing any connection.',
    'nf_comment': '''Endpoint device authentication has been verified for Xen Orchestra.

The XO API correctly rejects unauthenticated requests (HTTP 401/403). All management operations require authentication tokens. HTTP traffic is redirected to HTTPS.

Evidence examined:
- Unauthenticated API access test (401/403 response)
- HTTP to HTTPS redirect verification
- WebSocket authentication requirements''',
    'open_comment': '''Endpoint device authentication requires verification for Xen Orchestra.

Remediation actions:
1. Verify all API endpoints require authentication tokens
2. Ensure HTTP redirects to HTTPS for all connections
3. Verify WebSocket connections require valid session tokens
4. Implement network access controls to limit endpoint connections''',
}

ENTRIES['V-222534'] = {
    'title': 'Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.',
    'nf_comment': '''Mutual SSL/TLS for service-oriented access has been verified for Xen Orchestra.

XO REST API endpoints use TLS with client certificate authentication for service consumers handling non-releasable virtualization management data.

Evidence examined:
- REST API TLS configuration
- Client certificate requirements
- Data classification assessment''',
    'open_comment': '''Mutual SSL/TLS is not configured for XO service-oriented endpoints.

Current state: REST API uses token-based authentication over server-side TLS. No client certificate requirements for API consumers.

Remediation actions:
1. Configure TLS client certificate requirements for REST API
2. Deploy client certificates to authorized service consumers
3. Document data classification and mutual TLS requirements
4. Test mTLS with API consumers''',
}

ENTRIES['V-222535'] = {
    'title': 'The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.',
    'nf_comment': '''Device identifier management has been assessed for Xen Orchestra. XO authenticates users, not devices, making this requirement Not Applicable per STIG guidance.''',
    'open_comment': '''Device identifier inactivity management requires review.

Remediation: If XO is configured to authenticate devices, ensure device identifiers are disabled after 35 days of inactivity. If using DoD PKI certificates for device authentication, the expiration date on the certificate fulfills this requirement.''',
    'na_comment': '''Not Applicable. Xen Orchestra is a web-based management application that authenticates users, not devices. XO does not use device identifiers for authentication.

Per STIG guidance: "If the application is not designed to authenticate devices, this is Not Applicable."

User authentication is managed through individual user accounts with email/username credentials. Browser sessions are authenticated via user credentials, not device identifiers.''',
}

# --- Batch 11: Password Complexity ---

ENTRIES['V-222537'] = {
    'title': 'The application must enforce password complexity by requiring that at least one uppercase character be used.',
    'nf_comment': '''Password uppercase requirement has been verified for Xen Orchestra.

PAM pwquality module is configured with ucredit = -1 (or stricter), requiring at least one uppercase character in passwords.

Evidence examined:
- /etc/security/pwquality.conf ucredit setting
- PAM module configuration
- External authentication delegation (LDAP/AD)''',
    'open_comment': '''Password uppercase requirement is not enforced for Xen Orchestra.

Current state: PAM pwquality ucredit not configured to require uppercase characters.

Remediation actions:
1. Set ucredit = -1 in /etc/security/pwquality.conf
2. Ensure pam_pwquality is loaded in PAM stack (/etc/pam.d/common-password)
3. If using LDAP/AD, verify directory password policy enforces uppercase
4. Test password change with all-lowercase password (should be rejected)''',
}

ENTRIES['V-222538'] = {
    'title': 'The application must enforce password complexity by requiring that at least one lowercase character be used.',
    'nf_comment': '''Password lowercase requirement has been verified. PAM pwquality lcredit = -1 configured.''',
    'open_comment': '''Password lowercase requirement is not enforced.

Remediation: Set lcredit = -1 in /etc/security/pwquality.conf. Ensure pam_pwquality is loaded in PAM stack. If using LDAP/AD, verify directory password policy enforces lowercase.''',
}

ENTRIES['V-222539'] = {
    'title': 'The application must enforce password complexity by requiring that at least one numeric character be used.',
    'nf_comment': '''Password numeric requirement has been verified. PAM pwquality dcredit = -1 configured.''',
    'open_comment': '''Password numeric character requirement is not enforced.

Remediation: Set dcredit = -1 in /etc/security/pwquality.conf. Ensure pam_pwquality is loaded in PAM stack. If using LDAP/AD, verify directory password policy enforces numeric characters.''',
}

ENTRIES['V-222540'] = {
    'title': 'The application must enforce password complexity by requiring that at least one special character be used.',
    'nf_comment': '''Password special character requirement has been verified. PAM pwquality ocredit = -1 configured.''',
    'open_comment': '''Password special character requirement is not enforced.

Remediation: Set ocredit = -1 in /etc/security/pwquality.conf. Ensure pam_pwquality is loaded in PAM stack. If using LDAP/AD, verify directory password policy enforces special characters.''',
}

ENTRIES['V-222541'] = {
    'title': 'The application must require the change of at least eight of the total number of characters when passwords are changed.',
    'nf_comment': '''Password change difference requirement has been verified. PAM pwquality difok = 8 (or higher) configured, requiring at least 8 characters differ from old password.''',
    'open_comment': '''Password change difference requirement is not enforced.

Current state: PAM pwquality difok not configured to require 8+ character changes (default is 1).

Remediation: Set difok = 8 in /etc/security/pwquality.conf. Ensure pam_pwquality is loaded in PAM stack.''',
}

ENTRIES['V-222544'] = {
    'title': 'The application must enforce 24 hours/1 day as the minimum password lifetime.',
    'nf_comment': '''Minimum password lifetime of 24 hours has been verified. PASS_MIN_DAYS is set to 1 or greater in /etc/login.defs.''',
    'open_comment': '''Minimum password lifetime is not enforced.

Current state: PASS_MIN_DAYS not configured or set to 0 in /etc/login.defs.

Remediation: Set PASS_MIN_DAYS 1 in /etc/login.defs. Apply to existing users with: chage --mindays 1 username. If using LDAP/AD, verify directory enforces minimum password age.''',
}

ENTRIES['V-222545'] = {
    'title': 'The application must enforce a 60-day maximum password lifetime restriction.',
    'nf_comment': '''Maximum password lifetime of 60 days has been verified. PASS_MAX_DAYS is set to 60 or less in /etc/login.defs.''',
    'open_comment': '''Maximum password lifetime is not properly configured.

Current state: PASS_MAX_DAYS not set to 60 or less in /etc/login.defs.

Remediation: Set PASS_MAX_DAYS 60 in /etc/login.defs. Apply to existing users with: chage --maxdays 60 username. If using LDAP/AD, verify directory enforces maximum password age of 60 days.''',
}


def escape_xml(text):
    """Escape XML special characters in text content."""
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    return text


def build_entry(vid, entry):
    """Build a complete XML answer file entry."""
    title = escape_xml(entry['title'])
    nf = escape_xml(entry['nf_comment'].strip())
    op = escape_xml(entry['open_comment'].strip())

    xml = f'  <Vuln ID="{vid}">\n'
    xml += f'    <!--RuleTitle: {title}-->\n'
    xml += f'    <AnswerKey Name="XO">\n'

    # Index 1: NotAFinding
    xml += f'      <Answer Index="1" ExpectedStatus="NotAFinding">\n'
    xml += f'        <ValidTrueStatus>NotAFinding</ValidTrueStatus>\n'
    xml += f'        <ValidTrueComment>{nf}</ValidTrueComment>\n'
    xml += f'      </Answer>\n'

    # Index 2: Open
    xml += f'      <Answer Index="2" ExpectedStatus="Open">\n'
    xml += f'        <ValidTrueStatus>Open</ValidTrueStatus>\n'
    xml += f'        <ValidTrueComment>{op}</ValidTrueComment>\n'
    xml += f'      </Answer>\n'

    # Index 3: Not_Applicable (if applicable)
    if 'na_comment' in entry:
        na = escape_xml(entry['na_comment'].strip())
        xml += f'      <Answer Index="3" ExpectedStatus="Not_Applicable">\n'
        xml += f'        <ValidTrueStatus>Not_Applicable</ValidTrueStatus>\n'
        xml += f'        <ValidTrueComment>{na}</ValidTrueComment>\n'
        xml += f'      </Answer>\n'

    xml += f'    </AnswerKey>\n'
    xml += f'  </Vuln>'
    return xml


def find_stub_entry(content, vid):
    """Find and return the start/end positions of a stub entry."""
    pattern = rf'  <Vuln ID="{vid}">'
    start = content.find(pattern)
    if start == -1:
        return None, None

    end_tag = '  </Vuln>'
    end = content.find(end_tag, start)
    if end == -1:
        return None, None

    return start, end + len(end_tag)


def main():
    print(f"Reading answer file: {AF_PATH}")
    with open(AF_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    original_size = len(content)
    replacements = 0

    for vid in sorted(ENTRIES.keys()):
        entry = ENTRIES[vid]
        start, end = find_stub_entry(content, vid)
        if start is None:
            print(f"  WARNING: Could not find stub for {vid}")
            continue

        old_entry = content[start:end]
        new_entry = build_entry(vid, entry)
        content = content[:start] + new_entry + content[end:]
        replacements += 1
        print(f"  Replaced {vid} ({len(old_entry)} -> {len(new_entry)} chars)")

    with open(AF_PATH, 'w', encoding='utf-8') as f:
        f.write(content)

    new_size = len(content)
    print(f"\nDone: {replacements}/20 replacements")
    print(f"Answer file size: {original_size:,} -> {new_size:,} bytes ({new_size - original_size:+,})")


if __name__ == '__main__':
    main()
