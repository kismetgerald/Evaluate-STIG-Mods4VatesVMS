#!/usr/bin/env python3
"""
Update answer file with entries for Batch 9: PKI & Certificates (10 functions).
Inserts answer entries for V-203622, V-203623, V-203624, V-203639,
V-203640, V-203641, V-203642, V-203643, V-203644, V-203729.
"""

import sys

AF_PATH = r"Evaluate-STIG\AnswerFiles\XO_v5.x_GPOS_Debian12_AnswerFile.xml"

# Answer entries: each has Index 1 (NotAFinding) and Index 2 (Open)
ENTRIES = {
    "V-203622": {
        "nf": "The system has ca-certificates installed with a functional CA trust store. OpenSSL is configured with standard certificate directories. Certificate path validation is available through the system trust store managed by update-ca-certificates. The ISSO/ISSM should verify that organizational trust anchors (DoD Root CAs) are included in the trust store and that OCSP/CRL validation is configured per organizational security policy.",
        "open": "PKI certificate path validation is not fully configured. To remediate: (1) Install ca-certificates package: apt install ca-certificates. (2) Add DoD Root CA certificates to /usr/local/share/ca-certificates/ and run update-ca-certificates. (3) Configure OCSP stapling or CRL distribution points for certificate revocation checking. (4) If using SSSD for PKI auth, configure certificate_verification in sssd.conf. (5) Document trust anchor configuration in the system security plan."
    },
    "V-203623": {
        "nf": "Private key files are stored with appropriate access controls. Key file permissions restrict access to root or the owning service account. The /etc/ssl/private directory is restricted to root-only access (mode 700). No world-readable or group-writable key files were detected. The ISSO/ISSM should verify that key file permissions are reviewed periodically and that key rotation procedures are documented.",
        "open": "Private key access controls require remediation. To fix: (1) Set key file permissions to 600 or 640: chmod 600 /etc/ssl/private/*.key. (2) Ensure key files are owned by root: chown root:root /etc/ssl/private/*.key. (3) Set /etc/ssl/private directory to mode 700: chmod 700 /etc/ssl/private. (4) Remove any world-readable key files. (5) Document key management procedures including rotation schedule and access control verification."
    },
    "V-203624": {
        "nf": "PKI-based identity mapping is configured through SSSD certificate mapping rules or PAM PKCS#11 mapper configuration. The system maps authenticated certificate identities to local user or group accounts. NSS is configured to resolve user accounts through appropriate sources. The ISSO/ISSM should verify that certificate-to-user mapping rules correctly associate organizational PKI credentials with the appropriate system accounts.",
        "open": "PKI identity mapping is not configured. To remediate: (1) Install SSSD with certificate support: apt install sssd. (2) Configure certmap rules in /etc/sssd/sssd.conf to map certificate attributes to user accounts. (3) Alternatively, install libpam-pkcs11 and configure /etc/pam_pkcs11/pam_pkcs11.conf with appropriate mapper settings. (4) Test certificate-to-user mapping with a known PKI credential. (5) Document the identity mapping configuration in the system security plan."
    },
    "V-203639": {
        "nf": "The system uniquely identifies all organizational users. No duplicate UIDs or usernames exist in /etc/passwd. Each user account has a unique UID assigned through standard Debian account management. NSS is configured to resolve user identities through local files and any configured directory services. The ISSO/ISSM should verify that account provisioning procedures ensure unique identification for all users.",
        "open": "Unique user identification issues detected. To remediate: (1) Resolve any duplicate UIDs by assigning unique values: usermod -u NEW_UID username. (2) Resolve any duplicate usernames. (3) Review /etc/passwd for accounts that should be removed or consolidated. (4) Ensure UID_MIN and UID_MAX in /etc/login.defs provide adequate range for organizational users. (5) Implement centralized identity management (LDAP/AD) to prevent UID collisions across systems."
    },
    "V-203640": {
        "nf": "MFA is configured for network access to privileged accounts. Smartcard/PKI authentication or TOTP is deployed through PAM modules. SSH is configured with AuthenticationMethods requiring multiple factors for privileged users. The ISSO/ISSM should verify that MFA enrollment is complete for all privileged account holders and that MFA bypass procedures are documented and controlled.",
        "open": "MFA for network access to privileged accounts is not deployed. To remediate: (1) Deploy smartcard infrastructure: apt install opensc pcscd libpam-pkcs11. (2) Configure PAM for MFA: add pam_pkcs11.so or pam_google_authenticator.so to /etc/pam.d/common-auth. (3) Configure SSH MFA: set AuthenticationMethods publickey,keyboard-interactive in sshd_config. (4) Enroll all privileged users in MFA. (5) For DoD environments, CAC/PIV with PIN satisfies the two-factor requirement (something you have + something you know)."
    },
    "V-203641": {
        "nf": "MFA is configured for network access to non-privileged accounts. Authentication requires multiple factors through PAM module configuration. The ISSO/ISSM should verify that MFA enrollment is complete for all non-privileged network users and that the authentication policy is enforced consistently.",
        "open": "MFA for network access to non-privileged accounts is not deployed. To remediate: (1) Deploy MFA infrastructure (smartcard or TOTP). (2) Configure PAM for MFA in /etc/pam.d/common-auth. (3) Configure SSH AuthenticationMethods for non-privileged users. (4) Enroll all non-privileged users in MFA. (5) For DoD environments, CAC/PIV authentication satisfies this requirement. Consider LDAP/AD integration to delegate MFA to enterprise identity provider."
    },
    "V-203642": {
        "nf": "MFA is configured for local access to privileged accounts. Console authentication requires multiple factors through PAM configuration. The ISSO/ISSM should verify that MFA is enforced for all local privileged access including console login, su, and sudo operations.",
        "open": "MFA for local access to privileged accounts is not deployed. To remediate: (1) Configure PAM for local MFA: add MFA module to /etc/pam.d/login and /etc/pam.d/su. (2) For smartcard: install pcscd and libpam-pkcs11, configure PAM stack. (3) For TOTP: install libpam-google-authenticator, enroll privileged users. (4) Ensure sudo requires re-authentication with MFA. (5) Document MFA requirements for local privileged access in the security plan."
    },
    "V-203643": {
        "nf": "MFA is configured for local access to nonprivileged accounts. Console authentication requires multiple factors through PAM configuration. The ISSO/ISSM should verify that MFA enrollment is complete for all local nonprivileged users.",
        "open": "MFA for local access to nonprivileged accounts is not deployed. To remediate: (1) Configure PAM for local MFA in /etc/pam.d/login. (2) Deploy smartcard or TOTP authentication for console access. (3) Enroll all nonprivileged users in the MFA system. (4) For DoD environments, CAC/PIV with PIN satisfies this requirement for both local and network access. (5) Consider enterprise identity management (LDAP/AD with MFA) for centralized enforcement."
    },
    "V-203644": {
        "nf": "Individual authentication is required before group account access. Users must authenticate with personal credentials before using sudo, su, or any shared/service accounts. PAM is configured to enforce individual authentication. No direct group account login is permitted. The ISSO/ISSM should verify that shared account access procedures require individual authentication and that access is logged for accountability.",
        "open": "Individual authentication before group/shared account access requires verification. To remediate: (1) Disable direct login to shared accounts: set shell to /usr/sbin/nologin for service accounts. (2) Require sudo for privileged operations: configure /etc/sudoers with individual user entries. (3) Ensure su requires authentication: verify pam_rootok is not set for non-root users. (4) Log all shared account access through sudo logging. (5) Document procedures requiring individual authentication before any shared account usage."
    },
    "V-203729": {
        "nf": "PIV credential verification infrastructure is deployed. The system has smartcard packages installed (opensc, pcscd, libpam-pkcs11) and the PC/SC daemon is active. PAM or SSSD is configured for smartcard authentication. The ISSO/ISSM should verify that PIV credentials are validated against DoD trust anchors and that certificate revocation checking is enabled.",
        "open": "PIV credential verification is not fully deployed. To remediate: (1) Install smartcard packages: apt install opensc pcscd libccid libpam-pkcs11. (2) Enable and start pcscd: systemctl enable --now pcscd. (3) Configure PAM for smartcard auth: add pam_pkcs11.so to /etc/pam.d/common-auth. (4) Install DoD Root CA certificates for PIV trust chain validation. (5) Configure certificate revocation checking (OCSP or CRL). (6) Test with a known CAC/PIV card to verify end-to-end authentication."
    },
}


def main():
    with open(AF_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    # Find the insertion point — before the closing </STIGComments> tag
    insert_marker = "</STIGComments>"
    if insert_marker not in content:
        print("ERROR: Could not find </STIGComments> in answer file")
        sys.exit(1)

    new_entries = []
    for vuln_id, comments in ENTRIES.items():
        nf_comment = comments["nf"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        open_comment = comments["open"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        entry = f'''  <Vuln ID="{vuln_id}">
    <AnswerKey Name="XO">
      <Answer Index="1" Hostname="" Instance="" Database="" Site="" ResultHash="" ExpectedStatus="NotAFinding">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" Hostname="" Instance="" Database="" Site="" ResultHash="" ExpectedStatus="Open">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{open_comment}</ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>'''
        new_entries.append(entry)

    all_entries = "\n".join(new_entries) + "\n"
    content = content.replace(insert_marker, all_entries + "  " + insert_marker)

    with open(AF_PATH, "w", encoding="utf-8-sig") as f:
        f.write(content)

    print(f"SUCCESS: Added {len(ENTRIES)} answer file entries")
    print(f"Vuln IDs: {', '.join(ENTRIES.keys())}")


if __name__ == "__main__":
    main()
