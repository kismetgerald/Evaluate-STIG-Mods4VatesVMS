#!/usr/bin/env python3
"""
Create answer file entries for Session #34 implementations.

Creates comprehensive ValidTrueComment entries for 7 new functions:
- V-206430, V-264339, V-264346, V-264347, V-264354, V-264357, V-279028

Usage:
    python create_answer_file_entries_session34.py
"""

import os
import re
from datetime import datetime
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
ANSWER_FILE_PATH = os.path.join(PROJECT_ROOT, 'AnswerFiles', 'XO_v5.x_WebSRG_AnswerFile.xml')

# Answer file entries (2 indices per function)
ANSWER_ENTRIES = {
    'V-206430': {
        'title': 'DoD PKI Client Certificate Validation',
        'NotAFinding': '''The automated check performed comprehensive DoD PKI trust anchor verification. System CA trust stores contain DoD Root CA certificates (DoD Root CA 3-6). TLS client certificate authentication is configured in XO config.toml. Certificate chain validation confirms DoD PKI issuer. Node.js is configured to use DoD CA bundle via NODE_EXTRA_CA_CERTS. All certificate validation uses DoD-approved PKI infrastructure. Manual ISSO/ISSM verification confirms ONLY DoD CAs are trusted and revocation checking is enabled.''',
        'Open': '''The automated check could not confirm DoD PKI trust anchor configuration or detected non-DoD CAs in trust stores. DoD requirement: Web server must use ONLY DoD PKI-established certificate authorities for TLS/SSL validation. REMEDIATION: (1) Install DoD Root CA 3-6 certificates from https://public.cyber.mil/pki-pke/; (2) Configure Node.js with NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt in systemd service; (3) Obtain XO TLS certificate from DoD PKI (not commercial CA); (4) Verify certificate chain with openssl verify; (5) Configure certificate revocation checking (CRL/OCSP); (6) Document DoD PKI configuration in organizational policy. MANUAL VERIFICATION REQUIRED: ISSO must confirm ONLY DoD CAs trusted, certificate revocation enabled, and DoD PKI compliance for ALL TLS connections.'''
    },
    'V-264339': {
        'title': 'Centralized Audit Record Review and Analysis',
        'NotAFinding': '''The automated check detected centralized logging infrastructure. Remote syslog forwarding configured (rsyslog/syslog-ng to SIEM server). XO audit plugin with remote forwarding detected. Systemd journal-upload or log aggregation tools (Splunk/Filebeat/Fluentd) active. Network connectivity to central log/SIEM server verified. Organizational SIEM documentation reviewed. System forwards audit records from multiple components (XO + systemd + nginx + system logs) to centralized SIEM for correlation and analysis. Manual ISSO/ISSM verification confirms SIEM receives logs from ALL components and performs multi-source correlation.''',
        'Open': '''The automated check detected no centralized logging or cannot verify SIEM integration. DoD requirement: Web server must implement capability to centrally review and analyze audit records from multiple components. REMEDIATION: (1) Configure rsyslog remote forwarding to SIEM (*.* @@siem-server.example.mil:514); (2) Enable XO audit plugin with remote forwarding (xo-cli plugin.enable id=xo-server-audit); (3) Install log aggregation tool (Splunk forwarder, Elastic Filebeat, Fluentd); (4) Configure systemd journal-upload for remote journald; (5) Test network connectivity to SIEM server on ports 514/6514/9997/5044; (6) Document SIEM integration in organizational policy. MANUAL VERIFICATION REQUIRED: ISSO must confirm SIEM receives logs from XO + XCP-ng + network + storage components, performs multi-component correlation, and provides centralized review capability for security analysts.'''
    },
    'V-264346': {
        'title': 'Password List Update Frequency (Organization-Defined)',
        'NotAFinding': '''The automated check detected password policy documentation and evidence of periodic updates. Organizational password policy defines update frequency (quarterly/annually). Password list files present with recent modification dates. Automated update mechanisms detected (cron/systemd timers). Password list maintenance performed on schedule. When LDAP/AD authentication used, password list managed by directory service. Manual ISSO/ISSM verification confirms password list updates occur at organization-defined frequency and documented in policy.''',
        'Open': '''The automated check could not verify password list update frequency or detected no organizational policy. DoD requirement: Update list of commonly-used/expected/compromised passwords on organization-defined frequency. REMEDIATION: (1) Establish organizational policy for password list update frequency (recommend quarterly); (2) Create password list file (reference NIST SP 800-63B Appendix A, HaveIBeenPwned breach database); (3) Configure automated update mechanism (cron job to download updated list); (4) Install PAM pwquality with dictionary=/path/to/password-list.txt; (5) Document update frequency in organizational password policy; (6) Schedule periodic reviews (quarterly) with calendar reminders. MANUAL VERIFICATION REQUIRED: ISSO must review organizational password policy, confirm update frequency defined, verify evidence of periodic updates, and validate password list currency matches policy requirements.'''
    },
    'V-264347': {
        'title': 'Password List Update When Compromised',
        'NotAFinding': '''The automated check detected incident response procedures and evidence of compromise-driven updates. Organizational security policy documents password list update upon compromise. Password list update history shows breach-responsive changes. Security incident logs or SIEM integration for breach detection present. Automated breach notification systems detected (HaveIBeenPwned API, breach feeds). Manual ISSO/ISSM verification confirms incident response procedures trigger immediate password list updates when organizational passwords suspected compromised.''',
        'Open': '''The automated check could not verify breach response procedures or detected no incident-driven update evidence. DoD requirement: Update password list when organizational passwords suspected compromised directly or indirectly. REMEDIATION: (1) Establish incident response procedures for password compromise; (2) Integrate breach notification service (HaveIBeenPwned API, breach intelligence feeds); (3) Document password compromise response in organizational security policy; (4) Create runbook for immediate password list update upon breach notification; (5) Configure SIEM alerts for credential compromise indicators; (6) Test breach response procedures annually. MANUAL VERIFICATION REQUIRED: ISSO must review incident response plan, confirm password compromise procedures defined, verify breach notification integration, and validate evidence of immediate action upon compromise detection.'''
    },
    'V-264354': {
        'title': 'Local Cache for Certificate Revocation Data',
        'NotAFinding': '''The automated check detected certificate revocation caching mechanisms. CRL cache directories present (/etc/ssl/crl, /var/cache/crl) with recent CRL files. OCSP stapling configured in Nginx or Node.js TLS settings. CRL download and caching scripts detected (cron/systemd timers). Certificate revocation checking enabled in OpenSSL configuration. System maintains local cache of revocation data to support offline validation and reduce latency. Manual verification confirms CRL/OCSP cache updated within validity period.''',
        'Open': '''The automated check could not confirm certificate revocation caching or detected no CRL/OCSP infrastructure. DoD requirement: Implement local cache of revocation data to support path discovery and validation. REMEDIATION: (1) Create CRL cache directory (mkdir -p /var/cache/crl); (2) Configure CRL download script (wget -P /var/cache/crl https://crl.dod.mil/...); (3) Schedule periodic CRL updates (cron: 0 */6 * * * /usr/local/bin/update-crls.sh); (4) Enable OCSP stapling in Nginx (ssl_stapling on; ssl_stapling_verify on;); (5) Configure Node.js TLS with crl property in config.toml; (6) Set OpenSSL to check revocation (openssl verify -crl_check). MANUAL VERIFICATION REQUIRED: Verify CRL/OCSP cache updates within validity period, test revocation checking with revoked certificate, confirm offline validation capability.'''
    },
    'V-264357': {
        'title': 'Protected Cryptographic Key Storage',
        'NotAFinding': '''The automated check detected protected key storage mechanisms. Private key files found with correct permissions (600/400) and ownership (root:root). HSM/TPM integration detected OR encrypted key files (password-protected PEM). File system searches confirmed keys stored in protected directories (/etc/ssl/private, /etc/pki/tls/private, /etc/xo-server, /opt/xo). No world-readable key files detected. Key management service integration may be present (vault, KMS). Manual verification confirms organizational key protection safeguards meet DoD requirements.''',
        'Open': '''The automated check detected keys with insufficient protection or cannot verify organizational safeguards. DoD requirement: Provide protected storage for cryptographic keys with organization-defined safeguards and/or hardware protected key store. REMEDIATION: (1) Set key file permissions (chmod 600 /path/to/private.key; chown root:root); (2) Use encrypted key files (openssl rsa -aes256 -in key.pem -out encrypted-key.pem); (3) Integrate HSM for key storage (PKCS#11 module, OpenSSL engine); (4) Configure TPM for key protection (tpm2-tools); (5) Implement key management service (HashiCorp Vault, AWS KMS); (6) Document key protection in organizational policy. MANUAL VERIFICATION REQUIRED: ISSO must verify keys stored with organization-defined safeguards (HSM/TPM/encryption), confirm key access restricted to authorized processes, and validate key protection meets FIPS 140-2 requirements.'''
    },
    'V-279028': {
        'title': 'Uniquely Identify Information Transfer Source',
        'NotAFinding': '''The automated check detected comprehensive source identification mechanisms. XO authentication captures user identity (LDAP/SAML/OAuth plugins or local accounts). TLS client certificate authentication provides X.509 identity. API token authentication includes user attribution. Session management tracks user identity in Redis. Audit logging records organization + system + application + individual for ALL information transfers. Manual ISSO/ISSM verification confirms complete source attribution (org + system + app + user) for ALL access attempts and data transfers.''',
        'Open': '''The automated check detected authentication but cannot verify complete source identification. DoD requirement: Uniquely identify and authenticate source by organization, system, application, AND individual for information transfer. REMEDIATION: (1) Enable LDAP/AD authentication with organizational context (install xo-server-auth-ldap, configure LDAP server with org attributes); (2) Configure TLS client certificates with X.509 subject DN including organization; (3) Implement audit logging with full source attribution (user + IP + system + org context); (4) Configure session management to capture and maintain source identity; (5) Enable XO audit plugin to log ALL information transfers with source details; (6) Document source identification requirements in organizational policy. MANUAL VERIFICATION REQUIRED: ISSO must verify ALL information transfers logged with organization + system + application + individual identity, confirm audit records demonstrate complete source attribution, and validate source identification meets DoD traceability requirements.'''
    }
}


def create_backup(filepath):
    """Create timestamped backup."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{filepath}.backup_{timestamp}"
    shutil.copy2(filepath, backup_path)
    print(f"[OK] Created backup: {os.path.basename(backup_path)}")
    return backup_path


def build_answer_entry(vuln_id, entry_data):
    """Build two-index answer entry."""
    # XML entity escaping
    nf_comment = entry_data['NotAFinding'].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    open_comment = entry_data['Open'].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    return f'''  <Vuln ID="{vuln_id}">
    <AnswerKey Name="XO">
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode>None</ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf_comment}</ValidTrueComment>
        <ValidFalseStatus>NotAFinding</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <!--Non-compliant or unverified systems requiring manual ISSO/ISSM review-->
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{open_comment}</ValidTrueComment>
        <ValidFalseStatus>Open</ValidFalseStatus>
        <ValidFalseComment></ValidFalseComment>
      </Answer>
    </AnswerKey>
  </Vuln>
'''


def main():
    print("=" * 80)
    print("Session #34: Create Answer File Entries (7 Functions)")
    print("=" * 80)
    print()

    # Read answer file
    print(f"Reading answer file: {os.path.basename(ANSWER_FILE_PATH)}")
    with open(ANSWER_FILE_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    original_size = len(content)
    print(f"  Original size: {original_size:,} bytes")
    print()

    # Create backup
    backup_path = create_backup(ANSWER_FILE_PATH)
    print()

    # Check for existing entries and update/create
    entries_updated = 0
    entries_created = 0

    for vuln_id in sorted(ANSWER_ENTRIES.keys()):
        entry_data = ANSWER_ENTRIES[vuln_id]
        print(f"Processing {vuln_id} ({entry_data['title']})...")

        # Check if entry exists
        pattern = rf'<Vuln ID="{vuln_id}">.*?</Vuln>'
        match = re.search(pattern, content, re.DOTALL)

        new_entry = build_answer_entry(vuln_id, entry_data)

        if match:
            # Update existing entry
            content = content.replace(match.group(0), new_entry.strip())
            entries_updated += 1
            print(f"  [OK] Updated existing entry")
        else:
            # Insert before </AnswerFile>
            insert_pos = content.rfind('</AnswerFile>')
            if insert_pos > 0:
                content = content[:insert_pos] + new_entry + '\n' + content[insert_pos:]
                entries_created += 1
                print(f"  [OK] Created new entry")
            else:
                print(f"  [ERROR] Could not find </AnswerFile> tag")

    print()
    print(f"Entries updated: {entries_updated}")
    print(f"Entries created: {entries_created}")
    print(f"Total: {entries_updated + entries_created}/7")
    print()

    # Write updated content
    new_size = len(content)
    print(f"New size: {new_size:,} bytes ({new_size - original_size:+,} bytes)")

    with open(ANSWER_FILE_PATH, 'w', encoding='utf-8') as f:
        f.write(content)

    print()
    print("=" * 80)
    print("[OK] Answer file entries created!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Validate XML structure")
    print("  2. Run Test119 framework test")
    print("  3. Verify COMMENTS populate for all 10 functions")

    return 0


if __name__ == '__main__':
    exit(main())
