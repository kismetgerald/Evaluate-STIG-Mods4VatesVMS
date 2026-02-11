#!/usr/bin/env python3
"""
Format ValidTrueComment text in answer file for the 5 functions fixed in Session #35.
Adds proper line breaks so COMMENTS don't appear as a wall of text in CKL.
"""
import re

af_path = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\AnswerFiles"
    r"\XO_v5.x_WebSRG_AnswerFile.xml"
)

# Formatted replacements: (vuln_id, expected_status) -> new comment text
# Uses actual newlines which XML preserves and PowerShell | Out-String passes through.
NEW_COMMENTS = {

    ("V-206430", "NotAFinding"): """\
DoD PKI trust anchors have been verified on this system.

Xen Orchestra uses only DoD Root CA certificates (DoD Root CA 3-6) for TLS chain
validation. No commercial or non-DoD CAs are present in the trust store. Certificate
revocation checking (CRL/OCSP) is enabled.

No corrective action required.

ISSO: Document the DoD PKI certificate configuration and NODE_EXTRA_CA_CERTS setting
in the System Security Plan.""",

    ("V-206430", "Open"): """\
DoD PKI trust anchor configuration is incomplete or non-DoD certificate authorities
are present in the trust store.

The DoD requires that web servers use ONLY DoD PKI-established CAs for TLS validation.

ISSO Action Required:

1. Install DoD Root CA 3-6 certificates:
   - Download from https://public.cyber.mil/pki-pke/
   - Add to /etc/ssl/certs/

2. Set NODE_EXTRA_CA_CERTS to the DoD CA bundle in the xo-server systemd unit file.

3. Obtain the XO TLS server certificate from DoD PKI (not a commercial CA).

4. Enable certificate revocation checking (CRL/OCSP) in the TLS configuration.

5. Verify the full certificate chain:
   openssl verify -CApath /etc/ssl/certs &lt;cert.pem&gt;

Document remediation in the POA&amp;M and record the corrected DoD PKI configuration
in the System Security Plan.""",

    ("V-264339", "NotAFinding"): """\
Centralized audit log collection has been verified on this system.

Xen Orchestra audit records are forwarded to the organizational SIEM via rsyslog/
syslog-ng or a log aggregation agent (Splunk UF, Elastic Filebeat, or Fluentd).
This provides multi-component correlation across XO, XCP-ng, network, and storage.

No corrective action required.

ISSO: Document the SIEM integration architecture, log forwarding configuration, and
the components covered in the System Security Plan.""",

    ("V-264339", "Open"): """\
Centralized audit log collection cannot be confirmed on this system.

The DoD requires that web servers implement a capability to centrally review and
analyze audit records from multiple components.

ISSO Action Required:

1. Configure rsyslog or syslog-ng to forward logs to the organizational SIEM:
   *.* @@siem-server.example.mil:514  (in /etc/rsyslog.conf)

2. Enable the XO audit plugin and configure remote forwarding:
   xo-cli plugin.enable id=xo-server-audit

3. Install and configure a log aggregation agent (Splunk UF, Elastic Filebeat, or
   Fluentd) to forward XO and system logs.

4. Verify network connectivity to the SIEM server and test log receipt.

5. Confirm the SIEM correlates logs from XO, XCP-ng, network, and storage.

Document remediation in the POA&amp;M.""",

    ("V-264354", "NotAFinding"): """\
Certificate revocation caching is operational on this system.

A local CRL cache directory is present with current DoD CRL files, and OCSP stapling
is configured, enabling offline path validation and reducing revocation-check latency.
CRL updates are scheduled via cron or systemd timer.

No corrective action required.

ISSO: Document the CRL update frequency, distribution point URLs, and OCSP
configuration in the System Security Plan.""",

    ("V-264354", "Open"): """\
Certificate revocation caching infrastructure is not configured or cannot be confirmed.

The DoD requires a local cache of revocation data to support path discovery and
validation, including offline scenarios.

ISSO Action Required:

1. Create a local CRL cache directory and download current DoD CRL files:
   mkdir -p /var/cache/crl

2. Configure a scheduled CRL update (e.g., cron: 0 */6 * * * /usr/local/bin/update-crls.sh)

3. Enable OCSP stapling in Nginx (ssl_stapling on; ssl_stapling_verify on) or in the
   Node.js TLS options.

4. Set OpenSSL certificate verification to check revocation (-crl_check flag or via
   OPENSSL_CONF policy).

5. Test offline validation by temporarily blocking OCSP/CRL network access.

Document remediation in the POA&amp;M.""",

    ("V-264357", "Not_Reviewed"): """\
Manual verification of cryptographic key storage safeguards is required.

ISSO must perform the following:

1. Locate all private key files:
   - Check config.toml for key paths
   - Search /etc/ssl/private, /etc/ssl, /opt/xo, /etc/xo-server, /etc/pki/tls/private

2. Verify each key file has permissions 600 or 400 with root:root ownership:
   stat -c "%a %U:%G" &lt;keyfile&gt;

3. Confirm keys are protected by organization-defined safeguards:
   - Encrypted PEM, HSM/TPM, or KMS (e.g., HashiCorp Vault)

4. Document key locations, permissions, and the specific protection mechanism
   in the System Security Plan.

The DoD requires hardware-protected key storage (HSM/TPM) where feasible.""",

    ("V-264357", "Open"): """\
Private key files were found without adequate organizational safeguards.

The DoD requires cryptographic keys to be stored with organization-defined protections
and, where feasible, hardware-protected key storage.

ISSO Action Required:

1. Restrict permissions on all private key files:
   chmod 400 /path/to/private.key &amp;&amp; chown root:root /path/to/private.key

2. Move keys from accessible directories to /etc/ssl/private or /etc/xo-server
   (directory permissions 700, root:root).

3. Encrypt key files at rest:
   openssl rsa -aes256 -in key.pem -out encrypted-key.pem

4. Evaluate integration with an HSM, TPM, or secrets manager (HashiCorp Vault) for
   hardware-backed key protection.

5. Document the chosen key protection mechanism in organizational policy.

Document remediation in the POA&amp;M.""",

    ("V-264357", "NotAFinding"): """\
Cryptographic key storage safeguards have been verified on this system.

Private key files are stored with restrictive permissions (600 or 400), owned by
root:root, and protected by organization-defined safeguards (encrypted PEM, HSM/TPM
integration, or KMS). No world-readable key files were detected.

No corrective action required.

ISSO: Document the key protection mechanism, storage locations, and any HSM/KMS
integration details in the System Security Plan.""",

    ("V-279028", "NotAFinding"): """\
Source identification for information transfers has been verified on this system.

Xen Orchestra authenticates users via LDAP/SAML/OAuth or local accounts, capturing
organization, system, application, and individual identity for every session. The XO
audit plugin records full source attribution (user, IP, system context) for all access
attempts and data transfers.

No corrective action required.

ISSO: Document the authentication configuration and audit logging architecture in the
System Security Plan, confirming all four source elements (organization, system,
application, individual) are captured and retained.""",

    ("V-279028", "Open"): """\
Complete source identification for information transfers cannot be confirmed.

The DoD requires that all transfers be attributable to organization, system,
application, AND individual.

ISSO Action Required:

1. Enable LDAP/AD integration to provide organizational context with user authentication:
   - Install xo-server-auth-ldap
   - Configure LDAP server with org unit attributes

2. Verify the XO audit plugin (xo-server-audit) is active and logging all transfers
   with full user identity and source IP.

3. Review a sample of recent audit log entries to confirm all four source elements
   are present (org, system, app, individual).

4. If source attribution gaps exist, configure TLS client certificate authentication
   (X.509 DN includes organization field) as a complement.

5. Document the source identification architecture in the System Security Plan.

Document remediation in the POA&amp;M.""",
}


with open(af_path, 'r', encoding='utf-8') as f:
    content = f.read()

changes = 0

for (vuln_id, expected_status), new_comment in NEW_COMMENTS.items():
    # Find the Vuln block
    vuln_start = content.find(f'<Vuln ID="{vuln_id}">')
    if vuln_start == -1:
        print(f"WARNING: {vuln_id} not found")
        continue
    vuln_end = content.find('</Vuln>', vuln_start) + len('</Vuln>')
    vuln_block = content[vuln_start:vuln_end]

    # Find the specific Answer block for this ExpectedStatus
    answer_pattern = rf'(<Answer Index="\d+" ExpectedStatus="{expected_status}".*?<ValidTrueComment>)(.*?)(</ValidTrueComment>)'
    def replace_comment(m):
        return m.group(1) + new_comment + m.group(3)

    new_vuln_block, n = re.subn(answer_pattern, replace_comment, vuln_block, count=1, flags=re.DOTALL)
    if n == 0:
        print(f"WARNING: Could not find Answer ExpectedStatus={expected_status} in {vuln_id}")
        continue

    content = content[:vuln_start] + new_vuln_block + content[vuln_end:]
    changes += 1
    print(f"Updated {vuln_id} {expected_status}")

print(f"\nTotal: {changes} comments reformatted")

# Validate XML
try:
    import xml.etree.ElementTree as ET
    ET.fromstring(content.encode('utf-8'))
    print("XML validation: PASSED")
except Exception as e:
    print(f"XML validation: FAILED - {e}")

with open(af_path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"Written to {af_path}")
