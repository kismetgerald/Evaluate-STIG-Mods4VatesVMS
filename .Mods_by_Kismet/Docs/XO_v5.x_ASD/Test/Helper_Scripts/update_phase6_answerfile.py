#!/usr/bin/env python3
"""
update_phase6_answerfile.py — Replace stub answer file entries for Phase 6 VulnIDs
with proper 2-index (or 3-index for N/A) entries.

15 functions: V-222581–V-222600 (skipping V-222585, V-222588, V-222589, V-222590, V-222596)
"""

import re
import sys

AF_PATH = (
    r"d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG"
    r"\v1.2507.6_Mod4VatesVMS_OpenCode"
    r"\Evaluate-STIG\AnswerFiles\XO_v5.x_ASD_AnswerFile.xml"
)

# ---------------------------------------------------------------------------
# Answer file entries — keyed by VulnID
# Each entry: (expected_status_1, comment_1, expected_status_2, comment_2, [optional: es3, c3])
# ---------------------------------------------------------------------------
ENTRIES = {}

# Helper to build the XML block
def make_entry(vuln_id, items):
    """items is a list of (index, expected_status, true_status, comment) tuples"""
    lines = [f'  <Vuln ID="{vuln_id}">']
    lines.append('    <AnswerKey Name="XO">')
    for idx, es, ts, comment in items:
        lines.append(f'      <Answer Index="{idx}" ExpectedStatus="{es}" Hostname="" Instance="" Database="" Site="" ResultHash="">')
        lines.append(f'        <ValidationCode />')
        lines.append(f'        <ValidTrueStatus>{ts}</ValidTrueStatus>')
        lines.append(f'        <ValidTrueComment>{comment}</ValidTrueComment>')
        lines.append(f'        <ValidFalseStatus />')
        lines.append(f'        <ValidFalseComment />')
        lines.append(f'      </Answer>')
    lines.append('    </AnswerKey>')
    lines.append('  </Vuln>')
    return '\n'.join(lines)


# ===== BATCH 14 =====

ENTRIES["V-222581"] = make_entry("V-222581", [
    (1, "NotAFinding", "NotAFinding",
     "XO uses Express.js cookie-based session management. Session identifiers are transmitted exclusively via HTTP Set-Cookie headers, not embedded in URLs. No URL rewriting or session ID query parameters are configured. This meets the STIG requirement to avoid URL-embedded session IDs, preventing session fixation via referrer headers or browser history."),
    (2, "Open", "Open",
     "Session ID transmission method requires verification. Review XO and any reverse proxy configuration to confirm session tokens are not appended to URLs as query parameters or path segments. Ensure Express.js session middleware uses cookie transport exclusively. Check for URL rewriting rules that might expose session identifiers in application logs or referrer headers."),
])

ENTRIES["V-222582"] = make_entry("V-222582", [
    (1, "NotAFinding", "NotAFinding",
     "XO generates new session IDs upon each authentication event. Express.js session management creates unique identifiers per login and invalidates previous sessions on logout. Session IDs are not reused or recycled after user logout. The session store (in-memory or Redis) enforces TTL-based expiration preventing stale session reuse."),
    (2, "Open", "Open",
     "Session ID lifecycle management requires verification. Confirm that XO regenerates session identifiers on authentication and does not reuse session IDs after logout. Test by logging in, noting the session cookie value, logging out, and logging back in to verify a new session ID is assigned. Check session store configuration for proper expiration settings."),
])

ENTRIES["V-222583"] = make_entry("V-222583", [
    (1, "NotAFinding", "NotAFinding",
     "XO uses Node.js crypto.randomBytes() via the uid-safe library for session ID generation. The system is in FIPS mode (fips_enabled=1), confirming FIPS 140-2/140-3 validated random number generation for session identifiers. OpenSSL provides the CSPRNG backend with FIPS-validated algorithms."),
    (2, "Open", "Open",
     "System FIPS mode is not enabled. While XO uses OpenSSL CSPRNG via Node.js crypto.randomBytes() for session ID generation (which provides cryptographic-quality randomness), FIPS 140-2/140-3 validation requires system-level FIPS mode. Enable FIPS mode: edit /etc/default/grub to add fips=1 to GRUB_CMDLINE_LINUX, run update-grub, and install the libssl FIPS provider package, then reboot."),
])

ENTRIES["V-222584"] = make_entry("V-222584", [
    (1, "NotAFinding", "NotAFinding",
     "XO server certificate is issued by a DoD-approved Certificate Authority. The certificate chain validates to a trusted DoD PKI or ECA root CA. Certificate details confirm proper issuance and validity dates. DoD CA certificates are installed in the system trust store."),
    (2, "Open", "Open",
     "XO server is using a self-signed or non-DoD certificate. For DoD environments, obtain and install a certificate from a DoD-approved PKI or ECA Certificate Authority. Update /etc/xo-server/config.toml (XOA) or /opt/xo/xo-server/config.toml (XOCE) with the new certificate and key paths. Import DoD root CA certificates into the system trust store at /usr/local/share/ca-certificates/ and run update-ca-certificates."),
])

ENTRIES["V-222586"] = make_entry("V-222586", [
    (1, "NotAFinding", "NotAFinding",
     "XO preserves failure diagnostic information via systemd journal and application log files. Error events are captured with timestamps, severity levels, and contextual information sufficient for root cause analysis. The Winston logging framework provides structured log output. Journal persistence ensures log data survives service restarts."),
    (2, "Open", "Open",
     "Diagnostic information preservation could not be verified. Ensure XO logging is configured to capture error events with sufficient detail for root cause analysis. Verify systemd journal is configured for persistent storage (Storage=persistent in /etc/systemd/journald.conf). Configure log rotation to preserve historical diagnostic data. Document operational requirements for failure recovery information."),
])

ENTRIES["V-222587"] = make_entry("V-222587", [
    (1, "NotAFinding", "NotAFinding",
     "XO stored data is protected with appropriate file system permissions. Data directories (/var/lib/xo-server, /etc/xo-server) have restrictive permissions preventing unauthorized access. No world-readable files exist in sensitive data directories. Configuration files containing credentials are protected with owner-only read permissions."),
    (2, "Open", "Open",
     "Data protection concerns identified. Review and tighten file permissions on XO data directories. Ensure /var/lib/xo-server and /etc/xo-server are not world-readable (chmod 750 or stricter). Remove world-readable permissions from sensitive files. Consider enabling disk encryption (LUKS/dm-crypt) for data at rest protection. Document data classification and protection requirements per organizational policy."),
])

ENTRIES["V-222591"] = make_entry("V-222591", [
    (1, "NotAFinding", "NotAFinding",
     "XO maintains separate execution domains for each process. Node.js V8 isolates provide memory and execution separation between JavaScript contexts. The xo-server process runs under its own user context with systemd service management. Process isolation is enforced at the operating system level through standard Linux process separation mechanisms."),
    (2, "Open", "Open",
     "Process execution domain separation requires verification. Confirm that XO server processes run under dedicated user accounts. Review systemd service unit for sandboxing directives (PrivateTmp, ProtectSystem, ProtectHome, NoNewPrivileges). Consider enabling additional systemd security features to enhance process isolation. Verify that plugin execution does not share memory space with the main application."),
])

ENTRIES["V-222592"] = make_entry("V-222592", [
    (1, "NotAFinding", "NotAFinding",
     "XO does not share system resources with other applications via file sharing protocols. No NFS or SMB services are running on the system. Data directories are protected by file system permissions restricting access to the xo-server process. Network listeners are limited to application-specific ports (HTTPS 443)."),
    (2, "Open", "Open",
     "File sharing services or shared resources detected. Verify that XO data is not accessible via NFS, SMB, or other file sharing protocols. If file sharing services are required for other purposes, ensure XO data directories are excluded from shared exports. Implement security boundaries (file permissions, network segmentation) to prevent unauthorized information transfer between applications."),
])

# ===== BATCH 15 =====

ENTRIES["V-222593"] = make_entry("V-222593", [
    (1, "Not_Applicable", "Not_Applicable",
     "XO does not utilize XML-based web services. The application uses JSON for all API communication via REST endpoints. No SOAP, WSDL, or XML-RPC services are exposed. XML DoS protections (entity expansion, recursive payloads, oversized payloads) are not applicable to this JSON-based application."),
    (2, "Open", "Open",
     "If XO has been configured to process XML input (custom plugins, third-party integrations), verify protections against XML DoS attacks including: validation against recursive payloads (billion laughs), validation against oversized payloads, protection against XML entity expansion (XXE), validation against overlong element names, and optimized configuration for maximum message throughput."),
])

ENTRIES["V-222594"] = make_entry("V-222594", [
    (1, "NotAFinding", "NotAFinding",
     "XO has adequate DoS protections in place. Firewall rules restrict network access, rate limiting prevents abuse, and system-level connection limits are configured. The application cannot be weaponized to attack other systems due to restricted outbound access and purpose-built architecture."),
    (2, "Open", "Open",
     "DoS protection assessment requires organizational verification. Implement: firewall rules (UFW/iptables) to restrict access to authorized networks, application-level rate limiting in XO configuration, fail2ban for brute-force protection, system connection limits (net.core.somaxconn), and network-level DDoS mitigation. ISSO must confirm anti-DoS controls are adequate for the deployment risk profile."),
])

ENTRIES["V-222595"] = make_entry("V-222595", [
    (1, "NotAFinding", "NotAFinding",
     "XO high availability requirements are met with redundancy mechanisms including load balancers, redundant application instances, and automated failover. The deployment architecture meets documented availability requirements."),
    (2, "Open", "Open",
     "XO is deployed as a single instance without high availability mechanisms. If designated as a high availability system, implement: load balancer (HAProxy/nginx) for traffic distribution, multiple XO instances for redundancy, shared session store (Redis) for session persistence across instances, database replication for data availability, and documented failover procedures. If not designated as HA, document the risk acceptance."),
    (3, "Not_Applicable", "Not_Applicable",
     "XO has not been designated as a high availability system. This requirement only applies to applications that have been designated as requiring high availability. Per STIG guidance, if the application has not been designated as a high availability system, this requirement is not applicable."),
])

ENTRIES["V-222597"] = make_entry("V-222597", [
    (1, "NotAFinding", "NotAFinding",
     "XO implements TLS encryption for all data transmission. TLS 1.2 is confirmed active with strong cipher suites. HTTPS is configured on port 443 with valid certificate. HTTP to HTTPS redirect is configured. All management API communications between XO and XCP-ng hosts use TLS-encrypted XAPI connections."),
    (2, "Open", "Open",
     "TLS encryption for data transmission could not be confirmed. Ensure HTTPS is properly configured in XO server configuration (/etc/xo-server/config.toml or /opt/xo/xo-server/config.toml). Verify TLS 1.2 or higher is enabled. Configure HTTP to HTTPS redirect. Ensure inter-tier communications (XO to XCP-ng) use TLS. Test with: openssl s_client -connect hostname:443 -tls1_2"),
])

ENTRIES["V-222598"] = make_entry("V-222598", [
    (1, "NotAFinding", "NotAFinding",
     "XO maintains data confidentiality during preparation for transmission. All data is encrypted via TLS/HTTPS before being transmitted. The HTTPS listener on port 443 confirms that data is protected from the point of preparation through transmission. Node.js TLS module handles encryption before network transmission."),
    (2, "Open", "Open",
     "HTTPS listener not confirmed on port 443. Verify TLS is configured for all XO communications. Ensure the XO server binds to HTTPS and that no unencrypted HTTP endpoints are exposed for data transmission. Configure TLS certificates and enable HTTPS in the XO server configuration. For tiered deployments, verify encryption between all application tiers."),
])

ENTRIES["V-222599"] = make_entry("V-222599", [
    (1, "NotAFinding", "NotAFinding",
     "XO maintains data confidentiality during reception. All incoming connections are received via TLS/HTTPS on port 443. The TLS handshake completes before any application data is exchanged, ensuring confidentiality from the point of reception. Inter-tier communication with XCP-ng hosts uses TLS-encrypted XAPI connections."),
    (2, "Open", "Open",
     "HTTPS reception not confirmed. Verify that all incoming connections to XO are received over TLS. Ensure port 443 has an active HTTPS listener. If HTTP port 80 is open, verify it redirects to HTTPS. Check that no application data is received over unencrypted channels. For tiered deployments, verify all communication tiers use encryption."),
])

ENTRIES["V-222600"] = make_entry("V-222600", [
    (1, "NotAFinding", "NotAFinding",
     "XO does not disclose unnecessary technical information to users. Server response headers do not reveal technology stack details. Error pages return generic responses without stack traces, internal paths, or debugging information. The application suppresses detailed error messages in production mode."),
    (2, "Open", "Open",
     "Information disclosure detected in server response headers or error pages. Remove X-Powered-By header by configuring Express.js: app.disable('x-powered-by'). Configure custom error pages that do not reveal stack traces, internal file paths, or technology versions. Set NODE_ENV=production to suppress detailed error messages. Review all HTTP response headers for unnecessary information disclosure."),
])


# ---------------------------------------------------------------------------
# Engine: replace stub entries in the answer file
# ---------------------------------------------------------------------------
def replace_entries(content: str) -> tuple[str, int]:
    replaced = 0
    for vuln_id, new_block in ENTRIES.items():
        # Match the entire <Vuln ID="V-XXXXXX">...</Vuln> block
        pattern = re.compile(
            rf'  <Vuln ID="{re.escape(vuln_id)}">.*?</Vuln>',
            re.DOTALL
        )
        if pattern.search(content):
            content = pattern.sub(new_block, content)
            replaced += 1
        else:
            print(f"WARNING: {vuln_id} not found in answer file")
    return content, replaced


def main():
    with open(AF_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    print(f"Answer file size: {len(content):,} bytes")
    print(f"Entries to replace: {len(ENTRIES)}")

    new_content, count = replace_entries(content)
    print(f"Replaced {count}/{len(ENTRIES)} entries.")

    with open(AF_PATH, "w", encoding="utf-8-sig") as f:
        f.write(new_content)

    print(f"New answer file size: {len(new_content):,} bytes")

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.fromstring(new_content.encode("utf-8-sig"))
        print("XML validation: PASSED")
    except ET.ParseError as e:
        print(f"XML validation: FAILED - {e}")


if __name__ == "__main__":
    main()
