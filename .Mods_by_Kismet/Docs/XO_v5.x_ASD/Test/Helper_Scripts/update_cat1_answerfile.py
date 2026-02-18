#!/usr/bin/env python3
"""Update answer file entries for 13 CAT I functions fixed in Session #49.

Replaces stub entries (ExpectedStatus=Not_Reviewed, no comments) with
proper 2-3 index entries matching actual function return statuses.

Session #49 (Feb 2026): CAT I completion
"""

import os
import sys
import xml.etree.ElementTree as ET

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', '..', '..', '..'))
AF_PATH = os.path.join(PROJECT_ROOT, 'Evaluate-STIG', 'AnswerFiles',
                        'XO_v5.x_ASD_AnswerFile.xml')

SESSION = "Session #49 (Feb 2026): CAT I completion"


def make_entry(vuln_id, answers):
    """Build XML string for a Vuln entry with proper answer indices.

    answers: list of dicts with keys:
      index, expected_status, valid_true_status, valid_true_comment,
      valid_false_status, valid_false_comment
    """
    lines = [f'  <Vuln ID="{vuln_id}">']
    lines.append(f'    <!--{SESSION}-->')
    lines.append('    <AnswerKey Name="XO">')
    for a in answers:
        lines.append(f'      <Answer Index="{a["index"]}" ExpectedStatus="{a["expected_status"]}">')
        lines.append(f'        <ValidationCode />')
        lines.append(f'        <ValidTrueStatus>{a["valid_true_status"]}</ValidTrueStatus>')
        lines.append(f'        <ValidTrueComment>{a["valid_true_comment"]}</ValidTrueComment>')
        lines.append(f'        <ValidFalseStatus>{a["valid_false_status"]}</ValidFalseStatus>')
        lines.append(f'        <ValidFalseComment>{a["valid_false_comment"]}</ValidFalseComment>')
        lines.append(f'      </Answer>')
    lines.append('    </AnswerKey>')
    lines.append('  </Vuln>')
    return '\n'.join(lines)


# ── Answer file entries for each VulnID ──────────────────────────────────

ENTRIES = {}

ENTRIES["V-222430"] = make_entry("V-222430", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "XO Server runs as a non-root service account with appropriate group memberships. No excessive Linux capabilities detected on Node.js binary. Redis runs as dedicated redis user. The systemd service configuration enforces least privilege execution. Service account does not have sudo, wheel, or adm group membership.",
     "valid_false_status": "Open",
     "valid_false_comment": "Automated check determined XO does not run with least privilege."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "XO Server is running as root or with excessive account permissions. Remediation: Configure XO to run as a dedicated non-root service account. Remove the service account from sudo/wheel/adm groups. Set appropriate file ownership on /opt/xo directories. Verify no excessive Linux capabilities are assigned to the node binary.",
     "valid_false_status": "Open",
     "valid_false_comment": "Automated check determined excessive permissions exist."},
])

ENTRIES["V-222550"] = make_entry("V-222550", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "PKI certificate path validation is properly configured. SSL/TLS certificate chain validates successfully against the system CA bundle. CA certificate bundle is present with trusted root certificates. Node.js TLS certificate validation is enabled (NODE_TLS_REJECT_UNAUTHORIZED is not set to 0). Active TLS connections verify certificate chains correctly.",
     "valid_false_status": "Open",
     "valid_false_comment": "Automated check could not confirm certificate validation."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "PKI certificate path validation issues detected. This may include: self-signed certificates, missing CA bundle, disabled TLS validation (NODE_TLS_REJECT_UNAUTHORIZED=0), or certificate chain validation failures. Remediation: Install a CA-signed certificate, ensure the system CA bundle is present at /etc/ssl/certs/ca-certificates.crt, and verify NODE_TLS_REJECT_UNAUTHORIZED is not set to 0 in the XO server environment.",
     "valid_false_status": "Open",
     "valid_false_comment": "Certificate validation issues require remediation."},
])

ENTRIES["V-222551"] = make_entry("V-222551", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "PKI private keys are properly protected. Key files have restrictive permissions (600 or 400), are owned by root or the appropriate service account, and are not located in web-accessible directories. No private keys are tracked in version control repositories.",
     "valid_false_status": "Open",
     "valid_false_comment": "Private key protection issues detected."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Private key protection violations detected. This may include: permissive file permissions (should be 600 or 400), keys in web-accessible directories, or keys tracked in git repositories. Remediation: Set key file permissions to 600 (chmod 600), ensure root ownership, remove keys from web directories, and add *.key to .gitignore.",
     "valid_false_status": "Open",
     "valid_false_comment": "Private key protection requires remediation."},
    {"index": "3", "expected_status": "Not_Applicable",
     "valid_true_status": "Not_Applicable",
     "valid_true_comment": "No private key files were detected on the system. If PKI is not used by this application, this requirement is not applicable.",
     "valid_false_status": "Not_Applicable",
     "valid_false_comment": "No private keys present."},
])

ENTRIES["V-222554"] = make_entry("V-222554", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "XO web interface properly masks password input. React framework provides automatic input masking for password-type fields. No cleartext password display detected in HTML/JSX source files. Log files do not contain cleartext passwords. API responses do not expose password field values.",
     "valid_false_status": "Open",
     "valid_false_comment": "Password masking could not be confirmed."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Cleartext password display detected. This may include: input fields using type=text instead of type=password, cleartext passwords in log files, or API responses exposing password values. Remediation: Ensure all password input fields use type=password, configure log sanitization to redact passwords, and verify API endpoints do not return password fields.",
     "valid_false_status": "Open",
     "valid_false_comment": "Cleartext password exposure requires remediation."},
])

ENTRIES["V-222577"] = make_entry("V-222577", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "Session IDs are properly protected from exposure. Sessions are transmitted exclusively over HTTPS (port 443). Cookie security flags (HttpOnly, Secure) prevent client-side access and plaintext transmission. No session ID exposure detected in URL parameters or log files. Redis is used for secure server-side session storage.",
     "valid_false_status": "Open",
     "valid_false_comment": "Session ID exposure protection could not be confirmed."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Session ID exposure risks detected. This may include: missing HttpOnly/Secure cookie flags, session IDs in URL parameters, or session references in log files. Remediation: Configure cookie flags (HttpOnly, Secure, SameSite=Strict), ensure HTTPS enforcement, and verify session IDs are not logged or passed in URLs.",
     "valid_false_status": "Open",
     "valid_false_comment": "Session ID protection requires remediation."},
])

ENTRIES["V-222578"] = make_entry("V-222578", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "XO properly destroys session IDs on logoff. The session.signOut API endpoint handles session invalidation. Server-side logout handlers explicitly destroy session data. Redis sessions have finite TTL for automatic cleanup. Cookie settings prevent persistent session storage beyond browser close.",
     "valid_false_status": "Open",
     "valid_false_comment": "Session destruction could not be confirmed."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Session destruction on logoff could not be verified. No explicit session.destroy or signOut handlers were detected in the application source. Remediation: Verify the XO web interface implements server-side session invalidation on logout. Check that Redis sessions have appropriate TTL values. Ensure browser cookies are session-only (no persistent expiration).",
     "valid_false_status": "Open",
     "valid_false_comment": "Session destruction mechanism requires verification."},
])

ENTRIES["V-222596"] = make_entry("V-222596", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "Transmitted information is protected with TLS encryption. HTTPS is active on port 443 with TLS 1.2 or higher. No plaintext protocols (FTP, Telnet, HTTP) are exposed on network interfaces. XO configuration includes certificate and key settings for HTTPS enforcement.",
     "valid_false_status": "Open",
     "valid_false_comment": "Transmission protection could not be confirmed."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Transmitted information protection is insufficient. This may include: HTTPS not active, plaintext protocols exposed, or outdated TLS version. Remediation: Configure XO with a valid TLS certificate (cert and key in config.toml), ensure HTTPS on port 443, disable plaintext protocols, and verify TLS 1.2+ is enforced.",
     "valid_false_status": "Open",
     "valid_false_comment": "Transmission encryption requires configuration."},
])

ENTRIES["V-222601"] = make_entry("V-222601", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "No sensitive information stored in hidden fields. XO uses React SPA architecture which minimizes server-rendered hidden fields. Automated scan of web application source files found no hidden fields containing passwords, tokens, secrets, API keys, SSNs, or credit card data.",
     "valid_false_status": "Open",
     "valid_false_comment": "Hidden field scan could not confirm compliance."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Sensitive information detected in hidden form fields. Remediation: Remove sensitive data from hidden fields. Use server-side session storage (Redis) for sensitive values. If hidden fields are required for CSRF tokens, ensure they use cryptographically random values that cannot be used to extract sensitive information.",
     "valid_false_status": "Open",
     "valid_false_comment": "Hidden field sensitive data requires remediation."},
])

ENTRIES["V-222602"] = make_entry("V-222602", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "XO is protected from XSS vulnerabilities. The application uses the React framework which provides automatic XSS protection through JSX escaping. React escapes all values embedded in JSX before rendering, preventing injection of malicious scripts. No dangerous patterns (dangerouslySetInnerHTML) were detected without proper sanitization.",
     "valid_false_status": "Open",
     "valid_false_comment": "XSS protection could not be confirmed."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "XSS protection mechanisms are insufficient. Remediation: Implement Content-Security-Policy headers, add X-Content-Type-Options: nosniff header, review and sanitize any dangerouslySetInnerHTML usage, and consider adding a sanitization library (DOMPurify) for user-generated content. React provides baseline protection but CSP headers add defense-in-depth.",
     "valid_false_status": "Open",
     "valid_false_comment": "XSS protection requires enhancement."},
])

ENTRIES["V-222604"] = make_entry("V-222604", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "XO is protected from command injection. The application uses safer command execution patterns (spawn/execFile with argument arrays) rather than shell-interpreted exec() calls. Input validation libraries are present. No string concatenation in command execution was detected.",
     "valid_false_status": "Open",
     "valid_false_comment": "Command injection protection could not be confirmed."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Command injection risk detected. The application uses child_process.exec() with potential string concatenation, which could allow command injection. Remediation: Replace exec() calls with spawn() or execFile() using argument arrays. Validate and sanitize all user input before passing to system commands. Implement allowlists for permitted command arguments.",
     "valid_false_status": "Open",
     "valid_false_comment": "Command injection protection requires code review."},
])

ENTRIES["V-222609"] = make_entry("V-222609", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "XO implements input handling validation. The ajv (Another JSON Validator) library provides JSON Schema validation for API inputs. Express.js body-parser middleware enforces Content-Type requirements. Type checking is used throughout the codebase for input validation.",
     "valid_false_status": "Open",
     "valid_false_comment": "Input validation could not be confirmed."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Input validation is insufficient. No dedicated input validation library (ajv, joi, express-validator) was detected. Remediation: Implement JSON Schema validation using ajv for all API endpoints. Add Content-Type enforcement middleware. Validate input types, lengths, and ranges at all system boundaries.",
     "valid_false_status": "Open",
     "valid_false_comment": "Input handling validation requires implementation."},
])

ENTRIES["V-222612"] = make_entry("V-222612", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "XO is not vulnerable to overflow attacks. Node.js is a memory-safe runtime — the V8 JavaScript engine provides automatic garbage collection, bounds checking on ArrayBuffer/TypedArray, and no direct memory pointer access. ASLR is enabled on the operating system (randomize_va_space=2). Modern Node.js version provides latest security patches.",
     "valid_false_status": "Open",
     "valid_false_comment": "Overflow protection could not be confirmed."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Overflow protection is insufficient. This may include outdated Node.js version or ASLR disabled. Remediation: Update Node.js to the latest LTS version. Ensure ASLR is enabled (sysctl kernel.randomize_va_space=2). Replace any Buffer.allocUnsafe() calls with Buffer.alloc(). Run npm audit to check for known memory-related vulnerabilities.",
     "valid_false_status": "Open",
     "valid_false_comment": "Overflow protection requires remediation."},
])

ENTRIES["V-222642"] = make_entry("V-222642", [
    {"index": "1", "expected_status": "NotAFinding",
     "valid_true_status": "NotAFinding",
     "valid_true_comment": "No embedded authentication data detected in XO source code. Credentials are managed through environment variables and configuration files rather than hardcoded in source. No plaintext passwords, API keys, or secrets found in JavaScript source files. No embedded private keys or certificates in application code. Configuration files do not contain plaintext credential values.",
     "valid_false_status": "Open",
     "valid_false_comment": "Embedded credential scan could not confirm compliance."},
    {"index": "2", "expected_status": "Open",
     "valid_true_status": "Open",
     "valid_true_comment": "Embedded authentication data detected in source code or configuration. This may include hardcoded passwords, API keys, secrets, or embedded private keys. Remediation: Move all credentials to environment variables or secure configuration management. Rotate any exposed credentials immediately. Add credential scanning to CI/CD pipeline. Use .gitignore to prevent credential files from being committed.",
     "valid_false_status": "Open",
     "valid_false_comment": "Embedded credentials require removal and rotation."},
])


def main():
    if not os.path.isfile(AF_PATH):
        print(f"ERROR: Answer file not found at {AF_PATH}")
        sys.exit(1)

    with open(AF_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    replaced = 0
    for vuln_id, new_entry in ENTRIES.items():
        # Find the existing stub entry
        # Pattern: <Vuln ID="V-XXXXXX">...</Vuln>
        pattern = f'<Vuln ID="{vuln_id}">'
        start_idx = content.find(pattern)
        if start_idx == -1:
            print(f"WARNING: {vuln_id} not found in answer file")
            continue

        # Find the closing </Vuln> tag
        end_tag = '</Vuln>'
        end_idx = content.find(end_tag, start_idx)
        if end_idx == -1:
            print(f"WARNING: Closing </Vuln> not found for {vuln_id}")
            continue
        end_idx += len(end_tag)

        # Find proper indentation (look for whitespace before the <Vuln tag)
        line_start = content.rfind('\n', 0, start_idx)
        indent = content[line_start+1:start_idx] if line_start != -1 else '  '

        # Replace
        old_block = content[start_idx:end_idx]
        content = content[:start_idx] + new_entry.lstrip() + content[end_idx:]

        replaced += 1
        print(f"  [{replaced}/13] Replaced {vuln_id}")

    # Write updated answer file
    with open(AF_PATH, 'w', encoding='utf-8') as f:
        f.write(content)

    # Validate XML
    try:
        ET.parse(AF_PATH)
        print(f"\nXML Validation: PASSED")
    except ET.ParseError as e:
        print(f"\nXML Validation: FAILED - {e}")

    # Check for duplicates
    tree = ET.parse(AF_PATH)
    root = tree.getroot()
    vuln_ids = [v.get('ID') for v in root.findall('.//Vuln')]
    dupes = [v for v in set(vuln_ids) if vuln_ids.count(v) > 1]
    if dupes:
        print(f"DUPLICATE Vuln IDs: {dupes}")
    else:
        print(f"Duplicate check: 0 duplicates")

    print(f"\nDone: {replaced}/13 entries replaced")
    print(f"Answer file size: {os.path.getsize(AF_PATH):,} bytes")


if __name__ == '__main__':
    main()
