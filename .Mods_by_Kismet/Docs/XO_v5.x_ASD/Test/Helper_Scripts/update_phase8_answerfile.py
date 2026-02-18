#!/usr/bin/env python3
"""
Phase 8 Answer File Update Script
Updates answer file entries for all 28 Phase 8 functions (V-222644-V-222673 + V-265634)
"""

import re
import os
import sys

AF_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "..", "..",
    "Evaluate-STIG", "AnswerFiles", "XO_v5.x_ASD_AnswerFile.xml"
)
AF_PATH = os.path.normpath(AF_PATH)


def make_entry(vulnid, title, nf_comment, open_comment, na_comment=None):
    """Create a properly structured answer file entry."""
    for var_name in ['nf_comment', 'open_comment']:
        val = locals()[var_name]
        val = val.replace('&', '&amp;')
        val = val.replace('<', '&lt;')
        val = val.replace('>', '&gt;')
        if var_name == 'nf_comment':
            nf_comment = val
        else:
            open_comment = val

    title_esc = title.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    entry = f'''  <Vuln ID="{vulnid}">
    <!--RuleTitle: {title_esc}-->
    <AnswerKey Name="XO">
      <!--Session #48 (Feb 2026): Phase 8 implementation-->
      <Answer Index="1" ExpectedStatus="NotAFinding" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>NotAFinding</ValidTrueStatus>
        <ValidTrueComment>{nf_comment}
        </ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>Manual verification required if status cannot be confirmed.</ValidFalseComment>
      </Answer>
      <Answer Index="2" ExpectedStatus="Open" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Open</ValidTrueStatus>
        <ValidTrueComment>{open_comment}
        </ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>Manual verification required.</ValidFalseComment>
      </Answer>'''

    if na_comment:
        na_esc = na_comment.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        entry += f'''
      <Answer Index="3" ExpectedStatus="Not_Applicable" Hostname="" Instance="" Database="" Site="" ResultHash="">
        <ValidationCode></ValidationCode>
        <ValidTrueStatus>Not_Applicable</ValidTrueStatus>
        <ValidTrueComment>{na_esc}
        </ValidTrueComment>
        <ValidFalseStatus>NR</ValidFalseStatus>
        <ValidFalseComment>Manual verification required.</ValidFalseComment>
      </Answer>'''

    entry += '''
    </AnswerKey>
  </Vuln>'''
    return entry


ENTRIES = {}

# ============================================================================
# BATCH 19: Security Design, Threat Modeling, Architecture Review (14 functions)
# ============================================================================

ENTRIES["V-222644"] = make_entry("V-222644",
    "Prior to each release of the application, updates to system, or applying patches; tests plans and procedures must be created and executed.",
    """Test plans and procedures are maintained by the application vendor (Vates SAS).

Checks Performed:
(1) Deployment type assessment (operational vs development)
(2) Development environment indicators

Finding: Not a Finding

Justification: This organization operates XO as a third-party application. Test plan creation and execution is a vendor responsibility.""",
    """Test plan and procedure documentation could not be verified.

DoD Requirement: Prior to each release, tests plans and procedures must be created and executed (APSC-DV-003150).

Remediation Steps:
1. Contact Vates SAS for release test documentation
2. Maintain local test procedures for configuration changes
3. Document test results prior to deploying updates
4. Include security testing in change management process""",
    na_comment="""Not Applicable. This is an operational deployment of Xen Orchestra. The organization does not perform application development. Test plan requirements apply to the vendor (Vates SAS).""")

ENTRIES["V-222645"] = make_entry("V-222645",
    "Application files must be cryptographically hashed prior to deploying to DoD operational networks.",
    """Application file integrity verification is in place.

Checks Performed:
(1) System package integrity via dpkg --verify
(2) XO application file SHA-256 hashes
(3) Secure package repository (apt sources)
(4) Repository GPG key verification

Finding: Not a Finding

Justification: System packages verified intact, application file hashes available for baseline comparison, and packages sourced from GPG-signed repositories.""",
    """Application file hash validation requires organizational documentation.

DoD Requirement: Application files must be cryptographically hashed prior to deploying to DoD operational networks (APSC-DV-003160).

Remediation Steps:
1. Generate SHA-256 hashes of all XO application files before deployment
2. Store hash values in a secure, tamper-evident location
3. Verify hashes after deployment to confirm integrity
4. Include hash verification in change management procedures
5. Use dpkg --verify regularly to check system package integrity""")

ENTRIES["V-222646"] = make_entry("V-222646",
    "At least one tester must be designated to test for security flaws in addition to functional testing.",
    """Security testing is performed by the vendor development team.

Finding: Not a Finding

Justification: This organization operates XO as a third-party application. Security tester designation is a vendor responsibility.""",
    """Security tester designation could not be verified.

Remediation Steps:
1. Contact Vates SAS for security testing documentation
2. Designate local personnel for security validation testing
3. Document security testing roles and responsibilities""",
    na_comment="""Not Applicable. The organization operating XO is not doing development work for the application. Security tester designation requirements apply to the vendor (Vates SAS).""")

ENTRIES["V-222647"] = make_entry("V-222647",
    "Test procedures must be created and at least annually executed to ensure system initialization, shutdown, and aborts are configured to verify the system remains in a secure state.",
    """System state testing procedures are documented and executed.

Checks Performed:
(1) Systemd service configuration (restart behavior)
(2) Process recovery behavior verification

Finding: Not a Finding

Justification: XO service configured for automatic recovery with systemd. Testing procedures verify secure state on initialization, shutdown, and abort.""",
    """System state testing procedures require organizational documentation.

DoD Requirement: Test procedures must be created and at least annually executed to verify secure state on initialization, shutdown, and aborts (APSC-DV-003180).

Remediation Steps:
1. Create test procedures for XO service startup/shutdown
2. Document expected secure state for each scenario
3. Execute test procedures at least annually
4. Record test results and remediate any findings
5. Include abort/crash recovery scenarios in testing""")

ENTRIES["V-222648"] = make_entry("V-222648",
    "An application code review must be performed on the application.",
    """Code review is performed by the vendor development team.

Finding: Not a Finding

Justification: This organization operates XO as a third-party application. Code review is a vendor responsibility.""",
    """Code review documentation could not be verified.

Remediation Steps:
1. Contact Vates SAS for code review documentation
2. Request evidence of security-focused code reviews
3. Review Vates GitHub for code review practices""",
    na_comment="""Not Applicable. This requirement is meant to apply to developers or organizations doing the application development work. The organization does not perform development or manage the development process for Xen Orchestra.""")

ENTRIES["V-222649"] = make_entry("V-222649",
    "Code coverage statistics must be maintained for each release of the application.",
    """Code coverage is tracked by the vendor development team.

Finding: Not a Finding

Justification: Code coverage tracking is a vendor responsibility (Vates SAS).""",
    """Code coverage statistics could not be verified.

Remediation Steps:
1. Contact Vates SAS for code coverage reports
2. Request coverage statistics for each release""",
    na_comment="""Not Applicable. The organization does not do or manage the application development work for Xen Orchestra. Code coverage tracking is a vendor responsibility (Vates SAS).""")

ENTRIES["V-222650"] = make_entry("V-222650",
    "Flaws found during a code review must be tracked in a defect tracking system.",
    """Defect tracking is managed by the vendor.

Finding: Not a Finding

Justification: Vates SAS uses GitHub Issues for defect tracking: https://github.com/vatesfr/xen-orchestra/issues""",
    """Defect tracking system documentation could not be verified.

Remediation Steps:
1. Verify Vates SAS defect tracking at GitHub
2. Monitor published security advisories
3. Track local configuration issues separately""",
    na_comment="""Not Applicable. Application development is not being done or managed by the organization. Vates SAS manages defect tracking via GitHub Issues.""")

ENTRIES["V-222651"] = make_entry("V-222651",
    "The changes to the application must be assessed for IA and accreditation impact prior to implementation.",
    """IA impact assessment is performed through the organizational CCB process.

Checks Performed:
(1) Change management process verification
(2) System version information

Finding: Not a Finding

Justification: Changes to XO are assessed for IA impact through the organizational change control board (CCB) process prior to implementation.""",
    """IA impact assessment process requires organizational verification.

DoD Requirement: Changes to the application must be assessed for IA and accreditation impact prior to implementation (APSC-DV-003220).

Remediation Steps:
1. Establish CCB process for XO configuration changes
2. Assess IA impact before applying patches or updates
3. Document impact assessment results
4. Obtain ISSO/ISSM approval before implementing changes
5. Update System Security Plan when changes affect security posture""")

ENTRIES["V-222652"] = make_entry("V-222652",
    "Security flaws must be fixed or addressed in the project plan.",
    """Security flaw tracking is managed by the vendor.

Finding: Not a Finding

Justification: Vates SAS manages security flaw tracking in their development project plan.""",
    """Security flaw project planning could not be verified.

Remediation Steps:
1. Monitor Vates SAS security advisories
2. Track known vulnerabilities in POA&M
3. Apply vendor patches when available""",
    na_comment="""Not Applicable. The organization is not performing or managing the development work. Security flaw project planning is a vendor responsibility (Vates SAS).""")

ENTRIES["V-222653"] = make_entry("V-222653",
    "The application development team must follow a set of coding standards.",
    """Coding standards are maintained by the vendor development team.

Finding: Not a Finding

Justification: Vates SAS maintains coding standards for the XO codebase.""",
    """Coding standards documentation could not be verified.

Remediation Steps:
1. Contact Vates SAS for coding standards documentation
2. Review Vates contribution guidelines on GitHub""",
    na_comment="""Not Applicable. The organization is not doing the development or managing the development work. Coding standards are a vendor responsibility (Vates SAS).""")

ENTRIES["V-222654"] = make_entry("V-222654",
    "The designer must create and update the Design Document for each release of the application.",
    """Design documentation is maintained by the vendor.

Finding: Not a Finding

Justification: Vates SAS maintains design documentation for XO releases.""",
    """Design document could not be verified.

Remediation Steps:
1. Contact Vates SAS for design documentation
2. Review architecture documentation on vendor website""",
    na_comment="""Not Applicable. The organization is not doing the development or managing the development work. Design documentation is a vendor responsibility (Vates SAS).""")

ENTRIES["V-222655"] = make_entry("V-222655",
    "Threat models must be documented and reviewed for each application release and updated as required by design and functionality changes or when new threats are discovered.",
    """Threat modeling is managed by the vendor development team.

Finding: Not a Finding

Justification: Vates SAS maintains threat models for XO as part of their development process.""",
    """Threat model documentation could not be verified.

Remediation Steps:
1. Contact Vates SAS for threat model documentation
2. Develop organizational threat model for XO deployment
3. Review threat model with each XO update""",
    na_comment="""Not Applicable. The organization is not doing the development or managing the development work. Threat model documentation is a vendor responsibility (Vates SAS).""")

ENTRIES["V-222656"] = make_entry("V-222656",
    "The application must not be subject to error handling vulnerabilities.",
    """Error handling has been verified and no vulnerabilities detected.

Checks Performed:
(1) Production mode configuration (NODE_ENV)
(2) Error handler middleware detection
(3) Stack trace exposure testing
(4) Known error handling vulnerabilities (npm audit)

Finding: Not a Finding

Justification: No stack traces in error responses, production mode configured, and no known error handling vulnerabilities detected.""",
    """Potential error handling vulnerabilities detected.

DoD Requirement: The application must not be subject to error handling vulnerabilities (APSC-DV-003245).

Remediation Steps:
1. Set NODE_ENV=production in systemd service configuration
2. Implement custom error handler middleware
3. Ensure stack traces are not exposed in responses
4. Run npm audit and remediate known vulnerabilities
5. Test error responses for information disclosure""")

ENTRIES["V-222657"] = make_entry("V-222657",
    "The application development team must provide an application incident response plan.",
    """Incident response is handled through Vates SAS vendor channels.

Finding: Not a Finding

Justification: Vates SAS publishes security advisories and patches through their GitHub repository.""",
    """Incident response plan could not be verified.

Remediation Steps:
1. Contact Vates SAS for incident response procedures
2. Develop local incident response plan for XO deployment
3. Document vulnerability reporting and patch procedures""",
    na_comment="""Not Applicable. XO is a third-party application and the development team is not directly accessible for interview. Incident response plan requirements apply to the vendor (Vates SAS).""")

# ============================================================================
# BATCH 20: Code Review, Security Testing, Penetration Testing (5 functions)
# ============================================================================

ENTRIES["V-222660"] = make_entry("V-222660",
    "Procedures must be in place to notify users when an application is decommissioned.",
    """Decommission notification procedures are established.

Checks Performed:
(1) Decommission procedure documentation
(2) Current user base enumeration

Finding: Not a Finding

Justification: Organizational procedures include user notification requirements for application decommissioning.""",
    """Decommission notification procedures require organizational documentation.

DoD Requirement: Procedures must be in place to notify users when an application is decommissioned (APSC-DV-003280).

Remediation Steps:
1. Create decommission notification procedure for XO
2. Maintain current user contact list
3. Define notification timeline (advance notice requirements)
4. Include data migration/archival procedures
5. Document decommission in change management process""")

ENTRIES["V-222661"] = make_entry("V-222661",
    "Unnecessary built-in application accounts must be disabled.",
    """Built-in account management has been verified.

Checks Performed:
(1) XO application accounts via REST API
(2) System accounts with login shell access
(3) Default/vendor account detection

Finding: Not a Finding

Justification: No unnecessary built-in accounts detected. XO accounts are individually created; no default vendor accounts present. System accounts are properly restricted.""",
    """Built-in or default accounts may need attention.

DoD Requirement: Unnecessary built-in application accounts must be disabled (APSC-DV-003290).

Remediation Steps:
1. Review all XO user accounts and disable unused ones
2. Check for default vendor accounts (admin, guest, test, demo)
3. Ensure system accounts have /usr/sbin/nologin shell
4. Configure strong authentication for all required accounts
5. Document account justification for each active account""")

ENTRIES["V-222663"] = make_entry("V-222663",
    "An Application Configuration Guide must be created and included with the application.",
    """Application Configuration Guide exists for this deployment.

Checks Performed:
(1) Vendor documentation availability
(2) Local configuration files
(3) Organization-specific configuration guide

Finding: Not a Finding

Justification: Vates provides comprehensive documentation. Organization has created deployment-specific configuration guide.""",
    """Application Configuration Guide requires organizational creation.

DoD Requirement: An Application Configuration Guide must be created documenting security settings, access controls, network architecture, and hardening steps (APSC-DV-003310).

Remediation Steps:
1. Create organization-specific Application Configuration Guide
2. Document all security configuration settings
3. Include access control lists and role definitions
4. Document network architecture and firewall rules
5. Include hardening steps specific to DoD requirements
6. Update guide with each configuration change""")

ENTRIES["V-222664"] = make_entry("V-222664",
    "If the application contains classified data, a Security Classification Guide must exist containing data elements and their classification.",
    """Classified data assessment completed.

Finding: Not a Finding

Justification: XO does not directly process classified information. It manages VM lifecycle operations.""",
    """Classification guide may be required for this deployment.

Remediation Steps:
1. Assess whether XO processes classified data
2. If classified data is processed, create a Security Classification Guide
3. Document all data elements and their classification levels""",
    na_comment="""Not Applicable. XO does not directly process classified information. It manages virtual machine lifecycle operations (create, delete, backup, migrate). Classified data resides within the VMs, not within the XO application itself.""")

ENTRIES["V-222665"] = make_entry("V-222665",
    "The designer must ensure uncategorized or emerging mobile code is not used in applications.",
    """Mobile code verification completed.

Checks Performed:
(1) Legacy mobile code technologies (Java, Flash, ActiveX, Silverlight)
(2) Modern web framework verification (Node.js, React/Vue.js)

Finding: Not a Finding

Justification: No legacy or uncategorized mobile code detected. XO uses modern web technologies (Node.js backend, React/Vue.js frontend).""",
    """Uncategorized or emerging mobile code detected.

DoD Requirement: Uncategorized or emerging mobile code must not be used without a waiver (APSC-DV-003330).

Remediation Steps:
1. Remove legacy mobile code (Java applets, Flash, ActiveX, Silverlight)
2. If uncategorized mobile code is required, obtain waiver
3. Document risk acceptance for any emerging mobile code types
4. Use modern web standards (HTML5, JavaScript) instead""")

# ============================================================================
# BATCH 21: Supply Chain, Third-Party, SBOM, Patch Management (9 functions)
# ============================================================================

ENTRIES["V-222666"] = make_entry("V-222666",
    "Production database exports must have database administration credentials and sensitive data removed before releasing the export.",
    """Database export procedures are properly controlled.

Checks Performed:
(1) Database technology identification (LevelDB, Redis)
(2) Export mechanism assessment
(3) Credential storage review

Finding: Not a Finding

Justification: Database export procedures include credential removal and sensitive data sanitization.""",
    """Database export sanitization procedures require verification.

DoD Requirement: Production database exports must have credentials and sensitive data removed before release (APSC-DV-003340).

Remediation Steps:
1. Document database export procedures for XO (LevelDB, Redis)
2. Implement credential scrubbing for any data exports
3. Remove bcrypt password hashes from export data
4. Sanitize API tokens and session data
5. Verify sanitization before releasing any exports""")

ENTRIES["V-222667"] = make_entry("V-222667",
    "Protections against DoS attacks must be implemented.",
    """DoS protections are implemented.

Checks Performed:
(1) Firewall status (UFW/iptables)
(2) Connection limits (kernel parameters)
(3) Intrusion prevention (Fail2ban)

Finding: Not a Finding

Justification: Firewall, connection limits, and intrusion prevention mechanisms are configured to mitigate DoS attacks.""",
    """DoS protection requires organizational verification.

DoD Requirement: Protections against DoS attacks must be implemented based on threat model (APSC-DV-002950).

Remediation Steps:
1. Document DoS threats in the threat model
2. Enable and configure UFW or iptables firewall
3. Configure connection rate limiting
4. Install and configure Fail2ban for brute force protection
5. Set appropriate kernel parameters for connection limits
6. Consider reverse proxy with rate limiting for web interface""")

ENTRIES["V-222668"] = make_entry("V-222668",
    "The system must alert an administrator when low resource conditions are encountered.",
    """Low resource alerting is configured.

Checks Performed:
(1) Disk space monitoring
(2) Monitoring agent detection
(3) Log rotation configuration
(4) Journal storage limits

Finding: Not a Finding

Justification: Resource monitoring and alerting mechanisms are in place for disk space, memory, and log storage.""",
    """Low resource alerting requires organizational implementation.

DoD Requirement: The system must alert administrators when low resource conditions are encountered (APSC-DV-002960).

Remediation Steps:
1. Install monitoring agent (Nagios, Zabbix, Prometheus, etc.)
2. Configure disk space threshold alerts (warn at 80%, critical at 90%)
3. Configure memory utilization alerts
4. Set up log rotation to prevent disk exhaustion
5. Configure journal storage limits in /etc/systemd/journald.conf
6. Test alerting mechanisms to verify administrator notification""")

ENTRIES["V-222669"] = make_entry("V-222669",
    "At least one application administrator must be registered to receive update notifications, or security alerts, when automated alerts are available.",
    """Administrators are registered for update notifications.

Checks Performed:
(1) Component version inventory
(2) Available notification channels
(3) Automated update mechanisms

Finding: Not a Finding

Justification: Administrators are registered to receive security notifications from Vates, Node.js, and Debian security channels.""",
    """Administrator registration for update notifications requires verification.

DoD Requirement: At least one administrator must be registered to receive update notifications and security alerts (APSC-DV-003350).

Remediation Steps:
1. Register administrator(s) for Vates/XO security advisories
2. Subscribe to Node.js vulnerability notifications
3. Subscribe to Debian security announcements (DSA)
4. Configure unattended-upgrades for automatic security patches
5. Document notification registrations and responsible personnel""")

ENTRIES["V-222670"] = make_entry("V-222670",
    "The application must provide notifications or alerts when product update and security related patches are available.",
    """Update notification mechanism is established.

Checks Performed:
(1) XO built-in update notification capability
(2) Deployment type (XOA vs XOCE)
(3) Pending security updates

Finding: Not a Finding

Justification: Update notification mechanisms are in place for the XO deployment and OS components.""",
    """Update notification mechanism requires organizational verification.

DoD Requirement: The application must provide notifications when security patches are available (APSC-DV-003360).

Remediation Steps:
1. For XOA: Verify dashboard update notifications are enabled
2. For XOCE: Subscribe to GitHub release notifications
3. Configure apt to notify of available security updates
4. Implement automated patch notification process
5. Document update distribution and notification procedures""")

ENTRIES["V-222671"] = make_entry("V-222671",
    "Connections between the DoD enclave and the Internet or other public or commercial wide area networks must require a DMZ.",
    """Network architecture verified.

Checks Performed:
(1) Network interface configuration
(2) Listening service ports
(3) Public accessibility assessment

Finding: Not a Finding

Justification: XO is deployed on an internal/private network and is not publicly accessible. DMZ requirement is met by network architecture.""",
    """DMZ configuration requires verification.

DoD Requirement: Connections between DoD enclave and public networks must require a DMZ (APSC-DV-002880).

Remediation Steps:
1. Verify XO is not directly accessible from public networks
2. Ensure management traffic is segmented from production
3. Configure firewall rules to restrict access to management VLAN
4. If public access is required, deploy reverse proxy in DMZ
5. Document network topology in System Security Plan""")

ENTRIES["V-222672"] = make_entry("V-222672",
    "The application must generate audit records when concurrent logons from different workstations occur.",
    """Concurrent logon auditing is configured.

Checks Performed:
(1) XO audit plugin status
(2) System authentication logging
(3) Concurrent session detection capability

Finding: Not a Finding

Justification: XO audit plugin is active and records session events (signIn/signOut) with user ID and timestamp, enabling concurrent logon detection through log analysis.""",
    """Concurrent logon auditing requires configuration.

DoD Requirement: The application must generate audit records when concurrent logons from different workstations occur (APSC-DV-002590).

Remediation Steps:
1. Enable the XO audit plugin in administration settings
2. Verify audit records include signIn/signOut events
3. Configure log analysis to detect concurrent sessions
4. Set up alerts for concurrent logon events
5. Review audit logs regularly for concurrent access patterns""")

ENTRIES["V-222673"] = make_entry("V-222673",
    "The Program Manager must verify all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.",
    """Annual security training is provided by the vendor.

Finding: Not a Finding

Justification: Vates SAS provides security training for their development team.""",
    """Annual security training documentation could not be verified.

Remediation Steps:
1. Contact Vates SAS for security training evidence
2. Verify local administrators receive annual security training
3. Document training completion records""",
    na_comment="""Not Applicable. This requirement is meant to be applied to developers and development teams only. The organization does not maintain a development team for Xen Orchestra. Annual security training for operational staff is tracked separately.""")

ENTRIES["V-265634"] = make_entry("V-265634",
    "The application must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.",
    """NSA-approved cryptography assessment completed.

Checks Performed:
(1) Classified data processing assessment
(2) FIPS cryptographic mode status
(3) TLS encryption configuration
(4) OpenSSL version

Finding: Not a Finding

Justification: Appropriate cryptographic controls are in place for the data classification level.""",
    """Cryptographic controls require verification for classified data.

DoD Requirement: NSA-approved cryptography must be used to protect classified information (APSC-DV-002200).

Remediation Steps:
1. Enable FIPS mode if processing classified data
2. Configure TLS 1.2+ with FIPS-approved cipher suites
3. Use NSA Suite B cryptographic algorithms
4. Verify OpenSSL FIPS module is active
5. Document cryptographic controls in System Security Plan""",
    na_comment="""Not Applicable. XO does not directly process classified information. It manages virtual machine lifecycle operations. NSA-approved cryptography requirements apply to systems that store/process classified data.""")


def main():
    if not os.path.isfile(AF_PATH):
        print(f"ERROR: Answer file not found at {AF_PATH}")
        sys.exit(1)

    with open(AF_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    replaced = 0
    for vulnid, entry in ENTRIES.items():
        pattern = re.compile(
            rf'  <Vuln ID="{vulnid}">.*?</Vuln>',
            re.DOTALL
        )
        match = pattern.search(content)
        if match:
            content = content[:match.start()] + entry + content[match.end():]
            replaced += 1
            print(f"  Replaced: {vulnid}")
        else:
            print(f"  WARNING: No entry found for {vulnid}")

    with open(AF_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    # Validate XML
    try:
        import xml.etree.ElementTree as ET
        ET.parse(AF_PATH)
        print(f"\nXML Validation: PASSED")
    except Exception as e:
        print(f"\nXML Validation: FAILED - {e}")

    print(f"Total replaced: {replaced}/{len(ENTRIES)}")
    print(f"Answer file: {AF_PATH}")


if __name__ == "__main__":
    main()
