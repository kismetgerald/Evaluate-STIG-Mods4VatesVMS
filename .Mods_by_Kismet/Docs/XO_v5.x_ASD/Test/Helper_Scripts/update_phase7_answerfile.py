#!/usr/bin/env python3
"""
Phase 7 Answer File Update Script
Updates answer file entries for all 33 Phase 7 functions (V-222603–V-222641)
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
    # Escape XML special characters
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
      <!--Session #47 (Feb 2026): Phase 7 implementation-->
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

# Batch 16
ENTRIES["V-222603"] = make_entry("V-222603",
    "The application must protect from Cross-Site Request Forgery (CSRF) vulnerabilities.",
    """Xen Orchestra has been verified to provide CSRF protection through its API architecture.

The automated check confirmed:
(1) XO REST API requires authentication token for all state-changing operations
(2) API uses JSON Content-Type which browsers enforce same-origin policy for
(3) SameSite cookie attribute provides defense-in-depth against CSRF
(4) Unauthenticated requests are rejected with 401 Unauthorized

Finding: Not a Finding

Justification: XO's token-based API authentication and JSON content type validation provide inherent CSRF protection. The REST API architecture is not susceptible to traditional CSRF attacks that target form-based submissions.""",
    """The automated check could not fully verify CSRF protection for Xen Orchestra.

DoD Requirement: Applications must implement anti-CSRF protections including challenge tokens and HTTP referrer validation (APSC-DV-002500).

Remediation Steps:
1. Verify SameSite=Strict or Lax attribute is set on session cookies
2. Implement CSRF token middleware if form-based submissions exist
3. Validate Origin and Referer headers for state-changing requests
4. Configure Content-Type validation to reject non-JSON payloads
5. Document CSRF protection mechanisms in security architecture

Contact ISSO/ISSM to verify CSRF protection is adequate for the deployment.""")

ENTRIES["V-222605"] = make_entry("V-222605",
    "The application must protect from canonical representation vulnerabilities.",
    """XO uses Node.js UTF-8 encoding defaults and Express.js URL normalization.

The automated check confirmed:
(1) HTTP responses include proper Content-Type with charset=utf-8
(2) Node.js enforces consistent UTF-8 encoding for all I/O
(3) Express.js normalizes URLs, decodes percent-encoding, and resolves path traversal

Finding: Not a Finding

Justification: Input is processed in canonical form before authorization decisions. Node.js and Express.js provide built-in canonicalization.""",
    """Canonical representation protection could not be fully verified.

DoD Requirement: Applications must sanitize and normalize all user input before processing to prevent encoding-based bypasses (APSC-DV-002520).

Remediation Steps:
1. Verify application uses consistent UTF-8 encoding throughout
2. Normalize input before authorization checks
3. Validate encoding methods are appropriate for input symbols
4. Conduct code review for encoding bypass vulnerabilities
5. Run vulnerability scans that test for canonicalization issues""")

ENTRIES["V-222606"] = make_entry("V-222606",
    "The application must validate all input.",
    """XO validates input through Express.js body parsing and JSON schema enforcement.

The automated check confirmed:
(1) Express.js body parser with size limits configured
(2) JSON Content-Type enforcement for API submissions
(3) Schema validation libraries detected in application packages

Finding: Not a Finding

Justification: XO uses type-safe JSON parsing with Express.js middleware providing input size limits and content type validation.""",
    """Comprehensive input validation could not be fully verified for Xen Orchestra.

DoD Requirement: Applications must validate all input for syntax, semantics, character sets, lengths, ranges, and acceptable values (APSC-DV-002530).

Remediation Steps:
1. Conduct vulnerability scan with input validation test cases
2. Perform fuzzing tests on all data entry fields
3. Verify input validation libraries are properly integrated
4. Review code for injection vulnerabilities (SQL, command, LDAP)
5. Reference OWASP Input Validation Cheat Sheet for coverage
6. Document validation approach in security architecture

Contact ISSO/ISSM to verify input validation testing has been performed.""")

ENTRIES["V-222610"] = make_entry("V-222610",
    "The application must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.",
    """XO error messages do not disclose sensitive system information to end users.

The automated check confirmed:
(1) No stack traces or internal paths in error responses
(2) No debug flags (--inspect, --debug) detected on Node.js process
(3) Error pages return generic messages without system details

Finding: Not a Finding

Justification: XO generates generic error messages for end users while logging detailed information server-side for administrator troubleshooting.""",
    """Error messages may disclose sensitive information to unauthorized users.

DoD Requirement: Error messages must not reveal variable names, SQL strings, source code, system paths, or PII (APSC-DV-002570).

Remediation Steps:
1. Set NODE_ENV=production in XO server configuration
2. Disable debug flags (--inspect, --debug) on Node.js process
3. Configure custom error pages that display generic messages
4. Verify error responses do not include stack traces
5. Review application logs to confirm detailed errors are logged server-side only

Contact system administrator to configure production error handling.""")

ENTRIES["V-222611"] = make_entry("V-222611",
    "The application must reveal error messages only to the ISSO, ISSM, or SA.",
    """Detailed error information is restricted to server-side log files accessible only to privileged users.

The automated check confirmed:
(1) Admin interface requires authentication (HTTP 401/403 for unauthenticated)
(2) Log files have appropriate access controls (root ownership)
(3) End users receive generic error messages only

Finding: Not a Finding

Justification: XO restricts detailed error logs to server-side files with root:root ownership. Non-privileged users see only generic error messages.""",
    """Error message access control could not be fully verified.

DoD Requirement: Detailed error messages must only be visible to ISSO, ISSM, or SA (APSC-DV-002580).

Remediation Steps:
1. Verify log file permissions restrict access to root/admin users
2. Confirm error pages show generic messages to non-privileged users
3. Configure log file ownership to root:adm or equivalent
4. Test error message content as both privileged and non-privileged users
5. Document error handling architecture""")

ENTRIES["V-222613"] = make_entry("V-222613",
    "The application must remove organization-defined software components after updated versions have been installed.",
    """XO installation does not have multiple versions of software components coexisting.

The automated check confirmed:
(1) Single XO installation detected
(2) Single Node.js version installed
(3) No packages flagged for autoremove

Finding: Not a Finding

Justification: Package management and update procedures remove old versions during upgrades.""",
    """Old software component removal could not be fully verified.

DoD Requirement: Previous versions of software components must be removed after updates to prevent exploitation of known vulnerabilities (APSC-DV-002610).

Remediation Steps:
1. Review change management procedures for component cleanup
2. Run apt autoremove to remove unnecessary packages
3. Verify no duplicate application installations exist
4. Document upgrade procedures that include old version removal
5. Check for orphaned Node.js module versions

Contact system administrator to review upgrade procedures.""")

ENTRIES["V-222614"] = make_entry("V-222614",
    "Security-relevant software updates and patches must be kept up to date.",
    """XO system is current on security patches with automated update mechanisms.

The automated check confirmed:
(1) No pending OS security updates detected
(2) npm audit shows no critical vulnerabilities
(3) Unattended-upgrades package installed for automatic patching

Finding: Not a Finding

Justification: System patching is current and automated security update mechanisms are configured.""",
    """Security patching may not meet DoD requirements.

DoD Requirement: Applications must check for updates weekly and apply patches immediately per IAVMs, CTOs, and DTMs (APSC-DV-002630).

Remediation Steps:
1. Install and configure unattended-upgrades for automatic security patches
2. Schedule weekly checks for application updates (npm audit, apt update)
3. Document patching procedures and responsible personnel
4. Subscribe to vendor security advisories (Vates, Node.js)
5. Maintain patch compliance records for audit trail
6. Apply IAVM/CTO patches within required timeframes

Contact ISSO/ISSM to verify patching cadence meets organizational requirements.""")

ENTRIES["V-222615"] = make_entry("V-222615",
    "The application performing organization-defined security functions must verify correct operation of security functions.",
    """XO performs security function verification through service health monitoring.

The automated check confirmed:
(1) xo-server systemd service is active and monitored
(2) TLS configuration verified at startup
(3) Startup events logged to systemd journal

Finding: Not a Finding""",
    """Security function verification could not be fully confirmed.

DoD Requirement: Applications performing security functions must verify their correct operation (APSC-DV-002760).

Remediation Steps:
1. Document security functions performed by XO (authentication, authorization, auditing)
2. Implement automated health checks for each security function
3. Configure monitoring to detect security function failures
4. Log security function verification results
5. Design built-in testing mechanisms for security controls

Contact ISSO/ISSM to verify security function testing is documented.""")

ENTRIES["V-222616"] = make_entry("V-222616",
    "The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.",
    """XO performs security verification on startup via systemd service management.

The automated check confirmed:
(1) Systemd restart configuration for xo-server service
(2) Service health monitoring through systemd
(3) Startup events logged for audit trail

Finding: Not a Finding""",
    """Periodic security function verification is not fully configured.

DoD Requirement: Security function testing must occur on startup/restart, upon privileged user command, and every 30 days (APSC-DV-002770).

Remediation Steps:
1. Configure automated security function tests on service startup
2. Implement admin-triggered security verification commands
3. Schedule monthly (30-day) security function tests via cron/systemd timer
4. Configure notifications for test failures
5. Document testing schedule and procedures

Contact ISSO/ISSM to verify periodic security testing is scheduled.""")

ENTRIES["V-222617"] = make_entry("V-222617",
    "The application must notify the ISSO and ISSM of failed security verification tests.",
    """Failed security test notifications are configured for security personnel.

The automated check confirmed:
(1) Email/alerting infrastructure available
(2) Systemd failure notifications configured
(3) XO notification plugins available

Finding: Not a Finding""",
    """ISSO/ISSM notification for failed security tests is not configured.

DoD Requirement: Failed security verification tests must generate notifications to ISSO and ISSM (APSC-DV-002780).

Remediation Steps:
1. Configure systemd OnFailure action for xo-server service
2. Set up email notifications to ISSO/ISSM for service failures
3. Configure monitoring alerts (Nagios, Zabbix, etc.) for security events
4. Document notification recipients and delivery mechanisms
5. Test notification delivery to ensure ISSO/ISSM receive alerts

Contact ISSO/ISSM to verify they are configured as notification recipients.""")

ENTRIES["V-222618"] = make_entry("V-222618",
    "Unsigned Category 1A mobile code must not be used in the application in accordance with DoD policy.",
    """XO does not use Category 1A mobile code technologies.

The automated check confirmed:
(1) No Java applet files (.jar, .class) detected
(2) No ActiveX control references found
(3) No Flash (.swf) or Silverlight (.xap) files detected
(4) XO uses React/Vue.js modern web framework

Finding: Not a Finding

Justification: XO is a modern web application using JavaScript frameworks. No legacy Category 1A mobile code (Java applets, ActiveX, Flash, Silverlight) is present.""",
    """Category 1A mobile code was detected or could not be verified as absent.

DoD Requirement: All Category 1A mobile code must be digitally signed (APSC-DV-002870).

Remediation Steps:
1. Remove any Java applets, ActiveX controls, Flash, or Silverlight content
2. Replace legacy mobile code with modern web standards (HTML5, JavaScript)
3. If mobile code is required, ensure it is digitally signed with valid certificate
4. Document mobile code usage and signing certificates

Contact application developer to remove legacy mobile code components.""")

ENTRIES["V-222619"] = make_entry("V-222619",
    "The ISSO must ensure an account management process is implemented.",
    """Account management processes are implemented for XO user accounts.

The automated check confirmed:
(1) XO user accounts enumerated via REST API
(2) System accounts with login shells identified
(3) Account lifecycle procedures documented

Finding: Not a Finding""",
    """Account management process requires organizational verification.

DoD Requirement: Only authorized users may access the application, and inactive/terminated accounts must be promptly removed (APSC-DV-002880).

Remediation Steps:
1. Document account creation, suspension, and termination procedures
2. Implement process to remove departed personnel accounts within 2 days
3. Conduct periodic account reviews (at least quarterly)
4. Maintain records of account lifecycle actions
5. Configure XO to integrate with enterprise directory (LDAP/AD) for centralized management

Contact ISSO/ISSM to verify account management procedures are documented and followed.""")

# Batch 17
ENTRIES["V-222621"] = make_entry("V-222621",
    "Audit trails must be retained for at least 30 months.",
    """Audit trail retention meets the 30-month requirement.

The automated check confirmed:
(1) Logrotate configuration provides log retention
(2) Systemd journal persistence configured
(3) Adequate disk space for log storage

Finding: Not a Finding""",
    """Audit trail retention may not meet the 30-month requirement.

DoD Requirement: Audit trails must be retained for 30 months minimum (12 months active + 18 months cold storage) (APSC-DV-002900).

Remediation Steps:
1. Configure logrotate to retain logs for at least 12 months
2. Implement log archival to offsite/cold storage for 18 additional months
3. Configure systemd journal MaxRetentionSec for appropriate retention
4. Document log retention policy and archival procedures
5. Verify disk space is adequate for retention requirements

Contact ISSO/ISSM to verify audit trail retention meets 30-month requirement.""")

ENTRIES["V-222622"] = make_entry("V-222622",
    "The ISSO must review audit trails periodically.",
    """Audit trail review processes are in place.

The automated check confirmed:
(1) XO audit plugin available for log review
(2) Recent log activity confirmed in systemd journal
(3) Log review infrastructure operational

Finding: Not a Finding""",
    """Audit trail periodic review could not be verified.

DoD Requirement: ISSO must review audit trails periodically based on system documentation or immediately upon security events (APSC-DV-002910).

Remediation Steps:
1. Document audit trail review schedule and responsible personnel
2. Configure automated alerts for security-relevant events
3. Establish procedures for immediate review upon security events
4. Maintain records of audit trail reviews conducted
5. Use XO audit plugin for centralized log review

Contact ISSO/ISSM to verify periodic audit trail review is conducted and documented.""")

ENTRIES["V-222623"] = make_entry("V-222623",
    "The ISSO must report all suspected IA policy violations.",
    """IA policy violation reporting procedures are in place.

The automated check confirmed:
(1) Security event logging active in systemd journal
(2) Authentication and authorization events captured
(3) Incident reporting infrastructure available

Finding: Not a Finding""",
    """IA policy violation reporting procedures could not be verified.

DoD Requirement: ISSO must report all suspected IA policy violations per DoD incident response procedures (APSC-DV-002920).

Remediation Steps:
1. Document incident reporting procedures per DoD requirements
2. Establish communication channels for ISSO to report violations
3. Configure automated alerts for suspicious security events
4. Maintain incident response plan with escalation procedures
5. Train personnel on IA violation identification and reporting

Contact ISSO/ISSM to verify IA violation reporting procedures are documented.""")

ENTRIES["V-222624"] = make_entry("V-222624",
    "Active vulnerability testing must be performed.",
    """Active vulnerability testing is performed on the system.

The automated check confirmed:
(1) npm audit available for application vulnerability scanning
(2) STIG compliance scanning actively running (this scan)
(3) Vulnerability scanning infrastructure in place

Finding: Not a Finding""",
    """Active vulnerability testing may not be performed regularly.

DoD Requirement: ISSO must ensure active vulnerability testing is performed on the application (APSC-DV-002930).

Remediation Steps:
1. Schedule regular vulnerability scans (at least monthly)
2. Run npm audit periodically for application dependency vulnerabilities
3. Conduct STIG compliance scans using Evaluate-STIG framework
4. Document vulnerability scanning schedule and tools used
5. Implement vulnerability remediation tracking process
6. Retain scan results for audit trail

Contact ISSO/ISSM to verify vulnerability testing schedule is documented.""")

ENTRIES["V-222625"] = make_entry("V-222625",
    "Execution flow diagrams and design documents must show deadlock/recursion mitigation.",
    """XO architecture inherently mitigates deadlock through Node.js event-driven model.

The automated check confirmed:
(1) Node.js single-threaded event loop avoids traditional deadlock
(2) Non-blocking I/O model prevents thread contention
(3) Application architecture documentation available

Finding: Not a Finding""",
    """Deadlock and recursion mitigation documentation could not be verified.

DoD Requirement: Design documents must show how deadlock and recursion issues are mitigated (APSC-DV-002950).

Remediation Steps:
1. Create execution flow diagrams for critical web service operations
2. Document Node.js event loop architecture and deadlock mitigation
3. Identify recursion-prone code paths and document safeguards
4. Include timeout mechanisms for long-running operations
5. Review design for potential deadlock conditions in async operations

Contact application developer to produce required design documentation.""")

ENTRIES["V-222626"] = make_entry("V-222626",
    "Config and control files must not be stored in the same directory as user data.",
    """XO stores configuration files separately from user data.

The automated check confirmed:
(1) Configuration: /etc/xo-server/ or /opt/xo/xo-server/config.toml
(2) User data: /var/lib/xo-server/
(3) Application code: /opt/xo/xo-server/dist/
(4) Directories are properly separated

Finding: Not a Finding

Justification: XO follows Linux FHS conventions with configuration, data, and application code in separate directory trees.""",
    """Configuration and user data directory separation could not be verified.

DoD Requirement: Configuration files must not be stored in the same directory as user data (APSC-DV-002960).

Remediation Steps:
1. Verify /etc/xo-server/ contains only configuration files
2. Verify /var/lib/xo-server/ contains only user/application data
3. Move any data files found in configuration directories
4. Set appropriate file permissions for each directory
5. Document directory structure and file organization""")

ENTRIES["V-222627"] = make_entry("V-222627",
    "Third-party products must be configured following available guidance.",
    """XO is configured following applicable security guidance (ASD STIG, Web Server SRG).

The automated check confirmed:
(1) Evaluate-STIG framework applying ASD STIG guidance
(2) Web Server SRG also applied to XO
(3) Vendor documentation available for security configuration

Finding: Not a Finding""",
    """Third-party product configuration guidance verification required.

DoD Requirement: When no DoD STIG or NSA guide exists, third-party products must be configured following available guidance (APSC-DV-002970).

Remediation Steps:
1. Apply ASD STIG and Web Server SRG as applicable security guidance
2. Follow Vates vendor security documentation
3. Document deviations from guidance with risk acceptance
4. Apply CIS benchmarks for Debian 12 and Node.js if available
5. Maintain configuration baseline documentation

Contact ISSO/ISSM to verify available guidance is being followed.""")

ENTRIES["V-222628"] = make_entry("V-222628",
    "New IP addresses, data services, and ports must be submitted to approving authority.",
    """All XO ports and services are documented and approved.

The automated check confirmed:
(1) Active listening ports enumerated
(2) XO services use standard HTTPS (443) and HTTP (80)
(3) Port usage documented

Finding: Not a Finding""",
    """Port and protocol approval could not be verified.

DoD Requirement: New IP addresses, services, and ports must be submitted to the approving authority for organizational firewall/PPSM registration (APSC-DV-002980).

Remediation Steps:
1. Document all ports and protocols used by XO (HTTPS/443, HTTP/80)
2. Submit port usage to organizational approving authority
3. Register services in organizational firewall rules
4. Maintain current list of approved ports and protocols
5. Review and update registrations when services change

Contact ISSO/ISSM to verify port and protocol registration.""")

ENTRIES["V-222629"] = make_entry("V-222629",
    "The application must be registered with the DoD Ports and Protocols Database.",
    """XO services are registered in the DoD PPSM database.

The automated check confirmed:
(1) XO uses standard HTTPS (443) for web interface
(2) Service ports documented

Finding: Not a Finding""",
    """DoD PPSM registration could not be verified.

DoD Requirement: Application must be registered with DoD Ports, Protocols, and Services Management (PPSM) database (APSC-DV-002990).

Remediation Steps:
1. Access DoD PPSM website and register XO application
2. Document HTTPS/443 as primary service port
3. Include any additional ports used by XO plugins
4. Update registration when ports or protocols change
5. Maintain PPSM registration number for audit reference

Contact ISSO/ISSM to verify PPSM registration is current.""")

ENTRIES["V-222630"] = make_entry("V-222630",
    "The CM repository must be properly patched and STIG compliant.",
    """CM repository is properly patched and secured.

The automated check confirmed:
(1) Git version control system installed and current
(2) Repository access controls in place

Finding: Not a Finding""",
    """CM repository security could not be fully verified.

DoD Requirement: CM repository must be properly patched and STIG compliant (APSC-DV-002995).

Remediation Steps:
1. Verify CM repository platform (GitHub, GitLab, etc.) is current version
2. Apply applicable STIG to CM platform if one exists
3. Configure access controls with least privilege
4. Enable audit logging on repository access
5. Document CM repository security configuration

Contact ISSO/ISSM to verify CM repository security posture.""")

# Batch 18
ENTRIES["V-222631"] = make_entry("V-222631",
    "CM repository access privileges must be reviewed every three months.",
    """CM repository access reviews are conducted quarterly.

Finding: Not a Finding""",
    """Quarterly CM repository access review could not be verified.

DoD Requirement: Access privileges to CM repository must be reviewed every three months (APSC-DV-003000).

Remediation Steps:
1. Establish quarterly access review schedule
2. Document review process and responsible personnel
3. Revoke unauthorized access discovered during reviews
4. Maintain records of access reviews conducted
5. Align access with separation of duties requirements

Contact ISSO/ISSM to verify quarterly access reviews are conducted.""")

ENTRIES["V-222632"] = make_entry("V-222632",
    "A Software Configuration Management (SCM) plan must exist.",
    """SCM plan documents configuration control and change management.

Finding: Not a Finding""",
    """SCM plan could not be verified.

DoD Requirement: A documented SCM plan must describe configuration control and change management processes (APSC-DV-003010).

Remediation Steps:
1. Create SCM plan covering configuration identification and baselines
2. Document change control procedures and approval workflow
3. Include configuration status accounting procedures
4. Define configuration audit requirements
5. Obtain organizational approval of SCM plan

Contact ISSO/ISSM to verify SCM plan exists and is current.""")

ENTRIES["V-222633"] = make_entry("V-222633",
    "A Configuration Control Board (CCB) must be established.",
    """CCB is established and meets regularly.

Finding: Not a Finding""",
    """CCB establishment could not be verified.

DoD Requirement: A CCB must meet at least every release cycle to manage the CM process (APSC-DV-003020).

Remediation Steps:
1. Establish CCB with charter or terms of reference
2. Define meeting schedule aligned with release cycles
3. Include appropriate stakeholders in CCB membership
4. Maintain meeting minutes documenting change decisions
5. Review and update CCB charter annually

Contact ISSO/ISSM to verify CCB is established and meeting regularly.""")

ENTRIES["V-222634"] = make_entry("V-222634",
    "Application services and interfaces must be compatible with IPv6 networks.",
    """XO application services are IPv6 compatible.

The automated check confirmed:
(1) Linux kernel IPv6 support enabled
(2) Node.js natively supports IPv6 network operations
(3) XO can listen on IPv6 addresses

Finding: Not a Finding

Justification: Node.js and the Linux networking stack provide native IPv6 support for all XO services.""",
    """IPv6 compatibility could not be fully verified.

DoD Requirement: Application services must be compatible with and ready for IPv6 networks (APSC-DV-003030).

Remediation Steps:
1. Verify XO listen configuration supports IPv6 (:: or specific IPv6 address)
2. Test XO web interface accessibility over IPv6
3. Verify API endpoints respond on IPv6 connections
4. Update firewall rules to allow IPv6 traffic to XO ports
5. Document IPv6 compatibility in system security plan""")

ENTRIES["V-222635"] = make_entry("V-222635",
    "Critical/high-availability applications must not be hosted on general purpose machines.",
    """XO is hosted on a dedicated or purpose-built system.

Finding: Not a Finding""",
    """Hosting model verification required.

DoD Requirement: If XO is designated critical or high availability, it must not run on a general purpose machine (APSC-DV-003040).

Remediation Steps:
1. Verify XO criticality/availability designation with ISSO
2. If critical/HA, ensure dedicated hosting (VM or physical)
3. Remove non-essential services from the host
4. Document hosting model and justify any shared resources
5. Implement resource isolation if shared hosting is required

Contact ISSO/ISSM to verify hosting model meets criticality requirements.""")

ENTRIES["V-222636"] = make_entry("V-222636",
    "A contingency plan must exist in accordance with DoD policy.",
    """Contingency plan exists per DoD policy requirements.

Finding: Not a Finding""",
    """Contingency plan could not be verified.

DoD Requirement: A contingency plan must exist based on application availability requirements per DoD policy and NIST SP 800-34 (APSC-DV-003050).

Remediation Steps:
1. Develop contingency plan addressing RTO and RPO
2. Include backup and restoration procedures
3. Identify alternate processing site if required
4. Schedule annual plan testing and document results
5. Update plan based on system changes and test findings
6. Obtain organizational approval of contingency plan

Contact ISSO/ISSM to verify contingency plan exists and is tested.""")

ENTRIES["V-222637"] = make_entry("V-222637",
    "Recovery procedures must exist for secure and verifiable recovery.",
    """Secure recovery procedures are documented and tested.

Finding: Not a Finding""",
    """Secure recovery procedures could not be verified.

DoD Requirement: Recovery must be performed securely and verifiably with documented circumstances and procedures (APSC-DV-003060).

Remediation Steps:
1. Document recovery procedures for XO system and data
2. Include integrity verification steps for restored data
3. Define post-recovery security validation checklist
4. Test recovery procedures periodically
5. Document circumstances requiring recovery activation

Contact ISSO/ISSM to verify recovery procedures are documented and tested.""")

ENTRIES["V-222638"] = make_entry("V-222638",
    "Data backup must be performed at required intervals.",
    """Data backups are performed at required intervals.

The automated check confirmed:
(1) XO backup infrastructure available
(2) System backup mechanisms detected
(3) Backup scheduling in place

Finding: Not a Finding""",
    """Data backup intervals could not be verified.

DoD Requirement: Data backups must be performed at intervals defined by DoD policy (APSC-DV-003070).

Remediation Steps:
1. Configure XO backup jobs for VM data protection
2. Schedule system configuration backups (daily recommended)
3. Configure database/data directory backups
4. Verify backup completion and integrity regularly
5. Document backup schedule, retention, and verification procedures

Contact ISSO/ISSM to verify backup intervals meet organizational requirements.""")

ENTRIES["V-222639"] = make_entry("V-222639",
    "Backup copies must be stored in a fire-rated container or offsite.",
    """Backup copies are stored in appropriate fire-rated or offsite location.

Finding: Not a Finding""",
    """Backup storage location could not be verified.

DoD Requirement: Backups must be stored in GSA-approved fire-rated container or at separate offsite location (APSC-DV-003080).

Remediation Steps:
1. Store backup media in GSA-approved fire-rated safe, OR
2. Transfer backups to separate offsite storage facility
3. Ensure storage location has appropriate physical security
4. Maintain inventory of backup media and storage locations
5. Document backup storage procedures and locations

Contact ISSO/ISSM to verify backup storage meets physical security requirements.""")

ENTRIES["V-222640"] = make_entry("V-222640",
    "Procedures must assure appropriate protection of backup and restoration.",
    """Backup protection procedures are documented and followed.

Finding: Not a Finding""",
    """Backup protection procedures could not be verified.

DoD Requirement: Physical and technical protection procedures must exist for backup and restoration operations (APSC-DV-003090).

Remediation Steps:
1. Document physical security measures for backup media
2. Implement encryption for backup data at rest and in transit
3. Configure access controls on backup systems and media
4. Include integrity verification in restoration procedures
5. Test restoration procedures periodically and document results

Contact ISSO/ISSM to verify backup protection procedures are documented.""")

ENTRIES["V-222641"] = make_entry("V-222641",
    "The application must use encryption for key exchange and endpoint authentication.",
    """XO uses TLS with strong key exchange algorithms for all connections.

The automated check confirmed:
(1) TLS key exchange uses ECDHE or X25519 algorithms
(2) Server endpoint authenticated via TLS certificate
(3) SSH key exchange uses approved algorithms

Finding: Not a Finding

Justification: All key exchange operations use FIPS-approved or industry-standard cryptographic algorithms with authenticated endpoints.""",
    """Key exchange encryption could not be fully verified.

DoD Requirement: Application must use encryption for key exchange and authenticate endpoints before establishing communication channels (APSC-DV-003100).

Remediation Steps:
1. Verify TLS key exchange uses ECDHE or X25519 algorithms
2. Configure server certificate for endpoint authentication
3. Disable weak key exchange algorithms (DHE-1024, RSA key transport)
4. Configure SSH to use approved KexAlgorithms
5. Implement mutual TLS if client authentication is required

Contact system administrator to verify key exchange configuration.""")


def main():
    if not os.path.isfile(AF_PATH):
        print(f"ERROR: Answer file not found at {AF_PATH}")
        sys.exit(1)

    with open(AF_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    replaced = 0
    for vulnid, entry in ENTRIES.items():
        # Find existing stub entry
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
