# Web Server SRG - CAT I Vulnerabilities Check Content

Extracted from: `U_Web_Server_SRG_V4R4_Manual-xccdf.xml`

## Overview

This document contains the detailed check content, fix text, and discussion for the three CAT I (Category I / High Severity) vulnerabilities from the Web Server SRG. These are used as reference when writing ValidationCode for automated checks.

---

## V-206390 - Cryptographic Modules Meeting Federal Requirements

**VulnID:** V-206390  
**Rule ID:** SV-206390r961050_rule  
**Severity:** HIGH (CAT I)  
**STIG ID:** SRG-APP-000179-WSR-000110  
**CCI:** CCI-000803

### Title
The web server must use cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when encrypting stored data.

### Discussion
Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified, and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms.

FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The web server must provide FIPS-compliant encryption modules when storing encrypted data and configuration settings.

### Check Content (Procedure for Auditor)
Review web server documentation and deployed configuration to determine whether the encryption modules utilized for storage of data are FIPS 140-2 compliant.

Reference the following NIST site to identify validated encryption modules: 

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

If the encryption modules used for storage of data are not FIPS 140-2 validated, this is a finding.

### Fix Text (Remediation Guidance)
Configure the web server to utilize FIPS 140-2 approved encryption modules when the web server is storing data.

### Validation Notes
- Check if cryptographic modules are FIPS 140-2 validated
- Look for configuration settings that enable/disable FIPS mode
- Verify against NIST CMVP (Cryptographic Module Validation Program) list
- For Xen Orchestra/XCP-ng: Check if Node.js crypto module is in FIPS mode
- May need to check system-level FIPS configuration

---

## V-206399 - Unique Session IDs Using FIPS 140-2 RNG

**VulnID:** V-206399  
**Rule ID:** SV-206399r1043181_rule  
**Severity:** HIGH (CAT I)  
**STIG ID:** SRG-APP-000224-WSR-000135  
**CCI:** CCI-001188

### Title
The web server must generate a unique session identifier for each session using a FIPS 140-2 approved random number generator.

### Discussion
Communication between a client and the web server is done using the HTTP protocol, but HTTP is a stateless protocol. In order to maintain a connection or session, a web server will generate a session identifier (ID) for each client session when the session is initiated. The session ID allows the web server to track a user session and, in many cases, the user, if the user previously logged into a hosted application.

Unique session IDs are the opposite of sequentially generated session IDs, which can be easily guessed by an attacker. Unique session identifiers help to reduce predictability of generated identifiers. Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, the attacker will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

### Check Content (Procedure for Auditor)
Review the web server documentation and deployed configuration to verify that the web server is configured to generate unique session identifiers with a FIPS 140-2 approved random number generator.

Request two users access the web server and view the session identifier generated for each user to verify that the session IDs are not sequential.

If the web server is not configured to generate unique session identifiers or the random number generator is not FIPS 140-2 approved, this is a finding.

### Fix Text (Remediation Guidance)
Configure the web server to generate unique session identifiers using a FIPS 140-2 random number generator.

### Validation Notes
- Check session management configuration
- Verify the random number generator is FIPS 140-2 approved
- Test that session IDs are not sequential or predictable
- For Express.js/Node.js applications: Check session middleware configuration
- Verify crypto library is using FIPS-approved algorithms (e.g., `crypto.randomBytes()` in FIPS mode)
- Look for session configuration in application code or session store configuration

---

## V-279029 - Vendor-Supported Version

**VulnID:** V-279029  
**Rule ID:** SV-279029r1138083_rule  
**Severity:** HIGH (CAT I)  
**STIG ID:** SRG-APP-001035-WSR-000340  
**CCI:** CCI-003376

### Title
The web server must be a version supported by the vendor.

### Discussion
Unsupported software and systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.

Software and systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, software is no longer considered supported and should be upgraded or decommissioned.

### Check Content (Procedure for Auditor)
Verify that the web server is a version supported by the vendor.

If the web server is not a version supported by the vendor, this is a finding.

### Fix Text (Remediation Guidance)
Install or upgrade the webserver to a version supported by the vendor.

### Validation Notes
- Check current version of the web server software
- Verify against vendor's official support lifecycle/End of Life (EOL) documentation
- For Xen Orchestra (XO): Check that it's a currently supported version (v5.x)
- For XCP-ng: Verify it's v8.3 or later if specified in the STIG
- For Node.js runtime: Check against Node.js release schedule (https://nodejs.org/en/about/previous-releases)
- For Express.js: Check against Express support policy
- Consider both the application version AND underlying runtime/platform versions
- Document version found and support status from vendor

---

## Implementation Guidance for ValidationCode

### General Approach
When implementing automated checks for these CAT I vulnerabilities:

1. **V-206390 (FIPS Cryptographic Modules)**
   - Check configuration files for FIPS mode settings
   - Query system-level FIPS status if available
   - Verify loaded cryptographic libraries/modules
   - Return "Open" if FIPS mode is not enabled or cannot be verified

2. **V-206399 (FIPS RNG for Session IDs)**
   - Review session management code/configuration
   - Check if session middleware uses FIPS-approved RNG
   - Verify crypto library is in FIPS mode when generating session IDs
   - Return "Open" if non-FIPS RNG is used or cannot be determined

3. **V-279029 (Vendor-Supported Version)**
   - Determine current version of web server/application
   - Compare against known EOL/support dates
   - Check multiple components: app, runtime (Node.js), web framework
   - Return "Open" if any component is unsupported
   - Consider documenting version information in Comments/FindingDetails

### Return Values
- **NotAFinding**: Check passes, requirement is met
- **Open**: Vulnerability exists, requirement is NOT met
- **Not_Reviewed**: Unable to determine compliance (check is manual)
- **Not_Applicable**: Check does not apply to this system

### Common Patterns
```powershell
# Example structure for validation code
if (Test-ComplianceCondition) {
    $Status = "NotAFinding"
    $FindingDetails += "Configuration meets requirements.`n"
} else {
    $Status = "Open"
    $FindingDetails += "FINDING: Configuration does not meet requirements.`n"
}
```

---

*Document generated on 2026-01-22*  
*Source: Web Server Security Requirements Guide Version 4 Release 4*  
*Benchmark Date: 28 Oct 2025*
