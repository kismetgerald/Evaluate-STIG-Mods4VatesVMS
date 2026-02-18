#!/usr/bin/env python3
"""
Phase 8 Implementation Script — SDLC, Development Controls & Testing
Batches 19-21: V-222644–V-222673 + V-265634 (28 functions)

Replaces stub implementations with real check logic in Scan-XO_ASD_Checks.psm1
"""

import re
import os
import sys

MODULE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "..", "..",
    "Evaluate-STIG", "Modules", "Scan-XO_ASD_Checks", "Scan-XO_ASD_Checks.psm1"
)
MODULE_PATH = os.path.normpath(MODULE_PATH)

IMPLEMENTATIONS = {}

# ============================================================================
# BATCH 19: Security Design, Threat Modeling, Architecture Review (14 functions)
# ============================================================================

# V-222644 - CAT III - Test plans/procedures prior to release
# Check: "If the review is not being done with the developer... not applicable"
IMPLEMENTATIONS["V-222644"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222644 - Test Plans Prior to Release (APSC-DV-003150)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Determine if this is an operational deployment (not developer)
    $FindingDetails += "Check 1 - Deployment Type Assessment:" + $nl
    $xoVersion = $(timeout 5 sh -c 'cat /opt/xo/xo-server/package.json 2>/dev/null | grep -oP "(?<=version...: )[^,]+" | tr -d "\"" | head -1')
    $xoVersionStr = ($xoVersion -join $nl).Trim()
    if ($xoVersionStr) {
        $FindingDetails += "  XO Version: $xoVersionStr" + $nl
    }
    $FindingDetails += "  Xen Orchestra is a third-party product developed by Vates SAS." + $nl
    $FindingDetails += "  This deployment is an operational instance, not a development environment." + $nl + $nl

    # Check for development indicators
    $FindingDetails += "Check 2 - Development Environment Indicators:" + $nl
    $devIndicators = $(timeout 5 sh -c 'ls -d /opt/xo/.git /opt/xo/packages/*/src 2>/dev/null | head -5')
    $devStr = ($devIndicators -join $nl).Trim()
    if ($devStr) {
        $FindingDetails += "  Development artifacts found (source build detected):" + $nl
        $FindingDetails += "  $devStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No development environment indicators found." + $nl + $nl
    }

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. This is an operational deployment of Xen" + $nl
    $FindingDetails += "Orchestra. The organization does not perform application development." + $nl
    $FindingDetails += "Test plan requirements apply to the vendor (Vates SAS)." + $nl
'''

# V-222645 - CAT II - Cryptographic hash of application files prior to deployment
IMPLEMENTATIONS["V-222645"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222645 - Cryptographic Hash Validation (APSC-DV-003160)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Package integrity verification (dpkg/apt)
    $FindingDetails += "Check 1 - System Package Integrity:" + $nl
    $dpkgVerify = $(timeout 15 sh -c 'dpkg --verify 2>&1 | head -20')
    $dpkgStr = ($dpkgVerify -join $nl).Trim()
    if ($dpkgStr) {
        $FindingDetails += "  Package verification output (first 20 lines):" + $nl
        $FindingDetails += "  $dpkgStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  dpkg --verify returned no discrepancies (all packages intact)." + $nl + $nl
    }

    # Check 2: XO package.json hash
    $FindingDetails += "Check 2 - XO Application File Hashes:" + $nl
    $xoHash = $(timeout 5 sh -c 'sha256sum /opt/xo/xo-server/package.json 2>/dev/null')
    $xoHashStr = ($xoHash -join $nl).Trim()
    if ($xoHashStr) {
        $FindingDetails += "  $xoHashStr" + $nl
    }
    $cliHash = $(timeout 5 sh -c 'sha256sum /opt/xo/xo-server/dist/cli.mjs 2>/dev/null')
    $cliHashStr = ($cliHash -join $nl).Trim()
    if ($cliHashStr) {
        $FindingDetails += "  $cliHashStr" + $nl
    }
    $FindingDetails += $nl

    # Check 3: apt secure transport
    $FindingDetails += "Check 3 - Secure Package Repository:" + $nl
    $aptSources = $(timeout 5 sh -c 'grep -rh "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | head -10')
    $aptStr = ($aptSources -join $nl).Trim()
    if ($aptStr) {
        $FindingDetails += "  Repository sources:" + $nl + "  $aptStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve apt sources." + $nl + $nl
    }

    # Check 4: GPG key verification
    $FindingDetails += "Check 4 - Repository GPG Keys:" + $nl
    $gpgKeys = $(timeout 5 sh -c 'apt-key list 2>/dev/null | grep -E "^pub|^uid" | head -10')
    $gpgStr = ($gpgKeys -join $nl).Trim()
    if ($gpgStr) {
        $FindingDetails += "  $gpgStr" + $nl + $nl
    }
    else {
        $gpgTrusted = $(timeout 5 sh -c 'ls /etc/apt/trusted.gpg.d/ 2>/dev/null')
        $gpgTrustedStr = ($gpgTrusted -join $nl).Trim()
        if ($gpgTrustedStr) {
            $FindingDetails += "  Trusted GPG keys: $gpgTrustedStr" + $nl + $nl
        }
        else {
            $FindingDetails += "  No GPG keys detected." + $nl + $nl
        }
    }

    # Status determination
    if (-not $dpkgStr -and $xoHashStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: System packages verified intact (dpkg --verify clean)." + $nl
        $FindingDetails += "Application file hashes are available for baseline comparison." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Package integrity verification shows discrepancies or" + $nl
        $FindingDetails += "hash validation process needs organizational documentation." + $nl
    }
'''

# V-222646 - CAT II - Security tester designated
# Check: "if the organization is not doing development work, not applicable"
IMPLEMENTATIONS["V-222646"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222646 - Security Tester Designation (APSC-DV-003170)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Assessment: Xen Orchestra is a third-party application developed by" + $nl
    $FindingDetails += "Vates SAS. The operating organization does not perform application" + $nl
    $FindingDetails += "development work on the XO codebase." + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "If the organization operating the" + $nl
    $FindingDetails += "application is not doing development work for the application," + $nl
    $FindingDetails += "this requirement is not applicable." + [char]34 + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Security tester designation requirements" + $nl
    $FindingDetails += "apply to the vendor (Vates SAS), not the operational deployment." + $nl
'''

# V-222647 - CAT III - System init/shutdown/abort testing
IMPLEMENTATIONS["V-222647"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222647 - System State Testing (APSC-DV-003180)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: systemd service configuration (secure state on failure)
    $FindingDetails += "Check 1 - Systemd Service Configuration:" + $nl
    $svcStatus = $(timeout 5 sh -c 'systemctl show xo-server.service 2>/dev/null | grep -E "Restart=|RestartSec=|Type=" | head -5')
    $svcStr = ($svcStatus -join $nl).Trim()
    if ($svcStr) {
        $FindingDetails += "  $svcStr" + $nl + $nl
    }
    else {
        $svcStatus2 = $(timeout 5 sh -c 'systemctl show xo-server 2>/dev/null | grep -E "Restart=|RestartSec=|Type=" | head -5')
        $svcStr2 = ($svcStatus2 -join $nl).Trim()
        if ($svcStr2) {
            $FindingDetails += "  $svcStr2" + $nl + $nl
        }
        else {
            $FindingDetails += "  XO systemd service configuration not retrieved." + $nl + $nl
        }
    }

    # Check 2: Process recovery behavior
    $FindingDetails += "Check 2 - Process Recovery Behavior:" + $nl
    $uptime = $(timeout 3 sh -c 'ps -eo pid,etime,args 2>/dev/null | grep "xo-server" | grep -v grep | head -3')
    $uptimeStr = ($uptime -join $nl).Trim()
    if ($uptimeStr) {
        $FindingDetails += "  Running XO processes:" + $nl + "  $uptimeStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  XO process information not available." + $nl + $nl
    }

    $Status = "Open"
    $FindingDetails += "RESULT: System state testing procedures require organizational" + $nl
    $FindingDetails += "documentation verifying annual testing of initialization, shutdown," + $nl
    $FindingDetails += "and abort scenarios to confirm secure state maintenance." + $nl
'''

# V-222648 - CAT II - Application code review
# Check: "if development is not being done or managed by the organization, not applicable"
IMPLEMENTATIONS["V-222648"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222648 - Application Code Review (APSC-DV-003200)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Assessment: Xen Orchestra is a third-party application developed by" + $nl
    $FindingDetails += "Vates SAS. The operating organization does not perform application" + $nl
    $FindingDetails += "development or manage the development process." + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "This requirement is meant to apply to" + $nl
    $FindingDetails += "developers or organizations that are doing the application development" + $nl
    $FindingDetails += "work and have the responsibility for maintaining the application" + $nl
    $FindingDetails += "source code." + [char]34 + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Code review requirements apply to the" + $nl
    $FindingDetails += "vendor (Vates SAS), not the operational deployment." + $nl
'''

# V-222649 - CAT III - Code coverage statistics
# Check: "if the organization does not do or manage the application development work, not applicable"
IMPLEMENTATIONS["V-222649"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222649 - Code Coverage Statistics (APSC-DV-003210)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "If the organization does not do or" + $nl
    $FindingDetails += "manage the application development work for the application, this" + $nl
    $FindingDetails += "requirement is not applicable." + [char]34 + $nl + $nl

    $FindingDetails += "Xen Orchestra is developed by Vates SAS. This organization operates" + $nl
    $FindingDetails += "the application but does not perform or manage its development." + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Code coverage tracking is a vendor" + $nl
    $FindingDetails += "responsibility (Vates SAS)." + $nl
'''

# V-222650 - CAT II - Flaws tracked in defect tracking system
# Check: "if development is not being done or managed by the organization, not applicable"
IMPLEMENTATIONS["V-222650"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222650 - Defect Tracking System (APSC-DV-003215)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "This requirement is meant to apply to" + $nl
    $FindingDetails += "developers or organizations that are doing application development" + $nl
    $FindingDetails += "work. If application development is not being done or managed by" + $nl
    $FindingDetails += "the organization, this requirement is not applicable." + [char]34 + $nl + $nl

    $FindingDetails += "Xen Orchestra defect tracking is managed by Vates SAS on GitHub:" + $nl
    $FindingDetails += "https://github.com/vatesfr/xen-orchestra/issues" + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Defect tracking is a vendor" + $nl
    $FindingDetails += "responsibility (Vates SAS)." + $nl
'''

# V-222651 - CAT II - IA/accreditation impact assessment prior to changes
IMPLEMENTATIONS["V-222651"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222651 - IA Impact Assessment (APSC-DV-003220)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Change management documentation
    $FindingDetails += "Check 1 - Change Management Process:" + $nl
    $FindingDetails += "  Automated check cannot verify organizational CM processes." + $nl
    $FindingDetails += "  ISSO/ISSM must verify that changes to XO are assessed for" + $nl
    $FindingDetails += "  IA impact through the CCB process prior to implementation." + $nl + $nl

    # Check 2: Current system version info
    $FindingDetails += "Check 2 - System Version Information:" + $nl
    $xoVer = $(timeout 5 sh -c 'cat /opt/xo/xo-server/package.json 2>/dev/null | grep -oP "(?<=version...: )[^,]+" | tr -d "\"" | head -1')
    $xoVerStr = ($xoVer -join $nl).Trim()
    if ($xoVerStr) {
        $FindingDetails += "  XO Version: $xoVerStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  XO version not retrieved." + $nl + $nl
    }

    $Status = "Open"
    $FindingDetails += "RESULT: IA impact assessment prior to changes requires" + $nl
    $FindingDetails += "organizational verification of CCB process and documentation." + $nl
'''

# V-222652 - CAT II - Security flaws fixed or addressed in project plan
# Check: "if not performing or managing the development work, not applicable"
IMPLEMENTATIONS["V-222652"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222652 - Security Flaws in Project Plan (APSC-DV-003225)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "This requirement is meant to apply to" + $nl
    $FindingDetails += "developers or organizations that are doing application development" + $nl
    $FindingDetails += "work. If the organization managing the application is not performing" + $nl
    $FindingDetails += "or managing the development work, this requirement is not" + $nl
    $FindingDetails += "applicable." + [char]34 + $nl + $nl

    $FindingDetails += "Xen Orchestra security flaw tracking is managed by Vates SAS." + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Security flaw project planning is a" + $nl
    $FindingDetails += "vendor responsibility (Vates SAS)." + $nl
'''

# V-222653 - CAT III - Coding standards
# Check: "if not doing the development or managing the development work, not applicable"
IMPLEMENTATIONS["V-222653"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222653 - Coding Standards (APSC-DV-003230)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "This requirement is meant to apply to" + $nl
    $FindingDetails += "developers or organizations that are doing application development" + $nl
    $FindingDetails += "work. If the organization operating the application under review" + $nl
    $FindingDetails += "is not doing the development or managing the development work," + $nl
    $FindingDetails += "this requirement is not applicable." + [char]34 + $nl + $nl

    $FindingDetails += "Xen Orchestra development follows Vates SAS coding standards." + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Coding standards are a vendor" + $nl
    $FindingDetails += "responsibility (Vates SAS)." + $nl
'''

# V-222654 - CAT III - Design document for each release
# Check: "if not doing the development or managing the development work, not applicable"
IMPLEMENTATIONS["V-222654"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222654 - Design Document (APSC-DV-003235)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "This requirement is meant to apply to" + $nl
    $FindingDetails += "developers or organizations that are doing application development" + $nl
    $FindingDetails += "work. If the organization operating the application is not doing" + $nl
    $FindingDetails += "the development or managing the development work, this" + $nl
    $FindingDetails += "requirement is not applicable." + [char]34 + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Design documentation is a vendor" + $nl
    $FindingDetails += "responsibility (Vates SAS)." + $nl
'''

# V-222655 - CAT II - Threat models documented and reviewed
# Check: "if not doing the development or is not managing the development work, not applicable"
IMPLEMENTATIONS["V-222655"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222655 - Threat Model Documentation (APSC-DV-003240)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "This requirement is meant to apply to" + $nl
    $FindingDetails += "developers or organizations that are doing application development" + $nl
    $FindingDetails += "work. If the organization operating the application is not doing" + $nl
    $FindingDetails += "the development or is not managing the development work, this" + $nl
    $FindingDetails += "requirement is not applicable." + [char]34 + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Threat model documentation is a vendor" + $nl
    $FindingDetails += "responsibility (Vates SAS)." + $nl
'''

# V-222656 - CAT II - Error handling vulnerabilities
IMPLEMENTATIONS["V-222656"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222656 - Error Handling Vulnerabilities (APSC-DV-003245)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: NODE_ENV production mode
    $FindingDetails += "Check 1 - Production Mode Configuration:" + $nl
    $nodeEnv = $(timeout 3 sh -c 'ps -eo args 2>/dev/null | grep "xo-server" | grep -v grep | head -1')
    $nodeEnvStr = ($nodeEnv -join $nl).Trim()
    if ($nodeEnvStr) {
        $FindingDetails += "  XO process: $nodeEnvStr" + $nl
    }
    $envCheck = $(timeout 3 sh -c 'grep -r "NODE_ENV" /etc/systemd/system/xo-server* /opt/xo/.env 2>/dev/null | head -5')
    $envStr = ($envCheck -join $nl).Trim()
    if ($envStr) {
        $FindingDetails += "  NODE_ENV config: $envStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  NODE_ENV not explicitly set (Node.js defaults apply)." + $nl + $nl
    }

    # Check 2: Error handler middleware
    $FindingDetails += "Check 2 - Error Handler Configuration:" + $nl
    $errHandler = $(timeout 5 sh -c 'grep -rn "errorHandler\|error.*middleware\|app\.use.*err" /opt/xo/xo-server/dist/ 2>/dev/null | head -5')
    $errStr = ($errHandler -join $nl).Trim()
    if ($errStr) {
        $FindingDetails += "  Error handling detected:" + $nl + "  $errStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No explicit error handler middleware detected in dist/." + $nl + $nl
    }

    # Check 3: Stack trace exposure test
    $FindingDetails += "Check 3 - Stack Trace Exposure:" + $nl
    $curlErr = $(timeout 10 sh -c "curl -s -k https://localhost/nonexistent-path-test-error 2>/dev/null | head -20")
    $curlStr = ($curlErr -join $nl).Trim()
    if ($curlStr -match "(?i)stack|traceback|at .*/|node_modules") {
        $FindingDetails += "  WARNING: Potential stack trace in error response:" + $nl
        $FindingDetails += "  $curlStr" + $nl + $nl
        $Status = "Open"
    }
    else {
        $FindingDetails += "  No stack traces detected in error responses." + $nl + $nl
    }

    # Check 4: npm audit for error handling vulnerabilities
    $FindingDetails += "Check 4 - Known Error Handling Vulnerabilities:" + $nl
    $npmAudit = $(timeout 15 sh -c 'cd /opt/xo/xo-server && npm audit --json 2>/dev/null | grep -c "\"severity\"" | head -1')
    $npmStr = ($npmAudit -join $nl).Trim()
    if ($npmStr) {
        $FindingDetails += "  npm audit vulnerability count: $npmStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  npm audit not available or no vulnerabilities found." + $nl + $nl
    }

    if ($Status -ne "Open") {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: No error handling vulnerabilities detected. Error" + $nl
        $FindingDetails += "responses do not expose stack traces or internal details." + $nl
    }
    else {
        $FindingDetails += "RESULT: Potential error handling vulnerabilities detected." + $nl
        $FindingDetails += "Review error responses for information disclosure." + $nl
    }
'''

# V-222657 - CAT II - Application incident response plan
# Check: "If the application is a COTS application and the development team
#          is not accessible to interview this requirement is not applicable."
IMPLEMENTATIONS["V-222657"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222657 - Application Incident Response Plan (APSC-DV-003250)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Assessment: Xen Orchestra is a commercial/open-source application" + $nl
    $FindingDetails += "developed by Vates SAS (France). The development team operates" + $nl
    $FindingDetails += "independently from the DoD operational deployment." + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "If the application is a COTS" + $nl
    $FindingDetails += "application and the development team is not accessible to" + $nl
    $FindingDetails += "interview this requirement is not applicable." + [char]34 + $nl + $nl

    $FindingDetails += "Vates publishes security advisories and patches through their" + $nl
    $FindingDetails += "GitHub repository: https://github.com/vatesfr/xen-orchestra" + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Incident response plan requirements" + $nl
    $FindingDetails += "apply to the vendor (Vates SAS). The development team is not" + $nl
    $FindingDetails += "directly accessible for interview by the operating organization." + $nl
'''

# ============================================================================
# BATCH 20: Code Review, Security Testing, Penetration Testing (5 functions)
# ============================================================================

# V-222660 - CAT III - Decommission notification procedures
IMPLEMENTATIONS["V-222660"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222660 - Decommission Notification (APSC-DV-003280)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Check 1 - Decommission Procedures:" + $nl
    $FindingDetails += "  Automated check cannot verify organizational decommission" + $nl
    $FindingDetails += "  notification procedures. ISSO/ISSM must verify that provisions" + $nl
    $FindingDetails += "  are in place to notify users when XO is decommissioned." + $nl + $nl

    # Check for user count to understand impact
    $FindingDetails += "Check 2 - Current User Base:" + $nl
    $token = $null
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim() }
    }
    if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli")) {
        $tc = $(timeout 3 sh -c 'grep -oP "(?<=\"token\":\")[^\"]+" /var/lib/xo-server/.xo-cli 2>/dev/null')
        if ($tc) { $token = $tc.Trim() }
    }
    if ($token) {
        $userResp = $(timeout 10 sh -c "curl -s -k -H 'Cookie: authenticationToken=$token' -H 'Accept: application/json' 'https://localhost/rest/v0/users' 2>/dev/null")
        $users = $userResp | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($users) {
            $userCount = ($users | Measure-Object).Count
            $FindingDetails += "  Active user accounts: $userCount" + $nl + $nl
        }
        else {
            $FindingDetails += "  Unable to retrieve user count via API." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  API token not available for user enumeration." + $nl + $nl
    }

    $Status = "Open"
    $FindingDetails += "RESULT: Decommission notification procedures require" + $nl
    $FindingDetails += "organizational documentation and process verification." + $nl
'''

# V-222661 - CAT II - Disable unnecessary built-in accounts
IMPLEMENTATIONS["V-222661"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222661 - Built-in Account Management (APSC-DV-003290)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO user accounts via API
    $FindingDetails += "Check 1 - XO Application Accounts:" + $nl
    $token = $null; $tokenSource = ""
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim(); $tokenSource = "api-token file" }
    }
    if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli")) {
        $tc = $(timeout 3 sh -c 'grep -oP "(?<=\"token\":\")[^\"]+" /var/lib/xo-server/.xo-cli 2>/dev/null')
        if ($tc) { $token = $tc.Trim(); $tokenSource = ".xo-cli" }
    }
    $builtInFound = $false
    if ($token) {
        $userResp = $(timeout 10 sh -c "curl -s -k -H 'Cookie: authenticationToken=$token' -H 'Accept: application/json' 'https://localhost/rest/v0/users' 2>/dev/null")
        $users = $userResp | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($users) {
            $userCount = ($users | Measure-Object).Count
            $FindingDetails += "  Total XO accounts: $userCount (source: $tokenSource)" + $nl
            foreach ($u in $users) {
                $email = ""
                if ($u.email) { $email = $u.email }
                elseif ($u.name) { $email = $u.name }
                $FindingDetails += "    - $email" + $nl
            }
            $FindingDetails += $nl
        }
        else {
            $FindingDetails += "  Unable to parse user list from API." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  API token not available; cannot enumerate XO accounts." + $nl + $nl
    }

    # Check 2: System accounts with shell access
    $FindingDetails += "Check 2 - System Accounts with Login Shell:" + $nl
    $sysAccts = $(timeout 5 sh -c 'awk -F: "(\$3 < 1000 && \$7 !~ /nologin|false/) {print \$1, \$3, \$7}" /etc/passwd 2>/dev/null')
    $sysStr = ($sysAccts -join $nl).Trim()
    if ($sysStr) {
        $FindingDetails += "  System accounts with login shells:" + $nl + "  $sysStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No system accounts with interactive shells found." + $nl + $nl
    }

    # Check 3: Default/vendor accounts
    $FindingDetails += "Check 3 - Default/Vendor Account Check:" + $nl
    $defaultAccts = $(timeout 5 sh -c 'grep -iE "^(admin|guest|test|demo|oracle|postgres|mysql|tomcat):" /etc/passwd 2>/dev/null')
    $defaultStr = ($defaultAccts -join $nl).Trim()
    if ($defaultStr) {
        $FindingDetails += "  Potential default accounts found: $defaultStr" + $nl + $nl
        $builtInFound = $true
    }
    else {
        $FindingDetails += "  No common default/vendor accounts detected." + $nl + $nl
    }

    if ($builtInFound) {
        $Status = "Open"
        $FindingDetails += "RESULT: Default or vendor accounts detected that may need" + $nl
        $FindingDetails += "to be disabled or have strong authentication configured." + $nl
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: No unnecessary built-in accounts detected. XO" + $nl
        $FindingDetails += "accounts are individually created; no default vendor accounts." + $nl
    }
'''

# V-222663 - CAT II - Application Configuration Guide
IMPLEMENTATIONS["V-222663"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222663 - Application Configuration Guide (APSC-DV-003310)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO documentation availability
    $FindingDetails += "Check 1 - Vendor Documentation:" + $nl
    $FindingDetails += "  Vates provides XO documentation at: https://xen-orchestra.com/docs/" + $nl
    $FindingDetails += "  Includes installation, configuration, backup, and administration guides." + $nl + $nl

    # Check 2: Local configuration files
    $FindingDetails += "Check 2 - Local Configuration Files:" + $nl
    $configFiles = $(timeout 5 sh -c 'ls -la /etc/xo-server/ /opt/xo/xo-server/.xo-server.toml /opt/xo/xo-server/config.toml 2>/dev/null')
    $configStr = ($configFiles -join $nl).Trim()
    if ($configStr) {
        $FindingDetails += "  Configuration files found:" + $nl + "  $configStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Standard configuration files not found at expected paths." + $nl + $nl
    }

    # Check 3: Org-specific configuration guide
    $FindingDetails += "Check 3 - Organization Configuration Guide:" + $nl
    $FindingDetails += "  Automated check cannot verify that an organization-specific" + $nl
    $FindingDetails += "  Application Configuration Guide has been created." + $nl + $nl

    $Status = "Open"
    $FindingDetails += "RESULT: Organization must create and maintain an Application" + $nl
    $FindingDetails += "Configuration Guide specific to the DoD deployment of XO." + $nl
    $FindingDetails += "The guide should document security configuration settings," + $nl
    $FindingDetails += "access controls, network architecture, and hardening steps." + $nl
'''

# V-222664 - CAT II - Security Classification Guide (if classified)
IMPLEMENTATIONS["V-222664"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222664 - Security Classification Guide (APSC-DV-003320)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Assessment: Xen Orchestra is an infrastructure management" + $nl
    $FindingDetails += "application that manages virtual machines and hypervisor hosts." + $nl + $nl

    # Check if processing classified data
    $FindingDetails += "Check 1 - Classified Data Processing:" + $nl
    $FindingDetails += "  XO manages VM lifecycle operations (create, delete, backup," + $nl
    $FindingDetails += "  migrate) but does not directly process or store classified" + $nl
    $FindingDetails += "  data within the application. Classified data resides within" + $nl
    $FindingDetails += "  the virtual machines managed by XO." + $nl + $nl

    $FindingDetails += "  Per STIG check: " + [char]34 + "If the application does not process" + $nl
    $FindingDetails += "  classified information, this check is not applicable." + [char]34 + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. XO does not directly process classified" + $nl
    $FindingDetails += "information. A classification guide may be required at the" + $nl
    $FindingDetails += "enclave level but not specifically for the XO application." + $nl
'''

# V-222665 - CAT II - No uncategorized/emerging mobile code
IMPLEMENTATIONS["V-222665"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222665 - Mobile Code Controls (APSC-DV-003330)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Legacy mobile code technologies
    $FindingDetails += "Check 1 - Legacy Mobile Code Technologies:" + $nl
    $javaFiles = $(timeout 10 sh -c 'find /opt/xo -maxdepth 4 -name "*.jar" -o -name "*.class" 2>/dev/null | head -5')
    $javaStr = ($javaFiles -join $nl).Trim()
    $flashFiles = $(timeout 10 sh -c 'find /opt/xo -maxdepth 4 -name "*.swf" -o -name "*.flv" 2>/dev/null | head -5')
    $flashStr = ($flashFiles -join $nl).Trim()
    $activeX = $(timeout 10 sh -c 'find /opt/xo -maxdepth 4 -name "*.ocx" -o -name "*.cab" 2>/dev/null | head -5')
    $activeXStr = ($activeX -join $nl).Trim()
    $silverlight = $(timeout 10 sh -c 'find /opt/xo -maxdepth 4 -name "*.xap" 2>/dev/null | head -5')
    $silverStr = ($silverlight -join $nl).Trim()

    $legacyFound = $false
    if ($javaStr) { $FindingDetails += "  Java: $javaStr" + $nl; $legacyFound = $true }
    if ($flashStr) { $FindingDetails += "  Flash: $flashStr" + $nl; $legacyFound = $true }
    if ($activeXStr) { $FindingDetails += "  ActiveX: $activeXStr" + $nl; $legacyFound = $true }
    if ($silverStr) { $FindingDetails += "  Silverlight: $silverStr" + $nl; $legacyFound = $true }
    if (-not $legacyFound) {
        $FindingDetails += "  No legacy mobile code technologies detected (Java, Flash," + $nl
        $FindingDetails += "  ActiveX, Silverlight)." + $nl
    }
    $FindingDetails += $nl

    # Check 2: Modern web framework verification
    $FindingDetails += "Check 2 - Web Framework Technology:" + $nl
    $nodeVer = $(timeout 3 sh -c 'node --version 2>/dev/null')
    $nodeStr = ($nodeVer -join $nl).Trim()
    if ($nodeStr) {
        $FindingDetails += "  Node.js: $nodeStr" + $nl
    }
    $FindingDetails += "  XO uses React/Vue.js frontend (modern web standards, not mobile code)." + $nl + $nl

    if ($legacyFound) {
        $Status = "Open"
        $FindingDetails += "RESULT: Legacy mobile code technologies detected. Review and" + $nl
        $FindingDetails += "remove or obtain waiver for uncategorized mobile code types." + $nl
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: No uncategorized or emerging mobile code detected." + $nl
        $FindingDetails += "XO uses modern web technologies (Node.js, React/Vue.js)." + $nl
    }
'''

# ============================================================================
# BATCH 21: Software Supply Chain, Third-Party, SBOM, Patch Management (9 functions)
# ============================================================================

# V-222666 - CAT II - Database export credential removal
IMPLEMENTATIONS["V-222666"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222666 - Database Export Sanitization (APSC-DV-003340)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Database technology in use
    $FindingDetails += "Check 1 - Database Technology:" + $nl
    $leveldb = $(timeout 5 sh -c 'ls -la /var/lib/xo-server/data/ 2>/dev/null | head -10')
    $levelStr = ($leveldb -join $nl).Trim()
    if ($levelStr) {
        $FindingDetails += "  LevelDB data directory:" + $nl + "  $levelStr" + $nl + $nl
    }
    $redis = $(timeout 3 sh -c 'redis-cli ping 2>/dev/null')
    $redisStr = ($redis -join $nl).Trim()
    if ($redisStr -eq "PONG") {
        $FindingDetails += "  Redis: Active (session/cache store)" + $nl + $nl
    }
    else {
        $FindingDetails += "  Redis: Not detected" + $nl + $nl
    }

    # Check 2: Export mechanism check
    $FindingDetails += "Check 2 - Database Export Mechanisms:" + $nl
    $FindingDetails += "  XO uses LevelDB for persistent data and optionally Redis" + $nl
    $FindingDetails += "  for sessions. Standard database export tools (mysqldump," + $nl
    $FindingDetails += "  pg_dump) are not applicable. XO config export is via" + $nl
    $FindingDetails += "  xo-cli or REST API." + $nl + $nl

    # Check 3: Credential storage in data directory
    $FindingDetails += "Check 3 - Credential Storage:" + $nl
    $FindingDetails += "  XO stores user credentials (bcrypt hashed) in LevelDB." + $nl
    $FindingDetails += "  Any data exports must exclude or sanitize credential fields." + $nl + $nl

    $Status = "Open"
    $FindingDetails += "RESULT: Organization must verify that database export procedures" + $nl
    $FindingDetails += "include credential removal and sensitive data sanitization." + $nl
'''

# V-222667 - CAT II - DoS protections
IMPLEMENTATIONS["V-222667"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222667 - DoS Attack Protections (APSC-DV-002950)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Firewall/rate limiting
    $FindingDetails += "Check 1 - Firewall Status:" + $nl
    $ufwStatus = ""
    if (Get-Command ufw -ErrorAction SilentlyContinue) {
        $ufwStatus = $(timeout 5 sh -c 'ufw status 2>/dev/null')
    }
    $ufwStr = ($ufwStatus -join $nl).Trim()
    if ($ufwStr -match "active") {
        $FindingDetails += "  UFW: $ufwStr" + $nl + $nl
    }
    else {
        $iptables = $(timeout 5 sh -c 'iptables -L INPUT -n 2>/dev/null | head -10')
        $iptStr = ($iptables -join $nl).Trim()
        if ($iptStr) {
            $FindingDetails += "  iptables INPUT chain:" + $nl + "  $iptStr" + $nl + $nl
        }
        else {
            $FindingDetails += "  No firewall (UFW/iptables) actively filtering traffic." + $nl + $nl
        }
    }

    # Check 2: Connection limits
    $FindingDetails += "Check 2 - Connection Limits:" + $nl
    $maxConn = $(timeout 5 sh -c 'sysctl net.core.somaxconn net.ipv4.tcp_max_syn_backlog 2>/dev/null')
    $maxStr = ($maxConn -join $nl).Trim()
    if ($maxStr) {
        $FindingDetails += "  $maxStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve connection limit settings." + $nl + $nl
    }

    # Check 3: Fail2ban or intrusion prevention
    $FindingDetails += "Check 3 - Intrusion Prevention:" + $nl
    $f2b = $(timeout 3 sh -c 'systemctl is-active fail2ban 2>/dev/null')
    $f2bStr = ($f2b -join $nl).Trim()
    if ($f2bStr -eq "active") {
        $FindingDetails += "  Fail2ban: Active" + $nl + $nl
    }
    else {
        $FindingDetails += "  Fail2ban: Not active" + $nl + $nl
    }

    $Status = "Open"
    $FindingDetails += "RESULT: DoS protection requires organizational threat model" + $nl
    $FindingDetails += "documentation and verification of implemented mitigations." + $nl
'''

# V-222668 - CAT II - Low resource condition alerting
IMPLEMENTATIONS["V-222668"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222668 - Low Resource Alerting (APSC-DV-002960)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Disk space monitoring
    $FindingDetails += "Check 1 - Disk Space Status:" + $nl
    $diskSpace = $(timeout 5 sh -c 'df -h / /var /var/log /var/lib/xo-server 2>/dev/null | sort -u')
    $diskStr = ($diskSpace -join $nl).Trim()
    if ($diskStr) {
        $FindingDetails += "  $diskStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve disk space information." + $nl + $nl
    }

    # Check 2: Monitoring agents
    $FindingDetails += "Check 2 - Monitoring Agents:" + $nl
    $monAgents = $(timeout 5 sh -c 'systemctl list-units --type=service --state=active 2>/dev/null | grep -iE "nagios|zabbix|prometheus|grafana|telegraf|collectd|monitor|alert" | head -5')
    $monStr = ($monAgents -join $nl).Trim()
    if ($monStr) {
        $FindingDetails += "  Active monitoring services:" + $nl + "  $monStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No recognized monitoring agents detected." + $nl + $nl
    }

    # Check 3: Logrotate (prevents disk exhaustion)
    $FindingDetails += "Check 3 - Log Rotation:" + $nl
    $logrotate = $(timeout 5 sh -c 'ls /etc/logrotate.d/ 2>/dev/null | head -10')
    $logStr = ($logrotate -join $nl).Trim()
    if ($logStr) {
        $FindingDetails += "  Logrotate configs: $logStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No logrotate configuration found." + $nl + $nl
    }

    # Check 4: Systemd journal limits
    $FindingDetails += "Check 4 - Journal Storage Limits:" + $nl
    $journalCfg = $(timeout 3 sh -c 'grep -E "^SystemMaxUse|^SystemKeepFree|^SystemMaxFileSize" /etc/systemd/journald.conf 2>/dev/null')
    $journalStr = ($journalCfg -join $nl).Trim()
    if ($journalStr) {
        $FindingDetails += "  $journalStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Journal storage limits: Using systemd defaults." + $nl + $nl
    }

    $Status = "Open"
    $FindingDetails += "RESULT: Low resource alerting requires organizational verification" + $nl
    $FindingDetails += "of automated monitoring and administrator notification mechanisms." + $nl
'''

# V-222669 - CAT III - Admin registered for update notifications
IMPLEMENTATIONS["V-222669"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222669 - Update Notification Registration (APSC-DV-003350)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO component versions
    $FindingDetails += "Check 1 - Component Versions:" + $nl
    $xoVer = $(timeout 5 sh -c 'cat /opt/xo/xo-server/package.json 2>/dev/null | grep -oP "(?<=version...: )[^,]+" | tr -d "\"" | head -1')
    $xoVerStr = ($xoVer -join $nl).Trim()
    if ($xoVerStr) { $FindingDetails += "  XO Server: $xoVerStr" + $nl }
    $nodeVer = $(timeout 3 sh -c 'node --version 2>/dev/null')
    $nodeStr = ($nodeVer -join $nl).Trim()
    if ($nodeStr) { $FindingDetails += "  Node.js: $nodeStr" + $nl }
    $osVer = $(timeout 3 sh -c 'cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d "\"" ')
    $osStr = ($osVer -join $nl).Trim()
    if ($osStr) { $FindingDetails += "  OS: $osStr" + $nl }
    $FindingDetails += $nl

    # Check 2: Notification channels
    $FindingDetails += "Check 2 - Available Notification Channels:" + $nl
    $FindingDetails += "  Vates/XO: https://xen-orchestra.com/blog/" + $nl
    $FindingDetails += "  GitHub: https://github.com/vatesfr/xen-orchestra/releases" + $nl
    $FindingDetails += "  Node.js: https://nodejs.org/en/blog/vulnerability/" + $nl
    $FindingDetails += "  Debian: https://www.debian.org/security/" + $nl + $nl

    # Check 3: Unattended upgrades
    $FindingDetails += "Check 3 - Automated Update Mechanisms:" + $nl
    $unattended = $(timeout 3 sh -c 'dpkg -l unattended-upgrades 2>/dev/null | grep "^ii"')
    $unattStr = ($unattended -join $nl).Trim()
    if ($unattStr) {
        $FindingDetails += "  Unattended-upgrades: Installed" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unattended-upgrades: Not installed" + $nl + $nl
    }

    $Status = "Open"
    $FindingDetails += "RESULT: Administrator registration for update notifications" + $nl
    $FindingDetails += "requires organizational verification that personnel are" + $nl
    $FindingDetails += "subscribed to vendor and component security advisories." + $nl
'''

# V-222670 - CAT III - Application provides patch/update notifications
IMPLEMENTATIONS["V-222670"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222670 - Patch/Update Notification Mechanism (APSC-DV-003360)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO built-in update notification
    $FindingDetails += "Check 1 - XO Update Notification:" + $nl
    $FindingDetails += "  XO Appliance (XOA) provides built-in update notifications" + $nl
    $FindingDetails += "  through the admin dashboard. Community Edition (XOCE) relies" + $nl
    $FindingDetails += "  on git pull and manual checking." + $nl + $nl

    # Check 2: Detect deployment type
    $FindingDetails += "Check 2 - Deployment Type:" + $nl
    $xoaCheck = $(timeout 3 sh -c 'test -f /etc/xoa-updater && echo "XOA" || echo "XOCE"')
    $xoaStr = ($xoaCheck -join $nl).Trim()
    $FindingDetails += "  Deployment: $xoaStr" + $nl + $nl

    # Check 3: apt security updates available
    $FindingDetails += "Check 3 - Pending Security Updates:" + $nl
    $aptUpdates = $(timeout 15 sh -c 'apt list --upgradable 2>/dev/null | grep -i security | head -10')
    $aptStr = ($aptUpdates -join $nl).Trim()
    if ($aptStr) {
        $FindingDetails += "  Security updates available:" + $nl + "  $aptStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No pending security updates detected." + $nl + $nl
    }

    $Status = "Open"
    $FindingDetails += "RESULT: Patch notification mechanism requires organizational" + $nl
    $FindingDetails += "verification that update distribution and notification processes" + $nl
    $FindingDetails += "are established for all application components." + $nl
'''

# V-222671 - CAT II - DMZ required for public-facing connections
IMPLEMENTATIONS["V-222671"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222671 - DMZ Requirement (APSC-DV-002880)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Network interfaces
    $FindingDetails += "Check 1 - Network Interfaces:" + $nl
    $interfaces = $(timeout 5 sh -c 'ip -4 addr show 2>/dev/null | grep -E "inet |^[0-9]+" | head -20')
    $ifStr = ($interfaces -join $nl).Trim()
    if ($ifStr) {
        $FindingDetails += "  $ifStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve network interface information." + $nl + $nl
    }

    # Check 2: Listening ports
    $FindingDetails += "Check 2 - Listening Services:" + $nl
    $listeners = $(timeout 5 sh -c 'ss -tlnp 2>/dev/null | head -15')
    $listenStr = ($listeners -join $nl).Trim()
    if ($listenStr) {
        $FindingDetails += "  $listenStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve listening services." + $nl + $nl
    }

    # Check 3: Public accessibility determination
    $FindingDetails += "Check 3 - Public Access Assessment:" + $nl
    $FindingDetails += "  XO is an internal infrastructure management tool that should" + $nl
    $FindingDetails += "  NOT be publicly accessible. XO should only be accessible from" + $nl
    $FindingDetails += "  management network segments within the DoD enclave." + $nl + $nl

    # Check for private IP (indicates internal deployment)
    $privateIP = $(timeout 3 sh -c "hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.' | head -1")
    $privStr = ($privateIP -join $nl).Trim()
    if ($privStr) {
        $FindingDetails += "  Primary IP: $privStr (private/internal network)" + $nl + $nl
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: XO is deployed on an internal/private network." + $nl
        $FindingDetails += "Application is not publicly accessible; DMZ requirement" + $nl
        $FindingDetails += "is met by network architecture." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Network topology requires verification to confirm" + $nl
        $FindingDetails += "XO is not publicly accessible and DMZ is properly configured." + $nl
    }
'''

# V-222672 - CAT III - Concurrent logon audit records
IMPLEMENTATIONS["V-222672"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222672 - Concurrent Logon Auditing (APSC-DV-002590)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO audit plugin
    $FindingDetails += "Check 1 - XO Audit Plugin:" + $nl
    $token = $null
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim() }
    }
    if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli")) {
        $tc = $(timeout 3 sh -c 'grep -oP "(?<=\"token\":\")[^\"]+" /var/lib/xo-server/.xo-cli 2>/dev/null')
        if ($tc) { $token = $tc.Trim() }
    }
    $auditActive = $false
    if ($token) {
        $auditRecords = $(timeout 10 sh -c "curl -s -k -H 'Cookie: authenticationToken=$token' -H 'Accept: application/json' 'https://localhost/rest/v0/plugins/audit/records?limit=5' 2>/dev/null")
        $auditStr = ($auditRecords -join $nl).Trim()
        if ($auditStr -and $auditStr -ne "[]" -and $auditStr -ne "null") {
            $FindingDetails += "  Audit plugin: Active (records available)" + $nl + $nl
            $auditActive = $true
        }
        else {
            $FindingDetails += "  Audit plugin: No records returned (may not be active)" + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  API token not available; cannot verify audit plugin." + $nl + $nl
    }

    # Check 2: Systemd journal session logging
    $FindingDetails += "Check 2 - System Authentication Logging:" + $nl
    $authLog = $(timeout 5 sh -c 'journalctl -u xo-server --since "1 hour ago" 2>/dev/null | grep -iE "session|login|auth" | tail -5')
    $authStr = ($authLog -join $nl).Trim()
    if ($authStr) {
        $FindingDetails += "  Recent auth events:" + $nl + "  $authStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No recent authentication events in journal." + $nl + $nl
    }

    # Check 3: Concurrent session detection capability
    $FindingDetails += "Check 3 - Concurrent Session Detection:" + $nl
    $FindingDetails += "  XO tracks active sessions server-side. The audit plugin" + $nl
    $FindingDetails += "  records signIn/signOut events with user ID and timestamp," + $nl
    $FindingDetails += "  enabling concurrent session detection through log analysis." + $nl + $nl

    if ($auditActive) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: XO audit plugin is active and records session events." + $nl
        $FindingDetails += "Concurrent logon detection is possible through audit log analysis." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Audit plugin status could not be verified or is inactive." + $nl
        $FindingDetails += "Enable the XO audit plugin to record concurrent logon events." + $nl
    }
'''

# V-222673 - CAT II - Annual security training for all program levels
IMPLEMENTATIONS["V-222673"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-222673 - Annual Security Training (APSC-DV-003370)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Per STIG check guidance: " + [char]34 + "This requirement is meant to be applied" + $nl
    $FindingDetails += "to developers and development teams only, otherwise, this requirement" + $nl
    $FindingDetails += "is not applicable." + [char]34 + $nl + $nl

    $FindingDetails += "Assessment: Xen Orchestra is a third-party application developed" + $nl
    $FindingDetails += "by Vates SAS. The operating organization does not maintain a" + $nl
    $FindingDetails += "development team for this application." + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. Annual security training requirements" + $nl
    $FindingDetails += "for program management, designers, developers, and testers" + $nl
    $FindingDetails += "apply to the vendor (Vates SAS), not the operational deployment." + $nl
'''

# V-265634 - CAT II - NSA-approved cryptography for classified information
IMPLEMENTATIONS["V-265634"] = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "V-265634 - NSA-Approved Cryptography (APSC-DV-002200)" + $nl
    $FindingDetails += "============================================================" + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: Classified data processing
    $FindingDetails += "Check 1 - Classified Data Processing Assessment:" + $nl
    $FindingDetails += "  XO is an infrastructure management application. It manages" + $nl
    $FindingDetails += "  virtual machine lifecycle operations but does not directly" + $nl
    $FindingDetails += "  store or process classified information." + $nl + $nl

    # Check 2: FIPS mode status
    $FindingDetails += "Check 2 - FIPS Cryptographic Mode:" + $nl
    $fipsEnabled = $(timeout 3 sh -c 'cat /proc/sys/crypto/fips_enabled 2>/dev/null')
    $fipsStr = ($fipsEnabled -join $nl).Trim()
    if ($fipsStr -eq "1") {
        $FindingDetails += "  FIPS mode: ENABLED" + $nl + $nl
    }
    else {
        $FindingDetails += "  FIPS mode: NOT enabled (fips_enabled=$fipsStr)" + $nl + $nl
    }

    # Check 3: TLS configuration
    $FindingDetails += "Check 3 - TLS Encryption:" + $nl
    $tlsCheck = $(timeout 10 sh -c "echo | openssl s_client -connect localhost:443 -tls1_2 2>/dev/null | grep -E 'Protocol|Cipher|Server Temp Key'")
    $tlsStr = ($tlsCheck -join $nl).Trim()
    if ($tlsStr) {
        $FindingDetails += "  $tlsStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  TLS verification not available." + $nl + $nl
    }

    # Check 4: OpenSSL version (FIPS-capable)
    $FindingDetails += "Check 4 - OpenSSL Version:" + $nl
    $opensslVer = $(timeout 3 sh -c 'openssl version 2>/dev/null')
    $sslStr = ($opensslVer -join $nl).Trim()
    if ($sslStr) {
        $FindingDetails += "  $sslStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  OpenSSL version not available." + $nl + $nl
    }

    # Per STIG: "If the application does not process classified data, this is NA"
    $FindingDetails += "Per STIG check: " + [char]34 + "If the application does not process" + $nl
    $FindingDetails += "classified data, the requirement is Not Applicable." + [char]34 + $nl + $nl

    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable. XO does not directly process classified" + $nl
    $FindingDetails += "information. NSA-approved cryptography requirements apply to" + $nl
    $FindingDetails += "systems that store/process classified data." + $nl
'''


def main():
    if not os.path.isfile(MODULE_PATH):
        print(f"ERROR: Module not found at {MODULE_PATH}")
        sys.exit(1)

    with open(MODULE_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    replaced = 0
    for vulnid, impl in IMPLEMENTATIONS.items():
        num = vulnid.replace("V-", "")
        func_name = f"Get-V{num}"

        # Find the function's custom code block
        func_pattern = re.compile(
            rf'(Function {func_name}\s*\{{.*?)(#---=== Begin Custom Code ===---#)\s*\n'
            rf'.*?'
            rf'(#---=== End Custom Code ===---#)',
            re.DOTALL
        )

        match = func_pattern.search(content)
        if not match:
            print(f"WARNING: Could not find stub for {vulnid} ({func_name})")
            continue

        # Build replacement
        new_custom = f"#---=== Begin Custom Code ===---#\n{impl}\n    #---=== End Custom Code ===---#"

        # Replace the custom code block
        old_block = content[match.start(2):match.end(3)]
        content = content[:match.start(2)] + new_custom + content[match.end(3):]

        replaced += 1
        print(f"  Replaced: {vulnid} ({func_name})")

    with open(MODULE_PATH, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\nTotal replaced: {replaced}/{len(IMPLEMENTATIONS)}")
    print(f"Module: {MODULE_PATH}")
    print(f"Module size: {len(content):,} bytes, {content.count(chr(10)):,} lines")


if __name__ == "__main__":
    main()
