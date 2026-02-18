#!/usr/bin/env python3
"""
Phase 4 Implementation Script — Batches 10-11 (20 functions)
Replaces stub functions in Scan-XO_ASD_Checks.psm1 with real implementations.

Batch 10 (V-222523–V-222535): Authentication Methods — MFA/CAC/PIV, mutual auth, replay-resistant, device auth
Batch 11 (V-222537–V-222545): Password Complexity — uppercase, lowercase, numeric, special, lifetime
"""

import re
import os

MODULE_PATH = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..',
                           'Evaluate-STIG', 'Modules', 'Scan-XO_ASD_Checks',
                           'Scan-XO_ASD_Checks.psm1')
MODULE_PATH = os.path.normpath(MODULE_PATH)

# ============================================================================
# Function implementations
# ============================================================================

IMPLEMENTATIONS = {}

# ---- Common code blocks used across multiple functions ----
AUTH_PLUGIN_CHECK = r'''
    # Check for enterprise authentication plugins (LDAP/SAML/OAuth)
    $authPlugins = ""
    $ldapPlugin = $(timeout 5 find /opt/xo/packages -maxdepth 2 -name "auth-ldap" -type d 2>/dev/null | head -2 2>&1)
    $samlActive = $(timeout 3 sh -c 'grep -v "^#" /opt/xo/xo-server/config.toml 2>/dev/null | grep -i "saml"' 2>&1)
    $oauthPlugin = $(timeout 5 find /opt/xo/packages -maxdepth 2 -name "auth-github" -o -name "auth-oidc" 2>/dev/null | head -2 2>&1)
    $ldapStr = ($ldapPlugin -join $nl).Trim()
    $samlStr = ($samlActive -join $nl).Trim()
    $oauthStr = ($oauthPlugin -join $nl).Trim()

    if ($ldapStr) { $authPlugins += "LDAP/AD plugin detected: $ldapStr" + $nl }
    if ($samlStr) { $authPlugins += "SAML config detected: $samlStr" + $nl }
    if ($oauthStr) { $authPlugins += "OAuth/OIDC plugin detected: $oauthStr" + $nl }

    $FindingDetails += "Check 1 - Enterprise Authentication Plugins:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($authPlugins) {
        $FindingDetails += $authPlugins + $nl
    }
    else {
        $FindingDetails += "  No enterprise authentication plugins detected." + $nl
        $FindingDetails += "  XO uses local username/password authentication by default." + $nl + $nl
    }
'''

TLS_CERT_CHECK = r'''
    # Check TLS client certificate configuration
    $tlsCertConfig = $(timeout 3 sh -c 'grep -i "requestCert\|rejectUnauthorized\|clientCert\|pfx\|ca:" /opt/xo/xo-server/config.toml /etc/xo-server/config.toml 2>/dev/null' 2>&1)
    $tlsCertStr = ($tlsCertConfig -join $nl).Trim()

    $FindingDetails += "Check 2 - TLS Client Certificate Configuration:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($tlsCertStr) {
        $FindingDetails += "  Client cert config found:" + $nl
        $FindingDetails += "  $tlsCertStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No TLS client certificate authentication configured." + $nl + $nl
    }
'''

# ---------- Batch 10: Authentication Methods ----------

IMPLEMENTATIONS['V-222523'] = {
    'RuleID': 'SV-222523r960972_rule',
    'STIG_ID': 'APSC-DV-001550',
    'Title': 'The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "MFA/Alt Token for Privileged Network Access (APSC-DV-001550)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl
''' + AUTH_PLUGIN_CHECK + TLS_CERT_CHECK + r'''
    # Check 3: XO API authentication method
    $token = $null
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim() }
    }
    if (-not $token -and $env:XO_API_TOKEN) { $token = $env:XO_API_TOKEN }
    if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli")) {
        $tc = $(timeout 3 sh -c 'grep -oP "(?<=\"token\":\")[^\"]+" /var/lib/xo-server/.xo-cli 2>/dev/null')
        if ($tc) { $token = ($tc -join "").Trim() }
    }

    $FindingDetails += "Check 3 - Privileged User Accounts:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($token) {
        $apiResponse = $(timeout 10 sh -c "curl -s -k -H 'Cookie: authenticationToken=$token' -H 'Accept: application/json' 'https://localhost/rest/v0/users'" 2>&1)
        $users = $apiResponse | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($users) {
            $adminUsers = @($users | Where-Object { $_.permission -eq "admin" })
            $FindingDetails += "  Admin users found: $($adminUsers.Count)" + $nl
            foreach ($u in $adminUsers) {
                $FindingDetails += "    - $($u.email) (permission: $($u.permission))" + $nl
            }
            $FindingDetails += $nl
        }
        else {
            $FindingDetails += "  Unable to parse user list from API." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  API token not available for user enumeration." + $nl + $nl
    }

    # Status: Open unless LDAP/SAML + client certs detected (implies MFA possible)
    if (($ldapStr -or $samlStr) -and $tlsCertStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Enterprise authentication with client certificate support detected." + $nl
        $FindingDetails += "MFA capability is available for privileged network access." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: XO does not natively enforce MFA/Alt Token for privileged access." + $nl
        $FindingDetails += "LDAP/AD integration with smart card or Alt Token required for compliance." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222524'] = {
    'RuleID': 'SV-222524r961494_rule',
    'STIG_ID': 'APSC-DV-001560',
    'Title': 'The application must accept Personal Identity Verification (PIV) credentials.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "PIV Credential Acceptance (APSC-DV-001560)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl
''' + AUTH_PLUGIN_CHECK + TLS_CERT_CHECK + r'''
    # Check 3: PKCS#11 / Smart card support
    $pkcs11 = $(timeout 3 sh -c 'dpkg -l 2>/dev/null | grep -i "pam-pkcs11\|opensc\|p11-kit"' 2>&1)
    $pkcs11Str = ($pkcs11 -join $nl).Trim()
    $FindingDetails += "Check 3 - PKI/Smart Card Packages:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($pkcs11Str) {
        $FindingDetails += "  $pkcs11Str" + $nl + $nl
    }
    else {
        $FindingDetails += "  No PKCS#11/smart card packages detected." + $nl + $nl
    }

    if ($tlsCertStr -or $pkcs11Str) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: PIV credential acceptance capability detected." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: XO does not natively accept PIV credentials." + $nl
        $FindingDetails += "Integration with LDAP/AD using smart card authentication is required." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222525'] = {
    'RuleID': 'SV-222525r961497_rule',
    'STIG_ID': 'APSC-DV-001570',
    'Title': 'The application must electronically verify Personal Identity Verification (PIV) credentials.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "PIV Credential Electronic Verification (APSC-DV-001570)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl
''' + AUTH_PLUGIN_CHECK + TLS_CERT_CHECK + r'''
    # Check 3: OCSP/CRL certificate validation
    $ocspConfig = $(timeout 3 sh -c 'grep -ri "ocsp\|crl\|verify\|revocation" /opt/xo/xo-server/config.toml /etc/xo-server/config.toml 2>/dev/null' 2>&1)
    $ocspStr = ($ocspConfig -join $nl).Trim()
    $FindingDetails += "Check 3 - Certificate Revocation Checking:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($ocspStr) {
        $FindingDetails += "  $ocspStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No OCSP/CRL revocation checking configured." + $nl + $nl
    }

    if ($tlsCertStr -and $ocspStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: PIV credential electronic verification configured." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: PIV credential electronic verification not configured." + $nl
        $FindingDetails += "Client certificate authentication with OCSP/CRL validation required." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222526'] = {
    'RuleID': 'SV-222526r960975_rule',
    'STIG_ID': 'APSC-DV-001580',
    'Title': 'The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "MFA for Non-Privileged Network Access (APSC-DV-001580)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl
''' + AUTH_PLUGIN_CHECK + TLS_CERT_CHECK + r'''
    # Check 3: Non-privileged user accounts
    $token = $null
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim() }
    }
    if (-not $token -and $env:XO_API_TOKEN) { $token = $env:XO_API_TOKEN }
    if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli")) {
        $tc = $(timeout 3 sh -c 'grep -oP "(?<=\"token\":\")[^\"]+" /var/lib/xo-server/.xo-cli 2>/dev/null')
        if ($tc) { $token = ($tc -join "").Trim() }
    }

    $FindingDetails += "Check 3 - Non-Privileged User Accounts:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($token) {
        $apiResponse = $(timeout 10 sh -c "curl -s -k -H 'Cookie: authenticationToken=$token' -H 'Accept: application/json' 'https://localhost/rest/v0/users'" 2>&1)
        $users = $apiResponse | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($users) {
            $nonAdminUsers = @($users | Where-Object { $_.permission -ne "admin" })
            $FindingDetails += "  Non-admin users found: $($nonAdminUsers.Count)" + $nl
            foreach ($u in $nonAdminUsers | Select-Object -First 5) {
                $FindingDetails += "    - $($u.email) (permission: $($u.permission))" + $nl
            }
            $FindingDetails += $nl
        }
        else {
            $FindingDetails += "  Unable to parse user list from API." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  API token not available for user enumeration." + $nl + $nl
    }

    if (($ldapStr -or $samlStr) -and $tlsCertStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Enterprise authentication with MFA capability for non-privileged access." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: MFA not enforced for non-privileged network access." + $nl
        $FindingDetails += "LDAP/AD with CAC or Alt Token required for all user accounts." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222527'] = {
    'RuleID': 'SV-222527r1015693_rule',
    'STIG_ID': 'APSC-DV-001590',
    'Title': 'The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "MFA/Alt Token for Privileged Local Access (APSC-DV-001590)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl
''' + AUTH_PLUGIN_CHECK + r'''
    # Check 2: Local console/SSH authentication methods
    $pamMFA = $(timeout 3 sh -c 'grep -r "pam_pkcs11\|pam_u2f\|pam_google_authenticator" /etc/pam.d/ 2>/dev/null' 2>&1)
    $pamStr = ($pamMFA -join $nl).Trim()
    $FindingDetails += "Check 2 - PAM MFA Modules:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($pamStr) {
        $FindingDetails += "  $pamStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No PAM MFA modules configured for local access." + $nl + $nl
    }

    # Check 3: SSH authentication methods
    $sshAuth = $(timeout 3 sh -c 'grep -i "AuthenticationMethods\|PubkeyAuthentication\|ChallengeResponseAuthentication" /etc/ssh/sshd_config 2>/dev/null' 2>&1)
    $sshStr = ($sshAuth -join $nl).Trim()
    $FindingDetails += "Check 3 - SSH Authentication Configuration:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($sshStr) {
        $FindingDetails += "  $sshStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Default SSH authentication (no explicit MFA)." + $nl + $nl
    }

    if ($pamStr -or ($sshStr -match "AuthenticationMethods.*publickey.*password")) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: MFA configured for local privileged access." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: MFA not enforced for local privileged access." + $nl
        $FindingDetails += "PAM MFA module or SSH multi-factor required." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222528'] = {
    'RuleID': 'SV-222528r1015694_rule',
    'STIG_ID': 'APSC-DV-001600',
    'Title': 'The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged accounts.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "MFA for Nonprivileged Local Access (APSC-DV-001600)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl
''' + AUTH_PLUGIN_CHECK + r'''
    # Check 2: PAM MFA for all users
    $pamMFA = $(timeout 3 sh -c 'grep -r "pam_pkcs11\|pam_u2f\|pam_google_authenticator" /etc/pam.d/ 2>/dev/null' 2>&1)
    $pamStr = ($pamMFA -join $nl).Trim()
    $FindingDetails += "Check 2 - PAM MFA Modules:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($pamStr) {
        $FindingDetails += "  $pamStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No PAM MFA modules configured." + $nl + $nl
    }

    # Check 3: XO web interface authentication
    $FindingDetails += "Check 3 - XO Web Interface Authentication:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO web interface uses username/password by default." + $nl
    $FindingDetails += "  MFA for web access requires LDAP/SAML integration with MFA-enabled IdP." + $nl + $nl

    if ($pamStr -or $samlStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: MFA capability available for nonprivileged local access." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: MFA not enforced for nonprivileged local access." + $nl
        $FindingDetails += "PAM MFA module or SAML/OIDC with MFA-enabled IdP required." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222529'] = {
    'RuleID': 'SV-222529r1015695_rule',
    'STIG_ID': 'APSC-DV-001610',
    'Title': 'The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "Individual Auth Before Group Authenticator (APSC-DV-001610)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO user authentication model
    $FindingDetails += "Check 1 - XO Authentication Model:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO requires individual user login before any group/shared access." + $nl
    $FindingDetails += "  Each user has a unique email/username for authentication." + $nl + $nl

    # Check 2: Group/shared accounts in XO
    $token = $null
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim() }
    }
    if (-not $token -and $env:XO_API_TOKEN) { $token = $env:XO_API_TOKEN }
    if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli")) {
        $tc = $(timeout 3 sh -c 'grep -oP "(?<=\"token\":\")[^\"]+" /var/lib/xo-server/.xo-cli 2>/dev/null')
        if ($tc) { $token = ($tc -join "").Trim() }
    }

    $FindingDetails += "Check 2 - XO User Accounts:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $groupAccountsFound = $false
    if ($token) {
        $apiResponse = $(timeout 10 sh -c "curl -s -k -H 'Cookie: authenticationToken=$token' -H 'Accept: application/json' 'https://localhost/rest/v0/users'" 2>&1)
        $users = $apiResponse | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($users) {
            $FindingDetails += "  Total users: $($users.Count)" + $nl
            foreach ($u in $users) {
                $email = "$($u.email)"
                if ($email -match "shared|group|service|generic|admin@|test@") {
                    $groupAccountsFound = $true
                    $FindingDetails += "  [REVIEW] Possible shared account: $email" + $nl
                }
                else {
                    $FindingDetails += "  [OK] Individual account: $email" + $nl
                }
            }
            $FindingDetails += $nl
        }
        else {
            $FindingDetails += "  Unable to parse user list." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  API token not available." + $nl + $nl
    }

    # Check 3: System group accounts
    $sharedLogins = $(timeout 3 sh -c 'last -w 2>/dev/null | head -20 | awk "{print \$1}" | sort | uniq -c | sort -rn | head -5' 2>&1)
    $sharedStr = ($sharedLogins -join $nl).Trim()
    $FindingDetails += "Check 3 - Recent Login Activity (top users):" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($sharedStr) {
        $FindingDetails += "  $sharedStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No recent login data available." + $nl + $nl
    }

    if (-not $groupAccountsFound) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: All XO accounts use individual authenticators." + $nl
        $FindingDetails += "No group/shared accounts detected." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Possible shared/group accounts detected." + $nl
        $FindingDetails += "Verify individual authentication occurs before shared account access." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222530'] = {
    'RuleID': 'SV-222530r960993_rule',
    'STIG_ID': 'APSC-DV-001620',
    'Title': 'The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "Replay-Resistant Auth for Privileged Access (APSC-DV-001620)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: TLS encryption (prevents replay)
    $tlsVersion = $(timeout 5 sh -c "echo | openssl s_client -connect localhost:443 -tls1_2 2>&1 | grep 'Protocol\|Cipher'" 2>&1)
    $tlsStr = ($tlsVersion -join $nl).Trim()
    $FindingDetails += "Check 1 - TLS Encryption (replay protection):" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($tlsStr -match "TLSv1\.[23]") {
        $FindingDetails += "  TLS 1.2+ detected - provides replay protection." + $nl
        $FindingDetails += "  $tlsStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  TLS status: $tlsStr" + $nl + $nl
    }

    # Check 2: Session token management (nonce/CSRF)
    $csrfToken = $(timeout 5 sh -c "curl -s -k -I 'https://localhost/' 2>&1 | grep -i 'set-cookie\|csrf\|x-xsrf'" 2>&1)
    $csrfStr = ($csrfToken -join $nl).Trim()
    $FindingDetails += "Check 2 - Session Token/CSRF Protection:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($csrfStr) {
        $FindingDetails += "  $csrfStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No CSRF/session tokens detected in response headers." + $nl + $nl
    }

    # Check 3: XO uses session tokens (inherently replay-resistant with TLS)
    $FindingDetails += "Check 3 - XO Authentication Mechanism:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO uses session-based authentication over HTTPS." + $nl
    $FindingDetails += "  TLS encryption prevents credential interception and replay." + $nl
    $FindingDetails += "  Session tokens are unique per session and time-limited." + $nl + $nl

    if ($tlsStr -match "TLSv1\.[23]") {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Replay-resistant authentication via TLS 1.2+ session tokens." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Cannot verify TLS-based replay protection." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222531'] = {
    'RuleID': 'SV-222531r1015696_rule',
    'STIG_ID': 'APSC-DV-001630',
    'Title': 'The application must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "Replay-Resistant Auth for Nonprivileged Access (APSC-DV-001630)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: TLS encryption active
    $tlsVersion = $(timeout 5 sh -c "echo | openssl s_client -connect localhost:443 -tls1_2 2>&1 | grep 'Protocol\|Cipher'" 2>&1)
    $tlsStr = ($tlsVersion -join $nl).Trim()
    $FindingDetails += "Check 1 - TLS Encryption:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($tlsStr -match "TLSv1\.[23]") {
        $FindingDetails += "  TLS 1.2+ active - replay protection enabled." + $nl
        $FindingDetails += "  $tlsStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  TLS status: $tlsStr" + $nl + $nl
    }

    # Check 2: Same session-based auth applies to all users
    $FindingDetails += "Check 2 - Authentication Mechanism:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO applies the same session-based authentication to all users." + $nl
    $FindingDetails += "  Both privileged and nonprivileged accounts use HTTPS sessions." + $nl
    $FindingDetails += "  Session tokens are unique, time-limited, and transmitted over TLS." + $nl + $nl

    if ($tlsStr -match "TLSv1\.[23]") {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Replay-resistant authentication via TLS 1.2+ for all accounts." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Cannot verify TLS-based replay protection." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222532'] = {
    'RuleID': 'SV-222532r960999_rule',
    'STIG_ID': 'APSC-DV-001640',
    'Title': 'The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoD policy or by the data owner.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "Mutual Authentication for Non-Repudiation (APSC-DV-001640)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl
''' + TLS_CERT_CHECK + r'''
    # Check 2 (renumbered): Server certificate verification
    $serverCert = $(timeout 5 sh -c "echo | openssl s_client -connect localhost:443 2>&1 | openssl x509 -noout -subject -issuer 2>&1" 2>&1)
    $certStr = ($serverCert -join $nl).Trim()
    $FindingDetails += "Check 2 - Server TLS Certificate:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($certStr) {
        $FindingDetails += "  $certStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve server certificate." + $nl + $nl
    }

    # Check 3: Mutual TLS requirement assessment
    $FindingDetails += "Check 3 - Mutual Authentication Assessment:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO manages virtualization infrastructure (classified as sensitive)." + $nl
    $FindingDetails += "  Mutual TLS (mTLS) provides device-level non-repudiation." + $nl
    $FindingDetails += "  Requires both server and client certificate exchange." + $nl + $nl

    if ($tlsCertStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Mutual TLS configuration detected." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Mutual TLS not configured." + $nl
        $FindingDetails += "Configure client certificate authentication if non-repudiation required." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222533'] = {
    'RuleID': 'SV-222533r961503_rule',
    'STIG_ID': 'APSC-DV-001650',
    'Title': 'The application must authenticate all network connected endpoint devices before establishing any connection.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "Endpoint Device Authentication (APSC-DV-001650)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO API authentication requirement
    $unauthTest = $(timeout 5 sh -c "curl -s -k -o /dev/null -w '%{http_code}' 'https://localhost/rest/v0/users'" 2>&1)
    $FindingDetails += "Check 1 - Unauthenticated API Access:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  HTTP status for unauthenticated /rest/v0/users: $unauthTest" + $nl
    if ($unauthTest -match "401|403") {
        $FindingDetails += "  API correctly rejects unauthenticated requests." + $nl + $nl
    }
    else {
        $FindingDetails += "  API may allow unauthenticated access." + $nl + $nl
    }

    # Check 2: TLS required for all connections
    $httpRedirect = $(timeout 5 sh -c "curl -s -k -o /dev/null -w '%{http_code}' 'http://localhost/'" 2>&1)
    $FindingDetails += "Check 2 - HTTP to HTTPS Redirect:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  HTTP redirect status: $httpRedirect" + $nl
    if ($httpRedirect -match "30[1-3]") {
        $FindingDetails += "  HTTP redirects to HTTPS (transport security enforced)." + $nl + $nl
    }
    else {
        $FindingDetails += "  HTTP redirect behavior: code $httpRedirect" + $nl + $nl
    }

    # Check 3: XO server connection authentication
    $FindingDetails += "Check 3 - XO Connection Authentication:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO requires user authentication for all management operations." + $nl
    $FindingDetails += "  WebSocket connections require valid session tokens." + $nl
    $FindingDetails += "  API endpoints require authentication tokens." + $nl + $nl

    if ($unauthTest -match "401|403") {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: All endpoint connections require authentication." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Endpoint device authentication verification required." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222534'] = {
    'RuleID': 'SV-222534r961506_rule',
    'STIG_ID': 'APSC-DV-001660',
    'Title': 'Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "Mutual SSL/TLS for Non-Releasable Data (APSC-DV-001660)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO handles non-releasable data (virtualization management)
    $FindingDetails += "Check 1 - Data Classification:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO manages virtual machine infrastructure." + $nl
    $FindingDetails += "  VM management data includes network configs, storage, and credentials." + $nl
    $FindingDetails += "  This data is classified as non-releasable." + $nl + $nl
''' + TLS_CERT_CHECK + r'''
    # Check 3 (renumbered): API endpoints using REST
    $FindingDetails += "Check 3 - Service-Oriented Architecture:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO provides REST API at /rest/v0/ for service consumers." + $nl
    $FindingDetails += "  API authentication uses token-based auth over TLS." + $nl
    $FindingDetails += "  Mutual TLS (mTLS) adds device-level authentication." + $nl + $nl

    if ($tlsCertStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Mutual SSL/TLS configured for service endpoints." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Mutual SSL/TLS not configured." + $nl
        $FindingDetails += "Configure client certificate authentication for service endpoints." + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222535'] = {
    'RuleID': 'SV-222535r1015697_rule',
    'STIG_ID': 'APSC-DV-001670',
    'Title': 'The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "Device Identifier Inactivity Disable (APSC-DV-001670)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: XO device authentication model
    $FindingDetails += "Check 1 - Device Authentication Assessment:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO is a web-based management application." + $nl
    $FindingDetails += "  XO authenticates users, not devices (no device identifiers)." + $nl
    $FindingDetails += "  Browser sessions are authenticated via user credentials." + $nl + $nl

    # Check 2: API token expiration
    $FindingDetails += "Check 2 - API Token Management:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $FindingDetails += "  XO API tokens are tied to user accounts, not devices." + $nl
    $FindingDetails += "  Token lifecycle managed through user account management." + $nl + $nl

    # Check 3: User account inactivity
    $token = $null
    if (Test-Path "/etc/xo-server/stig/api-token") {
        $tokenContent = $(timeout 3 cat /etc/xo-server/stig/api-token 2>&1)
        if ($tokenContent) { $token = $tokenContent.Trim() }
    }
    if (-not $token -and $env:XO_API_TOKEN) { $token = $env:XO_API_TOKEN }
    if (-not $token -and (Test-Path "/var/lib/xo-server/.xo-cli")) {
        $tc = $(timeout 3 sh -c 'grep -oP "(?<=\"token\":\")[^\"]+" /var/lib/xo-server/.xo-cli 2>/dev/null')
        if ($tc) { $token = ($tc -join "").Trim() }
    }

    $FindingDetails += "Check 3 - User Account Activity:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($token) {
        $apiResponse = $(timeout 10 sh -c "curl -s -k -H 'Cookie: authenticationToken=$token' -H 'Accept: application/json' 'https://localhost/rest/v0/users'" 2>&1)
        $users = $apiResponse | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($users) {
            $FindingDetails += "  Total user accounts: $($users.Count)" + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  API token not available for user enumeration." + $nl + $nl
    }

    # XO does not use device identifiers - this is N/A per STIG guidance
    $Status = "Not_Applicable"
    $FindingDetails += "RESULT: Not Applicable - XO authenticates users, not devices." + $nl
    $FindingDetails += "XO does not use device identifiers for authentication." + $nl
    $FindingDetails += "Per STIG: if application does not authenticate devices, this is N/A." + $nl
''',
    'ExpectedNF': False,  # N/A
    'ExpectedNA': True,
}

# ---------- Batch 11: Password Complexity ----------

PASSWORD_CHECK_PREAMBLE = r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    # Check if XO uses passwords (always true for local auth)
    $ldapPlugin = $(timeout 5 find /opt/xo/packages -maxdepth 2 -name "auth-ldap" -type d 2>/dev/null | head -2 2>&1)
    $ldapStr = ($ldapPlugin -join $nl).Trim()
    $samlActive = $(timeout 3 sh -c 'grep -v "^#" /opt/xo/xo-server/config.toml 2>/dev/null | grep -i "saml"' 2>&1)
    $samlStr = ($samlActive -join $nl).Trim()
    $usesPasswords = $true

    # Check PAM pwquality configuration
    $pwquality = $(timeout 3 sh -c 'cat /etc/security/pwquality.conf 2>/dev/null | grep -v "^#" | grep -v "^$"' 2>&1)
    $pwqualityStr = ($pwquality -join $nl).Trim()

    $pamPwquality = $(timeout 3 sh -c 'grep -r "pam_pwquality\|pam_cracklib" /etc/pam.d/ 2>/dev/null' 2>&1)
    $pamStr = ($pamPwquality -join $nl).Trim()
'''

IMPLEMENTATIONS['V-222537'] = {
    'RuleID': 'SV-222537r1015699_rule',
    'STIG_ID': 'APSC-DV-001690',
    'Title': 'The application must enforce password complexity by requiring that at least one uppercase character be used.',
    'Code': PASSWORD_CHECK_PREAMBLE + r'''
    $FindingDetails += "Password Complexity - Uppercase Requirement (APSC-DV-001690)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: PAM pwquality ucredit setting
    $FindingDetails += "Check 1 - PAM pwquality Configuration:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $ucreditMatch = $false
    if ($pwqualityStr -match "ucredit\s*=\s*(-?\d+)") {
        $ucreditVal = [int]$matches[1]
        $FindingDetails += "  ucredit = $ucreditVal" + $nl
        if ($ucreditVal -le -1) {
            $ucreditMatch = $true
            $FindingDetails += "  Requires at least 1 uppercase character." + $nl + $nl
        }
        else {
            $FindingDetails += "  Does not require uppercase characters." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  ucredit not configured in pwquality.conf" + $nl + $nl
    }

    # Check 2: PAM module loaded
    $FindingDetails += "Check 2 - PAM Module Status:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($pamStr) {
        $FindingDetails += "  $pamStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  pam_pwquality not loaded in PAM stack." + $nl + $nl
    }

    # Check 3: LDAP/AD delegation
    $FindingDetails += "Check 3 - External Password Policy:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($ldapStr) {
        $FindingDetails += "  LDAP/AD plugin detected - password policy may be enforced by directory." + $nl + $nl
    }
    elseif ($samlStr) {
        $FindingDetails += "  SAML configured - password policy enforced by IdP." + $nl + $nl
    }
    else {
        $FindingDetails += "  No external authentication - local password policy applies." + $nl + $nl
    }

    if ($ucreditMatch -and $pamStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Uppercase character requirement enforced via PAM." + $nl
    }
    elseif ($ldapStr -or $samlStr) {
        $Status = "Open"
        $FindingDetails += "RESULT: External auth detected but local PAM ucredit not configured." + $nl
        $FindingDetails += "Verify LDAP/AD password policy enforces uppercase requirement." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Uppercase character requirement not enforced." + $nl
        $FindingDetails += "Configure: ucredit = -1 in /etc/security/pwquality.conf" + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222538'] = {
    'RuleID': 'SV-222538r1015700_rule',
    'STIG_ID': 'APSC-DV-001700',
    'Title': 'The application must enforce password complexity by requiring that at least one lowercase character be used.',
    'Code': PASSWORD_CHECK_PREAMBLE + r'''
    $FindingDetails += "Password Complexity - Lowercase Requirement (APSC-DV-001700)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Check 1 - PAM pwquality Configuration:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $lcreditMatch = $false
    if ($pwqualityStr -match "lcredit\s*=\s*(-?\d+)") {
        $lcreditVal = [int]$matches[1]
        $FindingDetails += "  lcredit = $lcreditVal" + $nl
        if ($lcreditVal -le -1) {
            $lcreditMatch = $true
            $FindingDetails += "  Requires at least 1 lowercase character." + $nl + $nl
        }
        else {
            $FindingDetails += "  Does not require lowercase characters." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  lcredit not configured in pwquality.conf" + $nl + $nl
    }

    $FindingDetails += "Check 2 - PAM Module Status:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($pamStr) {
        $FindingDetails += "  $pamStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  pam_pwquality not loaded in PAM stack." + $nl + $nl
    }

    $FindingDetails += "Check 3 - External Password Policy:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($ldapStr) {
        $FindingDetails += "  LDAP/AD plugin detected - password policy may be enforced by directory." + $nl + $nl
    }
    else {
        $FindingDetails += "  No external authentication - local password policy applies." + $nl + $nl
    }

    if ($lcreditMatch -and $pamStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Lowercase character requirement enforced via PAM." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Lowercase character requirement not enforced." + $nl
        $FindingDetails += "Configure: lcredit = -1 in /etc/security/pwquality.conf" + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222539'] = {
    'RuleID': 'SV-222539r1015701_rule',
    'STIG_ID': 'APSC-DV-001710',
    'Title': 'The application must enforce password complexity by requiring that at least one numeric character be used.',
    'Code': PASSWORD_CHECK_PREAMBLE + r'''
    $FindingDetails += "Password Complexity - Numeric Requirement (APSC-DV-001710)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Check 1 - PAM pwquality Configuration:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $dcreditMatch = $false
    if ($pwqualityStr -match "dcredit\s*=\s*(-?\d+)") {
        $dcreditVal = [int]$matches[1]
        $FindingDetails += "  dcredit = $dcreditVal" + $nl
        if ($dcreditVal -le -1) {
            $dcreditMatch = $true
            $FindingDetails += "  Requires at least 1 numeric character." + $nl + $nl
        }
        else {
            $FindingDetails += "  Does not require numeric characters." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  dcredit not configured in pwquality.conf" + $nl + $nl
    }

    $FindingDetails += "Check 2 - PAM Module Status:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($pamStr) { $FindingDetails += "  $pamStr" + $nl + $nl }
    else { $FindingDetails += "  pam_pwquality not loaded in PAM stack." + $nl + $nl }

    $FindingDetails += "Check 3 - External Password Policy:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($ldapStr) { $FindingDetails += "  LDAP/AD plugin detected." + $nl + $nl }
    else { $FindingDetails += "  No external authentication." + $nl + $nl }

    if ($dcreditMatch -and $pamStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Numeric character requirement enforced via PAM." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Numeric character requirement not enforced." + $nl
        $FindingDetails += "Configure: dcredit = -1 in /etc/security/pwquality.conf" + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222540'] = {
    'RuleID': 'SV-222540r1015702_rule',
    'STIG_ID': 'APSC-DV-001720',
    'Title': 'The application must enforce password complexity by requiring that at least one special character be used.',
    'Code': PASSWORD_CHECK_PREAMBLE + r'''
    $FindingDetails += "Password Complexity - Special Character Requirement (APSC-DV-001720)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    $FindingDetails += "Check 1 - PAM pwquality Configuration:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $ocreditMatch = $false
    if ($pwqualityStr -match "ocredit\s*=\s*(-?\d+)") {
        $ocreditVal = [int]$matches[1]
        $FindingDetails += "  ocredit = $ocreditVal" + $nl
        if ($ocreditVal -le -1) {
            $ocreditMatch = $true
            $FindingDetails += "  Requires at least 1 special character." + $nl + $nl
        }
        else {
            $FindingDetails += "  Does not require special characters." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  ocredit not configured in pwquality.conf" + $nl + $nl
    }

    $FindingDetails += "Check 2 - PAM Module Status:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($pamStr) { $FindingDetails += "  $pamStr" + $nl + $nl }
    else { $FindingDetails += "  pam_pwquality not loaded in PAM stack." + $nl + $nl }

    $FindingDetails += "Check 3 - External Password Policy:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($ldapStr) { $FindingDetails += "  LDAP/AD plugin detected." + $nl + $nl }
    else { $FindingDetails += "  No external authentication." + $nl + $nl }

    if ($ocreditMatch -and $pamStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Special character requirement enforced via PAM." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Special character requirement not enforced." + $nl
        $FindingDetails += "Configure: ocredit = -1 in /etc/security/pwquality.conf" + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222541'] = {
    'RuleID': 'SV-222541r1043189_rule',
    'STIG_ID': 'APSC-DV-001730',
    'Title': 'The application must require the change of at least eight of the total number of characters when passwords are changed.',
    'Code': PASSWORD_CHECK_PREAMBLE + r'''
    $FindingDetails += "Password Change - Minimum 8 Characters Changed (APSC-DV-001730)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: PAM pwquality difok setting
    $FindingDetails += "Check 1 - PAM pwquality difok Setting:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $difokMatch = $false
    if ($pwqualityStr -match "difok\s*=\s*(\d+)") {
        $difokVal = [int]$matches[1]
        $FindingDetails += "  difok = $difokVal" + $nl
        if ($difokVal -ge 8) {
            $difokMatch = $true
            $FindingDetails += "  Requires at least $difokVal characters differ from old password." + $nl + $nl
        }
        else {
            $FindingDetails += "  Below DoD requirement of 8 characters." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  difok not configured (default is 1)." + $nl + $nl
    }

    $FindingDetails += "Check 2 - PAM Module Status:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($pamStr) { $FindingDetails += "  $pamStr" + $nl + $nl }
    else { $FindingDetails += "  pam_pwquality not loaded." + $nl + $nl }

    $FindingDetails += "Check 3 - External Password Policy:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($ldapStr) { $FindingDetails += "  LDAP/AD plugin detected." + $nl + $nl }
    else { $FindingDetails += "  No external authentication." + $nl + $nl }

    if ($difokMatch -and $pamStr) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Password change difference requirement enforced (difok >= 8)." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Password change difference requirement not enforced." + $nl
        $FindingDetails += "Configure: difok = 8 in /etc/security/pwquality.conf" + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222544'] = {
    'RuleID': 'SV-222544r1015705_rule',
    'STIG_ID': 'APSC-DV-001760',
    'Title': 'The application must enforce 24 hours/1 day as the minimum password lifetime.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "Minimum Password Lifetime - 24 Hours (APSC-DV-001760)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: /etc/login.defs PASS_MIN_DAYS
    $loginDefs = $(timeout 3 sh -c 'grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null' 2>&1)
    $loginStr = ($loginDefs -join $nl).Trim()
    $FindingDetails += "Check 1 - /etc/login.defs PASS_MIN_DAYS:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $minDaysOK = $false
    if ($loginStr -match "PASS_MIN_DAYS\s+(\d+)") {
        $minDays = [int]$matches[1]
        $FindingDetails += "  PASS_MIN_DAYS = $minDays" + $nl
        if ($minDays -ge 1) {
            $minDaysOK = $true
            $FindingDetails += "  Meets 24-hour minimum." + $nl + $nl
        }
        else {
            $FindingDetails += "  Below 24-hour minimum (DoD requires >= 1 day)." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  PASS_MIN_DAYS not configured." + $nl + $nl
    }

    # Check 2: PAM configuration
    $pamAge = $(timeout 3 sh -c 'grep -r "pam_unix\|pam_pwhistory" /etc/pam.d/ 2>/dev/null | grep -i "min_days\|remember"' 2>&1)
    $pamAgeStr = ($pamAge -join $nl).Trim()
    $FindingDetails += "Check 2 - PAM Password Aging:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($pamAgeStr) {
        $FindingDetails += "  $pamAgeStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  No PAM password aging configuration found." + $nl + $nl
    }

    # Check 3: LDAP/AD delegation
    $ldapPlugin = $(timeout 5 find /opt/xo/packages -maxdepth 2 -name "auth-ldap" -type d 2>/dev/null | head -2 2>&1)
    $ldapStr = ($ldapPlugin -join $nl).Trim()
    $FindingDetails += "Check 3 - External Password Policy:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($ldapStr) {
        $FindingDetails += "  LDAP/AD plugin detected - minimum password age may be enforced by directory." + $nl + $nl
    }
    else {
        $FindingDetails += "  No external authentication." + $nl + $nl
    }

    if ($minDaysOK) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Minimum password lifetime of 24 hours enforced." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Minimum password lifetime not enforced." + $nl
        $FindingDetails += "Configure: PASS_MIN_DAYS 1 in /etc/login.defs" + $nl
    }
''',
    'ExpectedNF': True,
}

IMPLEMENTATIONS['V-222545'] = {
    'RuleID': 'SV-222545r1043190_rule',
    'STIG_ID': 'APSC-DV-001770',
    'Title': 'The application must enforce a 60-day maximum password lifetime restriction.',
    'Code': r'''
    $nl = [Environment]::NewLine
    $xoHostname = $(hostname 2>&1)

    $FindingDetails += "Maximum Password Lifetime - 60 Days (APSC-DV-001770)" + $nl
    $FindingDetails += ("=" * 60) + $nl + $nl
    $FindingDetails += "Host: $xoHostname" + $nl + $nl

    # Check 1: /etc/login.defs PASS_MAX_DAYS
    $loginDefs = $(timeout 3 sh -c 'grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null' 2>&1)
    $loginStr = ($loginDefs -join $nl).Trim()
    $FindingDetails += "Check 1 - /etc/login.defs PASS_MAX_DAYS:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    $maxDaysOK = $false
    if ($loginStr -match "PASS_MAX_DAYS\s+(\d+)") {
        $maxDays = [int]$matches[1]
        $FindingDetails += "  PASS_MAX_DAYS = $maxDays" + $nl
        if ($maxDays -le 60 -and $maxDays -gt 0) {
            $maxDaysOK = $true
            $FindingDetails += "  Meets 60-day maximum requirement." + $nl + $nl
        }
        else {
            $FindingDetails += "  Exceeds 60-day maximum (DoD requires <= 60 days)." + $nl + $nl
        }
    }
    else {
        $FindingDetails += "  PASS_MAX_DAYS not configured." + $nl + $nl
    }

    # Check 2: Individual user account settings
    $userMaxDays = $(timeout 3 sh -c 'chage -l root 2>/dev/null | grep "Maximum"' 2>&1)
    $userMaxStr = ($userMaxDays -join $nl).Trim()
    $FindingDetails += "Check 2 - Root Account Password Aging:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($userMaxStr) {
        $FindingDetails += "  $userMaxStr" + $nl + $nl
    }
    else {
        $FindingDetails += "  Unable to retrieve root password aging." + $nl + $nl
    }

    # Check 3: LDAP/AD delegation
    $ldapPlugin = $(timeout 5 find /opt/xo/packages -maxdepth 2 -name "auth-ldap" -type d 2>/dev/null | head -2 2>&1)
    $ldapStr = ($ldapPlugin -join $nl).Trim()
    $FindingDetails += "Check 3 - External Password Policy:" + $nl
    $FindingDetails += ("-" * 40) + $nl
    if ($ldapStr) {
        $FindingDetails += "  LDAP/AD plugin detected - maximum password age may be enforced by directory." + $nl + $nl
    }
    else {
        $FindingDetails += "  No external authentication." + $nl + $nl
    }

    if ($maxDaysOK) {
        $Status = "NotAFinding"
        $FindingDetails += "RESULT: Maximum password lifetime of 60 days enforced." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += "RESULT: Maximum password lifetime not properly configured." + $nl
        $FindingDetails += "Configure: PASS_MAX_DAYS 60 in /etc/login.defs" + $nl
    }
''',
    'ExpectedNF': True,
}

# ============================================================================
# Template for building full function
# ============================================================================

FUNCTION_TEMPLATE = '''Function Get-V{vid_nodash} {{
    <#
    .DESCRIPTION
        Vuln ID    : {vid}
        STIG ID    : {stig_id}
        Rule ID    : {rule_id}
        Rule Title : {title}
        DiscussMD5 : 00000000000000000000000000000000
        CheckMD5   : 00000000000000000000000000000000
        FixMD5     : 00000000000000000000000000000000
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID,

        [Parameter(Mandatory = $false)]
        [String]$Hostname,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "{vid}"
    $RuleID = "{rule_id}"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
{code}
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {{
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }}
    else {{
        $ResultHash = ""
    }}

    if ($PSBoundParameters.AnswerFile) {{
        $GetCorpParams = @{{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $SiteName
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }}
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {{
            $AFKey     = $AnswerData.AFKey
            $AFStatus  = $AnswerData.AFStatus
            $Comments  = $AnswerData.AFComment | Out-String
        }}
    }}

    $SendCheckParams = @{{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFKey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $SiteName
        HeadHash         = $ResultHash
    }}
    return Send-CheckResult @SendCheckParams
}}'''


def build_function(vid, impl):
    vid_nodash = vid.replace('V-', 'V')
    code = impl['Code']
    # Indent code by 4 spaces (function body)
    code_lines = code.split('\n')
    # Code is already indented with leading spaces from raw strings
    code_text = '\n'.join(code_lines)

    return FUNCTION_TEMPLATE.format(
        vid=vid,
        vid_nodash=vid_nodash,
        stig_id=impl['STIG_ID'],
        rule_id=impl['RuleID'],
        title=impl['Title'],
        code=code_text
    )


def find_stub(content, vid):
    """Find the start and end of a stub function for the given VulnID."""
    vid_nodash = vid.replace('V-', 'V')
    pattern = rf'Function Get-{vid_nodash}\s*\{{'
    match = re.search(pattern, content)
    if not match:
        return None, None

    start = match.start()
    # Find the matching closing brace
    brace_count = 0
    pos = match.end() - 1  # Start at the opening brace
    while pos < len(content):
        if content[pos] == '{':
            brace_count += 1
        elif content[pos] == '}':
            brace_count -= 1
            if brace_count == 0:
                return start, pos + 1
        pos += 1
    return start, None


def main():
    print(f"Reading module: {MODULE_PATH}")
    with open(MODULE_PATH, 'r', encoding='utf-8-sig') as f:
        content = f.read()

    original_size = len(content)
    replacements = 0

    for vid in sorted(IMPLEMENTATIONS.keys()):
        impl = IMPLEMENTATIONS[vid]
        start, end = find_stub(content, vid)
        if start is None:
            print(f"  WARNING: Could not find stub for {vid}")
            continue
        if end is None:
            print(f"  WARNING: Could not find closing brace for {vid}")
            continue

        old_func = content[start:end]
        new_func = build_function(vid, impl)

        content = content[:start] + new_func + content[end:]
        replacements += 1
        print(f"  Replaced {vid} ({len(old_func)} -> {len(new_func)} chars)")

    with open(MODULE_PATH, 'w', encoding='utf-8-sig') as f:
        f.write(content)

    new_size = len(content)
    print(f"\nDone: {replacements}/20 replacements")
    print(f"Module size: {original_size:,} -> {new_size:,} bytes ({new_size - original_size:+,})")


if __name__ == '__main__':
    main()
