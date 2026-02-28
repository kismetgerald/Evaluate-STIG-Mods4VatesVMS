#!/usr/bin/env python3
"""
Batch 9: PKI & Certificates + MFA (10 functions)
Replaces stub functions with full implementations.

V-203622: PKI certificate path validation
V-203623: PKI private key access control
V-203624: Map auth identity to user/group for PKI
V-203639: Uniquely identify org users
V-203640: MFA for network access (privileged)
V-203641: MFA for network access (non-privileged)
V-203642: MFA for local access (privileged)
V-203643: MFA for local access (non-privileged)
V-203644: Individual auth before group auth
V-203729: PIV credential verification
"""

import re
import sys

MODULE_PATH = r"Evaluate-STIG\Modules\Scan-XO_GPOS_Debian12_Checks\Scan-XO_GPOS_Debian12_Checks.psm1"

# Each function implementation as a complete replacement
IMPLEMENTATIONS = {}

# Common param block and boilerplate generator
def make_function(vuln_id, rule_id, stig_id, check_md5, custom_code):
    """Generate complete function with standard boilerplate."""
    return f'''Function Get-{vuln_id.replace("-", "")} {{
    <#
    .DESCRIPTION
        Vuln ID    : {vuln_id}
        STIG ID    : {stig_id}
        Rule ID    : {rule_id}
        DiscussMD5 : 00000000000000000000000000000000
        CheckMD5   : {check_md5}
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
    $VulnID = "{vuln_id}"
    $RuleID = "{rule_id}"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""
    $nl = [Environment]::NewLine

    #---=== Begin Custom Code ===---#
{custom_code}
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
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
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
    }}
    return Send-CheckResult @SendCheckParams
}}'''

# ============================================================
# V-203622: PKI certificate path validation
# ============================================================
IMPLEMENTATIONS["V-203622"] = make_function(
    "V-203622", "SV-203622r958448_rule", "SRG-OS-000066-GPOS-00034",
    "e2a8270752f047a81d141756d1bfaa12",
    r'''
    $FindingDetails += "--- Check 1: CA Certificate Trust Store ---" + $nl
    $caCertsInstalled = $(dpkg -l ca-certificates 2>&1)
    if ($LASTEXITCODE -eq 0 -and ($caCertsInstalled -join $nl) -match "ii\s+ca-certificates") {
        $FindingDetails += "  ca-certificates package: INSTALLED" + $nl
        $certCount = $(timeout 10 find /etc/ssl/certs -maxdepth 1 -name "*.pem" 2>/dev/null | wc -l)
        $FindingDetails += "  Trusted CA certificates: $certCount" + $nl
    }
    else {
        $FindingDetails += "  ca-certificates package: NOT INSTALLED" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: OpenSSL Certificate Validation ---" + $nl
    $opensslVer = $(openssl version 2>&1)
    $FindingDetails += "  OpenSSL version: $opensslVer" + $nl
    $caPath = $(openssl version -d 2>&1)
    $FindingDetails += "  OpenSSL directory: $caPath" + $nl
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: PKI Authentication Configuration ---" + $nl
    $sssdInstalled = $(dpkg -l sssd 2>&1)
    if ($LASTEXITCODE -eq 0 -and ($sssdInstalled -join $nl) -match "ii\s+sssd") {
        $FindingDetails += "  SSSD: INSTALLED" + $nl
        $sssdConf = $(timeout 5 grep -i "certificate_verification" /etc/sssd/sssd.conf 2>/dev/null)
        if ($sssdConf) {
            $FindingDetails += "  Certificate verification config: $sssdConf" + $nl
        }
        else {
            $FindingDetails += "  Certificate verification: Not explicitly configured" + $nl
        }
    }
    else {
        $FindingDetails += "  SSSD: Not installed" + $nl
    }
    $pamPkcs11 = $(dpkg -l libpam-pkcs11 2>&1)
    if ($LASTEXITCODE -eq 0 -and ($pamPkcs11 -join $nl) -match "ii\s+libpam-pkcs11") {
        $FindingDetails += "  libpam-pkcs11: INSTALLED (PKI PAM module)" + $nl
    }
    else {
        $FindingDetails += "  libpam-pkcs11: Not installed" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: Update-CA-Certificates Status ---" + $nl
    $updateCa = $(timeout 5 update-ca-certificates --fresh 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $FindingDetails += "  update-ca-certificates: Functional" + $nl
    }
    else {
        $FindingDetails += "  update-ca-certificates: Error or not available" + $nl
    }

    # Status determination
    if (($caCertsInstalled -join $nl) -match "ii\s+ca-certificates") {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: CA trust store installed but PKI-based authentication" + $nl
        $FindingDetails += "requires organizational configuration of certificate validation" + $nl
        $FindingDetails += "policies (OCSP, CRL, trust anchors)." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: CA certificates package not detected." + $nl
    }
''')

# ============================================================
# V-203623: PKI private key access control
# ============================================================
IMPLEMENTATIONS["V-203623"] = make_function(
    "V-203623", "SV-203623r958450_rule", "SRG-OS-000067-GPOS-00035",
    "8d6b85c6e6aaf242631121963a4a7365",
    r'''
    $FindingDetails += "--- Check 1: Private Key File Permissions ---" + $nl
    $keyDirs = @("/etc/ssl/private", "/etc/pki/tls/private", "/etc/xo-server", "/opt/xo")
    $keysFound = 0
    $permIssues = 0
    foreach ($dir in $keyDirs) {
        $keys = $(timeout 10 find $dir -maxdepth 3 -name "*.key" -o -name "*.pem" 2>/dev/null)
        if ($keys) {
            foreach ($keyFile in ($keys -split $nl)) {
                if (-not $keyFile) { continue }
                $keysFound++
                $perms = $(stat -c "%a %U:%G" $keyFile 2>&1)
                $FindingDetails += "  $keyFile : $perms" + $nl
                if ($perms -match "^(\d+)") {
                    $mode = $matches[1]
                    $worldBits = [int]($mode[-1].ToString())
                    $groupBits = [int]($mode[-2].ToString())
                    if ($worldBits -gt 0 -or $groupBits -gt 4) {
                        $FindingDetails += "    [FAIL] Permissions too permissive" + $nl
                        $permIssues++
                    }
                    else {
                        $FindingDetails += "    [PASS] Permissions restrictive" + $nl
                    }
                }
            }
        }
    }
    if ($keysFound -eq 0) {
        $FindingDetails += "  No private key files found in standard locations" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: SSL Private Directory Permissions ---" + $nl
    $sslPrivDir = "/etc/ssl/private"
    if (Test-Path $sslPrivDir -ErrorAction SilentlyContinue) {
        $dirPerms = $(stat -c "%a %U:%G" $sslPrivDir 2>&1)
        $FindingDetails += "  $sslPrivDir : $dirPerms" + $nl
        if ($dirPerms -match "^700\s+root:") {
            $FindingDetails += "    [PASS] Directory restricted to root only" + $nl
        }
        else {
            $FindingDetails += "    [WARN] Directory permissions may be too open" + $nl
            $permIssues++
        }
    }
    else {
        $FindingDetails += "  /etc/ssl/private: Directory not found" + $nl
    }

    # Status determination
    if ($keysFound -gt 0 -and $permIssues -eq 0) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: $keysFound private key(s) found with appropriate access controls." + $nl
    }
    elseif ($keysFound -gt 0 -and $permIssues -gt 0) {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: $permIssues permission issue(s) found on private key files." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: No private key files detected in standard locations." + $nl
    }
''')

# ============================================================
# V-203624: Map auth identity to user/group for PKI
# ============================================================
IMPLEMENTATIONS["V-203624"] = make_function(
    "V-203624", "SV-203624r958452_rule", "SRG-OS-000068-GPOS-00036",
    "b17847cde3dfdaf2994807bdfa7b9055",
    r'''
    $FindingDetails += "--- Check 1: PAM PKI Identity Mapping ---" + $nl
    $pamPkcs11 = $(dpkg -l libpam-pkcs11 2>&1)
    if ($LASTEXITCODE -eq 0 -and ($pamPkcs11 -join $nl) -match "ii\s+libpam-pkcs11") {
        $FindingDetails += "  libpam-pkcs11: INSTALLED" + $nl
        $mapperConf = $(timeout 5 cat /etc/pam_pkcs11/pam_pkcs11.conf 2>/dev/null)
        if ($mapperConf) {
            $FindingDetails += "  PAM PKCS#11 config: Found" + $nl
            $mapperLines = ($mapperConf -join $nl) -split $nl | Where-Object { $_ -match "mapper" }
            foreach ($line in $mapperLines) {
                $FindingDetails += "    $($line.Trim())" + $nl
            }
        }
        else {
            $FindingDetails += "  PAM PKCS#11 config: /etc/pam_pkcs11/pam_pkcs11.conf not found" + $nl
        }
    }
    else {
        $FindingDetails += "  libpam-pkcs11: Not installed" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: SSSD Certificate Mapping ---" + $nl
    $sssdInstalled = $(dpkg -l sssd 2>&1)
    if ($LASTEXITCODE -eq 0 -and ($sssdInstalled -join $nl) -match "ii\s+sssd") {
        $FindingDetails += "  SSSD: INSTALLED" + $nl
        $certMap = $(timeout 5 grep -i "certmap\|certificate" /etc/sssd/sssd.conf 2>/dev/null)
        if ($certMap) {
            $FindingDetails += "  Certificate mapping rules found:" + $nl
            foreach ($line in ($certMap -split $nl)) {
                $FindingDetails += "    $($line.Trim())" + $nl
            }
        }
        else {
            $FindingDetails += "  No certificate mapping rules in sssd.conf" + $nl
        }
    }
    else {
        $FindingDetails += "  SSSD: Not installed" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: NSS/PAM User Lookup ---" + $nl
    $nsswitch = $(timeout 5 grep -E "^passwd:" /etc/nsswitch.conf 2>/dev/null)
    $FindingDetails += "  nsswitch passwd: $nsswitch" + $nl
    $pamAuth = $(timeout 5 grep -v "^#" /etc/pam.d/common-auth 2>/dev/null)
    if ($pamAuth) {
        $FindingDetails += "  PAM auth modules:" + $nl
        foreach ($line in ($pamAuth -split $nl)) {
            if ($line.Trim()) {
                $FindingDetails += "    $($line.Trim())" + $nl
            }
        }
    }

    # Status determination — PKI mapping requires org config
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: PKI-based identity mapping requires organizational" + $nl
    $FindingDetails += "configuration of certificate-to-user mapping (SSSD certmap rules" + $nl
    $FindingDetails += "or PAM PKCS#11 mapper configuration)." + $nl
''')

# ============================================================
# V-203639: Uniquely identify org users
# ============================================================
IMPLEMENTATIONS["V-203639"] = make_function(
    "V-203639", "SV-203639r958482_rule", "SRG-OS-000104-GPOS-00051",
    "993e303cc0524e389a86324889b585ab",
    r'''
    $FindingDetails += "--- Check 1: Unique User Accounts ---" + $nl
    $userCount = $(timeout 5 grep -c "^" /etc/passwd 2>&1)
    $FindingDetails += "  Total accounts in /etc/passwd: $userCount" + $nl
    $humanUsers = $(timeout 5 awk -F: "(\$3 >= 1000 && \$3 < 65534) {print \$1 \":\" \$3}" /etc/passwd 2>&1)
    if ($humanUsers) {
        $FindingDetails += "  Human user accounts (UID >= 1000):" + $nl
        foreach ($user in ($humanUsers -split $nl)) {
            if ($user.Trim()) {
                $FindingDetails += "    $user" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No human user accounts (UID >= 1000) found" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Duplicate UID Detection ---" + $nl
    $dupUids = $(timeout 5 awk -F: "{print \$3}" /etc/passwd 2>/dev/null | sort | uniq -d)
    if ($dupUids) {
        $FindingDetails += "  [FAIL] Duplicate UIDs found: $dupUids" + $nl
    }
    else {
        $FindingDetails += "  [PASS] No duplicate UIDs detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: Duplicate Username Detection ---" + $nl
    $dupNames = $(timeout 5 awk -F: "{print \$1}" /etc/passwd 2>/dev/null | sort | uniq -d)
    if ($dupNames) {
        $FindingDetails += "  [FAIL] Duplicate usernames found: $dupNames" + $nl
    }
    else {
        $FindingDetails += "  [PASS] No duplicate usernames detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: Authentication Method ---" + $nl
    $loginDefs = $(timeout 5 grep -E "^(UID_MIN|UID_MAX|LOGIN_RETRIES)" /etc/login.defs 2>/dev/null)
    if ($loginDefs) {
        foreach ($line in ($loginDefs -split $nl)) {
            $FindingDetails += "  $($line.Trim())" + $nl
        }
    }
    $nsswitch = $(timeout 5 grep -E "^passwd:" /etc/nsswitch.conf 2>/dev/null)
    $FindingDetails += "  nsswitch passwd: $nsswitch" + $nl

    # Status determination
    if (-not $dupUids -and -not $dupNames) {
        $Status = "NotAFinding"
        $FindingDetails += $nl + "RESULT: All user accounts have unique UIDs and usernames." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Duplicate UIDs or usernames detected." + $nl
    }
''')

# ============================================================
# V-203640: MFA for network access (privileged)
# ============================================================
MFA_CHECK_CODE = r'''
    $FindingDetails += "--- Check 1: Smartcard/PKI Authentication ---" + $nl
    $pkcs11 = $(dpkg -l libpam-pkcs11 2>&1)
    $opensc = $(dpkg -l opensc 2>&1)
    if ($LASTEXITCODE -eq 0 -and ($pkcs11 -join $nl) -match "ii\s+libpam-pkcs11") {
        $FindingDetails += "  libpam-pkcs11: INSTALLED" + $nl
    }
    else {
        $FindingDetails += "  libpam-pkcs11: Not installed" + $nl
    }
    if (($opensc -join $nl) -match "ii\s+opensc") {
        $FindingDetails += "  opensc (smartcard): INSTALLED" + $nl
    }
    else {
        $FindingDetails += "  opensc (smartcard): Not installed" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: SSSD with MFA ---" + $nl
    $sssdInstalled = $(dpkg -l sssd 2>&1)
    if ($LASTEXITCODE -eq 0 -and ($sssdInstalled -join $nl) -match "ii\s+sssd") {
        $FindingDetails += "  SSSD: INSTALLED" + $nl
        $mfaConf = $(timeout 5 grep -iE "auth_provider|certificate|two_factor|prompting" /etc/sssd/sssd.conf 2>/dev/null)
        if ($mfaConf) {
            foreach ($line in ($mfaConf -split $nl)) {
                $FindingDetails += "    $($line.Trim())" + $nl
            }
        }
        else {
            $FindingDetails += "  No MFA-related SSSD configuration found" + $nl
        }
    }
    else {
        $FindingDetails += "  SSSD: Not installed" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: PAM MFA Modules ---" + $nl
    $pamGoogle = $(dpkg -l libpam-google-authenticator 2>&1)
    $pamYubi = $(dpkg -l libpam-yubico 2>&1)
    $pamOath = $(dpkg -l libpam-oath 2>&1)
    if (($pamGoogle -join $nl) -match "ii\s+libpam-google") {
        $FindingDetails += "  libpam-google-authenticator: INSTALLED (TOTP)" + $nl
    }
    if (($pamYubi -join $nl) -match "ii\s+libpam-yubico") {
        $FindingDetails += "  libpam-yubico: INSTALLED (YubiKey)" + $nl
    }
    if (($pamOath -join $nl) -match "ii\s+libpam-oath") {
        $FindingDetails += "  libpam-oath: INSTALLED (OATH)" + $nl
    }
    if (-not (($pamGoogle -join $nl) -match "ii") -and -not (($pamYubi -join $nl) -match "ii") -and -not (($pamOath -join $nl) -match "ii")) {
        $FindingDetails += "  No PAM MFA modules detected" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: SSH MFA Configuration ---" + $nl
    $sshAuth = $(timeout 5 grep -E "^(AuthenticationMethods|ChallengeResponseAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config 2>/dev/null)
    if ($sshAuth) {
        foreach ($line in ($sshAuth -split $nl)) {
            $FindingDetails += "  $($line.Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No explicit MFA SSH configuration found" + $nl
    }

    # Status determination — MFA requires organizational deployment
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: MFA {mfa_scope} requires organizational deployment" + $nl
    $FindingDetails += "of smartcard/PKI (CAC/PIV), TOTP, or hardware token authentication." + $nl
'''

IMPLEMENTATIONS["V-203640"] = make_function(
    "V-203640", "SV-203640r958484_rule", "SRG-OS-000105-GPOS-00052",
    "2a691d0d44ab7c9b1d83005d50dd23ce",
    MFA_CHECK_CODE.replace("{mfa_scope}", "for network access to privileged accounts"))

IMPLEMENTATIONS["V-203641"] = make_function(
    "V-203641", "SV-203641r958486_rule", "SRG-OS-000106-GPOS-00053",
    "94fafe4d6838a29495b6fd5728bdf2bc",
    MFA_CHECK_CODE.replace("{mfa_scope}", "for network access to non-privileged accounts"))

IMPLEMENTATIONS["V-203642"] = make_function(
    "V-203642", "SV-203642r982203_rule", "SRG-OS-000107-GPOS-00054",
    "f0fc62130e0b3d39e98b46ff64542bb9",
    MFA_CHECK_CODE.replace("{mfa_scope}", "for local access to privileged accounts"))

IMPLEMENTATIONS["V-203643"] = make_function(
    "V-203643", "SV-203643r982204_rule", "SRG-OS-000108-GPOS-00055",
    "b9d7a810ddfbf05e9fece6cdd05998fb",
    MFA_CHECK_CODE.replace("{mfa_scope}", "for local access to nonprivileged accounts"))

# ============================================================
# V-203644: Individual auth before group auth
# ============================================================
IMPLEMENTATIONS["V-203644"] = make_function(
    "V-203644", "SV-203644r982205_rule", "SRG-OS-000109-GPOS-00056",
    "b872fc215bac694c6c176b5baef971f2",
    r'''
    $FindingDetails += "--- Check 1: Shared/Group Accounts ---" + $nl
    $groupAccounts = $(timeout 5 awk -F: "(\$3 >= 1000 && \$3 < 65534)" /etc/passwd 2>&1)
    if ($groupAccounts) {
        $FindingDetails += "  User accounts (UID >= 1000):" + $nl
        foreach ($acct in ($groupAccounts -split $nl)) {
            if ($acct.Trim()) {
                $parts = $acct -split ":"
                $uname = $parts[0]
                $uid = $parts[2]
                $shell = $parts[-1]
                $FindingDetails += "    $uname (UID:$uid, Shell:$shell)" + $nl
            }
        }
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: Concurrent Login Detection ---" + $nl
    $whoOutput = $(who 2>&1)
    if ($whoOutput) {
        $FindingDetails += "  Currently logged in users:" + $nl
        foreach ($line in ($whoOutput -split $nl)) {
            if ($line.Trim()) {
                $FindingDetails += "    $($line.Trim())" + $nl
            }
        }
        # Check for same user logged in multiple times
        $userLogins = ($whoOutput -split $nl) | ForEach-Object { ($_ -split "\s+")[0] } | Where-Object { $_ }
        $dupLogins = $userLogins | Group-Object | Where-Object { $_.Count -gt 1 }
        if ($dupLogins) {
            $FindingDetails += "  [INFO] Users with multiple sessions:" + $nl
            foreach ($dup in $dupLogins) {
                $FindingDetails += "    $($dup.Name): $($dup.Count) sessions" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No users currently logged in" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: PAM Individual Authentication ---" + $nl
    $pamAuth = $(timeout 5 grep -v "^#" /etc/pam.d/common-auth 2>/dev/null)
    if ($pamAuth) {
        foreach ($line in ($pamAuth -split $nl)) {
            if ($line.Trim()) {
                $FindingDetails += "  $($line.Trim())" + $nl
            }
        }
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: Sudo Configuration ---" + $nl
    $sudoGroup = $(timeout 5 grep -E "^%sudo|^%wheel|^%admin" /etc/sudoers 2>/dev/null)
    if ($sudoGroup) {
        $FindingDetails += "  Sudo group rules:" + $nl
        foreach ($line in ($sudoGroup -split $nl)) {
            $FindingDetails += "    $($line.Trim())" + $nl
        }
    }
    $sudoersD = $(timeout 10 find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)
    if ($sudoersD) {
        $FindingDetails += "  Sudoers.d files:" + $nl
        foreach ($f in ($sudoersD -split $nl)) {
            if ($f.Trim()) { $FindingDetails += "    $f" + $nl }
        }
    }

    # Status determination — individual auth before group is org policy
    $Status = "Open"
    $FindingDetails += $nl + "RESULT: Individual authentication before group/shared account" + $nl
    $FindingDetails += "access requires organizational policy enforcement. Verify that" + $nl
    $FindingDetails += "users authenticate with individual credentials before accessing" + $nl
    $FindingDetails += "any shared or group accounts (e.g., via sudo, su)." + $nl
''')

# ============================================================
# V-203729: PIV credential verification
# ============================================================
IMPLEMENTATIONS["V-203729"] = make_function(
    "V-203729", "SV-203729r958818_rule", "SRG-OS-000377-GPOS-00162",
    "fbf1d4f3f4b5af312549c85078b39fdd",
    r'''
    $FindingDetails += "--- Check 1: Smartcard Packages ---" + $nl
    $packages = @("opensc", "opensc-pkcs11", "libpam-pkcs11", "pcscd", "libccid", "pcsc-tools")
    $pkgInstalled = 0
    foreach ($pkg in $packages) {
        $result = $(dpkg -l $pkg 2>&1)
        if ($LASTEXITCODE -eq 0 -and ($result -join $nl) -match "ii\s+$pkg") {
            $FindingDetails += "  $pkg : INSTALLED" + $nl
            $pkgInstalled++
        }
        else {
            $FindingDetails += "  $pkg : Not installed" + $nl
        }
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 2: PC/SC Smart Card Daemon ---" + $nl
    $pcscdStatus = $(systemctl is-active pcscd 2>&1)
    $FindingDetails += "  pcscd service: $pcscdStatus" + $nl
    $pcscdEnabled = $(systemctl is-enabled pcscd 2>&1)
    $FindingDetails += "  pcscd enabled: $pcscdEnabled" + $nl
    $FindingDetails += $nl

    $FindingDetails += "--- Check 3: PAM Smartcard Configuration ---" + $nl
    $pamSC = $(timeout 5 grep -r "pam_pkcs11\|pam_sss.*require_cert" /etc/pam.d/ 2>/dev/null)
    if ($pamSC) {
        $FindingDetails += "  PAM smartcard modules found:" + $nl
        foreach ($line in ($pamSC -split $nl)) {
            if ($line.Trim()) {
                $FindingDetails += "    $($line.Trim())" + $nl
            }
        }
    }
    else {
        $FindingDetails += "  No PAM smartcard authentication configured" + $nl
    }
    $FindingDetails += $nl

    $FindingDetails += "--- Check 4: SSSD Smartcard Authentication ---" + $nl
    $sssdSC = $(timeout 5 grep -iE "pam_cert_auth|certificate" /etc/sssd/sssd.conf 2>/dev/null)
    if ($sssdSC) {
        $FindingDetails += "  SSSD smartcard config:" + $nl
        foreach ($line in ($sssdSC -split $nl)) {
            $FindingDetails += "    $($line.Trim())" + $nl
        }
    }
    else {
        $FindingDetails += "  No SSSD smartcard configuration found" + $nl
    }

    # Status determination
    if ($pkgInstalled -ge 2 -and $pcscdStatus -eq "active") {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: Smartcard infrastructure detected but PIV credential" + $nl
        $FindingDetails += "verification requires organizational configuration of trust" + $nl
        $FindingDetails += "anchors and certificate validation policies." + $nl
    }
    else {
        $Status = "Open"
        $FindingDetails += $nl + "RESULT: PIV credential verification infrastructure not fully" + $nl
        $FindingDetails += "deployed. Required: opensc, pcscd, libpam-pkcs11 or SSSD" + $nl
        $FindingDetails += "with certificate authentication." + $nl
    }
''')


def main():
    with open(MODULE_PATH, "r", encoding="utf-8-sig") as f:
        content = f.read()

    replacements = 0
    for vuln_id, impl in IMPLEMENTATIONS.items():
        func_name = f"Get-{vuln_id.replace('-', '')}"
        # Find the stub function boundaries
        pattern = rf'(Function {func_name} \{{.*?\n\}})'
        match = re.search(pattern, content, re.DOTALL)
        if match:
            old_func = match.group(1)
            content = content.replace(old_func, impl, 1)
            replacements += 1
            print(f"  Replaced {vuln_id} ({func_name})")
        else:
            print(f"  WARNING: Could not find {func_name} in module")

    with open(MODULE_PATH, "w", encoding="utf-8-sig") as f:
        f.write(content)

    print(f"\nSUCCESS: {replacements}/10 functions replaced")


if __name__ == "__main__":
    main()
