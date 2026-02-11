Function Get-V264344 {
    # PSScriptAnalyzer incorrectly flags these as unused - they are used in conditional logic
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'hasTOTPConfig')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'hasLDAPMFA')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'hasSAMLMFA')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'configCheck')]

    # Suppress false positive PSScriptAnalyzer warnings.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingCmdletAliases', '', Justification='echo is used as bash command, not PowerShell alias')]

    <#
    .DESCRIPTION
        Vuln ID    : V-264344
        STIG ID    : SRG-APP-000001-WSR-000001
        Rule ID    : SV-264344r508029_rule
        CCI ID     : CCI-000001
        Rule Name  : SRG-APP-000001-WSR-000001
        Rule Title : The web server must use multifactor authentication for network access to privileged accounts requiring MFA strength verification.
        DiscussMD5 : 68D4B03CACD1180E6744F482FFECD824
        CheckMD5   : 3D72FE4062F070C9FAE89B5CC4AF9A08
        FixMD5     : 8C1AD4B16B88F25387882F99401E275C
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
    $VulnID = "V-264344"
    $RuleID = "SV-264344r508029_rule"
    $Status = "Open"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $nl = [Environment]::NewLine
    $output = @()

    $output += "Vulnerability ID: ${VulnID}${nl}"
    $output += "Rule ID: ${RuleID}${nl}"
    $output += "CAT II / Medium - Multifactor Authentication Strength Requirements${nl}"
    $output += "---[Organizational Policy Check]---${nl}${nl}"

    # Check 1: Detect MFA method documentation (informational only)
    $output += "Check 1: MFA Method Detection${nl}"
    $hasTOTPConfig = $false
    $hasLDAPMFA = $false
    $hasSAMLMFA = $false

    try {
        # Check for TOTP/2FA npm packages (informational)
        $configCheck = $(grep -i "mfa\|totp\|authentication" /opt/xo/xo-server/config.toml 2>&1)
        if ($configCheck) {
            $output += "  [INFO] Authentication configuration detected in config.toml${nl}"
        }

        $totpPackages = $(npm list --prefix /opt/xo/xo-src/xen-orchestra/packages/xo-server 2>&1 | grep -iE 'authenticator|totp|2fa|otp' | head -5)
        if ($totpPackages) {
            $hasTOTPConfig = $true
            $output += "  [INFO] TOTP/OTP-related npm packages detected${nl}"
        }

        # Check for LDAP/AD MFA integration
        $ldapConfig = $(grep -i "ldap" /opt/xo/xo-server/config.toml 2>&1)
        if ($ldapConfig) {
            $hasLDAPMFA = $true
            $output += "  [INFO] LDAP authentication configuration detected${nl}"
            $output += "        Note: LDAP may delegate MFA to Active Directory${nl}"
        }

        # Check for SAML/SSO integration
        $samlConfig = $(grep -i "saml" /opt/xo/xo-server/config.toml 2>&1)
        if ($samlConfig) {
            $hasSAMLMFA = $true
            $output += "  [INFO] SAML authentication configuration detected${nl}"
            $output += "        Note: SAML may delegate to external IdP${nl}"
        }

        if (-not ($hasTOTPConfig -or $hasLDAPMFA -or $hasSAMLMFA)) {
            $output += "  [WARN] No explicit MFA configuration detected${nl}"
            $output += "        This does NOT mean MFA is absent - may be handled externally${nl}"
        }
    }
    catch {
        $output += "  [INFO] Error checking MFA configuration: $($_.Exception.Message)${nl}"
    }
    $output += ${nl}

    # Check 2: MFA Strength Level Verification (policy requirement)
    $output += "Check 2: MFA Strength Level Requirements${nl}"
    $output += "  [MANUAL] Cannot automatically verify MFA strength compliance${nl}"
    $output += ${nl}
    $output += "  DoD 8500.01 MFA strength requirements:${nl}"
    $output += "  - FIPS 140-2 validated cryptographic modules${nl}"
    $output += "  - CAC/PIV preferred for privileged access${nl}"
    $output += "  - Hardware tokens (FIPS 140-2 compliant)${nl}"
    $output += "  - Approved biometric systems (multi-factor with liveness detection)${nl}"
    $output += "  - Software tokens (TOTP) acceptable for non-privileged access only${nl}"
    $output += ${nl}

    # Check 3: MFA Policy Compliance Documentation
    $output += "Check 3: Organizational MFA Policy Compliance${nl}"
    $output += "  [MANUAL] Requires ISSO/ISSM verification${nl}"
    $output += ${nl}
    $output += "  Required documentation:${nl}"
    $output += "  - MFA implementation plan (strength levels per account type)${nl}"
    $output += "  - Authentication mechanism approval by ISSO/ISSM${nl}"
    $output += "  - FIPS 140-2 validation certificates for cryptographic modules${nl}"
    $output += "  - MFA enrollment/revocation procedures${nl}"
    $output += "  - Exception/waiver documentation (if applicable)${nl}"
    $output += ${nl}

    # Check 4: Authentication Factor Types
    $output += "Check 4: Authentication Factor Type Analysis${nl}"
    $output += "  Required: At least TWO of the following three factor types:${nl}"
    $output += ${nl}
    $output += "  Factor Type 1 - Something you KNOW:${nl}"
    $output += "    - Password/PIN (DoD complexity requirements)${nl}"
    $output += "    - Memorized secret${nl}"
    $output += ${nl}
    $output += "  Factor Type 2 - Something you HAVE:${nl}"
    $output += "    - CAC/PIV card (preferred for privileged access)${nl}"
    $output += "    - Hardware TOTP token (FIPS 140-2 validated)${nl}"
    $output += "    - Software TOTP (acceptable for non-privileged)${nl}"
    $output += "    - Mobile authenticator app${nl}"
    $output += ${nl}
    $output += "  Factor Type 3 - Something you ARE:${nl}"
    $output += "    - Fingerprint (with liveness detection)${nl}"
    $output += "    - Facial recognition (DoD-approved system)${nl}"
    $output += "    - Iris scan${nl}"
    $output += ${nl}

    # Check 5: Organizational MFA Strength Approval
    $output += "Check 5: MFA Strength Approval Status${nl}"
    $output += "  [MANUAL] Cannot automatically verify ISSO/ISSM approval${nl}"
    $output += ${nl}
    $output += "  Verification steps for ISSO/ISSM:${nl}"
    $output += "  1. Review XO authentication architecture${nl}"
    $output += "  2. Identify MFA methods configured for privileged accounts${nl}"
    $output += "  3. Verify FIPS 140-2 compliance of cryptographic modules${nl}"
    $output += "  4. Confirm MFA strength meets role-based requirements${nl}"
    $output += "  5. Validate enrollment/revocation procedures${nl}"
    $output += "  6. Document approval in security authorization package${nl}"
    $output += ${nl}

    # Assessment
    $output += "Assessment:${nl}"
    $output += "  Finding: Open${nl}"
    $output += "  Reason: MFA strength verification requires organizational policy review${nl}"
    $output += ${nl}
    $output += "Required Manual Verification:${nl}"
    $output += "  1. Obtain MFA implementation documentation from system administrators${nl}"
    $output += "  2. Review authentication mechanisms configured for privileged accounts${nl}"
    $output += "  3. Verify FIPS 140-2 validation certificates for cryptographic modules${nl}"
    $output += "  4. Confirm CAC/PIV usage for administrative access (preferred)${nl}"
    $output += "  5. Validate MFA strength levels meet DoD 8500.01 requirements${nl}"
    $output += "  6. Document ISSO/ISSM approval in security authorization package${nl}"
    $output += "  7. If using LDAP/SAML: verify external IdP MFA strength compliance${nl}"
    $output += ${nl}
    $output += "Organizational Context:${nl}"
    $output += "  - XO integrates with Microsoft Active Directory (LDAP)${nl}"
    $output += "  - AD may enforce MFA via Group Policy${nl}"
    $output += "  - CAC/PIV authentication preferred for privileged access${nl}"
    $output += "  - SAML/SSO may delegate to external identity provider${nl}"
    $output += "  - MFA strength must align with account privilege level${nl}"
    $output += ${nl}
    $output += "Note: This is an ORGANIZATIONAL POLICY check. Technical detection of MFA${nl}"
    $output += "configuration does NOT constitute compliance - ISSO/ISSM must verify that${nl}"
    $output += "MFA strength levels meet DoD requirements based on account privilege levels.${nl}"

    $FindingDetails = $output -join ""
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
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
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
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
    }

    return Send-CheckResult @SendCheckParams
}
