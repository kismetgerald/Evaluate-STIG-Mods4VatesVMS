# ============================================================================
# Priority 3: Process/Service Checks - V-206379 to V-206383
# ============================================================================

Function Get-V206379 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206379
        STIG ID    : SRG-APP-000144-WSR-000016
        Rule ID    : SV-206379r508029_rule
        Rule Title : The web server must perform RFC 5280-compliant certificate validation.
        DiscussMD5 : 12345678901234567890123456789012
        CheckMD5   : 12345678901234567890123456789012
        FixMD5     : 12345678901234567890123456789012
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
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
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$ESPath,

        [Parameter(Mandatory = $false)]
        [String]$LogPath,

        [Parameter(Mandatory = $false)]
        [String]$LogComponent,

        [Parameter(Mandatory = $false)]
        [String]$OSPlatform
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-206379"
    $RuleID = "SV-206379r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    $output = "Check 1: Certificate Validation Configuration$nl"

    try {
        # Check nginx SSL configuration
        $nginxConfig = "/etc/nginx/conf.d/xo-server.conf"
        if (Test-Path $nginxConfig) {
            $config = Get-Content $nginxConfig -Raw
            $output += "   Nginx Configuration: FOUND$nl"

            # Check for ssl_verify_client directive
            if ($config -match 'ssl_verify_client\s+on') {
                $output += "   Client certificate verification: ENABLED$nl"
                $clientCertVerification = $true
            }
            elseif ($config -match 'ssl_verify_client\s+off') {
                $output += "   Client certificate verification: DISABLED$nl"
                $clientCertVerification = $false
            }
            else {
                $output += "   Client certificate verification: NOT CONFIGURED$nl"
                $clientCertVerification = $false
            }

            # Check for ssl_verify_depth
            if ($config -match 'ssl_verify_depth\s+(\d+)') {
                $verifyDepth = $matches[1]
                $output += "   Certificate verification depth: $verifyDepth$nl"
                if ($verifyDepth -ge 1) {
                    $output += "   [GOOD] Verification depth is adequate$nl"
                }
                else {
                    $output += "   [WARN] Verification depth may be insufficient$nl"
                }
            }
            else {
                $output += "   Certificate verification depth: NOT SET (using default)$nl"
            }

            # Check for CA certificate configuration
            if ($config -match 'ssl_client_certificate\s+([^;]+);') {
                $caCert = $matches[1].Trim()
                $output += "   CA Certificate configured: $caCert$nl"
                if (Test-Path $caCert) {
                    $output += "   CA Certificate file: EXISTS$nl"
                }
                else {
                    $output += "   [WARN] CA Certificate file: NOT FOUND$nl"
                }
            }
            else {
                $output += "   CA Certificate: NOT CONFIGURED$nl"
            }
        }
        else {
            $output += "   Nginx Configuration: NOT FOUND$nl"
        }

        # Check Node.js/OpenSSL certificate validation
        $output += "$nl" + "Check 2: Node.js Certificate Validation$nl"

        # Check if Node.js is configured to reject unauthorized certificates
        $nodeRejectUnauthorized = $env:NODE_TLS_REJECT_UNAUTHORIZED
        if ($nodeRejectUnauthorized -eq "0") {
            $output += "   [WARN] NODE_TLS_REJECT_UNAUTHORIZED = 0 (certificate validation disabled)$nl"
        }
        elseif ($nodeRejectUnauthorized -eq "1" -or -not $nodeRejectUnauthorized) {
            $output += "   NODE_TLS_REJECT_UNAUTHORIZED: ENABLED (default)$nl"
        }

        # Check XO server configuration for TLS settings
        $xoConfigPath = "/opt/xo/xo-server/config.toml"
        if (Test-Path $xoConfigPath) {
            $xoConfig = Get-Content $xoConfigPath -Raw
            $output += "$nl" + "XO Server TLS Configuration:$nl"

            # Check for certificate validation settings
            $tlsSettings = @('rejectUnauthorized', 'checkServerIdentity', 'ca', 'cert', 'key')
            $tlsConfigured = $false
            foreach ($setting in $tlsSettings) {
                if ($xoConfig -match "$setting\s*=") {
                    $output += "   TLS setting found: $setting$nl"
                    $tlsConfigured = $true
                }
            }

            if (-not $tlsConfigured) {
                $output += "   No explicit TLS validation settings found$nl"
            }
        }
        else {
            $output += "   XO Config: NOT FOUND$nl"
        }

        # Check system certificate store
        $output += "$nl" + "Check 3: System Certificate Store$nl"

        $caCertDirs = @("/etc/ssl/certs", "/usr/local/share/ca-certificates")
        $certsFound = $false
        foreach ($dir in $caCertDirs) {
            if (Test-Path $dir) {
                $certCount = (Get-ChildItem $dir -ErrorAction SilentlyContinue | Measure-Object).Count
                $output += "   CA Certificates in $dir : $certCount found$nl"
                if ($certCount -gt 0) {
                    $certsFound = $true
                }
            }
        }

        if (-not $certsFound) {
            $output += "   [WARN] No CA certificates found in standard locations$nl"
        }

    }
    catch {
        $output += "   [ERROR] Failed to check certificate validation: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Web server should perform RFC 5280-compliant certificate validation.$nl"
    $output += "   This includes verifying certificate chains, expiration dates, and revocation status.$nl"
    $output += "   Default XO configurations may not include client certificate validation.$nl"
    $output += "   Manual review required to ensure compliance with organizational requirements.$nl"

    $FindingDetails = $output
    $Status = "Not_Reviewed"

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

Function Get-V206380 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206380
        STIG ID    : SRG-APP-000145-WSR-000072
        Rule ID    : SV-206380r508029_rule
        Rule Title : The web server must perform RFC 5280-compliant certificate path validation.
        DiscussMD5 : 12345678901234567890123456789012
        CheckMD5   : 12345678901234567890123456789012
        FixMD5     : 12345678901234567890123456789012
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
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
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$ESPath,

        [Parameter(Mandatory = $false)]
        [String]$LogPath,

        [Parameter(Mandatory = $false)]
        [String]$LogComponent,

        [Parameter(Mandatory = $false)]
        [String]$OSPlatform
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-206380"
    $RuleID = "SV-206380r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    $output = "Check 1: Certificate Path Validation Configuration$nl"

    try {
        # Check nginx SSL configuration for certificate path validation
        $nginxConfig = "/etc/nginx/conf.d/xo-server.conf"
        if (Test-Path $nginxConfig) {
            $config = Get-Content $nginxConfig -Raw
            $output += "   Nginx Configuration: FOUND$nl"

            # Check for ssl_verify_client directive (implies path validation)
            if ($config -match 'ssl_verify_client\s+on') {
                $output += "   Client certificate verification: ENABLED$nl"
                $pathValidation = $true
            }
            elseif ($config -match 'ssl_verify_client\s+off') {
                $output += "   Client certificate verification: DISABLED$nl"
                $pathValidation = $false
            }
            else {
                $output += "   Client certificate verification: NOT CONFIGURED$nl"
                $pathValidation = $false
            }

            # Check for ssl_verify_depth (certificate chain depth)
            if ($config -match 'ssl_verify_depth\s+(\d+)') {
                $verifyDepth = $matches[1]
                $output += "   Certificate chain verification depth: $verifyDepth$nl"
                if ($verifyDepth -ge 1) {
                    $output += "   [GOOD] Chain verification depth is adequate$nl"
                }
                else {
                    $output += "   [WARN] Chain verification depth may be insufficient$nl"
                }
            }
            else {
                $output += "   Certificate chain verification depth: NOT SET$nl"
            }

            # Check for CA certificate configuration
            if ($config -match 'ssl_client_certificate\s+([^;]+);') {
                $caCert = $matches[1].Trim()
                $output += "   CA Certificate configured: $caCert$nl"
                if (Test-Path $caCert) {
                    $output += "   CA Certificate file: EXISTS$nl"
                    # Check if CA file contains valid certificates
                    try {
                        $certCount = (Get-Content $caCert | Where-Object { $_ -match '-----BEGIN CERTIFICATE-----' } | Measure-Object).Count
                        $output += "   CA certificates in file: $certCount$nl"
                    }
                    catch {
                        $output += "   [WARN] Could not parse CA certificate file$nl"
                    }
                }
                else {
                    $output += "   [WARN] CA Certificate file: NOT FOUND$nl"
                }
            }
            else {
                $output += "   CA Certificate: NOT CONFIGURED$nl"
            }
        }
        else {
            $output += "   Nginx Configuration: NOT FOUND$nl"
        }

        # Check Node.js certificate validation settings
        $output += "$nl" + "Check 2: Node.js Certificate Path Validation$nl"

        # Check NODE_TLS_REJECT_UNAUTHORIZED
        $nodeRejectUnauthorized = $env:NODE_TLS_REJECT_UNAUTHORIZED
        if ($nodeRejectUnauthorized -eq "0") {
            $output += "   [WARN] NODE_TLS_REJECT_UNAUTHORIZED = 0 (path validation disabled)$nl"
        }
        elseif ($nodeRejectUnauthorized -eq "1" -or -not $nodeRejectUnauthorized) {
            $output += "   NODE_TLS_REJECT_UNAUTHORIZED: ENABLED (default)$nl"
        }

        # Check XO server configuration
        $xoConfigPath = "/opt/xo/xo-server/config.toml"
        if (Test-Path $xoConfigPath) {
            $xoConfig = Get-Content $xoConfigPath -Raw
            $output += "$nl" + "XO Server Certificate Configuration:$nl"

            # Look for certificate-related settings
            $certSettings = @('ca', 'cert', 'key', 'rejectUnauthorized', 'checkServerIdentity')
            $certConfigured = $false
            foreach ($setting in $certSettings) {
                if ($xoConfig -match "$setting\s*=") {
                    $output += "   Certificate setting found: $setting$nl"
                    $certConfigured = $true
                }
            }

            if (-not $certConfigured) {
                $output += "   No explicit certificate validation settings found$nl"
            }
        }
        else {
            $output += "   XO Config: NOT FOUND$nl"
        }

        # Check system certificate store for trusted CAs
        $output += "$nl" + "Check 3: System Certificate Authorities$nl"

        $caCertDirs = @("/etc/ssl/certs", "/usr/local/share/ca-certificates")
        $trustedCAs = 0
        foreach ($dir in $caCertDirs) {
            if (Test-Path $dir) {
                $certFiles = Get-ChildItem $dir -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.pem', '.crt', '.cer') }
                $trustedCAs += $certFiles.Count
                $output += "   Trusted CA certificates in $dir : $($certFiles.Count)$nl"
            }
        }

        if ($trustedCAs -eq 0) {
            $output += "   [WARN] No trusted CA certificates found$nl"
        }
        else {
            $output += "   Total trusted CA certificates: $trustedCAs$nl"
        }

    }
    catch {
        $output += "   [ERROR] Failed to check certificate path validation: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Web server should perform RFC 5280-compliant certificate path validation.$nl"
    $output += "   This includes validating the certificate chain from the end entity certificate$nl"
    $output += "   to a trusted root CA, checking for certificate revocation, and ensuring$nl"
    $output += "   all intermediate certificates are valid.$nl"
    $output += "   Manual review required to verify proper certificate path validation.$nl"

    $FindingDetails = $output
    $Status = "Not_Reviewed"

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

Function Get-V206381 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206381
        STIG ID    : SRG-APP-000146-WSR-000077
        Rule ID    : SV-206381r508029_rule
        Rule Title : The web server must perform RFC 5280-compliant certificate revocation checking.
        DiscussMD5 : 12345678901234567890123456789012
        CheckMD5   : 12345678901234567890123456789012
        FixMD5     : 12345678901234567890123456789012
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
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
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$ESPath,

        [Parameter(Mandatory = $false)]
        [String]$LogPath,

        [Parameter(Mandatory = $false)]
        [String]$LogComponent,

        [Parameter(Mandatory = $false)]
        [String]$OSPlatform
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-206381"
    $RuleID = "SV-206381r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    $output = "Check 1: Certificate Revocation Checking Configuration$nl"

    try {
        # Check nginx configuration for OCSP/CRL settings
        $nginxConfig = "/etc/nginx/conf.d/xo-server.conf"
        if (Test-Path $nginxConfig) {
            $config = Get-Content $nginxConfig -Raw
            $output += "   Nginx Configuration: FOUND$nl"

            # Check for OCSP stapling
            if ($config -match 'ssl_stapling\s+on') {
                $output += "   OCSP Stapling: ENABLED$nl"
                $ocspEnabled = $true
            }
            elseif ($config -match 'ssl_stapling\s+off') {
                $output += "   OCSP Stapling: DISABLED$nl"
                $ocspEnabled = $false
            }
            else {
                $output += "   OCSP Stapling: NOT CONFIGURED$nl"
                $ocspEnabled = $false
            }

            # Check for OCSP responder URL
            if ($config -match 'ssl_stapling_responder\s+([^;]+);') {
                $ocspResponder = $matches[1].Trim()
                $output += "   OCSP Responder: $ocspResponder$nl"
            }
            else {
                $output += "   OCSP Responder: NOT CONFIGURED$nl"
            }

            # Check for CRL configuration
            if ($config -match 'ssl_crl\s+([^;]+);') {
                $crlFile = $matches[1].Trim()
                $output += "   CRL File configured: $crlFile$nl"
                if (Test-Path $crlFile) {
                    $output += "   CRL File: EXISTS$nl"
                    # Check CRL file size (basic validation)
                    $crlSize = (Get-Item $crlFile -ErrorAction SilentlyContinue).Length
                    $output += "   CRL File size: $([math]::Round($crlSize/1024, 2)) KB$nl"
                }
                else {
                    $output += "   [WARN] CRL File: NOT FOUND$nl"
                }
            }
            else {
                $output += "   CRL File: NOT CONFIGURED$nl"
            }

            # Check for ssl_verify_client (implies revocation checking)
            if ($config -match 'ssl_verify_client\s+on') {
                $output += "   Client certificate verification: ENABLED$nl"
                $output += "   [NOTE] Client cert verification may include revocation checking$nl"
            }
        }
        else {
            $output += "   Nginx Configuration: NOT FOUND$nl"
        }

        # Check Node.js/OpenSSL revocation settings
        $output += "$nl" + "Check 2: Node.js Certificate Revocation$nl"

        # Check for OpenSSL configuration
        $opensslConf = "/etc/ssl/openssl.cnf"
        if (Test-Path $opensslConf) {
            $opensslConfig = Get-Content $opensslConf -Raw
            $output += "   OpenSSL Configuration: FOUND$nl"

            # Check for CRL settings in OpenSSL config
            if ($opensslConfig -match '\[.*crl.*\]') {
                $output += "   CRL sections found in OpenSSL config$nl"
            }
            else {
                $output += "   No CRL sections found in OpenSSL config$nl"
            }
        }
        else {
            $output += "   OpenSSL Configuration: NOT FOUND$nl"
        }

        # Check XO server configuration
        $xoConfigPath = "/opt/xo/xo-server/config.toml"
        if (Test-Path $xoConfigPath) {
            $xoConfig = Get-Content $xoConfigPath -Raw
            $output += "$nl" + "XO Server Certificate Settings:$nl"

            # Look for certificate validation settings that might include revocation
            $revocationSettings = @('crl', 'ocsp', 'checkServerIdentity', 'rejectUnauthorized')
            $revocationConfigured = $false
            foreach ($setting in $revocationSettings) {
                if ($xoConfig -match "$setting\s*=") {
                    $output += "   Certificate setting found: $setting$nl"
                    $revocationConfigured = $true
                }
            }

            if (-not $revocationConfigured) {
                $output += "   No explicit certificate revocation settings found$nl"
            }
        }
        else {
            $output += "   XO Config: NOT FOUND$nl"
        }

        # Check for CRL files in system
        $output += "$nl" + "Check 3: Certificate Revocation Lists$nl"

        $crlLocations = @("/etc/ssl/crl", "/usr/local/share/ca-certificates/crl")
        $crlFiles = 0
        foreach ($location in $crlLocations) {
            if (Test-Path $location) {
                $files = Get-ChildItem $location -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.crl', '.pem') }
                $crlFiles += $files.Count
                $output += "   CRL files in $location : $($files.Count)$nl"
            }
        }

        if ($crlFiles -eq 0) {
            $output += "   No CRL files found in standard locations$nl"
        }

    }
    catch {
        $output += "   [ERROR] Failed to check certificate revocation: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Web server should perform RFC 5280-compliant certificate revocation checking.$nl"
    $output += "   This includes checking Certificate Revocation Lists (CRLs) and/or$nl"
    $output += "   Online Certificate Status Protocol (OCSP) responses to ensure$nl"
    $output += "   certificates have not been revoked before accepting them.$nl"
    $output += "   Manual review required to verify revocation checking implementation.$nl"

    $FindingDetails = $output
    $Status = "Not_Reviewed"

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

Function Get-V206382 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206382
        STIG ID    : SRG-APP-000147-WSR-000078
        Rule ID    : SV-206382r508029_rule
        Rule Title : The web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).
        DiscussMD5 : 12345678901234567890123456789012
        CheckMD5   : 12345678901234567890123456789012
        FixMD5     : 12345678901234567890123456789012
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
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
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$ESPath,

        [Parameter(Mandatory = $false)]
        [String]$LogPath,

        [Parameter(Mandatory = $false)]
        [String]$LogComponent,

        [Parameter(Mandatory = $false)]
        [String]$OSPlatform
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-206382"
    $RuleID = "SV-206382r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    $output = "Check 1: Client Certificate CA Configuration$nl"

    try {
        # Check nginx configuration for client certificate CA restrictions
        $nginxConfig = "/etc/nginx/conf.d/xo-server.conf"
        if (Test-Path $nginxConfig) {
            $config = Get-Content $nginxConfig -Raw
            $output += "   Nginx Configuration: FOUND$nl"

            # Check for ssl_client_certificate directive
            if ($config -match 'ssl_client_certificate\s+([^;]+);') {
                $clientCACert = $matches[1].Trim()
                $output += "   Client CA Certificate configured: $clientCACert$nl"

                if (Test-Path $clientCACert) {
                    $output += "   Client CA Certificate file: EXISTS$nl"

                    # Check if the CA file contains DoD PKI certificates
                    # This is a basic check - actual validation would require certificate parsing
                    $certContent = Get-Content $clientCACert -Raw
                    $dodIndicators = @('dod.mil', 'disa.mil', 'army.mil', 'navy.mil', 'airforce.mil', 'usmc.mil', 'uscg.mil')
                    $dodFound = $false
                    foreach ($indicator in $dodIndicators) {
                        if ($certContent -match $indicator) {
                            $output += "   [POTENTIAL] DoD-related certificate authority found ($indicator)$nl"
                            $dodFound = $true
                        }
                    }

                    if (-not $dodFound) {
                        $output += "   [NOTE] No obvious DoD PKI indicators found in CA file$nl"
                        $output += "   Manual review required to verify DoD PKI compliance$nl"
                    }

                    # Count certificates in the file
                    $certCount = ($certContent | Select-String '-----BEGIN CERTIFICATE-----' | Measure-Object).Count
                    $output += "   Number of CA certificates in file: $certCount$nl"

                }
                else {
                    $output += "   [WARN] Client CA Certificate file: NOT FOUND$nl"
                }
            }
            else {
                $output += "   Client CA Certificate: NOT CONFIGURED$nl"
                $output += "   [NOTE] Client certificate authentication may not be enabled$nl"
            }

            # Check ssl_verify_client setting
            if ($config -match 'ssl_verify_client\s+(on|optional)') {
                $verifyMode = $matches[1]
                $output += "   Client certificate verification: $verifyMode$nl"
                if ($verifyMode -eq 'on') {
                    $output += "   [GOOD] Client certificates are required$nl"
                }
                elseif ($verifyMode -eq 'optional') {
                    $output += "   [NOTE] Client certificates are optional$nl"
                }
            }
            elseif ($config -match 'ssl_verify_client\s+off') {
                $output += "   Client certificate verification: DISABLED$nl"
            }
            else {
                $output += "   Client certificate verification: NOT CONFIGURED$nl"
            }
        }
        else {
            $output += "   Nginx Configuration: NOT FOUND$nl"
        }

        # Check system certificate store for DoD PKI CAs
        $output += "$nl" + "Check 2: System Certificate Store$nl"

        $systemCertDirs = @("/etc/ssl/certs", "/usr/local/share/ca-certificates")
        $dodCertsFound = 0

        foreach ($dir in $systemCertDirs) {
            if (Test-Path $dir) {
                $certFiles = Get-ChildItem $dir -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.pem', '.crt', '.cer') }
                $output += "   Checking $dir for DoD certificates...$nl"

                foreach ($certFile in $certFiles) {
                    try {
                        $certContent = Get-Content $certFile.FullName -Raw
                        foreach ($indicator in $dodIndicators) {
                            if ($certContent -match $indicator) {
                                $output += "   DoD certificate found: $($certFile.Name)$nl"
                                $dodCertsFound++
                                break
                            }
                        }
                    }
                    catch {
                        # Skip files that can't be read
                    }
                }
            }
        }

        $output += "   Total DoD-related certificates found: $dodCertsFound$nl"

        # Check XO server configuration
        $xoConfigPath = "/opt/xo/xo-server/config.toml"
        if (Test-Path $xoConfigPath) {
            $xoConfig = Get-Content $xoConfigPath -Raw
            $output += "$nl" + "XO Server Certificate Configuration:$nl"

            # Look for certificate-related settings
            $certSettings = @('ca', 'clientCA', 'cert', 'key')
            $certConfigured = $false
            foreach ($setting in $certSettings) {
                if ($xoConfig -match "$setting\s*=") {
                    $output += "   Certificate setting found: $setting$nl"
                    $certConfigured = $true
                }
            }

            if (-not $certConfigured) {
                $output += "   No explicit certificate settings found in XO config$nl"
            }
        }
        else {
            $output += "   XO Config: NOT FOUND$nl"
        }

    }
    catch {
        $output += "   [ERROR] Failed to check client certificate CA configuration: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Web server should only accept client certificates issued by DoD PKI$nl"
    $output += "   or DoD-approved PKI Certification Authorities (CAs).$nl"
    $output += "   This requirement ensures that only authorized users with proper$nl"
    $output += "   DoD credentials can access the web server.$nl"
    $output += "   Manual review required to verify DoD PKI CA configuration.$nl"

    $FindingDetails = $output
    $Status = "Not_Reviewed"

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

Function Get-V206383 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206383
        STIG ID    : SRG-APP-000149-WSR-000087
        Rule ID    : SV-206383r508029_rule
        Rule Title : The web server must be configured to use a specified IP address and port.
        DiscussMD5 : 12345678901234567890123456789012
        CheckMD5   : 12345678901234567890123456789012
        FixMD5     : 12345678901234567890123456789012
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
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
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$ESPath,

        [Parameter(Mandatory = $false)]
        [String]$LogPath,

        [Parameter(Mandatory = $false)]
        [String]$LogComponent,

        [Parameter(Mandatory = $false)]
        [String]$OSPlatform
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-206383"
    $RuleID = "SV-206383r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#

    $output = "Check 1: Web Server IP Address and Port Configuration$nl"

    try {
        # Check nginx configuration for listen directives
        $nginxConfig = "/etc/nginx/conf.d/xo-server.conf"
        if (Test-Path $nginxConfig) {
            $config = Get-Content $nginxConfig -Raw
            $output += "   Nginx Configuration: FOUND$nl"

            # Find all listen directives
            $listenMatches = [regex]::Matches($config, 'listen\s+([^;]+);')
            if ($listenMatches.Count -gt 0) {
                $output += "   Listen directives found: $($listenMatches.Count)$nl"

                $listenConfigs = @()
                foreach ($match in $listenMatches) {
                    $listenConfig = $match.Groups[1].Value.Trim()
                    $listenConfigs += $listenConfig
                    $output += "   Listen: $listenConfig$nl"

                    # Parse IP address and port
                    if ($listenConfig -match '(\d+\.\d+\.\d+\.\d+):(\d+)') {
                        $ip = $matches[1]
                        $port = $matches[2]
                        $output += "     IP: $ip, Port: $port$nl"

                        # Check for non-specific IP addresses
                        if ($ip -eq '0.0.0.0') {
                            $output += "     [WARN] Listening on all interfaces (0.0.0.0)$nl"
                        }
                        elseif ($ip -eq '127.0.0.1' -or $ip -eq 'localhost') {
                            $output += "     [NOTE] Listening on localhost only$nl"
                        }
                        else {
                            $output += "     [INFO] Listening on specific IP: $ip$nl"
                        }

                        # Check port
                        if ($port -eq '80' -or $port -eq '443') {
                            $output += "     [INFO] Standard web port: $port$nl"
                        }
                        elseif ($port -ge 1024 -and $port -le 65535) {
                            $output += "     [INFO] Non-privileged port: $port$nl"
                        }
                        else {
                            $output += "     [WARN] Privileged port (< 1024): $port$nl"
                        }
                    }
                    elseif ($listenConfig -match ':(\d+)') {
                        $port = $matches[1]
                        $output += "     Port: $port (IP not specified - defaults to all interfaces)$nl"
                        $output += "     [WARN] No specific IP address configured$nl"
                    }
                    elseif ($listenConfig -match '(\d+)') {
                        $port = $matches[1]
                        $output += "     Port: $port (IP not specified - defaults to all interfaces)$nl"
                        $output += "     [WARN] No specific IP address configured$nl"
                    }
                }

                # Check for SSL/TLS configuration
                $sslConfigured = $false
                if ($config -match 'ssl\s+on') {
                    $output += "   SSL/TLS: ENABLED$nl"
                    $sslConfigured = $true
                }
                elseif ($config -match 'ssl_certificate\s+[^;]+;') {
                    $output += "   SSL/TLS: ENABLED (certificate configured)$nl"
                    $sslConfigured = $true
                }
                else {
                    $output += "   SSL/TLS: NOT CONFIGURED$nl"
                }

                # Check for default server
                if ($config -match 'default_server') {
                    $output += "   Default server: YES$nl"
                }
                else {
                    $output += "   Default server: NO$nl"
                }

            }
            else {
                $output += "   [WARN] No listen directives found$nl"
            }
        }
        else {
            $output += "   Nginx Configuration: NOT FOUND$nl"
        }

        # Check XO server configuration for port settings
        $output += "$nl" + "Check 2: XO Server Configuration$nl"

        $xoConfigPath = "/opt/xo/xo-server/config.toml"
        if (Test-Path $xoConfigPath) {
            $xoConfig = Get-Content $xoConfigPath -Raw
            $output += "   XO Configuration: FOUND$nl"

            # Check for port configuration
            if ($xoConfig -match 'port\s*=\s*(\d+)') {
                $xoPort = $matches[1]
                $output += "   XO Server Port: $xoPort$nl"
            }
            else {
                $output += "   XO Server Port: NOT SPECIFIED (using default)$nl"
            }

            # Check for host/interface configuration
            if ($xoConfig -match 'host\s*=\s*"([^"]+)"') {
                $xoHost = $matches[1]
                $output += "   XO Server Host: $xoHost$nl"
            }
            elseif ($xoConfig -match 'host\s*=\s*([^"\s]+)') {
                $xoHost = $matches[1]
                $output += "   XO Server Host: $xoHost$nl"
            }
            else {
                $output += "   XO Server Host: NOT SPECIFIED (using default)$nl"
            }
        }
        else {
            $output += "   XO Configuration: NOT FOUND$nl"
        }

        # Check systemd service configuration
        $output += "$nl" + "Check 3: Service Configuration$nl"

        $serviceFile = "/etc/systemd/system/xo-server.service"
        if (Test-Path $serviceFile) {
            $serviceConfig = Get-Content $serviceFile -Raw
            $output += "   Systemd Service: FOUND$nl"

            # Check for network-related settings
            if ($serviceConfig -match 'ListenStream|BindToDevice') {
                $output += "   Network binding configured in service$nl"
            }
            else {
                $output += "   No network binding in service configuration$nl"
            }
        }
        else {
            $output += "   Systemd Service: NOT FOUND$nl"
        }

    }
    catch {
        $output += "   [ERROR] Failed to check IP/port configuration: $($_.Exception.Message)$nl"
    }

    # Assessment
    $output += "$nl" + "Assessment:$nl"
    $output += "   Web server should be configured to use a specified IP address and port.$nl"
    $output += "   This prevents the server from listening on unintended interfaces$nl"
    $output += "   and ensures proper network isolation and security.$nl"
    $output += "   Manual review required to verify IP/port configuration meets$nl"
    $output += "   organizational requirements and security policies.$nl"

    $FindingDetails = $output
    $Status = "Not_Reviewed"

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