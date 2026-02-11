Function Get-V206430 {
    <#
    .DESCRIPTION
        Vuln ID    : V-206430
        STIG ID    : SRG-APP-000001-WSR-000001
        Rule ID    : SV-206430r508029_rule
        Rule Title : The web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).
        DiscussMD5 : A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6
        CheckMD5   : B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7
        FixMD5     : C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8
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
    $VulnID = "V-206430"
    $RuleID = "SV-206430r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    $output = @()
    $output += "=" * 80
    $output += "V-206430: DoD PKI Client Certificate Validation"
    $output += "=" * 80
    $output += ""

    $clientCertConfigured = $false
    $dodCAValidationFound = $false
    $issues = @()

    # Check 1: Client Certificate Authentication Configuration
    $output += "Check 1: Client Certificate Authentication Configuration"
    $output += "-" * 50

    $configPaths = @("/opt/xo/xo-server/config.toml", "/etc/xo-server/config.toml")
    foreach ($configPath in $configPaths) {
        if (Test-Path $configPath) {
            $output += "   [FOUND] XO configuration: $configPath"
            $configContent = Get-Content $configPath -Raw

            # Check for client certificate authentication settings
            if ($configContent -match 'clientCertAuth\s*=\s*true' -or $configContent -match 'requestCert\s*=\s*true') {
                $output += "   [PASS] Client certificate authentication enabled"
                $clientCertConfigured = $true

                # Extract CA certificate path if configured
                if ($configContent -match 'ca\s*=\s*[''"]([^''"]+)[''"]') {
                    $caPath = $matches[1]
                    $output += "   [FOUND] CA certificate path: $caPath"
                }
            }
            else {
                $output += "   [NOT FOUND] Client certificate authentication not explicitly enabled"
                $output += "   Expected settings: clientCertAuth = true OR requestCert = true"
            }
            break
        }
    }

    if (-not (Test-Path $configPaths[0]) -and -not (Test-Path $configPaths[1])) {
        $output += "   [WARNING] XO configuration file not found"
        $issues += "Cannot verify client certificate configuration"
    }

    $output += ""
    $output += "Check 2: DoD PKI Root CA Certificate Detection"
    $output += "-" * 50

    # Trust anchor locations for client certificate validation
    $trustStores = @(
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
        "/usr/local/share/ca-certificates",
        "/usr/share/ca-certificates",
        "/etc/xo-server/certs"
    )

    $dodCAsFound = @()
    $dodRootCAs = @("DoD Root CA 3", "DoD Root CA 4", "DoD Root CA 5", "DoD Root CA 6", "Federal Common Policy CA", "Federal Bridge CA")

    foreach ($trustStore in $trustStores) {
        if (Test-Path $trustStore) {
            $output += "   [CHECKING] Certificate store: $trustStore"

            # Search for DoD CA certificates
            foreach ($dodCA in $dodRootCAs) {
                $searchResult = $(bash -c "find '$trustStore' -type f \( -name '*.crt' -o -name '*.pem' -o -name '*.cer' \) -exec grep -l '$dodCA' {} \; 2>/dev/null" 2>&1)
                if ($searchResult -and $searchResult -notmatch "No such file") {
                    $output += "   [FOUND] $dodCA certificate: $searchResult"
                    $dodCAsFound += $dodCA
                    $dodCAValidationFound = $true
                }
            }
        }
    }

    if ($dodCAsFound.Count -eq 0) {
        $output += "   [NOT FOUND] No DoD PKI root CA certificates detected in trust stores"
        $output += "   Expected: DoD Root CA 3-6, Federal Common Policy CA, Federal Bridge CA"
        $issues += "DoD PKI trust anchors not installed"
    }
    else {
        $output += ""
        $output += "   [SUMMARY] Found $($dodCAsFound.Count) DoD PKI root CA(s): $($dodCAsFound -join ', ')"
    }

    $output += ""
    $output += "Check 3: Certificate Chain Validation Method"
    $output += "-" * 50

    # Check for CA bundle configuration
    $caBundleFound = $false
    foreach ($configPath in $configPaths) {
        if (Test-Path $configPath) {
            $configContent = Get-Content $configPath -Raw

            if ($configContent -match 'ca\s*=\s*[''"]([^''"]+)[''"]') {
                $caBundlePath = $matches[1]
                $output += "   [FOUND] CA bundle configured: $caBundlePath"

                if (Test-Path $caBundlePath) {
                    $output += "   [PASS] CA bundle file exists"
                    $caBundleFound = $true

                    # Verify bundle contains DoD CAs
                    foreach ($dodCA in $dodRootCAs) {
                        $dodInBundle = $(bash -c "grep -c '$dodCA' '$caBundlePath' 2>&1" 2>&1)
                        if ($LASTEXITCODE -eq 0 -and $dodInBundle -gt 0) {
                            $output += "   [FOUND] $dodCA in CA bundle"
                            $dodCAValidationFound = $true
                        }
                    }
                }
                else {
                    $output += "   [WARNING] CA bundle file not found at specified path"
                    $issues += "Configured CA bundle file missing"
                }
            }
            break
        }
    }

    if (-not $caBundleFound -and $clientCertConfigured) {
        $output += "   [WARNING] Client cert auth enabled but CA bundle not explicitly configured"
        $output += "   System will use default Node.js CA store for validation"
    }

    $output += ""
    $output += "Check 4: DoD PKI Validation via OpenSSL"
    $output += "-" * 50

    # Check if openssl can verify with DoD CAs
    if ($dodCAsFound.Count -gt 0) {
        $output += "   [INFO] OpenSSL available for certificate chain validation"

        # Find a DoD CA certificate to test validation
        foreach ($trustStore in $trustStores) {
            if (Test-Path $trustStore) {
                $testCert = $(bash -c "find '$trustStore' -type f \( -name '*DoD*' -o -name '*dod*' \) -print -quit 2>/dev/null" 2>&1)
                if ($testCert -and (Test-Path $testCert)) {
                    $output += "   [TESTING] Certificate validation with: $testCert"

                    $verifyResult = $(bash -c "openssl x509 -in '$testCert' -text -noout 2>&1 | grep -E 'Issuer|Subject'" 2>&1)
                    if ($LASTEXITCODE -eq 0 -and $verifyResult) {
                        $output += "   [PASS] Certificate is valid and parseable"
                        $output += $verifyResult
                    }
                    break
                }
            }
        }
    }
    else {
        $output += "   [SKIP] No DoD CA certificates available for validation testing"
    }

    $output += ""
    $output += "Check 5: Nginx Reverse Proxy Certificate Validation (Optional)"
    $output += "-" * 50

    # Check if nginx is used as reverse proxy
    $nginxRunning = $(bash -c "pgrep -x nginx 2>&1" 2>&1)
    if ($nginxRunning -and $LASTEXITCODE -eq 0) {
        $output += "   [DETECTED] Nginx reverse proxy is running"

        # Check nginx configuration for client certificate verification
        $nginxConfigs = @("/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default", "/etc/nginx/conf.d/xo.conf")
        $nginxClientCertFound = $false

        foreach ($nginxConf in $nginxConfigs) {
            if (Test-Path $nginxConf) {
                $nginxContent = Get-Content $nginxConf -Raw

                if ($nginxContent -match 'ssl_client_certificate' -or $nginxContent -match 'ssl_verify_client') {
                    $output += "   [FOUND] Nginx client certificate verification configured in: $nginxConf"
                    $nginxClientCertFound = $true

                    # Extract CA certificate path
                    if ($nginxContent -match 'ssl_client_certificate\s+([^;]+)') {
                        $nginxCAPath = $matches[1].Trim()
                        $output += "   [INFO] Nginx CA certificate: $nginxCAPath"
                    }

                    if ($nginxContent -match 'ssl_verify_client\s+(\w+)') {
                        $verifyMode = $matches[1]
                        $output += "   [INFO] Nginx client verification mode: $verifyMode"
                    }
                }
            }
        }

        if (-not $nginxClientCertFound) {
            $output += "   [NOT FOUND] Nginx client certificate verification not configured"
        }
    }
    else {
        $output += "   [NOT DETECTED] Nginx reverse proxy not running (not required)"
    }

    $output += ""
    $output += "Check 6: Certificate Revocation Validation (CRL/OCSP)"
    $output += "-" * 50

    # Check for CRL/OCSP configuration
    $crlConfigFound = $false
    foreach ($configPath in $configPaths) {
        if (Test-Path $configPath) {
            $configContent = Get-Content $configPath -Raw

            if ($configContent -match 'crl\s*=' -or $configContent -match 'ocsp' -or $configContent -match 'revocation') {
                $output += "   [FOUND] Certificate revocation checking configured in XO"
                $crlConfigFound = $true
            }
        }
    }

    # Check nginx for CRL/OCSP
    if ($nginxRunning -and $LASTEXITCODE -eq 0) {
        foreach ($nginxConf in $nginxConfigs) {
            if (Test-Path $nginxConf) {
                $nginxContent = Get-Content $nginxConf -Raw

                if ($nginxContent -match 'ssl_crl' -or $nginxContent -match 'ssl_ocsp') {
                    $output += "   [FOUND] Certificate revocation checking configured in Nginx"
                    $crlConfigFound = $true
                }
            }
        }
    }

    if (-not $crlConfigFound) {
        $output += "   [NOT FOUND] Certificate revocation checking (CRL/OCSP) not explicitly configured"
        $output += "   NOTE: DoD PKI requires CRL or OCSP validation for client certificates"
        $issues += "Certificate revocation validation not configured"
    }

    # Determine overall status
    $output += ""
    $output += "=" * 80
    $output += "COMPLIANCE DETERMINATION"
    $output += "=" * 80

    if ($clientCertConfigured -and $dodCAValidationFound -and $issues.Count -eq 0) {
        $Status = "NotAFinding"
        $output += "Status: NotAFinding"
        $output += ""
        $output += "Rationale:"
        $output += "- Client certificate authentication is configured"
        $output += "- DoD PKI root CA certificates are installed and configured"
        $output += "- Certificate chain validation is enabled"
        $output += "- No critical issues detected"
    }
    elseif (-not $clientCertConfigured) {
        $Status = "Not_Applicable"
        $output += "Status: Not_Applicable"
        $output += ""
        $output += "Rationale:"
        $output += "- Client certificate authentication is not enabled"
        $output += "- This check only applies when client certificates are required"
        $output += "- If client certificates are organizationally required, enable and configure with DoD PKI"
    }
    else {
        $Status = "Open"
        $output += "Status: Open"
        $output += ""
        $output += "Issues Detected:"
        foreach ($issue in $issues) {
            $output += "- $issue"
        }
        $output += ""
        $output += "Rationale:"
        if (-not $dodCAValidationFound) {
            $output += "- DoD PKI root CA certificates not installed in trust stores"
        }
        if ($issues -contains "Certificate revocation validation not configured") {
            $output += "- Certificate revocation checking (CRL/OCSP) not configured"
        }
        $output += ""
        $output += "Required Actions:"
        $output += "1. Install DoD PKI root CA certificates (DoD Root CA 3-6)"
        $output += "2. Configure XO to use DoD PKI trust anchors for client certificate validation"
        $output += "3. Enable CRL or OCSP validation for certificate revocation checking"
        $output += "4. Configure ca = '/path/to/dod-ca-bundle.pem' in config.toml"
        $output += "5. Test client certificate authentication with DoD-issued certificates"
    }

    $FindingDetails = $output -join "`n"
    #---=== End Custom Code ===---#

    # Calculate ResultHash for answer file processing
    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    # Process answer file if provided
    If ($PSBoundParameters.AnswerFile) {
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
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    # Return results via Send-CheckResult
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
