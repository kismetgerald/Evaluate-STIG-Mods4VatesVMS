    param(
        [Parameter(Mandatory=$true)]
        [String]$ScanType,
        [Parameter(Mandatory=$false)]
        [String]$AnswerFile,
        [Parameter(Mandatory=$false)]
        [String]$AnswerKey,
        [Parameter(Mandatory=$false)]
        [String]$Username,
        [Parameter(Mandatory=$false)]
        [String]$UserSID,
        [Parameter(Mandatory=$false)]
        [String]$Hostname,
        [Parameter(Mandatory=$false)]
        [String]$Instance,
        [Parameter(Mandatory=$false)]
        [String]$Database,
        [Parameter(Mandatory=$false)]
        [String]$SiteName
    )

    # Initialize variables
    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-206430"
    $RuleID = "SV-206430r965407_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    # Start finding details
    $FindingDetails = "V-206430 - DoD PKI Client Certificate Validation" + "`n"
    $FindingDetails += "=" * 60 + "`n`n"

    # Tracking variables
    $clientCertConfigured = $false
    $dodCADetected = $false
    $caStoreFound = $false
    $nginxClientCertDetected = $false
    $nodeTLSConfigFound = $false
    $orgPolicyFound = $false
    $dodRootCACount = 0

    # Check 1: TLS Client Certificate Authentication Configuration
    $FindingDetails += "Check 1: TLS Client Certificate Authentication Configuration" + "`n"
    $FindingDetails += "-" * 60 + "`n"

    $configPaths = @("/opt/xo/xo-server/config.toml", "/etc/xo-server/config.toml")
    foreach ($configPath in $configPaths) {
        if (Test-Path $configPath) {
            $FindingDetails += "XO Configuration: $configPath`n"
            $configContent = bash -c "cat '$configPath' 2>&1" 2>&1

            # Check for client certificate authentication settings
            if ($configContent -match 'clientCert|requestCert|ca\s*=') {
                $FindingDetails += "[FOUND] Client certificate authentication settings detected`n"
                $clientCertConfigured = $true

                # Extract CA certificate path if configured
                if ($configContent -match 'ca\s*=\s*[''"]([^''"]+)[''"]') {
                    $caPath = $matches[1]
                    $FindingDetails += "   CA certificate path: $caPath`n"

                    # Check if CA file exists and inspect it
                    if (Test-Path $caPath) {
                        $caCertInfo = bash -c "openssl x509 -in '$caPath' -noout -subject -issuer 2>&1 | head -n 10" 2>&1
                        $FindingDetails += "   CA Certificate Info:`n$caCertInfo`n"

                        if ($caCertInfo -match 'DoD|DOD|Department of Defense|U\.S\. Government') {
                            $FindingDetails += "   [PASS] DoD PKI CA certificate detected`n"
                            $dodCADetected = $true
                        }
                    }
                }
            } else {
                $FindingDetails += "[NOT FOUND] Client certificate authentication not explicitly configured`n"
                $FindingDetails += "Expected settings: clientCert = true, requestCert = true, or ca = &lt;path&gt;`n"
            }
            break
        }
    }

    if (-not (Test-Path $configPaths[0]) -and -not (Test-Path $configPaths[1])) {
        $FindingDetails += "[INFO] XO configuration file not found in standard locations`n"
    }
    $FindingDetails += "`n"

    # Check 2: Certificate Authority Trust Store Locations
    $FindingDetails += "Check 2: Certificate Authority (CA) Trust Store" + "`n"
    $FindingDetails += "-" * 60 + "`n"

    $caStoreLocations = @(
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
        "/usr/local/share/ca-certificates",
        "/etc/ca-certificates"
    )

    foreach ($caStore in $caStoreLocations) {
        if (Test-Path $caStore) {
            $FindingDetails += "CA Store Location: $caStore`n"
            $caStoreFound = $true

            # Count certificates in the store
            $certCount = bash -c "find '$caStore' -type f \( -name '*.crt' -o -name '*.pem' \) 2>/dev/null | wc -l" 2>&1
            $FindingDetails += "   Certificates found: $certCount`n"
        }
    }

    if (-not $caStoreFound) {
        $FindingDetails += "[WARNING] No standard CA trust store locations found`n"
    }
    $FindingDetails += "`n"

    # Check 3: DoD Root CA Certificates Presence
    $FindingDetails += "Check 3: DoD PKI Root CA Certificates Detection" + "`n"
    $FindingDetails += "-" * 60 + "`n"

    $dodCAPatterns = @(
        "DoD_Root_CA",
        "DOD_PKI",
        "DoD_EMAIL_CA",
        "DOD_CA",
        "DoD_CA",
        "DOD_ROOT",
        "Department_of_Defense",
        "U.S._Government"
    )

    foreach ($caStore in $caStoreLocations) {
        if (Test-Path $caStore) {
            foreach ($pattern in $dodCAPatterns) {
                $dodCerts = bash -c "find '$caStore' -type f \( -name '*$pattern*' -o -name '*${pattern}*' \) 2>/dev/null" 2>&1
                if ($dodCerts) {
                    $dodRootCACount += ($dodCerts -split "`n" | Where-Object { $_ }).Count
                    $FindingDetails += "[FOUND] DoD PKI certificates (pattern: $pattern):`n"
                    foreach ($cert in ($dodCerts -split "`n" | Where-Object { $_ } | Select-Object -First 3)) {
                        $certFile = Split-Path -Leaf $cert
                        $FindingDetails += "   - $certFile`n"

                        # Verify certificate subject/issuer
                        $certSubject = bash -c "openssl x509 -in '$cert' -noout -subject 2>&1" 2>&1
                        if ($certSubject -match 'DoD|DOD|Department of Defense|U\.S\. Government') {
                            $FindingDetails += "     Subject: $certSubject`n"
                            $dodCADetected = $true
                        }
                    }
                }
            }
        }
    }

    if ($dodRootCACount -eq 0) {
        $FindingDetails += "[NOT FOUND] No DoD PKI root CA certificates detected in standard locations`n"
        $FindingDetails += "DoD PKI certificates typically contain: DoD, DOD, Department of Defense, U.S. Government`n"
    } else {
        $FindingDetails += "[SUMMARY] Total DoD PKI certificates found: $dodRootCACount`n"
    }
    $FindingDetails += "`n"

    # Check 4: Nginx Reverse Proxy Client Certificate Configuration (Optional)
    $FindingDetails += "Check 4: Nginx Reverse Proxy Client Certificate (Optional)" + "`n"
    $FindingDetails += "-" * 60 + "`n"

    $nginxConfigPaths = @(
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-enabled/default",
        "/etc/nginx/conf.d/xo.conf",
        "/etc/nginx/sites-available/xo"
    )

    $nginxFound = $false
    foreach ($nginxConfig in $nginxConfigPaths) {
        if (Test-Path $nginxConfig) {
            $nginxFound = $true
            $nginxContent = bash -c "cat '$nginxConfig' 2>&1" 2>&1

            if ($nginxContent -match 'ssl_client_certificate|ssl_verify_client') {
                $FindingDetails += "Nginx Config: $nginxConfig`n"
                $FindingDetails += "[FOUND] Client certificate verification configured`n"
                $nginxClientCertDetected = $true

                # Extract ssl_client_certificate path
                if ($nginxContent -match 'ssl_client_certificate\s+([^;]+);') {
                    $nginxCAPath = $matches[1].Trim()
                    $FindingDetails += "   Client CA certificate: $nginxCAPath`n"

                    if (Test-Path $nginxCAPath) {
                        $nginxCAInfo = bash -c "openssl x509 -in '$nginxCAPath' -noout -subject -issuer 2>&1 | head -n 5" 2>&1
                        $FindingDetails += "   CA Info: $nginxCAInfo`n"
                    }
                }

                # Check ssl_verify_client setting
                if ($nginxContent -match 'ssl_verify_client\s+(on|optional);') {
                    $verifyMode = $matches[1]
                    $FindingDetails += "   Verify mode: $verifyMode`n"
                }
            }
            break
        }
    }

    if (-not $nginxFound) {
        $FindingDetails += "[INFO] Nginx reverse proxy not detected (standalone XO deployment)`n"
    } elseif (-not $nginxClientCertDetected) {
        $FindingDetails += "[INFO] Nginx detected but client certificate verification not configured`n"
    }
    $FindingDetails += "`n"

    # Check 5: Node.js TLS Settings for CA Validation
    $FindingDetails += "Check 5: Node.js TLS Configuration" + "`n"
    $FindingDetails += "-" * 60 + "`n"

    # Check environment variables for Node.js TLS CA configuration
    $nodeCAEnv = bash -c "printenv | grep -i 'NODE_EXTRA_CA_CERTS\|SSL_CERT_FILE\|SSL_CERT_DIR' 2>&1" 2>&1
    if ($nodeCAEnv) {
        $FindingDetails += "[FOUND] Node.js CA environment variables:`n$nodeCAEnv`n"
        $nodeTLSConfigFound = $true
    } else {
        $FindingDetails += "[INFO] No Node.js CA environment variables detected`n"
        $FindingDetails += "Environment variables: NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, SSL_CERT_DIR`n"
    }

    # Check if XO process is running with specific CA arguments
    $xoProcess = bash -c "pgrep -fa 'node.*xo-server.*cli\.mjs' 2>&1 | head -n 5" 2>&1
    if ($xoProcess) {
        $FindingDetails += "[INFO] XO server process detected:`n$xoProcess`n"

        if ($xoProcess -match '--tls-ca-file|--ca-file') {
            $FindingDetails += "[FOUND] TLS CA file argument detected in XO process`n"
            $nodeTLSConfigFound = $true
        }
    } else {
        $FindingDetails += "[INFO] XO server process not detected (may not be running)`n"
    }
    $FindingDetails += "`n"

    # Check 6: Organizational PKI Policy Documentation
    $FindingDetails += "Check 6: Organizational PKI Policy Documentation" + "`n"
    $FindingDetails += "-" * 60 + "`n"

    $policySearchPaths = @(
        "/usr/local/share/doc",
        "/opt/docs",
        "/etc/pki/docs",
        "/root",
        "/home"
    )

    $policyDocs = ""
    foreach ($searchPath in $policySearchPaths) {
        if (Test-Path $searchPath) {
            $docSearch = bash -c "find '$searchPath' -maxdepth 2 -type f \( -iname '*pki*policy*' -o -iname '*certificate*policy*' -o -iname '*dod*ca*' -o -iname '*trust*anchor*' \) 2>/dev/null | head -n 5" 2>&1
            if ($docSearch) {
                $policyDocs += $docSearch + "`n"
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($policyDocs)) {
        $FindingDetails += "[INFO] No organizational PKI policy documentation found in standard locations`n"
        $FindingDetails += "Manual verification required: Check for DoD PKI trust anchor documentation`n"
    } else {
        $FindingDetails += "[FOUND] Policy documents:`n$policyDocs`n"
        $orgPolicyFound = $true
    }
    $FindingDetails += "`n"

    # Determine Status (ALWAYS OPEN - Organizational Verification Required)
    $FindingDetails += "=" * 60 + "`n"
    $FindingDetails += "ASSESSMENT SUMMARY" + "`n"
    $FindingDetails += "=" * 60 + "`n"
    $FindingDetails += "Client Certificate Configured: $clientCertConfigured`n"
    $FindingDetails += "DoD CA Detected: $dodCADetected`n"
    $FindingDetails += "DoD Root CA Count: $dodRootCACount`n"
    $FindingDetails += "CA Trust Store Found: $caStoreFound`n"
    $FindingDetails += "Nginx Client Cert Detected: $nginxClientCertDetected`n"
    $FindingDetails += "Node.js TLS Config Found: $nodeTLSConfigFound`n"
    $FindingDetails += "Organizational Policy Found: $orgPolicyFound`n`n"

    # ALWAYS OPEN - Organizational verification required
    $Status = "Open"
    $FindingDetails += "RESULT: Organizational verification required for DoD PKI compliance`n`n"
    $FindingDetails += "DoD REQUIREMENT:`n"
    $FindingDetails += "The web server must ONLY accept client certificates issued by:`n"
    $FindingDetails += "1. DoD PKI Certificate Authorities (CAs)`n"
    $FindingDetails += "2. DoD-approved PKI Certificate Authorities`n`n"

    $FindingDetails += "AUTOMATED CHECKS PERFORMED:`n"
    $FindingDetails += "- Verified TLS client certificate authentication configuration`n"
    $FindingDetails += "- Searched system CA trust stores for DoD root CA certificates`n"
    $FindingDetails += "- Inspected certificate subjects/issuers for DoD PKI indicators`n"
    $FindingDetails += "- Checked Nginx reverse proxy client certificate settings`n"
    $FindingDetails += "- Reviewed Node.js TLS CA configuration`n"
    $FindingDetails += "- Searched for organizational PKI policy documentation`n`n"

    if ($dodCADetected -or $dodRootCACount -gt 0) {
        $FindingDetails += "EVIDENCE FOUND:`n"
        $FindingDetails += "- DoD PKI certificates detected in system trust stores`n"
        $FindingDetails += "- Certificate count: $dodRootCACount`n"
        $FindingDetails += "However, ISSO/ISSM verification is still required to confirm:`n"
        $FindingDetails += "1. ONLY DoD/DoD-approved CAs are trusted (no unauthorized CAs)`n"
        $FindingDetails += "2. DoD PKI root CA certificates are current and valid`n"
        $FindingDetails += "3. Client certificate validation is enforced for all connections`n"
        $FindingDetails += "4. Certificate revocation checking (CRL/OCSP) is enabled`n`n"
    } else {
        $FindingDetails += "NO DoD PKI CERTIFICATES DETECTED:`n"
        $FindingDetails += "- System CA trust stores do not contain recognizable DoD PKI certificates`n"
        $FindingDetails += "- Client certificate authentication may not be configured`n`n"
    }

    $FindingDetails += "MANUAL VERIFICATION REQUIRED (ISSO/ISSM):`n"
    $FindingDetails += "1. Verify DoD PKI root CA certificates are installed and current`n"
    $FindingDetails += "   - DoD Root CA 2, DoD Root CA 3, DoD Root CA 4, DoD Root CA 5`n"
    $FindingDetails += "   - DoD EMAIL CA certificates (if email authentication used)`n"
    $FindingDetails += "   - DoD ID CA certificates (if CAC/PIV authentication used)`n"
    $FindingDetails += "2. Confirm TLS client certificate authentication is required`n"
    $FindingDetails += "3. Verify ONLY DoD/DoD-approved CAs are in the trust store`n"
    $FindingDetails += "4. Test certificate validation with DoD-issued client certificate`n"
    $FindingDetails += "5. Test certificate rejection with non-DoD-issued certificate`n"
    $FindingDetails += "6. Verify certificate revocation checking is enabled (CRL/OCSP)`n"
    $FindingDetails += "7. Review organizational PKI policy for compliance requirements`n`n"

    $FindingDetails += "REMEDIATION GUIDANCE (if non-compliant):`n"
    $FindingDetails += "1. Install DoD PKI root CA certificates:`n"
    $FindingDetails += "   - Download from https://public.cyber.mil/pki-pke/tools-configuration-files/`n"
    $FindingDetails += "   - Place in /usr/local/share/ca-certificates/`n"
    $FindingDetails += "   - Run: update-ca-certificates`n"
    $FindingDetails += "2. Configure XO for client certificate authentication:`n"
    $FindingDetails += "   - Edit config.toml: clientCertAuth = true, requestCert = true`n"
    $FindingDetails += "   - Set CA path: ca = '/path/to/dod-root-ca-bundle.pem'`n"
    $FindingDetails += "3. Configure Nginx (if used as reverse proxy):`n"
    $FindingDetails += "   - ssl_client_certificate /path/to/dod-root-ca-bundle.pem;`n"
    $FindingDetails += "   - ssl_verify_client on;`n"
    $FindingDetails += "   - ssl_verify_depth 3;`n"
    $FindingDetails += "4. Enable certificate revocation checking:`n"
    $FindingDetails += "   - Configure CRL distribution points or OCSP responders`n"
    $FindingDetails += "5. Remove ALL non-DoD CA certificates from trust stores`n"
    $FindingDetails += "6. Document organizational PKI policy and trust anchor configuration`n"
    $FindingDetails += "7. Test with DoD-issued client certificates (CAC/PIV)`n"
    $FindingDetails += "8. Verify access is denied with non-DoD certificates`n`n"

    $FindingDetails += "SECURITY IMPACT:`n"
    $FindingDetails += "Accepting client certificates from unauthorized CAs can allow:`n"
    $FindingDetails += "- Unauthorized access to DoD systems and data`n"
    $FindingDetails += "- Impersonation of DoD users`n"
    $FindingDetails += "- Man-in-the-middle attacks`n"
    $FindingDetails += "- Compromise of DoD PKI trust model`n`n"

    $FindingDetails += "DoD PKI is the ONLY authorized PKI for DoD information systems.`n"
    $FindingDetails += "All client certificates MUST be traceable to DoD root CAs.`n"

    # Calculate result hash
    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    } else {
        $ResultHash = ""
    }

    # Answer file processing
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

    # Return via Send-CheckResult
    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFKey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
    }
    return Send-CheckResult @SendCheckParams
