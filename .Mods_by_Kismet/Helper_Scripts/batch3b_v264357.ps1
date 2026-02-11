function Get-V264357 {
    <#
    .SYNOPSIS
        V-264357 - Protected storage for cryptographic keys

    .DESCRIPTION
        SRG-APP-000514-WSR-000135
        Severity: CAT II (Medium)

        Cryptographic private keys must be stored in protected storage with
        access restricted to authorized users.
    #>

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

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = "V-264357"
    $RuleID = "SV-264357r1016925_rule"
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
    $output += "V-264357: Protected Cryptographic Key Storage"
    $output += "=" * 80
    $output += ""

    # Check 1: Private key discovery
    $output += "Check 1: Cryptographic Private Key Discovery"
    $output += "-" * 50
    $keyPaths = @()
    $keySearchPaths = @("/etc/ssl/private", "/etc/ssl", "/etc/pki/tls/private", "/etc/xo-server", "/opt/xo")
    $keyFound = $false

    foreach ($dir in $keySearchPaths) {
        if (Test-Path $dir) {
            $keys = bash -c "find '$dir' -maxdepth 3 \( -name '*.key' -o -name '*-key.pem' \) 2>/dev/null | head -10 2>&1" 2>&1
            if ($LASTEXITCODE -eq 0 -and $keys) {
                $output += "[FOUND] Private keys in ${dir}:"
                $output += $keys
                $keyPaths += ($keys -split "`n" | Where-Object { $_ })
                $keyFound = $true
            }
        }
    }
    if (-not $keyFound) {
        $output += "[INFO] No private key files detected"
        $output += "If no private keys exist, this check is Not_Applicable"
    }
    $output += ""

    # Check 2: File permissions
    $output += "Check 2: File Permissions (DoD Requirement: 600 or 400)"
    $output += "-" * 50
    $permCompliant = $true
    foreach ($key in $keyPaths) {
        if (Test-Path $key) {
            $octalPerms = bash -c "stat -c '%a' '$key' 2>/dev/null" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $output += "Key: $key - Permissions: $octalPerms"
                if ($octalPerms -eq "600" -or $octalPerms -eq "400") {
                    $output += "  [PASS] Compliant"
                } else {
                    $output += "  [FAIL] Non-compliant (should be 600 or 400)"
                    $permCompliant = $false
                }
            }
        }
    }
    $output += ""

    # Check 3: File ownership
    $output += "Check 3: File Ownership"
    $output += "-" * 50
    $ownerCompliant = $true
    foreach ($key in $keyPaths) {
        if (Test-Path $key) {
            $owner = bash -c "stat -c '%U:%G' '$key' 2>/dev/null" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $output += "Key: $key - Owner: $owner"
                if ($owner -match "^(root|xo-server):(root|ssl-cert|xo-server)") {
                    $output += "  [PASS] Authorized owner/group"
                } else {
                    $output += "  [WARNING] Non-standard ownership"
                    $ownerCompliant = $false
                }
            }
        }
    }
    $output += ""

    # Check 4: Hardware Security Module (HSM) detection
    $output += "Check 4: Hardware Security Module (HSM) Usage"
    $output += "-" * 50
    $hsmDetected = bash -c "lsusb 2>/dev/null | grep -i 'yubi\|smartcard\|hsm' 2>&1" 2>&1
    if ($LASTEXITCODE -eq 0 -and $hsmDetected) {
        $output += "[FOUND] HSM/Smart card device detected:"
        $output += $hsmDetected
        $output += "HSM provides enhanced cryptographic key protection"
    } else {
        $output += "[INFO] No HSM devices detected - software key storage in use"
    }
    $output += ""

    # Check 5: Disk encryption (LUKS/dm-crypt)
    $output += "Check 5: Encryption at Rest for Key Storage"
    $output += "-" * 50
    $encryptedStorage = bash -c "lsblk -f 2>/dev/null | grep -i 'crypt\|luks' 2>&1" 2>&1
    if ($LASTEXITCODE -eq 0 -and $encryptedStorage) {
        $output += "[FOUND] Encrypted storage (LUKS/dm-crypt):"
        $output += $encryptedStorage
    } else {
        $output += "[INFO] No disk encryption detected"
    }
    $output += ""

    # Assessment
    $output += "=" * 80
    $output += "ASSESSMENT"
    $output += "=" * 80
    $output += ""

    if (-not $keyFound) {
        $Status = "Not_Applicable"
        $output += "Status: Not_Applicable"
        $output += "Reason: No private key files detected on system"
    }
    elseif ($permCompliant -and $ownerCompliant) {
        $Status = "NotAFinding"
        $output += "Status: NotAFinding"
        $output += "Reason: All cryptographic keys have proper permissions and ownership"
    }
    else {
        $Status = "Open"
        $output += "Status: Open"
        $output += "Reason: One or more keys have improper permissions or ownership"
        if (-not $permCompliant) {
            $output += "  - Fix file permissions: chmod 600 <keyfile>"
        }
        if (-not $ownerCompliant) {
            $output += "  - Fix ownership: chown root:root <keyfile>"
        }
    }
    $output += ""

    $FindingDetails = ($output | Out-String).Trim()
    #---=== End Custom Code ===---#

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
            ResultHash   = ""
            ResultData   = $FindingDetails
            ESPath       = ""
            LogPath      = ""
            LogComponent = ""
            OSPlatform   = ""
        }
        If ($FindingDetails.Trim().Length -gt 0) {
            $GetCorpParams.ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
        }
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
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
    }
    return Send-CheckResult @SendCheckParams
}
