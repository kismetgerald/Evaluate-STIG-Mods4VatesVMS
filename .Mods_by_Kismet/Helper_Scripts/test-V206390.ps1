#!/usr/bin/env pwsh
# Standalone test script for V-206390 function
# Tests FIPS 140-2 cryptographic module compliance for XO
# Run on XO1: pwsh /tmp/test-V206390.ps1

Write-Host "`n=== Testing V-206390: FIPS 140-2 Cryptographic Module Compliance ===" -ForegroundColor Cyan
Write-Host "Starting at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

Function Get-V206390 {
    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = "Test"
    $VulnID = "V-206390"
    $RuleID = "SV-206390r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    # V-206390: FIPS 140-2 Cryptographic Modules Check
    # Validates FIPS 140-2 compliant cryptographic modules for encryption operations
    # Checks: Kernel FIPS mode, OpenSSL, Node.js, nginx cipher suites
    
    $Status = "Open"
    $output = @()
    $allPassed = $true
    
    try {
        $output += "=== FIPS 140-2 Cryptographic Module Compliance Check ==="
        $output += ""
        
        # Check 1: Kernel FIPS Mode
        Write-Host "  Running Check 1: Kernel FIPS Mode..." -ForegroundColor Gray
        $check1Start = Get-Date
        $output += "1. Kernel FIPS Mode:"
        if (Test-Path "/proc/sys/crypto/fips_enabled") {
            $fipsValue = bash -c "timeout 3 cat /proc/sys/crypto/fips_enabled </dev/null 2>&1"
            $output += "   Kernel FIPS mode value: $fipsValue"
            if ($fipsValue -eq "1") {
                $output += "   [PASS] Kernel FIPS mode is ENABLED"
            } else {
                $output += "   [FAIL] Kernel FIPS mode is DISABLED"
                $allPassed = $false
            }
        } else {
            $output += "   [FAIL] /proc/sys/crypto/fips_enabled not found"
            $allPassed = $false
        }
        $output += ""
        $check1End = Get-Date
        Write-Host "    Completed in $([Math]::Round(($check1End - $check1Start).TotalSeconds, 2)) seconds" -ForegroundColor Gray

        # Check 2: OpenSSL FIPS Support
        Write-Host "  Running Check 2: OpenSSL FIPS Support..." -ForegroundColor Gray
        $check2Start = Get-Date
        $output += "2. OpenSSL FIPS Support:"
        $opensslVersion = bash -c "timeout 5 openssl version </dev/null 2>&1"
        if ($LASTEXITCODE -eq 0) {
            $output += "   OpenSSL version: $opensslVersion"
            if ($opensslVersion -match "fips") {
                $output += "   [PASS] OpenSSL FIPS support detected"
            } else {
                $output += "   [FAIL] OpenSSL FIPS support not detected"
                $allPassed = $false
            }
        } else {
            $output += "   [FAIL] Unable to determine OpenSSL version: $opensslVersion"
            $allPassed = $false
        }
        $output += ""
        $check2End = Get-Date
        Write-Host "    Completed in $([Math]::Round(($check2End - $check2Start).TotalSeconds, 2)) seconds" -ForegroundColor Gray

        # Check 3: Node.js FIPS Mode
        Write-Host "  Running Check 3: Node.js FIPS Mode..." -ForegroundColor Gray
        $check3Start = Get-Date
        $output += "3. Node.js FIPS Mode:"
        $q = [char]34
        $sq = [char]39
        # Use proper quote characters to avoid nesting issues
        $nodeCmd = "timeout 5 node -e " + $sq + "console.log(require(" + $q + "crypto" + $q + ").getFips())" + $sq + " </dev/null 2>&1"
        $nodeFips = bash -c $nodeCmd
        if ($LASTEXITCODE -eq 0) {
            $output += "   Node.js crypto.getFips() result: $nodeFips"
            if ($nodeFips -match "^1") {
                $output += "   [PASS] Node.js FIPS mode is ENABLED"
            } else {
                $output += "   [FAIL] Node.js FIPS mode is DISABLED"
                $allPassed = $false
            }
        } else {
            $output += "   [FAIL] Unable to check Node.js FIPS mode: $nodeFips"
            $allPassed = $false
        }
        $output += ""
        $check3End = Get-Date
        Write-Host "    Completed in $([Math]::Round(($check3End - $check3Start).TotalSeconds, 2)) seconds" -ForegroundColor Gray
        
        # Overall Assessment
        $output += "Overall Assessment:"
        if ($allPassed) {
            $output += "All FIPS 140-2 cryptographic module checks PASSED"
            $Status = "NotAFinding"
        } else {
            $output += "One or more FIPS 140-2 cryptographic module checks FAILED"
            $Status = "Open"
        }
        
        $FindingDetails = $output -join [Environment]::NewLine
    }
    catch {
        $Status = "Open"
        $FindingDetails = "Error during FIPS compliance check: " + $_.Exception.Message
    }
    #---=== End Custom Code ===---#

    Return New-Object PSObject -Property @{
        VulnID           = $VulnID
        RuleID           = $RuleID
        Status           = $Status
        FindingDetails   = $FindingDetails
        Comments         = $Comments
        AFKey            = $AFKey
        AFStatus         = $AFStatus
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
    }
}

# Execute the function with test parameters
Write-Host "Executing V-206390 check..." -ForegroundColor Yellow
$startTime = Get-Date
$result = Get-V206390 -ScanType "Classified"
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

# Display results
Write-Host "`n=== TEST RESULTS ===" -ForegroundColor Yellow
Write-Host "Status: $($result.Status)" -ForegroundColor $(if ($result.Status -eq "NotAFinding") { "Green" } else { "Red" })
Write-Host "Total Execution Time: $([Math]::Round($duration, 2)) seconds" -ForegroundColor $(if ($duration -gt 60) { "Red" } elseif ($duration -gt 10) { "Yellow" } else { "Green" })
Write-Host "`nFinding Details:" -ForegroundColor Cyan
Write-Host $result.FindingDetails

Write-Host "`nCompleted at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "===================`n" -ForegroundColor Yellow
