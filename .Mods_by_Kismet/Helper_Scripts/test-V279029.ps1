#!/usr/bin/env pwsh
# Standalone test script for V-279029 function
# Tests vendor-supported software version checks for XO
# Run on XO1: pwsh /tmp/test-V279029.ps1

Write-Host "`n=== Testing V-279029: Vendor-Supported Software Versions ===" -ForegroundColor Cyan
Write-Host "Starting at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

Function Get-V279029 {
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
    $VulnID = "V-279029"
    $RuleID = "SV-279029r508029_rule"
    $Status = "Not_Reviewed"
    $FindingDetails = ""
    $Comments = ""
    $AFKey = ""
    $AFStatus = ""
    $SeverityOverride = ""
    $Justification = ""

    #---=== Begin Custom Code ===---#
    # V-279029: Vendor-Supported Software Versions Check
    # Validates that web server components use vendor-supported versions
    # Checks: nginx, Node.js, Debian OS, XO Server versions against known EOL dates
    
    $Status = "Open"
    $output = @()
    $allSupported = $true
    $nl = [Environment]::NewLine
    
    try {
        $output += "=== Vendor-Supported Software Version Check ==="
        $output += ""
        
        # Check 1: XO Server Service Status (XO is Node.js app, not nginx)
        $output += "1. Xen Orchestra Server Service:"
        $xoServiceStatus = bash -c "timeout 5 systemctl status xo-server 2>&1"
        if ($LASTEXITCODE -eq 0 -and $xoServiceStatus -match 'Active: active') {
            $output += "   [INFO] xo-server service is running"
            # Extract service path if available
            if ($xoServiceStatus -match 'Main PID.*ExecStart=([^\s]+)') {
                $output += "   Service path: $($matches[1])"
            }
        } else {
            $output += "   [WARN] Unable to verify xo-server service status"
            $output += "   Note: XO is a Node.js application, not nginx-based"
        }
        $output += ""
        
        # Check 2: Node.js version
        $output += "2. Node.js Runtime:"
        $nodeVersion = bash -c "timeout 3 node -v 2>&1"
        if ($LASTEXITCODE -eq 0 -and $nodeVersion) {
            $output += "   Installed version: $nodeVersion"
            if ($nodeVersion -match 'v(\d+)\.') {
                $nodeMajorVersion = [int]$matches[1]
                $output += "   Major version: $nodeMajorVersion"
                # Node.js Active LTS and Current: v18, v20, v21, v22+
                if ($nodeMajorVersion -ge 18) {
                    $output += "   [PASS] Version is within supported range (Active LTS or Current)"
                } else {
                    $output += "   [FAIL] Version is End-of-Life - upgrade required"
                    $allSupported = $false
                }
            }
        } else {
            $output += "   [FAIL] Unable to determine Node.js version"
            $allSupported = $false
        }
        $output += ""
        
        # Check 3: Debian OS version
        $output += "3. Debian Operating System:"
        $debianInfoRaw = bash -c "timeout 3 lsb_release -a 2>&1"
        if ($LASTEXITCODE -eq 0 -and $debianInfoRaw) {
            # Convert array to string (bash returns array when multiple lines)
            $debianInfo = $debianInfoRaw -join "`n"
            
            # Extract version from string
            $debianMajorVersion = 0
            if ($debianInfo -match 'Release:\s+(\d+)') {
                $debianMajorVersion = [int]$matches[1]
            }
            
            # Display information
            $output += "   OS Information:"
            $infoLines = $debianInfo -split "`n"
            foreach ($line in $infoLines) {
                if ($line -and -not ($line -match 'No LSB modules')) {
                    $output += "     $line"
                }
            }
            
            # Check version
            if ($debianMajorVersion -gt 0) {
                # Debian 11 (Bullseye) and 12 (Bookworm) are currently supported
                if ($debianMajorVersion -ge 11) {
                    $output += "   [PASS] Debian $debianMajorVersion is within supported lifecycle"
                } else {
                    $output += "   [FAIL] Debian $debianMajorVersion is End-of-Life"
                    $allSupported = $false
                }
            } else {
                $output += "   [WARN] Unable to parse Debian version from lsb_release"
            }
        } else {
            # Fallback to /etc/os-release
            $osRelease = bash -c "timeout 3 cat /etc/os-release 2>&1"
            if ($LASTEXITCODE -eq 0 -and $osRelease) {
                $output += "   OS Information (from /etc/os-release):"
                if ($osRelease -match 'PRETTY_NAME=(.+)') {
                    $output += "     $($matches[1])"
                }
                if ($osRelease -match 'VERSION_ID=' + [char]34 + '(\d+)' + [char]34) {
                    $debianMajorVersion = [int]$matches[1]
                    if ($debianMajorVersion -ge 11) {
                        $output += "   [PASS] Debian $debianMajorVersion is within supported lifecycle"
                    } else {
                        $output += "   [FAIL] Debian $debianMajorVersion is End-of-Life"
                        $allSupported = $false
                    }
                }
            } else {
                $output += "   [WARN] Unable to determine Debian version"
            }
        }
        $output += ""
        
        # Check 4: XO Server version (detect XOA vs XOCE)
        $output += "4. Xen Orchestra Application Version:"
        # Check for XOCE installation path first (community edition built from sources)
        $xoPackageJsonXOCE = "/opt/xo/xo-server/package.json"
        # Check for XOA installation path (official Vates appliance)
        $xoPackageJsonXOA = "/usr/local/lib/node_modules/xo-server/package.json"
        
        $xoPackageJson = $null
        $xoType = $null
        
        # Detect which XO variant is installed
        $testXOCE = bash -c "timeout 2 test -f '$xoPackageJsonXOCE' && echo 'found' 2>&1"
        if ($testXOCE -match "found") {
            $xoPackageJson = $xoPackageJsonXOCE
            $xoType = "XOCE"
        } else {
            $testXOA = bash -c "timeout 2 test -f '$xoPackageJsonXOA' && echo 'found' 2>&1"
            if ($testXOA -match "found") {
                $xoPackageJson = $xoPackageJsonXOA
                $xoType = "XOA"
            }
        }
        
        if ($xoPackageJson) {
            $output += "   Detected: $xoType (Xen Orchestra " + $(if ($xoType -eq "XOA") { "Appliance" } else { "Community Edition" }) + ")"
            $q = [char]34
            # Use improved version extraction command
            $xoVersionCmd = "timeout 3 cat " + $xoPackageJson + " | grep '" + $q + "version" + $q + "' | awk -F'" + $q + "' '{print " + [char]36 + "4}' 2>&1"
            $xoVersion = bash -c $xoVersionCmd
            if ($LASTEXITCODE -eq 0 -and $xoVersion -and $xoVersion.Trim()) {
                $output += "   XO Server version: $($xoVersion.Trim())"
                $output += "   [INFO] XO follows rolling release model - verify against Vates/XCP-ng project support"
            } else {
                $output += "   [WARN] Unable to extract XO Server version from package.json"
            }
        } else {
            $output += "   [WARN] XO Server package.json not found (checked XOCE and XOA paths)"
            $output += "   Paths checked: $xoPackageJsonXOCE, $xoPackageJsonXOA"
        }
        $output += ""
        
        # Overall Assessment
        $output += "Overall Assessment:"
        if ($allSupported) {
            $output += "All critical software components are using vendor-supported versions"
            $output += "Recommendation: Maintain regular update schedule per organizational patch management policy"
            $Status = "NotAFinding"
        } else {
            $output += "One or more software components are End-of-Life or unsupported"
            $output += "REQUIRED ACTION: Upgrade to vendor-supported versions immediately"
            $Status = "Open"
        }
        
        $FindingDetails = $output -join $nl
    }
    catch {
        $Status = "Open"
        $FindingDetails = "Error during vendor support check: " + $_.Exception.Message
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
$result = Get-V279029 -ScanType "Classified"

# Display results
Write-Host "=== TEST RESULTS ===" -ForegroundColor Yellow
Write-Host "Status: $($result.Status)" -ForegroundColor $(if ($result.Status -eq "NotAFinding") { "Green" } else { "Red" })
Write-Host "`nFinding Details:" -ForegroundColor Cyan
Write-Host $result.FindingDetails

Write-Host "`nCompleted at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "===================`n" -ForegroundColor Yellow
