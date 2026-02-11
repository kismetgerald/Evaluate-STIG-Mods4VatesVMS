<#
.SYNOPSIS
    Real-world testing and validation for Xen Orchestra STIG compliance modules
    
.DESCRIPTION
    Validates that custom XO modules (ASD, WebSRG, Debian12) properly detect and report
    STIG compliance findings across different XO deployment scenarios (XOCE vs XOA)
    
.PARAMETER ModulePath
    Path to .Mods_by_Kismet/Modules directory
    
.PARAMETER Environment
    Environment to test: 'XOCE', 'XOA', or 'Both'
    
.PARAMETER OutputFormat
    Output format: 'Console', 'JSON', 'CSV', 'All'
    
.EXAMPLE
    .\Test-XO-Modules.ps1 -Environment Both -OutputFormat All
    
.NOTES
    Author: Kismet Agbasi
    Date: January 17, 2026
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$ModulePath = ".\.Mods_by_Kismet\Modules",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('XOCE', 'XOA', 'Both')]
    [string]$Environment = 'Both',
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Console', 'JSON', 'CSV', 'All')]
    [string]$OutputFormat = 'Console'
)

$ErrorActionPreference = "Continue"
$testResults = @()

# ============================================================================
# Test Framework
# ============================================================================

Function Test-ModuleDetection {
    <#
    .DESCRIPTION
    Verify that Evaluate-STIG properly detects XO deployment type and applies correct modules
    #>
    
    Write-Host "`n[TEST] Module Detection" -ForegroundColor Cyan
    
    $tests = @(
        @{
            Name = "Detect XO Process"
            Command = { pgrep -fa 'node.*xo-server' }
            Expected = "Process found"
        },
        @{
            Name = "Detect XOCE vs XOA"
            Command = { 
                $xoPath = "/opt/xo"
                $xoaPath = "/opt/xoa"
                if (Test-Path $xoPath -and -not (Test-Path $xoaPath)) { "XOCE" }
                elseif (Test-Path $xoaPath) { "XOA" }
                else { "Unknown" }
            }
            Expected = "XOCE|XOA"
        },
        @{
            Name = "Load ASD Module"
            Command = { Get-Module -Name Scan-XO_ASD_Checks -ErrorAction SilentlyContinue }
            Expected = "Module loaded"
        },
        @{
            Name = "Load WebSRG Module"
            Command = { Get-Module -Name Scan-XO_WebSRG_Checks -ErrorAction SilentlyContinue }
            Expected = "Module loaded"
        }
    )
    
    foreach ($test in $tests) {
        try {
            $result = & $test.Command
            $status = if ($result) { "PASS" } else { "FAIL" }
            Write-Host "  [$status] $($test.Name): $result" -ForegroundColor $(if ($status -eq "PASS") { "Green" } else { "Red" })
            
            $testResults += @{
                Test = $test.Name
                Status = $status
                Result = $result
            }
        }
        catch {
            Write-Host "  [ERROR] $($test.Name): $_" -ForegroundColor Red
            $testResults += @{
                Test = $test.Name
                Status = "ERROR"
                Error = $_
            }
        }
    }
}

Function Test-CAT1Checks {
    <#
    .DESCRIPTION
    Execute all CAT I (critical) checks and validate they return proper status
    #>
    
    Write-Host "`n[TEST] CAT I Check Execution" -ForegroundColor Cyan
    
    $catIChecks = @(
        'V-222399', 'V-222400', 'V-222403', 'V-222404', 'V-222425', 'V-222430', 'V-222432',
        'V-222522', 'V-222536', 'V-222542', 'V-222543', 'V-222550', 'V-222551', 'V-222554',
        'V-222555', 'V-222577', 'V-222578', 'V-222585', 'V-222588', 'V-222589', 'V-222590'
    )
    
    $passCount = 0
    $failCount = 0
    
    foreach ($check in $catIChecks) {
        try {
            $funcName = "Get-$check"
            if (Get-Command $funcName -ErrorAction SilentlyContinue) {
                $result = & $funcName -ScanType "Compliance"
                
                # Validate result has required properties
                if ($result.Status -and $result.FindingDetails) {
                    Write-Host "  [PASS] $check executed successfully" -ForegroundColor Green
                    $passCount++
                }
                else {
                    Write-Host "  [FAIL] $check missing required properties" -ForegroundColor Red
                    $failCount++
                }
            }
            else {
                Write-Host "  [FAIL] $check function not found" -ForegroundColor Red
                $failCount++
            }
        }
        catch {
            Write-Host "  [ERROR] $check execution failed: $_" -ForegroundColor Red
            $failCount++
        }
    }
    
    Write-Host "`n  Summary: $passCount passed, $failCount failed" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
    $testResults += @{
        Test = "CAT I Execution"
        Status = if ($failCount -eq 0) { "PASS" } else { "FAIL" }
        Passed = $passCount
        Failed = $failCount
    }
}

Function Test-WebSRGChecks {
    <#
    .DESCRIPTION
    Execute Web Server SRG CAT I checks
    #>
    
    Write-Host "`n[TEST] Web Server SRG CAT I Execution" -ForegroundColor Cyan
    
    $webSrgChecks = @(
        'V-206390', 'V-206399', 'V-206431', 'V-206434', 'V-279029', 'V-279031'
    )
    
    $passCount = 0
    $failCount = 0
    
    foreach ($check in $webSrgChecks) {
        try {
            $funcName = "Get-$check"
            if (Get-Command $funcName -ErrorAction SilentlyContinue) {
                $result = & $funcName -ScanType "Compliance"
                
                if ($result.Status -and $result.FindingDetails) {
                    Write-Host "  [PASS] $check executed successfully" -ForegroundColor Green
                    $passCount++
                }
                else {
                    Write-Host "  [FAIL] $check missing required properties" -ForegroundColor Red
                    $failCount++
                }
            }
            else {
                Write-Host "  [FAIL] $check function not found" -ForegroundColor Red
                $failCount++
            }
        }
        catch {
            Write-Host "  [ERROR] $check execution failed: $_" -ForegroundColor Red
            $failCount++
        }
    }
    
    Write-Host "`n  Summary: $passCount passed, $failCount failed" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
    $testResults += @{
        Test = "WebSRG CAT I Execution"
        Status = if ($failCount -eq 0) { "PASS" } else { "FAIL" }
        Passed = $passCount
        Failed = $failCount
    }
}

Function Test-ConfigurationDetection {
    <#
    .DESCRIPTION
    Verify checks properly detect configuration files and settings
    #>
    
    Write-Host "`n[TEST] Configuration Detection" -ForegroundColor Cyan
    
    $configTests = @(
        @{
            Name = "XO Config File"
            Path = "/etc/xo-server/config.yaml"
        },
        @{
            Name = "nginx Config"
            Path = "/etc/nginx/conf.d/xo-server.conf"
        },
        @{
            Name = "XO Data Directory"
            Path = "/var/lib/xo"
        },
        @{
            Name = "XO Log Directory"
            Path = "/var/log/xo"
        }
    )
    
    foreach ($test in $configTests) {
        $exists = Test-Path $test.Path
        $status = if ($exists) { "FOUND" } else { "NOT FOUND" }
        Write-Host "  [$status] $($test.Name): $($test.Path)" -ForegroundColor $(if ($exists) { "Green" } else { "Yellow" })
        
        $testResults += @{
            Test = "Config: $($test.Name)"
            Status = $status
            Path = $test.Path
        }
    }
}

Function Test-PermissionsAndSecurity {
    <#
    .DESCRIPTION
    Verify file permissions on sensitive XO directories
    #>
    
    Write-Host "`n[TEST] Permissions and Security" -ForegroundColor Cyan
    
    $permTests = @(
        @{
            Path = "/var/lib/xo"
            MinPerm = "700"
            Description = "XO data directory"
        },
        @{
            Path = "/var/log/xo"
            MinPerm = "700"
            Description = "XO log directory"
        },
        @{
            Path = "/etc/xo-server"
            MinPerm = "755"
            Description = "XO config directory"
        }
    )
    
    foreach ($test in $permTests) {
        if (Test-Path $test.Path) {
            $perms = (Get-Item $test.Path).UnixFileMode
            Write-Host "  [INFO] $($test.Description): $perms" -ForegroundColor Cyan
            
            $testResults += @{
                Test = "Perms: $($test.Description)"
                Path = $test.Path
                Permissions = $perms
            }
        }
        else {
            Write-Host "  [SKIP] $($test.Description) not found" -ForegroundColor Yellow
        }
    }
}

Function Test-TLSConfiguration {
    <#
    .DESCRIPTION
    Verify TLS configuration for web services
    #>
    
    Write-Host "`n[TEST] TLS Configuration" -ForegroundColor Cyan
    
    $configPath = "/etc/nginx/conf.d/xo-server.conf"
    if (Test-Path $configPath) {
        $config = Get-Content $configPath -Raw
        
        $tlsTests = @(
            @{ Name = "TLS 1.2+"; Pattern = "TLSv1\.[23]" },
            @{ Name = "Server Tokens Off"; Pattern = "server_tokens\s+off" },
            @{ Name = "HSTS Header"; Pattern = "add_header.*Strict-Transport-Security" },
            @{ Name = "X-Frame-Options"; Pattern = "add_header.*X-Frame-Options" }
        )
        
        foreach ($test in $tlsTests) {
            $found = $config -match $test.Pattern
            $status = if ($found) { "FOUND" } else { "NOT FOUND" }
            Write-Host "  [$status] $($test.Name)" -ForegroundColor $(if ($found) { "Green" } else { "Yellow" })
            
            $testResults += @{
                Test = "TLS: $($test.Name)"
                Status = $status
            }
        }
    }
    else {
        Write-Host "  [SKIP] nginx config not found" -ForegroundColor Yellow
    }
}

Function Export-TestResults {
    <#
    .DESCRIPTION
    Export test results in specified format(s)
    #>
    
    Write-Host "`n[EXPORT] Test Results" -ForegroundColor Cyan
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    if ($OutputFormat -eq "Console" -or $OutputFormat -eq "All") {
        Write-Host "`nTest Results Summary:" -ForegroundColor Green
        $testResults | ForEach-Object {
            Write-Host "  $($_.Test): $($_.Status)" -ForegroundColor Cyan
        }
    }
    
    if ($OutputFormat -eq "JSON" -or $OutputFormat -eq "All") {
        $jsonPath = ".\.Mods_by_Kismet\test_results_$timestamp.json"
        $testResults | ConvertTo-Json | Set-Content $jsonPath
        Write-Host "  JSON export: $jsonPath" -ForegroundColor Green
    }
    
    if ($OutputFormat -eq "CSV" -or $OutputFormat -eq "All") {
        $csvPath = ".\.Mods_by_Kismet\test_results_$timestamp.csv"
        $testResults | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "  CSV export: $csvPath" -ForegroundColor Green
    }
}

# ============================================================================
# Main Test Execution
# ============================================================================

Write-Host "
╔══════════════════════════════════════════════════════════════════════════════╗
║                  XO STIG Modules - Real-World Validation Test               ║
║                          Environment: $Environment                              ║
║                    Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
" -ForegroundColor Cyan

try {
    # Load modules
    Write-Host "`n[INIT] Loading STIG modules..." -ForegroundColor Cyan
    Get-ChildItem -Path $ModulePath -Filter "*.psm1" -Recurse | ForEach-Object {
        Import-Module $_.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "  Loaded: $($_.BaseName)" -ForegroundColor Green
    }
    
    # Execute tests
    Test-ModuleDetection
    Test-CAT1Checks
    Test-WebSRGChecks
    Test-ConfigurationDetection
    Test-PermissionsAndSecurity
    Test-TLSConfiguration
    
    # Export results
    Export-TestResults
    
    # Summary
    $totalTests = $testResults.Count
    $passedTests = ($testResults | Where-Object { $_.Status -eq "PASS" }).Count
    
    Write-Host "`n
╔══════════════════════════════════════════════════════════════════════════════╗
║                          Test Execution Complete                              ║
║                    Total: $totalTests | Passed: $passedTests | Failed: $($totalTests - $passedTests)                                   ║
║                  Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
" -ForegroundColor Green
}
catch {
    Write-Host "`n[ERROR] Test execution failed: $_" -ForegroundColor Red
    Exit 1
}
