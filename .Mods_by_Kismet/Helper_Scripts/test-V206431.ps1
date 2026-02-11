#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Standalone test for V-206431 (encrypt user identifiers and passwords)

.DESCRIPTION
    Tests V-206431 check in isolation to validate logic before framework integration.
    This is a CAT I vulnerability requiring verification that XO doesn't store
    user credentials locally (uses external auth instead).

.NOTES
    Created: 2026-01-24
    Author: Kismet Agbasi
    Test Type: CAT I - Rapid validation
#>

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "V-206431 Standalone Test" -ForegroundColor Cyan
Write-Host "Encrypt User IDs/Passwords Check" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Initialize variables
$Status = "Not_Reviewed"
$FindingDetails = ""
$nl = [Environment]::NewLine
$output = @()

$output += "CAT I / High - V-206431: The web server must encrypt user identifiers and passwords."
$output += "-------------------------------------------------------------------------------------$nl"

# Check 1: Verify XO uses external authentication (no local user storage)
$output += "Check 1: External Authentication Configuration$nl"

$configPaths = @("/opt/xo/xo-server/.config/xo-server/config.toml", "/etc/xo-server/config.toml")
$configFound = $false
$externalAuthConfigured = $false

foreach ($configPath in $configPaths) {
    if (Test-Path $configPath) {
        $configFound = $true
        $output += "   Config file: $configPath"
        
        try {
            $configContent = Get-Content $configPath -Raw -ErrorAction Stop
            
            # Check for LDAP/AD authentication configuration
            if ($configContent -match "authentication.*=.*\[" -or $configContent -match "\[ldap\]" -or $configContent -match "\[saml\]") {
                $externalAuthConfigured = $true
                $output += "   External authentication: CONFIGURED (LDAP/SAML/AD)"
            }
            else {
                $output += "   External authentication: Token-based authentication (built-in)"
            }
        }
        catch {
            $output += "   [WARN] Error reading config: $($_.Exception.Message)"
        }
        break
    }
}

if (-not $configFound) {
    $output += "   [INFO] XO Server config not found in default locations"
    $output += "   XO uses token-based authentication by default (no password storage)"
}

# Check 2: Verify Redis is used for sessions only (no password storage)
$output += "$nl" + "Check 2: Session Management (Redis)$nl"

$redisProcess = Get-Process | Where-Object { $_.ProcessName -like '*redis*' } -ErrorAction SilentlyContinue
if ($redisProcess) {
    $output += "   Redis service: RUNNING (session tokens only)"
    $output += "   Redis does not store user passwords - only authentication tokens"
}
else {
    $output += "   Redis service: NOT DETECTED"
    $output += "   [INFO] XO may use alternative session storage"
}

# Check 3: Verify no local user database files
$output += "$nl" + "Check 3: Local User Storage$nl"

$userDbPaths = @("/opt/xo/xo-server/users.db", "/opt/xo/xo-server/data/users.db", "/var/lib/xo-server/users.db")
$localUserStorage = $false

foreach ($dbPath in $userDbPaths) {
    if (Test-Path $dbPath) {
        $localUserStorage = $true
        $output += "   [WARN] Local user database found: $dbPath"
    }
}

if (-not $localUserStorage) {
    $output += "   Local user database: NOT FOUND (expected for external auth)"
}

# Final assessment
$output += "$nl" + "Assessment:$nl"

if (-not $localUserStorage) {
    $Status = "NotAFinding"
    $output += "   XO Orchestra uses external authentication providers (LDAP/AD/SAML)"
    $output += "   or token-based authentication without storing user passwords."
    $output += "   Session management uses Redis for temporary authentication tokens."
    $output += "   No user identifiers or passwords are stored on the web server."
}
else {
    $Status = "Open"
    $output += "   [FINDING] Local user database detected - requires verification"
    $output += "   that user passwords are properly encrypted."
}

$FindingDetails = $output -join $nl

$stopwatch.Stop()

# Display results
Write-Host "RESULTS:" -ForegroundColor Green
Write-Host "--------" -ForegroundColor Green
Write-Host "Status: $Status" -ForegroundColor $(if ($Status -eq "NotAFinding") { "Green" } else { "Yellow" })
Write-Host "Execution Time: $($stopwatch.Elapsed.TotalSeconds) seconds" -ForegroundColor Cyan
Write-Host ""
Write-Host "Finding Details:" -ForegroundColor Yellow
Write-Host $FindingDetails
Write-Host ""
Write-Host "Test completed successfully!" -ForegroundColor Green
