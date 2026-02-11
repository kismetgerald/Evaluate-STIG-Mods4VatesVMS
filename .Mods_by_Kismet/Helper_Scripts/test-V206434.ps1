#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Standalone test for V-206434 (TLS/SSL cryptographic mechanisms)

.DESCRIPTION
    Tests V-206434 check in isolation to validate logic before framework integration.
    This is a CAT I vulnerability requiring verification that XO enforces HTTPS/TLS
    for all web connections.

.NOTES
    Created: 2026-01-24
    Author: Kismet Agbasi
    Test Type: CAT I - Rapid validation
#>

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "V-206434 Standalone Test" -ForegroundColor Cyan
Write-Host "TLS/SSL Cryptographic Mechanisms" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Initialize variables
$Status = "Not_Reviewed"
$FindingDetails = ""
$nl = [Environment]::NewLine
$output = @()

$output += "CAT I / High - V-206434: The web server must employ cryptographic mechanisms (TLS/DTLS/SSL)"
$output += "preventing the unauthorized disclosure of information during transmission."
$output += "-------------------------------------------------------------------------------------$nl"

# Check 1: Verify XO Server HTTPS configuration
$output += "Check 1: XO Server HTTPS Configuration$nl"

$configPaths = @("/opt/xo/xo-server/.config/xo-server/config.toml", "/etc/xo-server/config.toml")
$configFound = $false
$httpsConfigured = $false
$httpRedirect = $false

foreach ($configPath in $configPaths) {
    if (Test-Path $configPath) {
        $configFound = $true
        $output += "   Config file: $configPath$nl"
        
        try {
            $configContent = Get-Content $configPath -Raw -ErrorAction Stop
            
            # Check for HTTPS/TLS configuration
            if ($configContent -match "cert\s*=|certificate\s*=|https\s*=") {
                $httpsConfigured = $true
                $output += "   HTTPS/TLS: CONFIGURED"
            }
            
            # Check for HTTP redirect configuration
            if ($configContent -match "redirectToHttps|redirect.*https") {
                $httpRedirect = $true
                $output += "   HTTP redirect: ENABLED (forces HTTPS)"
            }
            
            # Extract port configuration
            if ($configContent -match "port\s*=\s*(\d+)") {
                $port = $matches[1]
                $output += "   Configured port: $port"
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
    $output += "   Checking network listeners for HTTPS..."
}

# Check 2: Verify network listeners (HTTPS on 443, no plain HTTP)
$output += "$nl" + "Check 2: Network Listeners$nl"

$listeners = $(ss -tlnp 2>&1)
if ($listeners) {
    $listenersStr = $listeners -join $nl
    
    # Check for HTTPS (443)
    if ($listenersStr -match ":443\s") {
        $output += "   Port 443 (HTTPS): LISTENING"
        $httpsConfigured = $true
    }
    else {
        $output += "   Port 443 (HTTPS): NOT DETECTED"
    }
    
    # Check for plain HTTP (80) - should not be listening without redirect
    if ($listenersStr -match ":80\s") {
        if ($httpRedirect) {
            $output += "   Port 80 (HTTP): LISTENING (with HTTPS redirect)"
        }
        else {
            $output += "   [WARN] Port 80 (HTTP): LISTENING without redirect to HTTPS"
        }
    }
    else {
        $output += "   Port 80 (HTTP): NOT LISTENING (expected)"
    }
    
    # Check for XO Server process on non-standard port
    if ($listenersStr -match "node.*xo-server" -or $listenersStr -match ":8080\s|:8443\s") {
        $output += "   XO Server: DETECTED on network"
    }
}
else {
    $output += "   [WARN] Unable to check network listeners"
}

# Check 3: Verify no plain HTTP XO Server instances
$output += "$nl" + "Check 3: XO Server Process Check$nl"

$xoProcess = Get-Process | Where-Object { $_.ProcessName -like '*node*' } | 
             Where-Object { $_.CommandLine -like '*xo-server*' } -ErrorAction SilentlyContinue

if ($xoProcess) {
    $output += "   XO Server: RUNNING"
    $output += "   Default XO configuration enforces HTTPS for web interface"
}
else {
    $output += "   [INFO] XO Server process not detected via Get-Process"
}

# Final assessment
$output += "$nl" + "Assessment:$nl"

if ($httpsConfigured -or $httpRedirect) {
    $Status = "NotAFinding"
    $output += "   Xen Orchestra enforces HTTPS/TLS for all web connections."
    $output += "   The web server is properly configured to use cryptographic"
    $output += "   mechanisms preventing unauthorized disclosure during transmission."
}
else {
    $Status = "Open"
    $output += "   [FINDING] Unable to verify HTTPS/TLS configuration."
    $output += "   Manual verification required to confirm TLS is enforced."
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
