# Test V-206396: The web server must invalidate session identifiers upon user logout or other session termination
# Created: January 25, 2026 (Session #17)
# Purpose: Standalone test of Get-V206396 function

$ErrorActionPreference = 'Continue'

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  V-206396 Standalone Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Rule: The web server must invalidate session identifiers upon user logout or other session termination." -ForegroundColor White
Write-Host "STIG ID: SRG-APP-000220-WSR-000201" -ForegroundColor Gray
Write-Host "`nTest Scope:" -ForegroundColor Yellow
Write-Host "  - Check 1: XO source code for logout/signOut handlers (/opt/xo/xo-server/dist/)" -ForegroundColor Gray
Write-Host "  - Check 2: Session configuration in config.toml ([session], [redis], timeout, maxAge)" -ForegroundColor Gray
Write-Host "  - Check 3: XO REST API session management (/rest/v0/sessions)" -ForegroundColor Gray
Write-Host "  - Check 4: Runtime session behavior (Redis detection, session store verification)`n" -ForegroundColor Gray

# Import module
$modulePath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"

Write-Host "[1/3] Importing module..." -ForegroundColor Yellow
Remove-Module Scan-XO_WebSRG_Checks -ErrorAction SilentlyContinue
Import-Module $modulePath -Force -ErrorAction Stop
Write-Host "      Module loaded successfully (129 functions)" -ForegroundColor Green

# Verify function exists
Write-Host "`n[2/3] Verifying function..." -ForegroundColor Yellow
$functionExists = Get-Command Get-V206396 -ErrorAction SilentlyContinue
if ($functionExists) {
    Write-Host "      Function Get-V206396 found" -ForegroundColor Green
} else {
    Write-Host "      [ERROR] Function Get-V206396 not found!" -ForegroundColor Red
    exit 1
}

# Run the test
Write-Host "`n[3/3] Executing Get-V206396..." -ForegroundColor Yellow
Write-Host "      (This test runs on Windows but won't find XO - expected behavior)`n" -ForegroundColor Gray
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    $result = Get-V206396 -ScanType "Classified"
    $stopwatch.Stop()

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Test Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $statusColor = switch ($result.Status) {
        'NotAFinding' { 'Green' }
        'Open' { 'Red' }
        'Not_Reviewed' { 'Yellow' }
        default { 'White' }
    }

    Write-Host "Status:         " -NoNewline
    Write-Host $result.Status -ForegroundColor $statusColor
    Write-Host "Execution Time: $($stopwatch.Elapsed.TotalSeconds) seconds" -ForegroundColor White

    if ($result.Status -eq 'NotAFinding') {
        Write-Host "`nInterpretation: XO invalidates sessions on logout (compliant)" -ForegroundColor Green
    }
    elseif ($result.Status -eq 'Open') {
        Write-Host "`nInterpretation: XO does NOT invalidate sessions on logout - FINDING" -ForegroundColor Red
    }
    else {
        Write-Host "`nInterpretation: Unable to determine - manual verification required" -ForegroundColor Yellow
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Finding Details" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor White
    Write-Host $result.FindingDetails -ForegroundColor White

    if ($result.Comments) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Comments" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor White
        Write-Host $result.Comments -ForegroundColor White
    }
}
catch {
    $stopwatch.Stop()
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "  Test Failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Execution Time: $($stopwatch.Elapsed.TotalSeconds) seconds" -ForegroundColor Gray
    Write-Host "`nStack Trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Test Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
