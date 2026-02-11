#!/usr/bin/env pwsh
# Test99 - Verify V-206400 through V-206409 function execution
# Session #18 - January 25, 2026
# Tests 10 new CAT II WebSRG functions

$TestName = "Test99"
$TestDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "$TestName - V-206400 through V-206409" -ForegroundColor Cyan
Write-Host "Started: $TestDate" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Change to Evaluate-STIG directory
Set-Location "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG"

# Run Evaluate-STIG scan
Write-Host "Running Evaluate-STIG scan on xo1.wgsdac.net..." -ForegroundColor Yellow
Write-Host "Scan Parameters:" -ForegroundColor Yellow
Write-Host "  - ComputerName: xo1.wgsdac.net" -ForegroundColor Gray
Write-Host "  - SelectSTIG: XO_WebSRG" -ForegroundColor Gray
Write-Host "  - ScanType: Classified" -ForegroundColor Gray
Write-Host "  - AnswerKey: XO" -ForegroundColor Gray
Write-Host "  - VulnTimeout: 15 seconds" -ForegroundColor Gray
Write-Host "  - Output: CKL, Summary, Console" -ForegroundColor Gray
Write-Host ""

$startTime = Get-Date

try {
    .\Evaluate-STIG.ps1 `
        -ComputerName xo1.wgsdac.net `
        -SelectSTIG "XO_WebSRG" `
        -ScanType Classified `
        -AnswerKey XO `
        -VulnTimeout 15 `
        -Output CKL,Summary,Console `
        -AllowIntegrityViolations

    $exitCode = $LASTEXITCODE
    $endTime = Get-Date
    $duration = $endTime - $startTime

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "$TestName Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Exit Code: $exitCode" -ForegroundColor $(if ($exitCode -eq 0) { 'Green' } else { 'Red' })
    Write-Host "Duration: $($duration.TotalSeconds) seconds" -ForegroundColor Cyan
    Write-Host "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan

    if ($exitCode -eq 0) {
        Write-Host "`n✅ Scan completed successfully!" -ForegroundColor Green
        Write-Host "`nNext steps:" -ForegroundColor Yellow
        Write-Host "  1. Review scan results in Results/Evaluate-STIG/xo1.wgsdac.net/" -ForegroundColor Gray
        Write-Host "  2. Check CKL file for V-206400 through V-206409 findings" -ForegroundColor Gray
        Write-Host "  3. Verify FindingDetails and Comments are populated correctly" -ForegroundColor Gray
        Write-Host "  4. Validate answer file matching for NF vs O status" -ForegroundColor Gray
    }
    else {
        Write-Host "`n❌ Scan failed with exit code $exitCode" -ForegroundColor Red
        Write-Host "Check scan logs for errors" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "`n❌ Test failed with exception:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
}

Write-Host "`n========================================`n" -ForegroundColor Cyan
