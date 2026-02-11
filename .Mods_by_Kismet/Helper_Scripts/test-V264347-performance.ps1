#!/usr/bin/env pwsh
# Test V-264347 performance after optimization fixes

Import-Module ../../Evaluate-STIG/Modules/Master_Functions/Master_Functions.psm1 -Force
Import-Module ../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1 -Force

Write-Host "Testing V-264347 (Password List Update When Compromised) - Performance Test" -ForegroundColor Cyan
Write-Host "=" * 80

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    $result = Get-V264347 -ScanType 'Classified' -AnswerFile '' -AnswerKey 'V-264347' -Username 'NA' -UserSID 'NA' -Hostname 'localhost' -Instance 'NA' -Database 'NA' -SiteName 'NA' -ErrorAction Stop

    $stopwatch.Stop()

    Write-Host "`nFunction completed successfully" -ForegroundColor Green
    Write-Host "Execution time: $($stopwatch.Elapsed.TotalSeconds) seconds" -ForegroundColor Cyan
    Write-Host "Status: $($result.Status)" -ForegroundColor Yellow
    Write-Host "FindingDetails length: $($result.FindingDetails.Length) characters" -ForegroundColor Yellow

    if ($stopwatch.Elapsed.TotalSeconds -lt 10) {
        Write-Host "`n[PASS] Execution time under 10 seconds - Performance optimization successful!" -ForegroundColor Green
    } elseif ($stopwatch.Elapsed.TotalSeconds -lt 30) {
        Write-Host "`n[WARNING] Execution time $($stopwatch.Elapsed.TotalSeconds)s - Acceptable but could be improved" -ForegroundColor Yellow
    } else {
        Write-Host "`n[FAIL] Execution time $($stopwatch.Elapsed.TotalSeconds)s - Still too slow!" -ForegroundColor Red
    }

} catch {
    $stopwatch.Stop()
    Write-Host "`nERROR after $($stopwatch.Elapsed.TotalSeconds) seconds:" -ForegroundColor Red
    Write-Host "Message: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
}

Write-Host "`nOptimization changes applied to V-264347:" -ForegroundColor Cyan
Write-Host "1. Added 'timeout 5' to all find commands (5-second max per find)"
Write-Host "2. Added '-maxdepth 3' to all find commands (limit recursion depth)"
Write-Host "3. Replaced 'grep -ri' with 'find + xargs grep -l' (avoid scanning node_modules)"
Write-Host "4. Specific file type filtering (-name '*.toml' -o -name '*.json' -o -name '*.conf')"
Write-Host ""
Write-Host "Expected improvement: From 830 seconds (13.8 minutes) to under 10 seconds"
