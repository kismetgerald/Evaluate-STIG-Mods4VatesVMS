#!/usr/bin/env pwsh
# Compare working vs non-working functions

Import-Module ../../Evaluate-STIG/Modules/Master_Functions/Master_Functions.psm1 -Force
Import-Module ../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1 -Force

$testParams = @{
    ScanType = 'Classified'
    AnswerFile = ''
    AnswerKey = 'test'
    Username = 'NA'
    UserSID = 'NA'
    Hostname = 'localhost'
    Instance = 'NA'
    Database = 'NA'
    SiteName = 'NA'
}

Write-Host "Testing Get-V206351 (Session #17, known working)..." -ForegroundColor Cyan
try {
    $result1 = Get-V206351 @testParams -ErrorAction Stop
    Write-Host "Status: $($result1.Status)" -ForegroundColor Green
    Write-Host "FindingDetails length: $($result1.FindingDetails.Length)" -ForegroundColor Green
} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
}

Write-Host "`nTesting Get-V264357 (Session #34, broken)..." -ForegroundColor Cyan
try {
    $result2 = Get-V264357 @testParams -ErrorAction Stop
    Write-Host "Status: $($result2.Status)" -ForegroundColor Yellow
    Write-Host "FindingDetails length: $($result2.FindingDetails.Length)" -ForegroundColor Yellow
} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
}

Write-Host "`nComparing ScriptBlock lengths..." -ForegroundColor Cyan
$func1 = Get-Command Get-V206351
$func2 = Get-Command Get-V264357
Write-Host "Get-V206351 ScriptBlock: $($func1.ScriptBlock.ToString().Length) chars"
Write-Host "Get-V264357 ScriptBlock: $($func2.ScriptBlock.ToString().Length) chars"
