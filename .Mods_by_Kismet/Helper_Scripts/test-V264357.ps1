#!/usr/bin/env pwsh
# Standalone Test for V-264357 (Protected Cryptographic Key Storage)
# Run from: Evaluate-STIG directory
# Command: .\.Mods_by_Kismet\Test\test-V264357.ps1

$ErrorActionPreference = 'Stop'

# Import Master_Functions (provides helper functions like Get-TextHash)
Remove-Module Master_Functions -Force -ErrorAction SilentlyContinue
Import-Module .\Modules\Master_Functions\Master_Functions.psm1 -Force

# Import module
Remove-Module Scan-XO_WebSRG_Checks -Force -ErrorAction SilentlyContinue
Import-Module .\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1 -Force

Write-Host "Testing V-264357 standalone..." -ForegroundColor Cyan

$testParams = @{
    ScanType = 'Classified'
    AnswerFile = ''
    AnswerKey  = 'V-264357'
    Username   = 'NA'
    UserSID    = 'NA'
    Hostname   = 'localhost'
    Instance   = 'NA'
    Database   = 'NA'
    SiteName   = 'NA'
}

$startTime = Get-Date
$result = Get-V264357 @testParams
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Host ("`n" + "="*80) -ForegroundColor Yellow
Write-Host "EXECUTION TIME: $([math]::Round($duration, 2)) seconds" -ForegroundColor Green
Write-Host ("="*80 + "`n") -ForegroundColor Yellow

Write-Host "STATUS: $($result.Status)" -ForegroundColor Yellow
Write-Host ("`n" + "FINDING DETAILS:") -ForegroundColor Cyan
Write-Host $result.FindingDetails

if ($result.Status -eq 'NotAFinding') {
    Write-Host ("`n" + "✅ Test PASSED - Status is NotAFinding") -ForegroundColor Green
} elseif ($result.Status -eq 'Open') {
    Write-Host ("`n" + "⚠️  Status is Open - Keys found with insufficient protection") -ForegroundColor Yellow
} elseif ($result.Status -eq 'Not_Applicable') {
    Write-Host ("`n" + "ℹ️  Status is Not_Applicable - No private keys found") -ForegroundColor Cyan
} else {
    Write-Host ("`n" + "❌ Status is $($result.Status) - Unexpected result") -ForegroundColor Red
}
