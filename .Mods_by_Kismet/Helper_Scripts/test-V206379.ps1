# Standalone Test for V-206379
# Run from: Evaluate-STIG directory
# Command: .\.Mods_by_Kismet\Test\test-V206379.ps1

$ErrorActionPreference = 'Stop'

# Import Master_Functions (provides helper functions like Get-TextHash)
Remove-Module Master_Functions -Force -ErrorAction SilentlyContinue
Import-Module .\Modules\Master_Functions\Master_Functions.psm1 -Force

# Import module
Remove-Module Scan-XO_WebSRG_Checks -Force -ErrorAction SilentlyContinue
Import-Module .\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1 -Force

Write-Host "Testing V-206379 standalone..." -ForegroundColor Cyan

$testParams = @{
    ScanType = 'Classified'
    AnswerFile = ''
    AnswerKey  = 'V-206379'
    Username   = 'NA'
    UserSID    = 'NA'
    Hostname   = 'localhost'
    Instance   = 'NA'
    Database   = 'NA'
    SiteName   = 'NA'
}

$startTime = Get-Date
$result = Get-V206379 @testParams
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Host ("`n" + "="*80) -ForegroundColor Yellow
Write-Host "EXECUTION TIME: $([math]::Round($duration, 2)) seconds" -ForegroundColor Green
Write-Host ("="*80 + "`n") -ForegroundColor Yellow

Write-Host "STATUS: $($result.Status)" -ForegroundColor $(if ($result.Status -eq 'NotAFinding') { 'Green' } else { 'Yellow' })
Write-Host ("`n" + "FINDING DETAILS:") -ForegroundColor Cyan
Write-Host $result.FindingDetails

if ($result.Status -eq 'NotAFinding') {
    Write-Host ("`n" + "✅ Test PASSED - Status is NotAFinding") -ForegroundColor Green
} else {
    Write-Host ("`n" + "⚠️  Status is $($result.Status) - May need review") -ForegroundColor Yellow
}