#!/usr/bin/env pwsh
# Test V-264357 with error trapping at every stage

Import-Module ../../Evaluate-STIG/Modules/Master_Functions/Master_Functions.psm1 -Force
Import-Module ../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1 -Force

Write-Host "Calling Get-V264357 with ErrorAction Stop..." -ForegroundColor Cyan

try {
    $result = Get-V264357 -ScanType 'Classified' -AnswerFile '' -AnswerKey 'V-264357' -Username 'NA' -UserSID 'NA' -Hostname 'localhost' -Instance 'NA' -Database 'NA' -SiteName 'NA' -ErrorAction Stop 2>&1
    Write-Host "`nFunction completed" -ForegroundColor Green
    Write-Host "Status: $($result.Status)"
    Write-Host "FindingDetails length: $($result.FindingDetails.Length)"
    Write-Host "Result type: $($result.GetType().Name)"
    Write-Host "Keys: $($result.Keys -join ', ')"
} catch {
    Write-Host "`nERROR CAUGHT:" -ForegroundColor Red
    Write-Host "Message: $($_.Exception.Message)"
    Write-Host "Type: $($_.Exception.GetType().FullName)"
    Write-Host "Line: $($_.InvocationInfo.ScriptLineNumber)"
    Write-Host "Position: $($_.InvocationInfo.PositionMessage)"
    Write-Host "`nStack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
}

Write-Host "`n`nNow testing with Write-Debug enabled..." -ForegroundColor Cyan
$DebugPreference = 'Continue'
$VerbosePreference = 'Continue'

try {
    $result2 = Get-V264357 -ScanType 'Classified' -AnswerFile '' -AnswerKey 'V-264357' -Username 'NA' -UserSID 'NA' -Hostname 'localhost' -Instance 'NA' -Database 'NA' -SiteName 'NA' -Debug -Verbose 2>&1 | Tee-Object -Variable output
    Write-Host "`nCaptured output:" -ForegroundColor Cyan
    $output | ForEach-Object { Write-Host $_ }
} catch {
    Write-Host "`nERROR: $_" -ForegroundColor Red
}
