#!/usr/bin/env pwsh
# Debug V-264357 execution flow

Import-Module ../../Evaluate-STIG/Modules/Master_Functions/Master_Functions.psm1 -Force
Import-Module ../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1 -Force

Write-Host "Module loaded, testing function..." -ForegroundColor Cyan

# Inject debug tracing by modifying $output array detection
$testCode = @'
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

Write-Verbose "=== Starting Get-V264357 ==="

$ModuleName = "Scan-XO_WebSRG_Checks"
$VulnID = "V-264357"
$RuleID = "SV-264357r984416_rule"
$Status = "Not_Reviewed"
$FindingDetails = ""
$Comments = ""
$AFKey = ""
$AFStatus = ""
$SeverityOverride = ""
$Justification = ""

Write-Verbose "Variables initialized"

#---=== Begin Custom Code ===---#
Write-Verbose "Starting custom code"
$output = @()
Write-Verbose "Output array created, type: $($output.GetType().Name)"

$output += "Test line 1"
Write-Verbose "Added test line, output count: $($output.Count)"

$output += "Test line 2"
Write-Verbose "Added second line, output count: $($output.Count)"

$FindingDetails = $output -join "`n"
Write-Verbose "FindingDetails populated, length: $($FindingDetails.Length)"
#---=== End Custom Code ===---#

Write-Verbose "Custom code complete"
Write-Verbose "Status: $Status"
Write-Verbose "FindingDetails: $FindingDetails"

$result = @{
    Status = $Status
    FindingDetails = $FindingDetails
    AFKey = $AFKey
    AFStatus = $AFStatus
    Comments = $Comments
}

return $result
'@

Write-Host "`nTesting minimal version with verbose output:" -ForegroundColor Yellow
$result = Invoke-Expression $testCode

Write-Host "`n=== Minimal Test Result ===" -ForegroundColor Cyan
Write-Host "Status: $($result.Status)"
Write-Host "FindingDetails: $($result.FindingDetails)"
Write-Host "FindingDetails Length: $($result.FindingDetails.Length)"

Write-Host "`n`nNow testing actual Get-V264357 function:" -ForegroundColor Yellow
$actualResult = Get-V264357 -ScanType 'Classified' -AnswerFile '' -AnswerKey 'V-264357' -Username 'NA' -UserSID 'NA' -Hostname 'localhost' -Instance 'NA' -Database 'NA' -SiteName 'NA'

Write-Host "`n=== Actual Function Result ===" -ForegroundColor Cyan
Write-Host "Status: $($actualResult.Status)"
Write-Host "FindingDetails Length: $($actualResult.FindingDetails.Length)"
Write-Host "Keys in result: $($actualResult.Keys -join ', ')"
