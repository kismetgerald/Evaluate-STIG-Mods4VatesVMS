# test-V206367.ps1
# Standalone test for V-206367: Internal system clock for timestamps
# Run from .Mods_by_Kismet/Test directory

# Import Master_Functions first
Remove-Module Master_Functions -Force -ErrorAction SilentlyContinue
Import-Module ../../Evaluate-STIG/Modules/Master_Functions/Master_Functions.psm1 -Force

# Import Scan-XO_WebSRG_Checks module
Remove-Module Scan-XO_WebSRG_Checks -Force -ErrorAction SilentlyContinue
Import-Module ../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1 -Force

# Test parameters
$ScanType = "Classified"
$Hostname = "XO1"
$Username = "root"
$UserSID = "NA"

$start = Get-Date
$result = Get-V206367 -ScanType $ScanType -Hostname $Hostname -Username $Username -UserSID $UserSID
$end = Get-Date
$duration = ($end - $start).TotalSeconds

Write-Host "--- V-206367 Standalone Test ---" -ForegroundColor Cyan
Write-Host "Execution Time: $duration sec" -ForegroundColor Yellow
Write-Host "Status: $($result.Status)" -ForegroundColor Green
Write-Host "Finding Details:" -ForegroundColor White
Write-Host $result.FindingDetails
Write-Host "ResultHash: $($result.ResultHash)" -ForegroundColor Magenta
Write-Host "----------------------------------" -ForegroundColor Cyan
