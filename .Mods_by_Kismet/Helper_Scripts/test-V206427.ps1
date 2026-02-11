# Test script for V-206427 - Application files privileged-only access

# Import the module
Import-Module "../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psd1" -Force

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Testing V-206427: Application files privileged-only access" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan

# Call the function
$result = Get-V206427 -ScanType "Classified"

# Display results
Write-Host ""
Write-Host "STATUS: $($result.Status)" -ForegroundColor $(if ($result.Status -eq "NotAFinding") { "Green" } elseif ($result.Status -eq "Open") { "Yellow" } else { "Cyan" })
Write-Host ""
Write-Host "FINDING DETAILS:" -ForegroundColor Cyan
Write-Host $result.FindingDetails
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
