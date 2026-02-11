# test-V206363.ps1
# Test script for V-206363 (Load balancer client IP identification)
# STIG Rule: SV-206363r879887_rule
# CAT II - Web server behind load balancer/proxy must record client IP

$ErrorActionPreference = 'Stop'

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Testing V-206363: Load Balancer Client IP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Remove and reload modules
Remove-Module Scan-XO_WebSRG_Checks -Force -ErrorAction SilentlyContinue
Remove-Module Master_Functions -Force -ErrorAction SilentlyContinue

# Import Master_Functions first (contains Get-TextHash and other helpers)
Import-Module .\Modules\Master_Functions\Master_Functions.psm1 -Force

# Import the WebSRG module
Import-Module .\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1 -Force

# Test parameters
$testParams = @{
    ScanType = 'Classified'
    Hostname = 'XO1'
    Username = 'root'
    UserSID  = 'NA'
}

# Execute function
$startTime = Get-Date
Write-Host "Executing Get-V206363..." -ForegroundColor Yellow
$result = Get-V206363 @testParams
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

# Display results
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Test Results" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "VulnID:       $($result.VulnID)"
Write-Host "RuleID:       $($result.RuleID)"
Write-Host "Status:       $($result.Status)" -ForegroundColor $(if ($result.Status -eq 'NotAFinding') { 'Green' } elseif ($result.Status -eq 'Open') { 'Red' } else { 'Yellow' })
Write-Host "Duration:     ${duration}s"
Write-Host ""
Write-Host "Finding Details:" -ForegroundColor Cyan
Write-Host $result.FindingDetails
Write-Host ""

if ($result.Comments) {
    Write-Host "Comments:" -ForegroundColor Cyan
    Write-Host $result.Comments
    Write-Host ""
}

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
