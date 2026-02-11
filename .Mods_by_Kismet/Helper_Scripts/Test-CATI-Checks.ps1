#!/usr/bin/env pwsh
#Requires -Version 7.1

<#
.SYNOPSIS
    Demonstration script for CAT I password security checks
.DESCRIPTION
    Tests the three newly implemented CAT I checks:
    - V-204424: Blank/null password check
    - V-204425: SSH empty password authentication
    - V-251702: Blank/null password check (duplicate)
#>

Import-Module ".\Evaluate-STIG\Modules\Scan-XCP-ng_Dom0_GPOS_Checks\Scan-XCP-ng_Dom0_GPOS_Checks.psm1" -Force

Write-Host "`n==========================================================================" -ForegroundColor Cyan
Write-Host "CAT I CHECK DEMONSTRATION - Scan-XCP-ng_Dom0_GPOS_Checks Module" -ForegroundColor Cyan
Write-Host "==========================================================================`n" -ForegroundColor Cyan

# Test V-204424
Write-Host "Testing Get-V204424 - Blank/Null Password Check`n" -ForegroundColor Yellow
$result1 = Get-V204424 -ScanType "Classified" -AnswerFile "test.xml" -ComputerName $env:COMPUTERNAME -OSGuess "XCPng"
Write-Host "VulnID: $($result1.VulnID)" -ForegroundColor Green
Write-Host "Status: $($result1.Status)" -ForegroundColor $(if($result1.Status -eq "NotAFinding"){"Green"}else{"Red"})
Write-Host "Finding Details Preview:" -ForegroundColor Magenta
Write-Host ($result1.FindingDetails -split "`n" | Select-Object -First 15 | Out-String)

Write-Host "`n--------------------------------------------------------------------------`n" -ForegroundColor Cyan

# Test V-204425
Write-Host "Testing Get-V204425 - SSH Empty Password Authentication Check`n" -ForegroundColor Yellow
$result2 = Get-V204425 -ScanType "Classified" -AnswerFile "test.xml" -ComputerName $env:COMPUTERNAME -OSGuess "XCPng"
Write-Host "VulnID: $($result2.VulnID)" -ForegroundColor Green
Write-Host "Status: $($result2.Status)" -ForegroundColor $(if($result2.Status -eq "NotAFinding"){"Green"}else{"Red"})
Write-Host "Finding Details Preview:" -ForegroundColor Magenta
Write-Host ($result2.FindingDetails -split "`n" | Select-Object -First 15 | Out-String)

Write-Host "`n--------------------------------------------------------------------------`n" -ForegroundColor Cyan

# Test V-251702
Write-Host "Testing Get-V251702 - Blank/Null Password Check (Duplicate)`n" -ForegroundColor Yellow
$result3 = Get-V251702 -ScanType "Classified" -AnswerFile "test.xml" -ComputerName $env:COMPUTERNAME -OSGuess "XCPng"
Write-Host "VulnID: $($result3.VulnID)" -ForegroundColor Green
Write-Host "Status: $($result3.Status)" -ForegroundColor $(if($result3.Status -eq "NotAFinding"){"Green"}else{"Red"})
Write-Host "Finding Details Preview:" -ForegroundColor Magenta
Write-Host ($result3.FindingDetails -split "`n" | Select-Object -First 15 | Out-String)

Write-Host "`n==========================================================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "==========================================================================`n" -ForegroundColor Cyan
Write-Host "V-204424 (Blank Passwords):        $($result1.Status)" -ForegroundColor $(if($result1.Status -eq "NotAFinding"){"Green"}else{"Red"})
Write-Host "V-204425 (SSH Empty Passwords):    $($result2.Status)" -ForegroundColor $(if($result2.Status -eq "NotAFinding"){"Green"}else{"Red"})
Write-Host "V-251702 (Blank Passwords Dup):    $($result3.Status)" -ForegroundColor $(if($result3.Status -eq "NotAFinding"){"Green"}else{"Red"})
Write-Host ""
