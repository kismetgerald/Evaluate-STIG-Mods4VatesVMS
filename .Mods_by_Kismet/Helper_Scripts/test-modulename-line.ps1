#!/usr/bin/env pwsh
# Test if the $ModuleName line causes issues

Import-Module ../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1 -Force

Write-Host "Testing Get-Command with MyInvocation..." -ForegroundColor Cyan

$testFunction = {
    param($ScanType)

    Write-Host "Inside function, MyInvocation.MyCommand = $($MyInvocation.MyCommand)" -ForegroundColor Yellow

    try {
        $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
        Write-Host "ModuleName resolved to: $ModuleName" -ForegroundColor Green
    } catch {
        Write-Host "ERROR getting ModuleName: $_" -ForegroundColor Red
        Write-Host "Error type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
    }

    # Test if execution continues after that line
    Write-Host "Execution continued after ModuleName line" -ForegroundColor Green

    $output = @()
    $output += "Test line"
    Write-Host "Output array populated: $($output.Count) items" -ForegroundColor Green

    return @{
        Status = "Open"
        FindingDetails = ($output -join "`n")
    }
}

Write-Host "`nCalling test function..." -ForegroundColor Cyan
$result = & $testFunction -ScanType 'Classified'

Write-Host "`nResult:" -ForegroundColor Cyan
Write-Host "Status: $($result.Status)"
Write-Host "FindingDetails: $($result.FindingDetails)"
Write-Host "FindingDetails Length: $($result.FindingDetails.Length)"
