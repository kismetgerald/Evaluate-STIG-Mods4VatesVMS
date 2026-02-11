# Test Script for 4 Enhanced CAT I Checks
# Tests V-222432, V-222542, V-222543, V-222662 on XO1

param(
    [string]$ComputerName = "xo1.wgsdac.net"
)

Write-Host "=== Testing 4 Enhanced CAT I Checks ===" -ForegroundColor Green
Write-Host "Target: $ComputerName`n" -ForegroundColor Cyan

# Import module
$modulePath = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_ASD_Checks"
Import-Module "$modulePath\Scan-XO_ASD_Checks.psd1" -Force

# Create PS Session
$session = New-PSSession -HostName $ComputerName -UserName root

# Test each check
$checks = @(
    @{VulnID="V-222432"; Name="Account Lockout"},
    @{VulnID="V-222542"; Name="Hashed Passwords"},
    @{VulnID="V-222543"; Name="Encrypted Transmission"},
    @{VulnID="V-222662"; Name="Default Passwords"}
)

$results = @()

foreach ($check in $checks) {
    Write-Host "`n[$($check.VulnID)] $($check.Name)" -ForegroundColor Cyan
    Write-Host "=" * 60
    
    try {
        # VulnID is already "V-222432", function name is "Get-V222432" (no hyphen)
        $funcName = "Get-" + ($check.VulnID -replace '-','')
        
        # Copy module to remote system
        Invoke-Command -Session $session -ScriptBlock {
            param($modPath)
            if (-not (Test-Path "/tmp/Scan-XO_ASD_Checks")) {
                New-Item -Path "/tmp/Scan-XO_ASD_Checks" -ItemType Directory -Force | Out-Null
            }
        } -ArgumentList $modulePath
        
        Copy-Item -Path "$modulePath\*" -Destination "/tmp/Scan-XO_ASD_Checks/" -ToSession $session -Recurse -Force
        
        # Run check remotely
        $result = Invoke-Command -Session $session -ScriptBlock {
            param($vulnID)
            Import-Module "/tmp/Scan-XO_ASD_Checks/Scan-XO_ASD_Checks.psd1" -Force
            # VulnID is "V-222432", function is "Get-V222432"
            $funcName = "Get-" + ($vulnID -replace '-','')
            & $funcName -ScanType "Compliance"
        } -ArgumentList $check.VulnID
        
        Write-Host "Status: $($result.Status)" -ForegroundColor $(
            switch ($result.Status) {
                "Open" { "Red" }
                "NotAFinding" { "Green" }
                "Not_Applicable" { "Yellow" }
                "Not_Reviewed" { "Cyan" }
                default { "White" }
            }
        )
        
        Write-Host "`nFinding Details (first 500 chars):"
        Write-Host $result.FindingDetails.Substring(0, [Math]::Min(500, $result.FindingDetails.Length))
        
        $results += [PSCustomObject]@{
            VulnID = $check.VulnID
            Name = $check.Name
            Status = $result.Status
            Success = $true
        }
        
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
        $results += [PSCustomObject]@{
            VulnID = $check.VulnID
            Name = $check.Name
            Status = "ERROR"
            Success = $false
        }
    }
}

# Cleanup
Remove-PSSession $session
Remove-Module Scan-XO_ASD_Checks

# Summary
Write-Host "`n`n=== SUMMARY ===" -ForegroundColor Green
Write-Host "=" * 60
$results | Format-Table -AutoSize

$passed = ($results | Where-Object { $_.Status -in @("NotAFinding", "Not_Applicable") }).Count
$findings = ($results | Where-Object { $_.Status -eq "Open" }).Count
$errors = ($results | Where-Object { $_.Success -eq $false }).Count

Write-Host "`nResults: $passed passed, $findings findings, $errors errors" -ForegroundColor $(
    if ($errors -gt 0) { "Red" } elseif ($findings -gt 0) { "Yellow" } else { "Green" }
)
