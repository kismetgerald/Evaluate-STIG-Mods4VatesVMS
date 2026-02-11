#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script for Debian 12 GPOS firewall-related compliance checks
    
.DESCRIPTION
    Runs all firewall-related checks from Scan-Debian12_GPOS_Checks module
    against the current Debian 12 system and displays results with details
    
.NOTES
    Requires PowerShell 7.1+ and the Debian12 GPOS module loaded
    Firewall checks are typically in the "Security Controls" category
#>

param(
    [switch]$Verbose,
    [switch]$ShowImplementation
)

$ErrorActionPreference = "Stop"

# Import required modules
Write-Host "Loading modules..." -ForegroundColor Cyan
Import-Module .\Modules\Master_Functions\STIGDetection\STIGDetection.psm1 -Force -WarningAction SilentlyContinue
Import-Module .\Modules\Scan-Debian12_GPOS_Checks\Scan-Debian12_GPOS_Checks.psd1 -Force -WarningAction SilentlyContinue

# Identify firewall-related checks
# Firewall is typically in "Security Controls & AppArmor" category (V-254436 through V-254455)
# But also might be in other categories, so we'll check comments/titles

$firewallCheckNumbers = @(436..455)  # Security Controls category - likely to contain firewall

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "Debian 12 GPOS Firewall Checks Test" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Yellow

Write-Host "System Information:" -ForegroundColor Cyan
Write-Host "  OS: $(uname -s)" 
Write-Host "  Kernel: $(uname -r)"
Write-Host "  Hostname: $(hostname)`n"

# Firewall Status Detection
Write-Host "Firewall Status Detection:" -ForegroundColor Cyan
Write-Host "  UFW:" $((systemctl is-active ufw 2>/dev/null) -eq "active" ? "ACTIVE" : "inactive")
Write-Host "  firewalld:" $((systemctl is-active firewalld 2>/dev/null) -eq "active" ? "ACTIVE" : "inactive")
Write-Host "  nftables:" $((systemctl is-active nftables 2>/dev/null) -eq "active" ? "ACTIVE" : "inactive")

# Check for iptables rules
$iptablesRules = @(iptables -L -n 2>/dev/null | grep -c "Chain" | Out-String).Trim()
Write-Host "  iptables rules: $(if ([int]$iptablesRules -gt 0) { "ACTIVE ($iptablesRules chains)" } else { "none" })"
Write-Host ""

# Run firewall checks
Write-Host "Running Firewall-Related Checks:" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Cyan

$results = @()
$firewall_findings = @()

foreach ($num in $firewallCheckNumbers) {
    $vulnID = "V-254$num"
    $functionName = "Get-V254$num"
    
    # Try to call the function
    try {
        Write-Host "Testing $vulnID..." -ForegroundColor Gray
        
        $result = & $functionName -ScanType "Full" -AnswerFile "" -ComputerName "$(hostname)" -OSGuess "Debian12"
        
        if ($result) {
            $results += $result
            $firewall_findings += @{
                VulnID = $vulnID
                Status = $result.Status
                Category = $result.Comments
                Details = $result.FindingDetails
            }
            
            Write-Host "  Status: $($result.Status)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Error: $_" -ForegroundColor Red
    }
}

# Display Summary
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "Test Results Summary" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Yellow

if ($results.Count -eq 0) {
    Write-Host "No firewall-specific checks found in V-254436-V-254455 range" -ForegroundColor Yellow
    Write-Host "This is expected - firewall checks may use template implementation" -ForegroundColor Gray
}
else {
    # Group by status
    $byStatus = $results | Group-Object -Property Status
    
    foreach ($group in $byStatus) {
        Write-Host "$($group.Name): $($group.Count)" -ForegroundColor Cyan
    }
}

# Show detailed findings
Write-Host "`nDetailed Findings:" -ForegroundColor Cyan
Write-Host "-----------------`n"

foreach ($finding in $firewall_findings) {
    Write-Host "Check: $($finding.VulnID)" -ForegroundColor Yellow
    Write-Host "Status: $($finding.Status)"
    Write-Host "Category: $($finding.Category)"
    if ($finding.Details) {
        Write-Host "Details: $($finding.Details.Substring(0, [Math]::Min(200, $finding.Details.Length)))..."
    }
    Write-Host ""
}

# Export results for review
$exportFile = "firewall_check_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$results | ConvertTo-Json | Out-File -FilePath $exportFile
Write-Host "Results exported to: $exportFile" -ForegroundColor Green

# Firewall Detection Test
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "Firewall Detection Test" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Yellow

Write-Host "Testing firewall detection logic:" -ForegroundColor Cyan
Write-Host ""

# Run the firewall detection commands
Write-Host "Available firewall packages:" -ForegroundColor Cyan
dpkg -l 2>/dev/null | grep -E 'ufw|firewalld|nftables|iptables' | awk '{print "  " $2 ": " $3}' || Write-Host "  (none found)"

Write-Host ""
Write-Host "Active firewall services:" -ForegroundColor Cyan
$activeFirewall = $null

foreach ($service in @("firewalld", "ufw", "nftables")) {
    $isActive = (systemctl is-active $service 2>/dev/null) -eq "active"
    if ($isActive) {
        Write-Host "  ✓ $service is ACTIVE"
        if ($null -eq $activeFirewall) { $activeFirewall = $service }
    } else {
        Write-Host "  ✗ $service is inactive"
    }
}

# Check iptables
$iptablesCount = iptables -L -n 2>/dev/null | grep "^Chain" | wc -l
if ($iptablesCount -gt 0) {
    Write-Host "  ✓ iptables has $iptablesCount chains configured"
    if ($null -eq $activeFirewall) { $activeFirewall = "iptables" }
}

if ($null -eq $activeFirewall) {
    Write-Host "  ⚠ No active firewall service detected"
    Write-Host "  This is valid for XOCE (Community Edition) deployments"
}

Write-Host ""
Write-Host "Recommendation:" -ForegroundColor Yellow
if ($null -eq $activeFirewall) {
    Write-Host "Firewall checks should return NotApplicable status"
} else {
    Write-Host "Firewall checks should validate $activeFirewall configuration"
}

Write-Host ""
