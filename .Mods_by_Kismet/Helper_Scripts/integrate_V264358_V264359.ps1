#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Integration helper script for V-264358 and V-264359 implementations

.DESCRIPTION
    This script replaces the stub functions for V-264358 and V-264359 in the
    Scan-XO_WebSRG_Checks module with the full implementations.

.NOTES
    Created: February 3, 2026
    Session: #32 Batch 1
    Functions: V-264358 (Time Sync), V-264359 (Sync Frequency)
#>

$ErrorActionPreference = "Stop"

# File paths
$moduleFile = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
$v264358File = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\V264358_implementation.ps1"
$v264359File = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\V264359_implementation.ps1"
$backupFile = $moduleFile -replace '\.psm1$', '_backup_before_session32.psm1'

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Session #32 Batch 1 Integration - V-264358 and V-264359" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Verify files exist
Write-Host "[1/6] Verifying files..." -ForegroundColor Yellow
if (-not (Test-Path $moduleFile)) {
    Write-Error "Module file not found: $moduleFile"
    exit 1
}
if (-not (Test-Path $v264358File)) {
    Write-Error "V-264358 implementation not found: $v264358File"
    exit 1
}
if (-not (Test-Path $v264359File)) {
    Write-Error "V-264359 implementation not found: $v264359File"
    exit 1
}
Write-Host "   ✓ All files found" -ForegroundColor Green

# Step 2: Create backup
Write-Host "[2/6] Creating backup..." -ForegroundColor Yellow
Copy-Item $moduleFile $backupFile -Force
Write-Host "   ✓ Backup created: $backupFile" -ForegroundColor Green

# Step 3: Read files
Write-Host "[3/6] Reading implementation files..." -ForegroundColor Yellow
$moduleContent = Get-Content $moduleFile -Raw
$v264358Content = Get-Content $v264358File -Raw
$v264359Content = Get-Content $v264359File -Raw
Write-Host "   ✓ Files read successfully" -ForegroundColor Green
Write-Host "      Module size: $($moduleContent.Length) characters" -ForegroundColor Gray
Write-Host "      V-264358 impl: $($v264358Content.Length) characters" -ForegroundColor Gray
Write-Host "      V-264359 impl: $($v264359Content.Length) characters" -ForegroundColor Gray

# Step 4: Find and replace V-264358 stub
Write-Host "[4/6] Replacing V-264358 stub function..." -ForegroundColor Yellow
$v264358Pattern = '(?s)(Function Get-V264358 \{.*?^})\s*(?=Function Get-V264359)'
if ($moduleContent -match $v264358Pattern) {
    $moduleContent = $moduleContent -replace $v264358Pattern, "$v264358Content`n"
    Write-Host "   ✓ V-264358 stub replaced" -ForegroundColor Green
}
else {
    Write-Error "Could not find V-264358 stub function in module"
    exit 1
}

# Step 5: Find and replace V-264359 stub
Write-Host "[5/6] Replacing V-264359 stub function..." -ForegroundColor Yellow
$v264359Pattern = '(?s)(Function Get-V264359 \{.*?^})\s*(?=Function Get-V264360)'
if ($moduleContent -match $v264359Pattern) {
    $moduleContent = $moduleContent -replace $v264359Pattern, "$v264359Content`n"
    Write-Host "   ✓ V-264359 stub replaced" -ForegroundColor Green
}
else {
    Write-Error "Could not find V-264359 stub function in module"
    exit 1
}

# Step 6: Write updated module
Write-Host "[6/6] Writing updated module..." -ForegroundColor Yellow
Set-Content -Path $moduleFile -Value $moduleContent -NoNewline
Write-Host "   ✓ Module updated successfully" -ForegroundColor Green
Write-Host "      New size: $($moduleContent.Length) characters" -ForegroundColor Gray

# Summary
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "INTEGRATION COMPLETE" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Test module loading:" -ForegroundColor White
Write-Host "   Import-Module '$moduleFile' -Force -Verbose" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Verify functions exported:" -ForegroundColor White
Write-Host "   Get-Command -Module Scan-XO_WebSRG_Checks | Where-Object { `$_.Name -match 'V264358|V264359' }" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Run standalone function tests:" -ForegroundColor White
Write-Host "   `$result358 = Get-V264358 -ScanType 'Unclassified'" -ForegroundColor Gray
Write-Host "   `$result359 = Get-V264359 -ScanType 'Unclassified'" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Run framework scan test:" -ForegroundColor White
Write-Host "   cd 'Evaluate-STIG'" -ForegroundColor Gray
Write-Host "   .\Evaluate-STIG.ps1 -ComputerName xo1.wgsdac.net -SelectSTIG 'XO_WebSRG' -Output Console -AllowIntegrityViolations" -ForegroundColor Gray
Write-Host ""
Write-Host "Backup location: $backupFile" -ForegroundColor Cyan
Write-Host ""
