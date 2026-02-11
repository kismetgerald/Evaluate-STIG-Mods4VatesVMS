#!/usr/bin/env pwsh
# Migration script to update relative paths after moving .Mods_by_Kismet folder up one level
# Created: February 9, 2026
# Purpose: Change ../../ paths to ../Evaluate-STIG/ paths in test scripts

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Relative Path Migration Script" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will update relative paths in test scripts after moving" -ForegroundColor Yellow
Write-Host ".Mods_by_Kismet folder from Evaluate-STIG/.Mods_by_Kismet to .Mods_by_Kismet" -ForegroundColor Yellow
Write-Host ""

# Define the scripts that need updating
$scriptsToUpdate = @(
    "test-V264347-performance.ps1",
    "test-V264357-with-traps.ps1",
    "compare-functions.ps1",
    "test-modulename-line.ps1",
    "debug-V264357-execution.ps1",
    "test-V206427.ps1",
    "test-V206367.ps1",
    "test-V206351.ps1"
)

# Define path replacements
$pathReplacements = @{
    # Module imports
    '../../Modules/Master_Functions/Master_Functions.psm1' = '../../Evaluate-STIG/Modules/Master_Functions/Master_Functions.psm1'
    '../../Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1' = '../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1'
    '../../Modules/Scan-XO_WebSRG_Checks' = '../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks'

    # Generic patterns for any other ../../Modules references
    '../../Modules/' = '../../Evaluate-STIG/Modules/'
    '../../AnswerFiles/' = '../../Evaluate-STIG/AnswerFiles/'
}

$scriptDir = $PSScriptRoot
$updatedCount = 0
$errorCount = 0

Write-Host "Processing $($scriptsToUpdate.Count) scripts..." -ForegroundColor Cyan
Write-Host ""

foreach ($scriptName in $scriptsToUpdate) {
    $scriptPath = Join-Path $scriptDir $scriptName

    if (-not (Test-Path $scriptPath)) {
        Write-Host "  [SKIP] $scriptName - File not found" -ForegroundColor Yellow
        continue
    }

    try {
        # Read the script content
        $content = Get-Content $scriptPath -Raw
        $originalContent = $content

        # Apply all replacements
        $replacementsMade = 0
        foreach ($oldPath in $pathReplacements.Keys) {
            $newPath = $pathReplacements[$oldPath]
            if ($content -match [regex]::Escape($oldPath)) {
                $content = $content -replace [regex]::Escape($oldPath), $newPath
                $replacementsMade++
            }
        }

        if ($replacementsMade -gt 0) {
            # Create backup
            $backupPath = "$scriptPath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Copy-Item $scriptPath $backupPath -Force

            # Write updated content
            Set-Content $scriptPath -Value $content -NoNewline

            Write-Host "  [UPDATED] $scriptName - $replacementsMade replacement(s) made" -ForegroundColor Green
            Write-Host "            Backup: $(Split-Path $backupPath -Leaf)" -ForegroundColor Gray
            $updatedCount++
        } else {
            Write-Host "  [NO CHANGE] $scriptName - No paths to update" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  [ERROR] $scriptName - $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }
}

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Migration Summary" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "  Scripts processed: $($scriptsToUpdate.Count)" -ForegroundColor White
Write-Host "  Scripts updated: $updatedCount" -ForegroundColor Green
Write-Host "  Scripts with no changes: $($scriptsToUpdate.Count - $updatedCount - $errorCount)" -ForegroundColor Gray
Write-Host "  Errors: $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($updatedCount -gt 0) {
    Write-Host "IMPORTANT: Backup files created with .backup_* extension" -ForegroundColor Yellow
    Write-Host "Test the updated scripts before deleting backups!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To remove backups after testing:" -ForegroundColor Cyan
    Write-Host "  Remove-Item '$scriptDir\*.backup_*'" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Migration complete!" -ForegroundColor Green

# Display example of changes made
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Example Changes Made:" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "OLD: Import-Module ../../Modules/Master_Functions/Master_Functions.psm1" -ForegroundColor Red
Write-Host "NEW: Import-Module ../../Evaluate-STIG/Modules/Master_Functions/Master_Functions.psm1" -ForegroundColor Green
Write-Host ""
Write-Host "OLD: Import-Module ../../Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1" -ForegroundColor Red
Write-Host "NEW: Import-Module ../../Evaluate-STIG/Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1" -ForegroundColor Green
