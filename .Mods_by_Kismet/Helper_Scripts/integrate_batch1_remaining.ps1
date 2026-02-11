#!/usr/bin/env pwsh
# integrate_batch1_remaining.ps1
# Integrates remaining 4 Session #32 Batch 1 functions into Scan-XO_WebSRG_Checks.psm1

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Session #32 Batch 1 Integration - Remaining 4 Functions" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# Paths
$projectRoot = "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode"
$modulePath = Join-Path $projectRoot "Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"
$backupPath = Join-Path $projectRoot "Evaluate-STIG\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks_backup_batch1.psm1"

# Implementation files
$implFiles = @(
    @{ VulnID = "V-206426"; File = Join-Path $projectRoot "V206426_implementation.ps1"; StartMarker = "Function Get-V206426" }
    @{ VulnID = "V-264341"; File = Join-Path $projectRoot "V264341_implementation.ps1"; StartMarker = "Function Get-V264341" }
    @{ VulnID = "V-264358"; File = Join-Path $projectRoot "V264358_implementation.ps1"; StartMarker = "Function Get-V264358" }
    @{ VulnID = "V-264359"; File = Join-Path $projectRoot "V264359_implementation.ps1"; StartMarker = "Function Get-V264359" }
)

# Step 1: Verify files
Write-Host "[1/5] Verifying files..." -ForegroundColor Yellow
if (-not (Test-Path $modulePath)) {
    Write-Error "Module file not found: $modulePath"
}
foreach ($impl in $implFiles) {
    if (-not (Test-Path $impl.File)) {
        Write-Error "Implementation file not found: $($impl.File)"
    }
}
Write-Host "   ✓ All files found" -ForegroundColor Green
Write-Host ""

# Step 2: Create backup
Write-Host "[2/5] Creating backup..." -ForegroundColor Yellow
Copy-Item $modulePath $backupPath -Force
Write-Host "   ✓ Backup created: $backupPath" -ForegroundColor Green
Write-Host ""

# Step 3: Read module content
Write-Host "[3/5] Reading module file..." -ForegroundColor Yellow
$moduleContent = Get-Content $modulePath -Raw
$originalSize = $moduleContent.Length
Write-Host "   ✓ Module read successfully ($originalSize characters)" -ForegroundColor Green
Write-Host ""

# Step 4: Integrate each function
Write-Host "[4/5] Integrating functions..." -ForegroundColor Yellow
$updatedContent = $moduleContent

foreach ($impl in $implFiles) {
    Write-Host "   Processing $($impl.VulnID)..." -ForegroundColor Cyan

    # Read implementation
    $implContent = Get-Content $impl.File -Raw

    # Find stub function (from "Function Get-V######" to next "Function Get-V" or end of file)
    $pattern = "(?s)($($impl.StartMarker)\s*\{.*?)(?=Function Get-V|\z)"

    if ($updatedContent -match $pattern) {
        $stubContent = $matches[1]
        $stubLines = ($stubContent -split "`n").Count

        # Replace stub with implementation
        $updatedContent = $updatedContent -replace [regex]::Escape($stubContent), $implContent.TrimEnd()

        $implLines = ($implContent -split "`n").Count
        $diff = $implLines - $stubLines

        Write-Host "      ✓ Replaced stub ($stubLines lines) with implementation ($implLines lines, $diff net)" -ForegroundColor Green
    }
    else {
        Write-Warning "      Could not find stub for $($impl.VulnID) - may already be integrated"
    }
}
Write-Host ""

# Step 5: Write updated module
Write-Host "[5/5] Writing updated module..." -ForegroundColor Yellow
$updatedContent | Set-Content $modulePath -NoNewline
$newSize = $updatedContent.Length
$sizeDiff = $newSize - $originalSize
Write-Host "   ✓ Module updated successfully" -ForegroundColor Green
Write-Host "   Old size: $originalSize characters" -ForegroundColor Gray
Write-Host "   New size: $newSize characters" -ForegroundColor Gray
Write-Host "   Difference: $sizeDiff characters" -ForegroundColor Gray
Write-Host ""

# Step 6: Verify module loads
Write-Host "[6/6] Verifying module loads..." -ForegroundColor Yellow
try {
    Import-Module $modulePath -Force -ErrorAction Stop
    $functionCount = (Get-Command -Module Scan-XO_WebSRG_Checks).Count
    Write-Host "   ✓ Module loads successfully" -ForegroundColor Green
    Write-Host "   Exported functions: $functionCount" -ForegroundColor Gray

    # Verify specific functions
    $targetFunctions = @("Get-V206426", "Get-V264341", "Get-V264358", "Get-V264359")
    $foundFunctions = Get-Command -Module Scan-XO_WebSRG_Checks | Where-Object { $_.Name -in $targetFunctions }
    Write-Host "   Verified functions: $($foundFunctions.Name -join ', ')" -ForegroundColor Gray
}
catch {
    Write-Error "Module failed to load: $_"
}
Write-Host ""

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Integration Complete!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Delete implementation files: V206426_implementation.ps1, V264341_implementation.ps1, V264358_implementation.ps1, V264359_implementation.ps1" -ForegroundColor Gray
Write-Host "2. Create answer file entries (4 functions × 2 indices = 8 entries)" -ForegroundColor Gray
Write-Host "3. Run Test111 (standalone function testing)" -ForegroundColor Gray
Write-Host "4. Run Test111b (framework validation on XO1.WGSDAC.NET)" -ForegroundColor Gray
Write-Host ""
