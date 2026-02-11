#!/usr/bin/env pwsh
# Test module loading after duplicate function declaration fix

cd "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG"

Write-Host "Testing module load after duplicate function declaration fix..."
Write-Host ""

try {
    Import-Module .\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psd1 -Force -ErrorAction Stop
    Write-Host "[OK] Module loaded successfully"

    $functionCount = (Get-Command -Module Scan-XO_WebSRG_Checks).Count
    Write-Host "[OK] Exported functions: $functionCount"
    Write-Host ""

    Write-Host "Checking Batch 2 functions:"
    $batch2Functions = @('Get-V206416','Get-V206417','Get-V206418','Get-V206421','Get-V206422')
    $foundCount = 0

    foreach ($funcName in $batch2Functions) {
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            Write-Host "  [OK] $funcName"
            $foundCount++
        } else {
            Write-Host "  [MISSING] $funcName"
        }
    }

    Write-Host ""
    if ($foundCount -eq 5) {
        Write-Host "[SUCCESS] All 5 Batch 2 functions available"
        exit 0
    } else {
        Write-Host "[ERROR] Only $foundCount/5 Batch 2 functions available"
        exit 1
    }

} catch {
    Write-Host "[ERROR] Module failed to load:"
    Write-Host $_.Exception.Message
    exit 2
}
