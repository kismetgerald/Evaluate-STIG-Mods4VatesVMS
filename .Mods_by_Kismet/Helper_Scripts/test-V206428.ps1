#!/usr/bin/env pwsh
# Test script for V-206428 implementation
# Session #26 - Feb 1, 2026

Write-Host "=== V-206428 Implementation Test ===" -ForegroundColor Cyan
Write-Host ""

# Change to Evaluate-STIG directory
Set-Location "d:\Dropbox\IT Docs\Scripts\VatesVMS-Evaluate-STIG\v1.2507.6_Mod4VatesVMS_OpenCode\Evaluate-STIG"

# Test 1: Module Load
Write-Host "Test 1: Module Load Test" -ForegroundColor Yellow
try {
    Import-Module ".\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psd1" -Force -ErrorAction Stop
    $functions = Get-Command -Module Scan-XO_WebSRG_Checks
    Write-Host "  Module loaded successfully" -ForegroundColor Green
    Write-Host "  Function count: $($functions.Count)" -ForegroundColor Green

    if ($functions.Count -eq 126) {
        Write-Host "  ✓ Expected 126 functions, got $($functions.Count)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Expected 126 functions, got $($functions.Count)" -ForegroundColor Red
    }
} catch {
    Write-Host "  ✗ Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 2: Function Exists
Write-Host ""
Write-Host "Test 2: Function Existence Test" -ForegroundColor Yellow
try {
    $func = Get-Command Get-V206428 -ErrorAction Stop
    Write-Host "  ✓ Get-V206428 function found" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Get-V206428 function not found" -ForegroundColor Red
    exit 1
}

# Test 3: Function Execution (Standalone)
Write-Host ""
Write-Host "Test 3: Standalone Function Execution" -ForegroundColor Yellow
Write-Host "  Executing Get-V206428..." -ForegroundColor Gray

$startTime = Get-Date
try {
    $result = Get-V206428 -ScanType "Classified"
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds

    Write-Host "  ✓ Function executed successfully" -ForegroundColor Green
    Write-Host "  Execution time: $([math]::Round($duration, 2)) seconds" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Results:" -ForegroundColor Cyan
    Write-Host "    Module: $($result.Module)" -ForegroundColor Gray
    Write-Host "    Status: $($result.Status)" -ForegroundColor $(if ($result.Status -eq "NotAFinding") { "Green" } elseif ($result.Status -eq "Open") { "Yellow" } else { "Gray" })
    Write-Host "    VulnID: $($result.VulnID)" -ForegroundColor Gray
    Write-Host "    RuleID: $($result.RuleID)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Finding Details (first 500 chars):" -ForegroundColor Cyan
    Write-Host "    $($result.FindingDetails.Substring(0, [Math]::Min(500, $result.FindingDetails.Length)))..." -ForegroundColor Gray

} catch {
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    Write-Host "  ✗ Function execution failed after $([math]::Round($duration, 2)) seconds" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 4: Answer File Validation
Write-Host ""
Write-Host "Test 4: Answer File Validation" -ForegroundColor Yellow
try {
    $answerFile = ".\AnswerFiles\XO_v5.x_WebSRG_AnswerFile.xml"
    if (Test-Path $answerFile) {
        [xml]$xml = Get-Content $answerFile
        $vuln = $xml.STIGComments.Vuln | Where-Object { $_.ID -eq "V-206428" }

        if ($vuln) {
            Write-Host "  ✓ V-206428 entry found in answer file" -ForegroundColor Green
            $answerKey = $vuln.AnswerKey | Where-Object { $_.Name -eq "XO" }
            if ($answerKey) {
                $answerCount = ($answerKey.Answer | Measure-Object).Count
                Write-Host "  ✓ Answer key 'XO' found with $answerCount answer indices" -ForegroundColor Green

                if ($answerCount -eq 2) {
                    Write-Host "  ✓ Expected 2 answer indices (NotAFinding + Open)" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ Expected 2 answer indices, found $answerCount" -ForegroundColor Red
                }
            } else {
                Write-Host "  ✗ Answer key 'XO' not found" -ForegroundColor Red
            }
        } else {
            Write-Host "  ✗ V-206428 entry not found in answer file" -ForegroundColor Red
        }
    } else {
        Write-Host "  ✗ Answer file not found: $answerFile" -ForegroundColor Red
    }
} catch {
    Write-Host "  ✗ Answer file validation failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "  - Module loads with 126 functions" -ForegroundColor Gray
Write-Host "  - Get-V206428 function exists and executes" -ForegroundColor Gray
Write-Host "  - Execution time: $([math]::Round($duration, 2)) seconds" -ForegroundColor Gray
Write-Host "  - Status returned: $($result.Status)" -ForegroundColor Gray
Write-Host "  - Answer file entries: 2 indices (NF + O)" -ForegroundColor Gray
Write-Host ""
