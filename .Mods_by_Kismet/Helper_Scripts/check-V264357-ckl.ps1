#!/usr/bin/env pwsh
# Check V-264357 results in Test119c CKL file

$cklPath = "./Results/XO1/Checklist/XO1_XO_WebSRG_V4R4_20260209-190419.ckl"

if (-not (Test-Path $cklPath)) {
    Write-Host "CKL file not found: $cklPath" -ForegroundColor Red
    exit 1
}

Write-Host "Loading CKL file..." -ForegroundColor Cyan
$ckl = [xml](Get-Content $cklPath)

Write-Host "Finding V-264357..." -ForegroundColor Cyan
$vuln = $ckl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object {
    $_.STIG_DATA | Where-Object {
        $_.VULN_ATTRIBUTE -eq 'Vuln_Num' -and $_.ATTRIBUTE_DATA -eq 'V-264357'
    }
}

if (-not $vuln) {
    Write-Host "V-264357 not found in CKL file" -ForegroundColor Red
    exit 1
}

Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "V-264357 RESULTS" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

Write-Host "`nSTATUS: $($vuln.STATUS)" -ForegroundColor $(if ($vuln.STATUS -eq 'Open') { 'Yellow' } elseif ($vuln.STATUS -eq 'NotAFinding') { 'Green' } else { 'Gray' })

Write-Host "`nFINDING_DETAILS Length: $($vuln.FINDING_DETAILS.Length) characters" -ForegroundColor Cyan
if ($vuln.FINDING_DETAILS.Length -gt 0) {
    Write-Host "First 800 characters:" -ForegroundColor Cyan
    Write-Host $vuln.FINDING_DETAILS.Substring(0, [Math]::Min(800, $vuln.FINDING_DETAILS.Length))
    if ($vuln.FINDING_DETAILS.Length -gt 800) {
        Write-Host "`n... (truncated, full length: $($vuln.FINDING_DETAILS.Length) chars)" -ForegroundColor Gray
    }
} else {
    Write-Host "[EMPTY]" -ForegroundColor Red
}

Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "COMMENTS Length: $($vuln.COMMENTS.Length) characters" -ForegroundColor Cyan
if ($vuln.COMMENTS.Length -gt 0) {
    Write-Host "First 800 characters:" -ForegroundColor Cyan
    Write-Host $vuln.COMMENTS.Substring(0, [Math]::Min(800, $vuln.COMMENTS.Length))
    if ($vuln.COMMENTS.Length -gt 800) {
        Write-Host "`n... (truncated, full length: $($vuln.COMMENTS.Length) chars)" -ForegroundColor Gray
    }
} else {
    Write-Host "[EMPTY]" -ForegroundColor Red
}

Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "VALIDATION" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

$success = $true

if ($vuln.STATUS -eq 'Not_Reviewed') {
    Write-Host "[FAIL] Status is Not_Reviewed (should be Open or NotAFinding)" -ForegroundColor Red
    $success = $false
} else {
    Write-Host "[PASS] Status is not Not_Reviewed" -ForegroundColor Green
}

if ($vuln.FINDING_DETAILS.Length -eq 0) {
    Write-Host "[FAIL] FINDING_DETAILS is empty" -ForegroundColor Red
    $success = $false
} else {
    Write-Host "[PASS] FINDING_DETAILS is populated ($($vuln.FINDING_DETAILS.Length) chars)" -ForegroundColor Green
}

if ($vuln.COMMENTS.Length -eq 0) {
    Write-Host "[FAIL] COMMENTS is empty (answer file not matched)" -ForegroundColor Red
    $success = $false
} else {
    Write-Host "[PASS] COMMENTS is populated ($($vuln.COMMENTS.Length) chars)" -ForegroundColor Green
}

if ($success) {
    Write-Host "`n[SUCCESS] V-264357 executed correctly!" -ForegroundColor Green
} else {
    Write-Host "`n[FAILURE] V-264357 has issues" -ForegroundColor Red
}
