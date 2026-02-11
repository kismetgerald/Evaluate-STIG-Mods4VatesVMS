#!/usr/bin/env pwsh
# Diagnostic test for V-264357
# Run from: Evaluate-STIG directory
# Command: .\.Mods_by_Kismet\Test\test-V264357-debug.ps1

Write-Host "================================" -ForegroundColor Cyan
Write-Host "V-264357 Diagnostic Test" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Import Master_Functions
Write-Host "[1] Importing Master_Functions..." -ForegroundColor Yellow
try {
    Remove-Module Master_Functions -Force -ErrorAction SilentlyContinue
    Import-Module .\Modules\Master_Functions\Master_Functions.psm1 -Force -ErrorAction Stop
    Write-Host "    [OK] Master_Functions imported" -ForegroundColor Green
} catch {
    Write-Host "    [FAIL] Master_Functions import error: $_" -ForegroundColor Red
    exit 1
}

# Import WebSRG module
Write-Host "[2] Importing Scan-XO_WebSRG_Checks..." -ForegroundColor Yellow
try {
    Remove-Module Scan-XO_WebSRG_Checks -Force -ErrorAction SilentlyContinue
    Import-Module .\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1 -Force -ErrorAction Stop
    $exportedCount = (Get-Command -Module Scan-XO_WebSRG_Checks).Count
    Write-Host "    [OK] Module imported, $exportedCount functions exported" -ForegroundColor Green
} catch {
    Write-Host "    [FAIL] Module import error: $_" -ForegroundColor Red
    exit 1
}

# Check if Get-V264357 exists
Write-Host "[3] Checking Get-V264357 function..." -ForegroundColor Yellow
$func = Get-Command Get-V264357 -ErrorAction SilentlyContinue
if ($func) {
    Write-Host "    [OK] Function exists" -ForegroundColor Green
} else {
    Write-Host "    [FAIL] Function not found" -ForegroundColor Red
    exit 1
}

# Check if Send-CheckResult exists
Write-Host "[4] Checking Send-CheckResult function..." -ForegroundColor Yellow
$sendFunc = Get-Command Send-CheckResult -ErrorAction SilentlyContinue
if ($sendFunc) {
    Write-Host "    [OK] Send-CheckResult exists in $($sendFunc.Source)" -ForegroundColor Green
} else {
    Write-Host "    [FAIL] Send-CheckResult not found" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[5] Executing Get-V264357 with error capture..." -ForegroundColor Yellow

# Capture all streams
$errors = @()
$warnings = @()
$verbose = @()

$testParams = @{
    ScanType = 'Classified'
    AnswerFile = ''
    AnswerKey  = 'V-264357'
    Username   = 'NA'
    UserSID    = 'NA'
    Hostname   = 'localhost'
    Instance   = 'NA'
    Database   = 'NA'
    SiteName   = 'NA'
}

$startTime = Get-Date
try {
    $result = Get-V264357 @testParams -ErrorVariable +errors -WarningVariable +warnings -Verbose:$false 2>&1 | Tee-Object -Variable verbose
} catch {
    Write-Host "    [EXCEPTION] $_" -ForegroundColor Red
    Write-Host "    Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
    Write-Host "    Stack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    exit 1
}
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Host "    [OK] Function completed in $([math]::Round($duration, 2)) seconds" -ForegroundColor Green
Write-Host ""

# Display errors
if ($errors.Count -gt 0) {
    Write-Host "[ERRORS CAPTURED: $($errors.Count)]" -ForegroundColor Red
    foreach ($err in $errors) {
        Write-Host "  - $err" -ForegroundColor Red
    }
    Write-Host ""
}

# Display warnings
if ($warnings.Count -gt 0) {
    Write-Host "[WARNINGS CAPTURED: $($warnings.Count)]" -ForegroundColor Yellow
    foreach ($warn in $warnings) {
        Write-Host "  - $warn" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Display verbose output
if ($verbose.Count -gt 0 -and $verbose[0] -ne $result) {
    Write-Host "[VERBOSE OUTPUT: $($verbose.Count)]" -ForegroundColor Cyan
    $verbose | Where-Object { $_ -ne $result } | ForEach-Object {
        Write-Host "  - $_" -ForegroundColor Gray
    }
    Write-Host ""
}

Write-Host "================================" -ForegroundColor Cyan
Write-Host "RESULT ANALYSIS" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

if ($null -eq $result) {
    Write-Host "[FAIL] Result is NULL" -ForegroundColor Red
    exit 1
}

Write-Host "Result Type: $($result.GetType().Name)" -ForegroundColor Cyan
Write-Host ""

# Check properties
$props = $result.PSObject.Properties.Name
Write-Host "Properties ($($props.Count)):" -ForegroundColor Cyan
foreach ($prop in $props) {
    $value = $result.$prop
    if ($null -eq $value) {
        Write-Host "  $prop = [NULL]" -ForegroundColor Gray
    } elseif ($value -eq "") {
        Write-Host "  $prop = [EMPTY STRING]" -ForegroundColor Gray
    } else {
        $displayValue = if ($value.ToString().Length -gt 80) {
            $value.ToString().Substring(0, 80) + "... (truncated)"
        } else {
            $value.ToString()
        }
        Write-Host "  $prop = $displayValue" -ForegroundColor White
    }
}

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "DIAGNOSIS" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

if ($result.Status -eq "Not_Reviewed") {
    Write-Host "[ISSUE] Status is Not_Reviewed (default value - function may not have executed custom code)" -ForegroundColor Yellow
}

if ([string]::IsNullOrEmpty($result.FindingDetails)) {
    Write-Host "[ISSUE] FindingDetails is empty (custom code did not populate \$output array)" -ForegroundColor Yellow
}

if ($result.Status -ne "Not_Reviewed" -or -not [string]::IsNullOrEmpty($result.FindingDetails)) {
    Write-Host "[OK] Function executed successfully" -ForegroundColor Green
}
