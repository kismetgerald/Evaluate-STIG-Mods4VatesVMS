# Standalone Test for V-206378
$ErrorActionPreference = 'Stop'

try {
	$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
	$mf = Join-Path $PSScriptRoot '..\..\Modules\Master_Functions\Master_Functions.psm1'
	if (-not (Test-Path $mf)) { throw "Master_Functions not found at $mf" }
	Import-Module $mf -Force -ErrorAction Stop

	$mod = Join-Path $PSScriptRoot '..\..\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1'
	if (-not (Test-Path $mod)) { throw "Scan-XO_WebSRG_Checks module not found at $mod" }
	Import-Module $mod -Force -ErrorAction Stop

	Write-Host "Running standalone test for V-206378..." -ForegroundColor Cyan
	if (-not (Get-Command Get-V206378 -ErrorAction SilentlyContinue)) { throw "Function Get-V206378 not exported after module import." }
	$result = Get-V206378 -ScanType 'Classified' -AllowedServices @('ssh','redis-server')
	Write-Host "STATUS: $($result.Status)"
	Write-Host "FINDING DETAILS:`n$($result.FindingDetails)"
}
catch {
	Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
	throw
}
