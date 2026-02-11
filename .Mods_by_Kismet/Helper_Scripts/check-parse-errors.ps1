#!/usr/bin/env pwsh
# Check for parse errors in V-264357

$modulePath = "../../Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1"

Write-Host "Parsing module file..." -ForegroundColor Cyan
$errors = @()
$ast = [System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$errors)

if ($errors.Count -gt 0) {
    Write-Host "Parse Errors Found: $($errors.Count)" -ForegroundColor Red
    $v264357Errors = $errors | Where-Object {
        $_.Extent.StartLineNumber -ge 34473 -and $_.Extent.StartLineNumber -le 35136
    }
    if ($v264357Errors) {
        Write-Host "`nErrors in V-264357 range (lines 34473-35136):" -ForegroundColor Red
        foreach ($err in $v264357Errors) {
            Write-Host "  Line $($err.Extent.StartLineNumber): $($err.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "`nNo errors in V-264357 range" -ForegroundColor Yellow
        Write-Host "Showing first 5 errors from module:" -ForegroundColor Yellow
        $errors | Select-Object -First 5 | ForEach-Object {
            Write-Host "  Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "No parse errors in module" -ForegroundColor Green
}

Write-Host "`nChecking if Get-V264357 function exists in AST..." -ForegroundColor Cyan
$func = $ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Get-V264357'
}, $true) | Select-Object -First 1

if ($func) {
    Write-Host "Function found at line $($func.Extent.StartLineNumber)" -ForegroundColor Green
    Write-Host "Function body has $($func.Body.Statements.Count) statements" -ForegroundColor Green
} else {
    Write-Host "Function NOT found in AST!" -ForegroundColor Red
}
