#!/usr/bin/env pwsh
# AST Analysis for V-264357

$modulePath = "..\..\Modules\Scan-XO_WebSRG_Checks\Scan-XO_WebSRG_Checks.psm1"

$parseErrors = @()
$ast = [System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$parseErrors)

if ($parseErrors.Count -gt 0) {
    Write-Host "Parse Errors Found:" -ForegroundColor Red
    $parseErrors | ForEach-Object { Write-Host "  Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
}

$func = $ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Get-V264357'
}, $true) | Select-Object -First 1

if ($func) {
    Write-Host "`n=== Get-V264357 AST Analysis ===" -ForegroundColor Cyan
    Write-Host "Function starts at line: $($func.Extent.StartLineNumber)" -ForegroundColor Green
    Write-Host "Function ends at line: $($func.Extent.EndLineNumber)" -ForegroundColor Green
    Write-Host "Body starts at line: $($func.Body.Extent.StartLineNumber)" -ForegroundColor Green
    Write-Host "Body ends at line: $($func.Body.Extent.EndLineNumber)" -ForegroundColor Green
    Write-Host "Statement count in body: $($func.Body.Statements.Count)" -ForegroundColor Green
    Write-Host "ScriptBlock length: $($func.Body.Extent.Text.Length) characters" -ForegroundColor Green

    # Check for early returns
    $returns = $func.FindAll({param($node)
        $node -is [System.Management.Automation.Language.ReturnStatementAst]
    }, $true)

    Write-Host "`nReturn statements found: $($returns.Count)" -ForegroundColor Yellow
    foreach ($return in $returns) {
        Write-Host "  Line $($return.Extent.StartLineNumber): $($return.Extent.Text.Substring(0, [Math]::Min(80, $return.Extent.Text.Length)))" -ForegroundColor Gray
    }
} else {
    Write-Host "Function not found in AST" -ForegroundColor Red
}
