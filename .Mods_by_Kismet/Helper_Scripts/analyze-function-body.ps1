#!/usr/bin/env pwsh
# Analyze why Get-V264357 body has 0 statements

$modulePath = "../../Modules/Scan-XO_WebSRG_Checks/Scan-XO_WebSRG_Checks.psm1"

Write-Host "Parsing module..." -ForegroundColor Cyan
$ast = [System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$null)

$func = $ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Get-V264357'
}, $true) | Select-Object -First 1

if ($func) {
    Write-Host "`nFunction: $($func.Name)" -ForegroundColor Cyan
    Write-Host "Start line: $($func.Extent.StartLineNumber)"
    Write-Host "End line: $($func.Extent.EndLineNumber)"
    Write-Host "Total lines: $($func.Extent.EndLineNumber - $func.Extent.StartLineNumber + 1)"

    Write-Host "`nFunction Body:" -ForegroundColor Cyan
    Write-Host "Body start line: $($func.Body.Extent.StartLineNumber)"
    Write-Host "Body end line: $($func.Body.Extent.EndLineNumber)"
    Write-Host "Statement count: $($func.Body.Statements.Count)"
    Write-Host "Body text length: $($func.Body.Extent.Text.Length) chars"

    Write-Host "`nFirst 500 chars of body text:" -ForegroundColor Yellow
    Write-Host $func.Body.Extent.Text.Substring(0, [Math]::Min(500, $func.Body.Extent.Text.Length))

    Write-Host "`n`nCompare with working function Get-V206351..." -ForegroundColor Cyan
    $func2 = $ast.FindAll({param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-V206351'
    }, $true) | Select-Object -First 1

    if ($func2) {
        Write-Host "Get-V206351 body statements: $($func2.Body.Statements.Count)"
        Write-Host "Get-V206351 body text length: $($func2.Body.Extent.Text.Length) chars"
    }
}
